package dockercontrol

import (
	"context"
	"fmt"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const controlStorageSocketTarget = "/run/control-storage-docker.sock"

// This exact held candidate is deliberately not a general permission profile.
func safeSourceControlAccess(c container.InspectResponse, b controlStorageBinding, back volume.Volume) bool {
	h := c.HostConfig
	if h == nil || len(h.GroupAdd) != 1 || h.GroupAdd[0] != "0" || len(h.Devices) != 8 || len(h.Mounts) != 3 || len(c.Mounts) != 3 || len(h.Tmpfs) != 0 || h.NetworkMode != "none" {
		return false
	}
	seen := map[string]bool{}
	for _, d := range h.Devices {
		ok := false
		for i := 0; i < 8; i++ {
			if d.PathOnHost == fmt.Sprintf("/dev/loop%d", i) {
				ok = true
			}
		}
		if !ok || seen[d.PathOnHost] || d.PathInContainer != d.PathOnHost || d.CgroupPermissions != "r" {
			return false
		}
		seen[d.PathOnHost] = true
	}
	backing, socket := 0, 0
	for _, m := range h.Mounts {
		if m.Target == controlstorage.SourceMountPath {
			if m.Type != "volume" || m.Source != back.Name || !m.ReadOnly || m.VolumeOptions == nil || !m.VolumeOptions.NoCopy || m.VolumeOptions.Subpath != "" {
				return false
			}
			backing++
		}
		if m.Target == controlStorageSocketTarget {
			if m.Type != "bind" || m.Source != b.SourceSocket || !m.ReadOnly || m.BindOptions != nil && m.BindOptions.Propagation != "" && m.BindOptions.Propagation != "rprivate" {
				return false
			}
			socket++
		}
	}
	if backing != 1 || socket != 1 {
		return false
	}
	backing, socket = 0, 0
	for _, m := range c.Mounts {
		if m.Destination == controlstorage.SourceMountPath {
			if m.Type != "volume" || m.Name != back.Name || m.Source != back.Mountpoint || m.Driver != "local" || m.RW || (m.Propagation != "" && m.Propagation != "rprivate") {
				return false
			}
			backing++
		}
		if m.Destination == controlStorageSocketTarget {
			if m.Type != "bind" || m.Source != b.SourceSocket || m.RW || m.Propagation != "rprivate" {
				return false
			}
			socket++
		}
	}
	return backing == 1 && socket == 1
}

// sourceBoundControlStorage owns both sessions; it does not expose its Store or
// accept an external observation callback. No production constructor exists.
type sourceBoundControlStorage struct {
	observer  *controlStorageUnixObserver
	poisoned  bool
	admission *controlOperatorSession
}

func openSourceBoundControlStorage(ctx context.Context, endpoint codingBoundUnixEndpoint, b controlStorageBinding, initialize bool) (*sourceBoundControlStorage, error) {
	if b.boundary != nil || controlTrustStorageHeld(b) || ctx == nil || ctx.Err() != nil || b.SourceSealDigest == "" || endpoint.path != controlStorageSocketTarget {
		return nil, ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	o, err := openControlStorageUnixObserver(endpoint, b, nil)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = o.api.Close()
			o.transport.CloseIdleConnections()
			if o.store != nil {
				_ = o.store.Close()
			}
		}
	}()
	a, err := readControlStorageInventory(ctx, o.api, b)
	if err != nil {
		return nil, err
	}
	z, err := readControlStorageInventory(ctx, o.api, b)
	if err != nil || a != z {
		return nil, ErrInvalidCodingInventory
	}
	b.sourceVolumes, err = readSourceVolumeBinding(ctx, o.api, b)
	if err != nil {
		return nil, err
	}
	o.binding = b
	if initialize {
		o.store, err = controlstorage.InitializeSourceBound(ctx, controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	} else {
		o.store, err = controlstorage.OpenSourceBound(controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	}
	if err != nil {
		return nil, err
	}
	// A failure after initialization retains its marker; never remove/retry it.
	observation, err := observeControlStorage(ctx, o.api, o.store, b)
	if err != nil || observation.InventoryDigest != a {
		return nil, controlstorage.ErrUncertain
	}
	ok = true
	return &sourceBoundControlStorage{observer: o}, nil
}

func controlTrustStorageHeld(b controlStorageBinding) bool {
	return b.profileSource != nil && len(b.profileSource.TrustAnchors) != 0 || b.boundary != nil && len(b.boundary.Review.TrustAnchors) != 0 || b.sourceService != nil && b.sourceService.Launch.Target == phase6security.ControlTrustTarget
}

func (s *sourceBoundControlStorage) operation(ctx context.Context, write bool, fn func(context.Context, *controlstorage.Store) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if !s.observer.acquire(ctx) {
		return ErrInvalidCodingInventory
	}
	o := s.observer
	defer func() { o.gate <- struct{}{} }()
	if s.poisoned || o.api == nil || (s.admission != nil && !s.admission.alive()) {
		return ErrInvalidCodingInventory
	}
	a, err := observeControlStorage(ctx, o.api, o.store, o.binding)
	if err != nil || (s.admission != nil && (a.RootDigest != s.admission.request.Root || a.InventoryDigest != s.admission.request.Inventory)) {
		s.poisoned = true
		if err == nil {
			err = ErrInvalidCodingInventory
		}
		return err
	}
	err = fn(ctx, o.store)
	z, end := observeControlStorage(ctx, o.api, o.store, o.binding)
	if end != nil || a != z || (s.admission != nil && !s.admission.alive()) {
		s.poisoned = true
		if write {
			return controlstorage.ErrUncertain
		}
		return ErrInvalidCodingInventory
	}
	return err
}
func (s *sourceBoundControlStorage) Put(ctx context.Context, class controlstorage.Class, key string, data []byte) error {
	return s.operation(ctx, true, func(ctx context.Context, store *controlstorage.Store) error { return store.Put(ctx, class, key, data) })
}
func (s *sourceBoundControlStorage) ReadState(ctx context.Context, key string) (controlstorage.StateSnapshot, error) {
	var out controlstorage.StateSnapshot
	err := s.operation(ctx, false, func(ctx context.Context, store *controlstorage.Store) error {
		var err error
		out, err = store.ReadState(ctx, key)
		return err
	})
	if err != nil {
		return controlstorage.StateSnapshot{}, err
	}
	return out, nil
}
func (s *sourceBoundControlStorage) Check(ctx context.Context) error {
	return s.operation(ctx, false, func(_ context.Context, store *controlstorage.Store) error { return store.Check() })
}

// Close releases local FDs even when the request context was canceled. The
// in-flight operation owns the gate until its bounded external reads finish.
func (s *sourceBoundControlStorage) Close() error {
	if s == nil || !s.observer.acquire(context.Background()) {
		return ErrInvalidCodingInventory
	}
	o := s.observer
	defer func() { o.gate <- struct{}{} }()
	s.poisoned = true
	if o.api != nil {
		_ = o.api.Close()
		o.transport.CloseIdleConnections()
		o.api = nil
	}
	return o.store.Close()
}

// Actual volume creation identities are persisted separately from a container
// session. Recreating the same named volume is not an implicit recovery path.
func readSourceVolumeBinding(ctx context.Context, api controlStorageReader, b controlStorageBinding) (string, error) {
	d, e := ObserveCodingDaemon(ctx, api, b.EndpointScopeDigest)
	if e != nil || d != b.Daemon {
		return "", ErrInvalidCodingInventory
	}
	v, e := api.VolumeInspect(ctx, b.Storage.StorageID, client.VolumeInspectOptions{})
	if e != nil || !validControlStorageVolume(v.Volume, b, false) {
		return "", ErrInvalidCodingInventory
	}
	back, e := api.VolumeInspect(ctx, b.backingVolume(), client.VolumeInspectOptions{})
	if e != nil || !validControlStorageVolume(back.Volume, b, true) {
		return "", ErrInvalidCodingInventory
	}
	return executionDigest("source-volume-binding", struct {
		SocketSource        string
		Daemon              CodingDaemonObservation
		Endpoint            string
		Filesystem, Backing volume.Volume
	}{b.SourceSocket, d, b.EndpointScopeDigest, v.Volume, back.Volume}), nil
}

func (s *sourceBoundControlStorage) CompareState(ctx context.Context, key string, expected controlstorage.StateSnapshot, data []byte) error {
	return s.operation(ctx, true, func(ctx context.Context, store *controlstorage.Store) error {
		return store.CompareState(ctx, key, expected, data)
	})
}

func sourceSocketOverlap(path string) bool {
	return pathsOverlap(path, "/var/run/docker.sock") || pathsOverlap(path, "/run/docker.sock") || pathsOverlap(path, "/run/host-services/docker.proxy.sock")
}
