package dockercontrol

import (
	"context"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
)

// ControlSourceSession owns a read-only source/root probe and a GET-only
// collector. It deliberately has no Store, Initialize, Open or write method.
// Canonical Profile input describes expected facts, not runtime authority.
type ControlSourceSession struct {
	mu           sync.Mutex
	observer     *controlStorageUnixObserver
	probe        *controlstorage.SourceProbe
	startup      phase6fdloader.StartupBinding
	service      phase6security.ControlServiceIdentityV1
	profileBytes string
	initial      phase6process.SourceObservation
	closed       bool
	anchors      []*trustanchor.DirectorySession
}

func sourceSessionBinding(document []byte, startup phase6fdloader.StartupBinding) (controlStorageBinding, phase6security.ControlServiceIdentityV1, string, error) {
	var zero controlStorageBinding
	var service phase6security.ControlServiceIdentityV1
	if len(startup.ContainerID) != 64 || !phase6security.ControlObservesSource(startup.Target) || startup.Validate(startup.ContainerID[:12]) != nil {
		return zero, service, "", ErrInvalidCodingInventory
	}
	review, e := phase6security.ReviewControlBootstrap(document)
	r, re := phase6security.ReviewControlSourceProfile(document)
	if e != nil || re != nil || review.Bootstrap.Target != startup.Target {
		return zero, service, "", ErrInvalidCodingInventory
	}
	for _, s := range review.Services {
		if s.Launch.Target == startup.Target {
			service = s
		}
	}
	ns := r.Source.Intent.Namespace
	b := controlStorageBinding{profileSource: &r, sourceService: &service, Storage: controlstorage.Binding{Layout: controlstorage.NewLayout(), Namespace: ns, StorageID: "control-execution-" + ns, ProfileDigest: r.ProfileDigest, TemplateDigest: r.TemplateDigest, ControlPrincipalDigest: r.Control.PrincipalDigest, UID: r.Control.UID, GID: r.Control.GID}, SourceSealDigest: r.Source.SealDigest, SourceSocket: r.Source.Intent.SocketSource, ControlID: startup.ContainerID, ControlName: "control-execution-" + ns, ControlImageID: sourceControlImageID(r.Control)}
	b.EndpointScopeDigest = executionDigest("control-source-observation-endpoint-v1", struct{ Profile, Socket string }{review.ProfileBytesDigest, controlStorageSocketTarget})
	b.Backend = controlstorage.DedicatedBackend{Protocol: controlstorage.DedicatedBackendProtocol, Device: r.Source.Intent.SelectedDevice, Bytes: r.Source.Intent.SealedImageBytes}
	return b, service, review.ProfileBytesDigest, nil
}

// CheckSourceControlContainer is a host-side read-only projection. It grants
// nothing and does not accept a caller-built review as canonical authority.
func CheckSourceControlContainer(document []byte, startup phase6fdloader.StartupBinding, c container.InspectResponse, back volume.Volume, running bool) error {
	b, service, _, e := sourceSessionBinding(document, startup)
	if e != nil || back.Name != b.backingVolume() || !safeStoragePath(back.Mountpoint) {
		return ErrInvalidCodingInventory
	}
	b.Backend.BackingFile = back.Mountpoint + "/receipt.ext4"
	b.Daemon.Platform = b.profileSource.Control.ImagePlatform
	if !validControlStorageVolume(back, b, true) || !sourceSessionContainer(c, b, service, startup, running) || !safeProfileSourceMountedAccess(c, b, back) || running && !safeProfileSourceControlAccess(c, b, back) {
		return ErrInvalidCodingInventory
	}
	return nil
}

func sourceSessionContainer(c container.InspectResponse, b controlStorageBinding, service phase6security.ControlServiceIdentityV1, startup phase6fdloader.StartupBinding, running bool) bool {
	if c.Config == nil || c.HostConfig == nil || !sourceSessionHostPolicy(c.HostConfig) || c.State == nil || c.ID != startup.ContainerID || len(c.ID) != 64 {
		return false
	}
	v, h, st := c.Config, c.HostConfig, c.State
	if c.Name != "/"+b.ControlName || !maps.Equal(v.Labels, b.labels("control")) || !sourceControlImageMatches(c, service.Principal) || c.RestartCount != 0 || st.Running != running || st.Paused || st.Restarting || st.Dead || st.OOMKilled || st.Error != "" || st.Health != nil {
		return false
	}
	created, ce := time.Parse(time.RFC3339Nano, c.Created)
	if ce != nil || created.IsZero() {
		return false
	}
	if running {
		started, e := time.Parse(time.RFC3339Nano, st.StartedAt)
		if e != nil || started.Before(created) || st.Pid <= 0 || st.Status != "running" {
			return false
		}
	} else if st.Status != "created" || st.Pid != 0 {
		return false
	}
	if c.Path != "/bin/sh" || !slices.Equal(c.Args, service.Entrypoint[1:]) || !slices.Equal(v.Entrypoint, service.Entrypoint) || len(v.Cmd) != 0 || v.User != fmt.Sprintf("%d:%d", b.Storage.UID, b.Storage.GID) || v.WorkingDir != "/" || v.Hostname != c.ID[:12] || v.Domainname != "" || v.Tty || !v.OpenStdin || !v.StdinOnce || len(v.ExposedPorts) != 0 || len(v.Volumes) != 0 || v.Healthcheck != nil || len(v.OnBuild) != 0 || v.StopSignal != "" {
		return false
	}
	want := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SR_PHASE6_FD_RUN_ID=" + startup.RunID, "SR_PHASE6_FD_TARGET=" + startup.Target, "SR_PHASE6_FD_NONCE=" + startup.Nonce}
	actual := slices.Clone(v.Env)
	slices.Sort(actual)
	slices.Sort(want)
	return slices.Equal(actual, want) && h.Runtime == "runc" && h.ReadonlyRootfs && !h.Privileged && slices.Equal(h.CapDrop, []string{"ALL"}) && len(h.CapAdd) == 0 && len(h.Binds) == 0 && len(h.VolumesFrom) == 0 && len(h.DeviceRequests) == 0 && len(h.DeviceCgroupRules) == 0 && h.PidMode == "" && h.Init == nil && !h.AutoRemove && h.RestartPolicy.Name == "no" && h.RestartPolicy.MaximumRetryCount == 0 && (h.OomKillDisable == nil || !*h.OomKillDisable)
}

// PrepareControlSource observes physical inputs without writing a namespace
// marker. The caller must retain and close it across its signature ceremony.
func PrepareControlSource(ctx context.Context, document []byte, startup phase6fdloader.StartupBinding) (out *ControlSourceSession, err error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	host, e := os.Hostname()
	if e != nil || startup.Validate(host) != nil {
		return nil, ErrInvalidCodingInventory
	}
	b, service, digest, e := sourceSessionBinding(document, startup)
	if e != nil {
		return nil, e
	}
	o, e := openControlStorageReadAPI(codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}, b, nil)
	if e != nil {
		return nil, e
	}
	s := &ControlSourceSession{observer: o, startup: startup, service: service, profileBytes: digest}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	b.Daemon, e = ObserveCodingDaemon(ctx, o.api, b.EndpointScopeDigest)
	if e != nil {
		return nil, e
	}
	back, e := o.api.VolumeInspect(ctx, b.backingVolume(), client.VolumeInspectOptions{})
	if e != nil || back.Volume.Name != b.backingVolume() || !safeStoragePath(back.Volume.Mountpoint) {
		return nil, ErrInvalidCodingInventory
	}
	b.Backend.BackingFile = back.Volume.Mountpoint + "/receipt.ext4"
	if b.validate() != nil {
		return nil, ErrInvalidCodingInventory
	}
	b.sourceVolumes, e = readSourceVolumeBinding(ctx, o.api, b)
	if e != nil {
		return nil, e
	}
	o.binding = b
	if _, e = readControlStorageInventory(ctx, o.api, b); e != nil {
		return nil, e
	}
	s.probe, e = controlstorage.ProbeSourceBound(ctx, controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	if e != nil {
		return nil, e
	}
	if startup.Target == phase6security.ControlTrustTarget {
		if len(b.profileSource.TrustAnchors) != 2 {
			return nil, ErrInvalidCodingInventory
		}
		for _, anchor := range b.profileSource.TrustAnchors {
			v, err := trustanchor.RetainDirectory(ctx, anchor, time.Now())
			if err != nil {
				return nil, ErrInvalidCodingInventory
			}
			s.anchors = append(s.anchors, v)
		}
	}
	s.initial, e = s.read(ctx)
	if e != nil {
		return nil, e
	}
	return s, nil
}

func (s *ControlSourceSession) process(ctx context.Context) (string, error) {
	// Listing registers the exact bounded set of IDs in the GET-only transport.
	if _, e := s.observer.api.ContainerList(ctx, client.ContainerListOptions{All: true}); e != nil {
		return "", e
	}
	v, e := s.observer.api.ContainerInspect(ctx, s.startup.ContainerID, client.ContainerInspectOptions{})
	if e != nil || !sourceSessionContainer(v.Container, s.observer.binding, s.service, s.startup, true) {
		return "", ErrInvalidCodingInventory
	}
	p, e := phase6process.ObservePID1(ctx)
	if e != nil || phase6process.Verify(p, s.service, "role") != nil {
		return "", ErrInvalidCodingInventory
	}
	c := v.Container
	return executionDigest("control-source-process-session-v1", struct {
		ID, Created, Started string
		PID                  int
		Process              phase6process.Observation
	}{c.ID, c.Created, c.State.StartedAt, c.State.Pid, p}), nil
}
func (s *ControlSourceSession) read(ctx context.Context) (phase6process.SourceObservation, error) {
	zero := phase6process.SourceObservation{}
	b, o := s.observer.binding, s.observer
	a, e := s.process(ctx)
	if e != nil {
		return zero, e
	}
	vol, e := readSourceVolumeBinding(ctx, o.api, b)
	if e != nil || vol != b.sourceVolumes {
		return zero, ErrInvalidCodingInventory
	}
	root, e := s.probe.Observe(ctx)
	if e != nil {
		return zero, e
	}
	trust, e := s.observeTrust(ctx)
	if e != nil {
		return zero, e
	}
	inv, e := readControlStorageInventory(ctx, o.api, b)
	if e != nil {
		return zero, e
	}
	end, e := readControlStorageInventory(ctx, o.api, b)
	if e != nil || inv != end {
		return zero, ErrInvalidCodingInventory
	}
	last, e := s.probe.Observe(ctx)
	if e != nil || root != last {
		return zero, ErrInvalidCodingInventory
	}
	vend, e := readSourceVolumeBinding(ctx, o.api, b)
	if e != nil || vol != vend {
		return zero, ErrInvalidCodingInventory
	}
	proc, e := s.process(ctx)
	if e != nil || a != proc || ctx.Err() != nil {
		return zero, ErrInvalidCodingInventory
	}
	endTrust, e := s.observeTrust(ctx)
	if e != nil || !reflect.DeepEqual(trust, endTrust) {
		return zero, ErrInvalidCodingInventory
	}
	protocol := phase6security.ControlSourceObservationProtocol
	if s.startup.Target == phase6security.ControlTrustTarget {
		protocol = phase6security.ControlTrustObservationProtocol
	}
	return phase6process.SourceObservation{Protocol: protocol, ProfileBytesDigest: s.profileBytes, Namespace: b.Storage.Namespace, Intent: b.profileSource.Source.IntentDigest, Seal: b.SourceSealDigest, Root: root, Volumes: vol, Inventory: inv, ProcessSession: proc, Trust: trust}, nil
}

func (s *ControlSourceSession) observeTrust(ctx context.Context) (*phase6process.TrustObservation, error) {
	if s.startup.Target != phase6security.ControlTrustTarget {
		if len(s.anchors) != 0 {
			return nil, ErrInvalidCodingInventory
		}
		return nil, nil
	}
	b := s.observer.binding
	if len(s.anchors) != 2 || len(b.profileSource.TrustAnchors) != 2 {
		return nil, ErrInvalidCodingInventory
	}
	out := &phase6process.TrustObservation{}
	for i, anchor := range b.profileSource.TrustAnchors {
		artifact, e := s.anchors[i].Observe(ctx, time.Now())
		if e != nil {
			return nil, ErrInvalidCodingInventory
		}
		v, e := s.observer.api.VolumeInspect(ctx, b.profileVolume(phase6security.Mount{StorageID: anchor.StorageID}), client.VolumeInspectOptions{})
		if e != nil {
			return nil, ErrInvalidCodingInventory
		}
		out.Anchors = append(out.Anchors, phase6process.AnchorObservation{ID: anchor.ID, StorageID: anchor.StorageID, VolumeDigest: executionDigest("control-trust-volume-v1", v.Volume), Artifact: artifact})
	}
	return out, nil
}
func (s *ControlSourceSession) Observe(ctx context.Context) (phase6process.SourceObservation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return phase6process.SourceObservation{}, ErrInvalidCodingInventory
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.observer == nil || s.probe == nil {
		return phase6process.SourceObservation{}, ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	v, e := s.read(ctx)
	if e != nil || !reflect.DeepEqual(v, s.initial) {
		s.closeLocked()
		return phase6process.SourceObservation{}, ErrInvalidCodingInventory
	}
	return v, nil
}
func (s *ControlSourceSession) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	for _, a := range s.anchors {
		_ = a.Close()
	}
	s.anchors = nil
	if s.probe != nil {
		s.probe.Close()
		s.probe = nil
	}
	if s.observer != nil {
		s.observer.api.Close()
		s.observer.transport.CloseIdleConnections()
		s.observer = nil
	}
}
func (s *ControlSourceSession) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
}

// This target has no daemon-side log exporter or resource override beyond the
// canonical Profile budget. These are executable policy, not caller defaults.
func sourceSessionHostPolicy(h *container.HostConfig) bool {
	if h == nil {
		return false
	}
	r := h.Resources
	if h.LogConfig.Type != "none" || len(h.LogConfig.Config) != 0 || h.ShmSize != 64<<20 || h.OomScoreAdj != 0 || h.ContainerIDFile != "" || h.VolumeDriver != "" || h.ConsoleSize != [2]uint{} || len(h.Annotations) != 0 || h.Cgroup != "" || len(h.StorageOpt) != 0 || h.Isolation != "" {
		return false
	}
	if r.CPUShares != 0 || r.CPUPeriod != 0 || r.CPUQuota != 0 || r.CPURealtimePeriod != 0 || r.CPURealtimeRuntime != 0 || r.CpusetCpus != "" || r.CpusetMems != "" || r.MemoryReservation != 0 || r.MemorySwappiness != nil || len(r.Ulimits) != 0 || r.BlkioWeight != 0 || len(r.BlkioWeightDevice)+len(r.BlkioDeviceReadBps)+len(r.BlkioDeviceWriteBps)+len(r.BlkioDeviceReadIOps)+len(r.BlkioDeviceWriteIOps) != 0 || r.CPUCount != 0 || r.CPUPercent != 0 || r.IOMaximumIOps != 0 || r.IOMaximumBandwidth != 0 {
		return false
	}
	masked := []string{"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore", "/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi", "/proc/timer_list", "/proc/timer_stats", "/sys/devices/virtual/powercap", "/sys/firmware"}
	readonly := []string{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}
	return slices.Equal(h.MaskedPaths, masked) && slices.Equal(h.ReadonlyPaths, readonly)
}
