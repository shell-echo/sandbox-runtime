package dockercontrol

import (
	"context"
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const controlStorageTarget = "/var/lib/sandbox-runtime/control-receipts"
const maxControlStorageContainers = 128
const maxControlStorageVolumes = 256

// Held source requirement, deliberately private. There is no production
// constructor while complete Profile admission and provisioning remain closed.
type controlStorageBinding struct {
	boundary                               *phase6security.ControlConsumerBoundary  // held diagnostic projection; not production admission
	profileSource                          *phase6security.ControlSourceReview      // held read-only source session or explicit test fixture
	sourceService                          *phase6security.ControlServiceIdentityV1 // canonical v3 service, never external admission
	sourceVolumes                          string                                   // derived by the closed constructor, never input authority
	Storage                                controlstorage.Binding
	SourceSealDigest                       string
	SourceSocket                           string
	Backend                                controlstorage.DedicatedBackend
	Daemon                                 CodingDaemonObservation
	EndpointScopeDigest                    string
	ControlID, ControlName, ControlImageID string
}

func (b controlStorageBinding) backingVolume() string {
	return "control-backing-" + b.Storage.Namespace
}
func (b controlStorageBinding) validate() error {
	if b.sourceService != nil && (b.profileSource == nil || !phase6security.ControlObservesSource(b.sourceService.Launch.Target) || len(b.sourceService.Launch.SourceRevision) != 40 || executionDigest("principal", b.sourceService.Principal) != executionDigest("principal", b.profileSource.Control)) {
		return ErrInvalidCodingInventory
	}
	if (b.SourceSealDigest == "") != (b.SourceSocket == "") || (b.SourceSealDigest != "" && (!controlDigest.MatchString(b.SourceSealDigest) || (b.SourceSocket != "/var/run/docker.sock" && b.SourceSocket != "/run/host-services/docker.proxy.sock") || b.Backend.Device != "/dev/loop7" || b.Storage.UID != 57010 || b.Storage.GID != 57011)) {
		return ErrInvalidCodingInventory
	}
	if b.boundary != nil && (b.profileSource == nil || b.boundary.Protocol != phase6security.ControlConsumerBoundaryProtocol || !controlDigest.MatchString(b.boundary.ProfileBytesDigest) || executionDigest("review", b.boundary.Review) != executionDigest("review", b.profileSource)) {
		return ErrInvalidCodingInventory
	}
	if !b.profileSourceMatches() || b.Storage.Validate() != nil || b.Backend.Validate() != nil || b.Storage.StorageID != "control-execution-"+b.Storage.Namespace ||
		!codingArchiveRuntimeID.MatchString(b.ControlID) || !controlDigest.MatchString(b.ControlImageID) ||
		b.ControlName != "control-execution-"+b.Storage.Namespace || !controlDigest.MatchString(b.EndpointScopeDigest) ||
		!controlDigest.MatchString(b.Daemon.IdentityDigest) || !controlDigest.MatchString(b.Daemon.EnvironmentDigest) ||
		(b.Daemon.Platform != "linux/arm64/v8" && b.Daemon.Platform != "linux/amd64") {
		return ErrInvalidCodingInventory
	}
	return nil
}
func (b controlStorageBinding) labels(role string) map[string]string {
	labels := map[string]string{"sandbox-runtime.control-storage.namespace": b.Storage.Namespace,
		"sandbox-runtime.control-storage.profile":   b.Storage.ProfileDigest,
		"sandbox-runtime.control-storage.principal": b.Storage.ControlPrincipalDigest,
		"sandbox-runtime.control-storage.backend":   executionDigest("dedicated-backend", b.Backend),
		"sandbox-runtime.control-storage.role":      role}
	if b.SourceSealDigest != "" && role != "backing" {
		labels["sandbox-runtime.control-storage.source"] = b.SourceSealDigest
	}
	if b.profileSource != nil {
		labels["sandbox-runtime.control-storage.mode"] = phase6security.ControlSourceAccessProtocol
		labels["sandbox-runtime.control-storage.intent"] = b.profileSource.Source.IntentDigest
		if role == "backing" {
			delete(labels, "sandbox-runtime.control-storage.profile")
		}
	}
	if b.boundary != nil && role != "backing" {
		labels["sandbox-runtime.control-storage.boundary"] = phase6security.ControlConsumerBoundaryProtocol
	}
	if role == "control" && b.sourceService != nil {
		maps.Copy(labels, phase6security.ControlSourceImageLabels(*b.sourceService))
	}
	return labels
}

// A bounded observation of daemon objects, not future exclusion, a host-writer
// proof, a provisioning receipt, or dispatch permission. No raw coordinates
// escape this private component; stopped containers count as consumers too.
type controlStorageObservation struct{ RootDigest, InventoryDigest string }

func observeControlStorage(ctx context.Context, api *client.Client, store *controlstorage.Store, b controlStorageBinding) (controlStorageObservation, error) {
	if ctx == nil || ctx.Err() != nil || api == nil || store == nil || b.validate() != nil {
		return controlStorageObservation{}, ErrInvalidCodingInventory
	}
	ctx, cancel := context.WithTimeout(ctx, maxCodingInventoryDuration)
	defer cancel()
	if b.SourceSealDigest != "" {
		v, e := readSourceVolumeBinding(ctx, api, b)
		if e != nil || v != b.sourceVolumes {
			return controlStorageObservation{}, ErrInvalidCodingInventory
		}
	}
	root, err := observeStorageRoot(ctx, store, b)
	if err != nil {
		return controlStorageObservation{}, ErrInvalidCodingInventory
	}
	a, err := readControlStorageInventory(ctx, api, b)
	if err != nil {
		return controlStorageObservation{}, err
	}
	z, err := readControlStorageInventory(ctx, api, b)
	if err != nil || a != z {
		return controlStorageObservation{}, ErrInvalidCodingInventory
	}
	end, err := observeStorageRoot(ctx, store, b)
	if err != nil || root != end || ctx.Err() != nil {
		return controlStorageObservation{}, ErrInvalidCodingInventory
	}
	if b.SourceSealDigest != "" {
		v, e := readSourceVolumeBinding(ctx, api, b)
		if e != nil || v != b.sourceVolumes {
			return controlStorageObservation{}, ErrInvalidCodingInventory
		}
	}
	return controlStorageObservation{root, a}, nil
}

func observeStorageRoot(ctx context.Context, store *controlstorage.Store, b controlStorageBinding) (string, error) {
	if b.SourceSealDigest != "" {
		return store.ObserveSourceBound(ctx, controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, b.sourceVolumes)
	}
	return store.ObserveDedicated(ctx, controlStorageTarget, b.Storage, b.Backend)
}

type controlStorageReader interface {
	codingInfoReader
	VolumeInspect(context.Context, string, client.VolumeInspectOptions) (client.VolumeInspectResult, error)
	VolumeList(context.Context, client.VolumeListOptions) (client.VolumeListResult, error)
	ContainerList(context.Context, client.ContainerListOptions) (client.ContainerListResult, error)
	ContainerInspect(context.Context, string, client.ContainerInspectOptions) (client.ContainerInspectResult, error)
}

func readControlStorageInventory(ctx context.Context, api controlStorageReader, b controlStorageBinding) (string, error) {
	fail := func() (string, error) { return "", ErrInvalidCodingInventory }
	if ctx == nil || ctx.Err() != nil || api == nil || b.validate() != nil {
		return fail()
	}
	daemon, err := ObserveCodingDaemon(ctx, api, b.EndpointScopeDigest)
	if err != nil || daemon != b.Daemon {
		return fail()
	}
	v, err := api.VolumeInspect(ctx, b.Storage.StorageID, client.VolumeInspectOptions{})
	if err != nil || !validControlStorageVolume(v.Volume, b, false) {
		return fail()
	}
	back, err := api.VolumeInspect(ctx, b.backingVolume(), client.VolumeInspectOptions{})
	if err != nil || !validControlStorageVolume(back.Volume, b, true) || b.Backend.BackingFile != back.Volume.Mountpoint+"/receipt.ext4" || pathsOverlap(v.Volume.Mountpoint, back.Volume.Mountpoint) {
		return fail()
	}
	volumes, err := api.VolumeList(ctx, client.VolumeListOptions{})
	if err != nil || len(volumes.Warnings) != 0 || len(volumes.Items) < 2 || len(volumes.Items) > maxControlStorageVolumes {
		return fail()
	}
	seen := map[string]bool{}
	for _, item := range volumes.Items {
		if item.Name == "" || seen[item.Name] || item.Driver != "local" || item.Scope != "local" || !safeStoragePath(item.Mountpoint) {
			return fail()
		}
		seen[item.Name] = true
		switch item.Name {
		case b.Storage.StorageID:
			if !sameControlStorageVolume(item, v.Volume) {
				return fail()
			}
		case b.backingVolume():
			if !sameControlStorageVolume(item, back.Volume) {
				return fail()
			}
		default:
			if pathsOverlap(item.Mountpoint, v.Volume.Mountpoint) || pathsOverlap(item.Mountpoint, back.Volume.Mountpoint) ||
				item.Options["device"] == b.Backend.Device || pathsOverlap(item.Options["device"], b.Backend.BackingFile) ||
				pathsOverlap(item.Options["device"], v.Volume.Mountpoint) || pathsOverlap(item.Options["device"], back.Volume.Mountpoint) || (b.SourceSealDigest != "" && sourceSocketOverlap(item.Options["device"])) {
				return fail()
			}
		}
	}
	if !seen[b.Storage.StorageID] || !seen[b.backingVolume()] {
		return fail()
	}
	list, err := api.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil || len(list.Items) == 0 || len(list.Items) > maxControlStorageContainers {
		return fail()
	}
	seen = map[string]bool{}
	projections := map[string]string{}
	inspected := map[string]container.InspectResponse{}
	for _, item := range list.Items {
		if !codingArchiveRuntimeID.MatchString(item.ID) || seen[item.ID] {
			return fail()
		}
		seen[item.ID] = true
		r, err := api.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		c := r.Container
		if err != nil || c.ID != item.ID || c.Config == nil || c.HostConfig == nil || c.State == nil || len(item.Names) != 1 || item.Names[0] != c.Name ||
			!sameControlStorageMounts(item.Mounts, c.Mounts, b, c.ID == b.ControlID) || item.State != c.State.Status ||
			!safeStorageContainer(c, b, v.Volume, back.Volume) {
			return fail()
		}
		// Validate the raw list projection too; a Desktop path representation
		// rule must never erase an unsafe source before the alias checks.
		listed := c
		listed.Mounts = item.Mounts
		if !safeStorageContainer(listed, b, v.Volume, back.Volume) {
			return fail()
		}
		inspected[c.ID] = c
		if c.ID == b.ControlID && b.profileSource != nil && b.boundary == nil {
			d, e := readControlProfileStagingObjects(ctx, api, b, c, volumes.Items)
			if e != nil {
				return fail()
			}
			projections["profile-objects"] = d
		}
		// Include only durable/configuration facts; health log timestamps and
		// counters are not identities. Relevant drift still rejects the bracket.
		projections[c.ID] = executionDigest("control-storage-container", struct {
			Name, Image, User           string
			Running, Paused, Restarting bool
			Host                        *container.HostConfig
			Mounts                      []container.MountPoint
			Labels                      map[string]string
		}{c.Name, c.Image, c.Config.User, c.State.Running, c.State.Paused, c.State.Restarting, c.HostConfig, c.Mounts, c.Config.Labels})
	}
	if b.boundary != nil {
		d, e := readControlBoundaryObjects(ctx, api, b, inspected, volumes.Items)
		if e != nil {
			return fail()
		}
		projections["boundary-objects"] = d
	}
	if !seen[b.ControlID] {
		return fail()
	}
	// Do not hide creates/removes during the per-container inspect walk.
	endList, err := api.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil || len(endList.Items) != len(list.Items) {
		return fail()
	}
	initial := map[string]string{}
	for _, c := range list.Items {
		initial[c.ID] = storageSummaryDigest(c)
	}
	for _, c := range endList.Items {
		if !seen[c.ID] || initial[c.ID] != storageSummaryDigest(c) {
			return fail()
		}
		delete(seen, c.ID)
	}
	after, err := ObserveCodingDaemon(ctx, api, b.EndpointScopeDigest)
	if err != nil || after != daemon || ctx.Err() != nil {
		return fail()
	}
	slices.SortFunc(volumes.Items, func(a, z volume.Volume) int { return strings.Compare(a.Name, z.Name) })
	return executionDigest("control-storage-inventory", struct {
		Volumes    []volume.Volume
		Containers map[string]string
		Summaries  map[string]string
	}{volumes.Items, projections, initial}), nil
}

// The observed Docker Desktop proxy represents unrelated macOS bind sources
// differently in list and inspect. Only this exact mapping is permitted for
// the new held local candidate. Owned/volume/socket projections stay exact.
func sameControlStorageMounts(listed, inspected []container.MountPoint, b controlStorageBinding, owned bool) bool {
	if len(listed) != len(inspected) {
		return false
	}
	copy := slices.Clone(listed)
	for i := range copy {
		a, z := copy[i], inspected[i]
		if !owned && b.SourceSealDigest != "" && b.SourceSocket == "/run/host-services/docker.proxy.sock" && a.Type == "bind" && z.Type == "bind" && safeStoragePath(a.Source) && safeStoragePath(z.Source) && strings.HasPrefix(z.Source, "/Users/") && a.Source == "/host_mnt"+z.Source {
			copy[i].Source = z.Source
		}
	}
	return executionDigest("mounts", copy) == executionDigest("mounts", inspected)
}

func storageSummaryDigest(c container.Summary) string {
	return executionDigest("control-storage-summary", struct {
		ID      string
		Names   []string
		ImageID string
		State   container.ContainerState
		Mounts  []container.MountPoint
		Labels  map[string]string
	}{c.ID, c.Names, c.ImageID, c.State, c.Mounts, c.Labels})
}

func safeStoragePath(p string) bool {
	return p != "" && path.IsAbs(p) && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n\t\\")
}
func pathsOverlap(a, b string) bool {
	return safeStoragePath(a) && safeStoragePath(b) && (a == b || strings.HasPrefix(a, strings.TrimSuffix(b, "/")+"/") || strings.HasPrefix(b, strings.TrimSuffix(a, "/")+"/"))
}
func sameControlStorageVolume(a, b volume.Volume) bool {
	return executionDigest("control-storage-volume", a) == executionDigest("control-storage-volume", b)
}
func validControlStorageVolume(v volume.Volume, b controlStorageBinding, backing bool) bool {
	name, role := b.Storage.StorageID, "filesystem"
	// Local-driver propagation is applied to the daemon's filesystem mount.
	// The live Store fd must still independently prove the resulting private
	// mount: this option string alone is never physical admission evidence.
	options := map[string]string{"type": "ext4", "device": b.Backend.Device, "o": "rw,nosuid,nodev,noexec,private"}
	if backing {
		name, role, options = b.backingVolume(), "backing", nil
	}
	return v.Name == name && v.Driver == "local" && v.Scope == "local" && safeStoragePath(v.Mountpoint) &&
		strings.HasSuffix(v.Mountpoint, "/volumes/"+name+"/_data") && maps.Equal(v.Labels, b.labels(role)) && maps.Equal(v.Options, options) && v.ClusterVolume == nil && len(v.Status) == 0
}

func safeStorageContainer(c container.InspectResponse, b controlStorageBinding, v, backing volume.Volume) bool {
	h := c.HostConfig
	owned := c.ID == b.ControlID
	source := owned && b.SourceSealDigest != ""
	// The held full-shape fixture has no other authorized input consumers, even
	// stopped. Production sharing with independently identified TLS/CA peers is
	// not implied by this private staging branch.
	peer := b.boundaryPeer(c)
	if peer != nil && !safeControlBoundaryPeer(c, b, *peer, backing) {
		return false
	}
	if !owned && b.profileSource != nil && peer == nil {
		for _, want := range b.profileSource.Control.Mounts {
			if want.Kind == "daemon_socket" || want.Kind == "persistent_ledger" || want.Kind == "control_source" {
				continue
			}
			name := b.profileVolume(want)
			root := strings.TrimSuffix(backing.Mountpoint, "/"+backing.Name+"/_data") + "/" + name + "/_data"
			for _, m := range c.Mounts {
				if m.Name == name || pathsOverlap(m.Source, root) {
					return false
				}
			}
			for _, m := range h.Mounts {
				if m.Source == name || pathsOverlap(m.Source, root) {
					return false
				}
			}
			for _, bind := range h.Binds {
				part := strings.Split(bind, ":")[0]
				if part == name || pathsOverlap(part, root) {
					return false
				}
			}
		}
	}
	if source && ((b.profileSource == nil && !safeSourceControlAccess(c, b, backing)) || (b.profileSource != nil && !safeProfileSourceControlAccess(c, b, backing))) {
		return false
	}
	// Refuse authority that defeats device/mount observation, even on stopped
	// containers that could be restarted. This is not a daemon-client census.
	if h.Privileged || (!source && len(h.Devices) != 0) || len(h.DeviceRequests) != 0 || len(h.DeviceCgroupRules) != 0 ||
		(h.PidMode != "" && h.PidMode != "private") || h.IpcMode.IsHost() || h.NetworkMode.IsHost() || h.UsernsMode.IsHost() {
		return false
	}
	for _, cap := range h.CapAdd {
		if cap == "ALL" || strings.TrimPrefix(cap, "CAP_") == "SYS_ADMIN" {
			return false
		}
	}
	if len(h.VolumesFrom) != 0 {
		return false
	}
	for _, bind := range h.Binds {
		parts := strings.Split(bind, ":")
		if len(parts) < 2 || len(parts) > 3 || !safeStoragePath(parts[1]) ||
			(b.SourceSealDigest != "" && sourceSocketOverlap(parts[0])) || parts[0] == v.Name || parts[0] == backing.Name || pathsOverlap(parts[0], v.Mountpoint) ||
			pathsOverlap(parts[0], backing.Mountpoint) || pathsOverlap(parts[0], b.Backend.Device) {
			return false
		}
	}
	for _, m := range h.Mounts {
		if b.SourceSealDigest != "" && !owned && sourceSocketOverlap(m.Source) {
			return false
		}
		if (m.Source == backing.Name || pathsOverlap(m.Source, backing.Mountpoint)) && !(source && m.Type == "volume" && m.Source == backing.Name && m.Target == controlstorage.SourceMountPath && m.ReadOnly && m.VolumeOptions != nil && m.VolumeOptions.NoCopy && m.VolumeOptions.Subpath == "") || pathsOverlap(m.Source, b.Backend.Device) {
			return false
		}
		if m.Source == v.Name || pathsOverlap(m.Source, v.Mountpoint) {
			if !owned || m.Type != "volume" || m.Source != v.Name || m.Target != controlStorageTarget {
				return false
			}
		}
	}
	count := 0
	for _, m := range c.Mounts {
		if b.SourceSealDigest != "" && !owned && sourceSocketOverlap(m.Source) {
			return false
		}
		if !safeStoragePath(m.Destination) {
			return false
		}
		exact := m.Type == "volume" && m.Name == v.Name && m.Source == v.Mountpoint
		if m.Type != "tmpfs" && !safeStoragePath(m.Source) {
			return false
		}
		if (m.Name == backing.Name || pathsOverlap(m.Source, backing.Mountpoint)) && !(source && m.Type == "volume" && m.Name == backing.Name && m.Source == backing.Mountpoint && m.Destination == controlstorage.SourceMountPath && !m.RW && m.Driver == "local" && (m.Propagation == "" || m.Propagation == "rprivate")) || pathsOverlap(m.Source, b.Backend.Device) {
			return false
		}
		if m.Name == v.Name || pathsOverlap(m.Source, v.Mountpoint) {
			if !owned || !exact || m.Destination != controlStorageTarget || !m.RW || m.Driver != "local" || (m.Propagation != "" && m.Propagation != "rprivate") || (m.Mode != "" && m.Mode != "rw" && m.Mode != "z") {
				return false
			}
			count++
		} else if owned && pathsOverlap(m.Destination, controlStorageTarget) {
			return false
		}
	}
	if !owned {
		return count == 0
	}
	if count != 1 || c.Name != "/"+b.ControlName || c.Image != b.ControlImageID || !maps.Equal(c.Config.Labels, b.labels("control")) ||
		c.Config.User != fmt.Sprintf("%d:%d", b.Storage.UID, b.Storage.GID) || !c.State.Running || c.State.Paused || c.State.Restarting || c.State.Dead ||
		!h.ReadonlyRootfs || len(h.CapAdd) != 0 || len(h.CapDrop) != 1 || h.CapDrop[0] != "ALL" ||
		!(slices.Contains(h.SecurityOpt, "no-new-privileges") || slices.Contains(h.SecurityOpt, "no-new-privileges:true")) || len(h.Binds) != 0 || len(h.VolumesFrom) != 0 {
		return false
	}
	for target := range h.Tmpfs {
		if pathsOverlap(target, controlStorageTarget) {
			return false
		}
	}
	count = 0
	for _, m := range h.Mounts {
		if pathsOverlap(m.Target, controlStorageTarget) {
			if m.Type != "volume" || m.Source != v.Name || m.Target != controlStorageTarget || m.ReadOnly || m.VolumeOptions == nil || !m.VolumeOptions.NoCopy || m.VolumeOptions.Subpath != "" {
				return false
			}
			count++
		}
	}
	return count == 1
}
