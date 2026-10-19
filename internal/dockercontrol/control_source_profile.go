package dockercontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The complete-shape branch remains held. The source session uses it only
// for read-only observation; only explicit integration tests compose a Store.
// Operator review is never admission or dispatch permission.
func (b controlStorageBinding) profileSourceMatches() bool {
	r := b.profileSource
	if r == nil {
		return true
	}
	s := r.Source.Intent
	d, e := s.Digest()
	return e == nil && d == r.Source.IntentDigest && r.Admission == "held-not-a-permit" && r.ProfileDigest == b.Storage.ProfileDigest && r.TemplateDigest == b.Storage.TemplateDigest &&
		r.Control.PrincipalDigest == b.Storage.ControlPrincipalDigest && r.Control.UID == b.Storage.UID && r.Control.GID == b.Storage.GID && s.Namespace == b.Storage.Namespace && r.Source.SealDigest == b.SourceSealDigest && s.SocketSource == b.SourceSocket && s.SelectedDevice == b.Backend.Device && s.SealedImageBytes == b.Backend.Bytes && r.Control.ImagePlatform == b.Daemon.Platform && sourceControlImageID(r.Control) == b.ControlImageID
}
func sourceControlImageID(p phase6security.Principal) string { return p.ImageDigest }
func sourceControlImageMatches(c container.InspectResponse, p phase6security.Principal) bool {
	if c.Config.Image != p.ImageReference || c.Image != p.ImageDigest {
		return false
	}
	if p.ImageIdentityKind == phase6security.ImageIdentityLocalConfig {
		return c.ImageManifestDescriptor == nil
	}
	d := c.ImageManifestDescriptor
	if d == nil || d.Platform == nil || d.MediaType != "application/vnd.oci.image.manifest.v1+json" || d.Size <= 0 {
		return false
	}
	manifest := p.ImageDigest
	if p.ImageIdentityKind == phase6security.ImageIdentityOCIIndex {
		manifest = p.ImageSelectedManifestDigest
	}
	platform := d.Platform.OS + "/" + d.Platform.Architecture
	variant := d.Platform.Variant
	if d.Platform.Architecture == "arm64" && variant == "" {
		variant = "v8"
	}
	if variant != "" {
		platform += "/" + variant
	}
	return d.Digest.String() == manifest && platform == p.ImagePlatform
}
func sourceObjectName(kind, ns, logical string) string {
	s := sha256.Sum256([]byte(logical))
	return "control-" + kind + "-" + ns + "-" + hex.EncodeToString(s[:8])
}
func (b controlStorageBinding) profileVolume(m phase6security.Mount) string {
	switch m.Kind {
	case "control_source":
		return b.backingVolume()
	case "persistent_ledger":
		return b.Storage.StorageID
	}
	return sourceObjectName("input", b.Storage.Namespace, m.StorageID)
}
func (b controlStorageBinding) profileNetwork(logical string) string {
	return sourceObjectName("net", b.Storage.Namespace, logical)
}

func sourceSeccompDigest(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return ""
	}
	data, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	d := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(d[:])
}
func safeProfileSourceConfiguredAccess(c container.InspectResponse, b controlStorageBinding) bool {
	r := b.profileSource
	h := c.HostConfig
	if r == nil || h == nil || c.Config == nil || c.NetworkSettings == nil || !b.profileSourceMatches() {
		return false
	}
	p := r.Control
	if !sourceControlImageMatches(c, p) {
		return false
	}
	if !slices.Equal(h.GroupAdd, []string{"0"}) || len(h.Devices) != 8 || len(h.Mounts) != len(p.Mounts) || len(h.Tmpfs) != 0 || len(h.SecurityOpt) != 2 || h.Memory != p.Resources.MemoryBytes || h.MemorySwap != p.Resources.MemoryBytes || h.NanoCPUs != p.Resources.CPUMillis*1000000 || h.PidsLimit == nil || *h.PidsLimit != p.Resources.PIDs || len(h.PortBindings) != 0 || h.PublishAllPorts || len(c.NetworkSettings.Ports) != 0 || len(c.NetworkSettings.Networks) != 3 || len(h.ExtraHosts) != 0 || len(h.DNS) != 0 || len(h.DNSOptions) != 0 || len(h.DNSSearch) != 0 || len(h.Links) != 0 || len(h.Sysctls) != 0 || h.UTSMode != "" || h.CgroupParent != "" || h.CgroupnsMode != "private" || h.UsernsMode != "" || (h.IpcMode != "private" && h.IpcMode != "") {
		return false
	}
	nnp, seccomp := 0, 0
	for _, opt := range h.SecurityOpt {
		if opt == "no-new-privileges:true" || opt == "no-new-privileges" {
			nnp++
		} else if strings.HasPrefix(opt, "seccomp=") && sourceSeccompDigest(strings.TrimPrefix(opt, "seccomp=")) == p.SeccompDigest {
			seccomp++
		} else {
			return false
		}
	}
	if nnp != 1 || seccomp != 1 {
		return false
	}
	seen := map[string]bool{}
	for _, d := range h.Devices {
		if seen[d.PathOnHost] {
			return false
		}
		seen[d.PathOnHost] = true
		found := false
		for _, want := range r.Source.Intent.Devices {
			if d.PathOnHost == want.Host && d.PathInContainer == want.Target && d.CgroupPermissions == want.Permissions {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	seen = map[string]bool{}
	for _, m := range h.Mounts {
		if seen[m.Target] {
			return false
		}
		seen[m.Target] = true
		found := false
		for _, want := range p.Mounts {
			if m.Target != want.Target {
				continue
			}
			found = true
			if m.ReadOnly != want.ReadOnly || m.Consistency != "" {
				return false
			}
			if want.Kind == "daemon_socket" {
				if m.Type != "bind" || m.Source != b.SourceSocket || m.VolumeOptions != nil || m.BindOptions != nil && (m.BindOptions.NonRecursive || m.BindOptions.CreateMountpoint || m.BindOptions.Propagation != "" && m.BindOptions.Propagation != "rprivate") {
					return false
				}
			} else {
				if m.Type != "volume" || m.Source != b.profileVolume(want) || m.BindOptions != nil || m.VolumeOptions == nil || !m.VolumeOptions.NoCopy || m.VolumeOptions.Subpath != "" || m.VolumeOptions.DriverConfig != nil || len(m.VolumeOptions.Labels) != 0 {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	modeOK := false
	for _, n := range r.Networks {
		name := b.profileNetwork(n.Network.Name)
		if string(h.NetworkMode) == name {
			modeOK = true
		}
		e := c.NetworkSettings.Networks[name]
		if e == nil || e.IPAMConfig == nil || e.IPAMConfig.IPv4Address.String() != n.Address || e.IPAMConfig.IPv6Address.IsValid() || len(e.IPAMConfig.LinkLocalIPs) != 0 || len(e.Aliases) != 0 || len(e.Links) != 0 {
			return false
		}
	}
	return modeOK
}

func safeProfileSourceMountedAccess(c container.InspectResponse, b controlStorageBinding, back volume.Volume) bool {
	if !safeProfileSourceConfiguredAccess(c, b) || len(c.Mounts) != len(b.profileSource.Control.Mounts) {
		return false
	}
	r := b.profileSource
	p := r.Control
	seen := map[string]bool{}
	for _, m := range c.Mounts {
		if seen[m.Destination] {
			return false
		}
		seen[m.Destination] = true
		found := false
		for _, want := range p.Mounts {
			if want.Target != m.Destination {
				continue
			}
			found = true
			if m.RW == want.ReadOnly {
				return false
			}
			if want.Kind == "daemon_socket" {
				if m.Type != "bind" || m.Source != b.SourceSocket || m.Propagation != "rprivate" {
					return false
				}
			} else {
				name := b.profileVolume(want)
				root := strings.TrimSuffix(back.Mountpoint, "/"+back.Name+"/_data") + "/" + name + "/_data"
				if m.Type != "volume" || m.Name != name || m.Source != root || m.Driver != "local" || m.Propagation != "" && m.Propagation != "rprivate" {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func safeProfileSourceControlAccess(c container.InspectResponse, b controlStorageBinding, back volume.Volume) bool {
	if !safeProfileSourceMountedAccess(c, b, back) {
		return false
	}
	r, h := b.profileSource, c.HostConfig
	modeOK := false
	for _, n := range r.Networks {
		name := b.profileNetwork(n.Network.Name)
		if string(h.NetworkMode) == name {
			modeOK = true
		}
		prefix, pe := netip.ParsePrefix(n.Network.IPv4Subnet)
		e := c.NetworkSettings.Networks[name]
		if pe != nil || e == nil || e.IPPrefixLen != prefix.Bits() || len(e.Aliases) != 0 || !codingArchiveRuntimeID.MatchString(e.NetworkID) || e.IPAddress.String() != n.Address || e.Gateway.IsValid() || e.GlobalIPv6Address.IsValid() || e.IPv6Gateway.IsValid() || len(e.Links) != 0 {
			return false
		}
	}
	return modeOK
}

type controlProfileNetworkReader interface {
	NetworkInspect(context.Context, string, client.NetworkInspectOptions) (client.NetworkInspectResult, error)
}

// This observer is Control-only staging. It intentionally rejects Provider/TLS
// peer consumers; full-topology admission must independently identify those
// declared peers and remains held. Empty input volumes do not prove TLS content.
func readControlProfileStagingObjects(ctx context.Context, api controlStorageReader, b controlStorageBinding, c container.InspectResponse, listed []volume.Volume) (string, error) {
	r := b.profileSource
	if r == nil {
		return "", nil
	}
	fail := func() (string, error) { return "", ErrInvalidCodingInventory }
	nr, ok := api.(controlProfileNetworkReader)
	if !ok {
		return fail()
	}
	objects := map[string]string{}
	for _, m := range r.Control.Mounts {
		if m.Kind == "daemon_socket" || m.Kind == "control_source" || m.Kind == "persistent_ledger" {
			continue
		}
		name := b.profileVolume(m)
		v, e := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
		if e != nil || v.Volume.Name != name || v.Volume.Driver != "local" || v.Volume.Scope != "local" || len(v.Volume.Options) != 0 || v.Volume.ClusterVolume != nil || len(v.Volume.Status) != 0 || !maps.Equal(v.Volume.Labels, b.labels("input:"+m.StorageID)) {
			return fail()
		}
		matches := 0
		for _, item := range listed {
			if item.Name == name {
				if !sameControlStorageVolume(item, v.Volume) {
					return fail()
				}
				matches++
			}
		}
		if matches != 1 || !safeStoragePath(v.Volume.Mountpoint) || !strings.HasSuffix(v.Volume.Mountpoint, "/volumes/"+name+"/_data") {
			return fail()
		}
		objects[name] = executionDigest("profile-source-volume", v.Volume)
	}
	for _, n := range r.Networks {
		name := b.profileNetwork(n.Network.Name)
		v, e := nr.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
		if e != nil {
			return fail()
		}
		vnet := v.Network
		if vnet.Name != name || !codingArchiveRuntimeID.MatchString(vnet.ID) || vnet.Driver != "bridge" || vnet.Scope != "local" || !vnet.Internal || vnet.EnableIPv6 || !vnet.EnableIPv4 || vnet.Attachable || vnet.Ingress || vnet.ConfigOnly || !maps.Equal(vnet.Labels, b.labels("network:"+n.Network.Name)) || !maps.Equal(vnet.Options, map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated", "com.docker.network.enable_ipv4": "true"}) || vnet.IPAM.Driver != "default" || len(vnet.IPAM.Options) != 0 || len(vnet.IPAM.Config) != 1 || vnet.IPAM.Config[0].Subnet.String() != n.Network.IPv4Subnet || vnet.IPAM.Config[0].Gateway.IsValid() || vnet.IPAM.Config[0].IPRange.IsValid() || len(vnet.IPAM.Config[0].AuxAddress) != 0 || len(vnet.Containers) != 1 {
			return fail()
		}
		ep := c.NetworkSettings.Networks[name]
		actual, ok := vnet.Containers[b.ControlID]
		if !ok || ep == nil || ep.NetworkID != vnet.ID || actual.Name != b.ControlName || actual.EndpointID != ep.EndpointID || actual.IPv4Address.String() != fmt.Sprintf("%s/%d", n.Address, ep.IPPrefixLen) {
			return fail()
		}
		objects[name] = executionDigest("profile-source-network", vnet)
	}
	return executionDigest("profile-source-objects", objects), nil
}
