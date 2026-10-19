package dockercontrol

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func (b controlStorageBinding) boundaryPeer(c container.InspectResponse) *phase6security.Principal {
	if b.boundary == nil || c.Config == nil {
		return nil
	}
	for _, p := range b.boundary.Consumers {
		if p.Name != b.profileSource.Control.Name && c.Name == "/"+sourceObjectName("peer", b.Storage.Namespace, p.Name) && maps.Equal(c.Config.Labels, b.labels("peer:"+p.Name)) {
			return &p
		}
	}
	return nil
}

// Every actual diagnostic mount and network must equal this projection. Merely
// appearing elsewhere in the complete Profile never authorizes an extra grant.
func safeControlBoundaryPeer(c container.InspectResponse, b controlStorageBinding, p phase6security.Principal, back volume.Volume) bool {
	h := c.HostConfig
	if h == nil || c.State == nil || c.NetworkSettings == nil || !sourceControlImageMatches(c, p) || c.Config.User != fmt.Sprintf("%d:%d", p.UID, p.GID) || !c.State.Running || c.State.Paused || c.State.Restarting || c.State.Dead || !h.ReadonlyRootfs || len(h.CapAdd) != 0 || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.GroupAdd) != 0 || len(h.Devices) != 0 || len(h.Binds) != 0 || len(h.Tmpfs) != 0 || len(h.SecurityOpt) != 2 || h.Memory != p.Resources.MemoryBytes || h.MemorySwap != p.Resources.MemoryBytes || h.NanoCPUs != p.Resources.CPUMillis*1000000 || h.PidsLimit == nil || *h.PidsLimit != p.Resources.PIDs || len(h.PortBindings) != 0 || h.PublishAllPorts || len(c.NetworkSettings.Ports) != 0 || len(h.ExtraHosts) != 0 || len(h.DNS) != 0 || len(h.DNSOptions) != 0 || len(h.DNSSearch) != 0 || len(h.Links) != 0 || len(h.Sysctls) != 0 || h.UTSMode != "" || h.CgroupParent != "" || h.CgroupnsMode != "private" || h.UsernsMode != "" || (h.IpcMode != "private" && h.IpcMode != "") {
		return false
	}
	nnp, sc := 0, 0
	for _, o := range h.SecurityOpt {
		if o == "no-new-privileges:true" || o == "no-new-privileges" {
			nnp++
		} else if strings.HasPrefix(o, "seccomp=") && sourceSeccompDigest(strings.TrimPrefix(o, "seccomp=")) == p.SeccompDigest {
			sc++
		} else {
			return false
		}
	}
	if nnp != 1 || sc != 1 {
		return false
	}
	mounts := b.boundary.Mounts(p)
	if len(h.Mounts) != len(mounts) || len(c.Mounts) != len(mounts) {
		return false
	}
	seen := map[string]bool{}
	for _, m := range h.Mounts {
		if seen[m.Target] {
			return false
		}
		seen[m.Target] = true
		found := false
		for _, want := range mounts {
			if m.Target == want.Target {
				found = true
				if m.Type != "volume" || m.Source != b.profileVolume(want) || m.ReadOnly != want.ReadOnly || m.Consistency != "" || m.BindOptions != nil || m.VolumeOptions == nil || !m.VolumeOptions.NoCopy || m.VolumeOptions.Subpath != "" || m.VolumeOptions.DriverConfig != nil || len(m.VolumeOptions.Labels) != 0 {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	seen = map[string]bool{}
	for _, m := range c.Mounts {
		if seen[m.Destination] {
			return false
		}
		seen[m.Destination] = true
		found := false
		for _, want := range mounts {
			if m.Destination == want.Target {
				found = true
				name := b.profileVolume(want)
				root := strings.TrimSuffix(back.Mountpoint, "/"+back.Name+"/_data") + "/" + name + "/_data"
				if m.Type != "volume" || m.Name != name || m.Source != root || m.RW == want.ReadOnly || m.Driver != "local" || m.Propagation != "" && m.Propagation != "rprivate" {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	nets := 0
	for _, end := range b.boundary.Endpoints {
		if end.ProviderDeployment != p.Name {
			continue
		}
		nets++
		name := b.profileNetwork(end.Network)
		ep := c.NetworkSettings.Networks[name]
		var subnet netip.Prefix
		for _, n := range b.profileSource.Networks {
			if n.Network.Name == end.Network {
				subnet, _ = netip.ParsePrefix(n.Network.IPv4Subnet)
				if ep != nil && ep.IPAddress.String() == n.Address {
					return false
				}
			}
		}
		if ep == nil || string(h.NetworkMode) != name || !codingArchiveRuntimeID.MatchString(ep.NetworkID) || !codingArchiveRuntimeID.MatchString(ep.EndpointID) || ep.IPAMConfig == nil || ep.IPAMConfig.IPv4Address != ep.IPAddress || ep.IPAMConfig.IPv6Address.IsValid() || len(ep.IPAMConfig.LinkLocalIPs) != 0 || len(ep.Aliases) != 0 || len(ep.Links) != 0 || ep.Gateway.IsValid() || ep.GlobalIPv6Address.IsValid() || ep.IPv6Gateway.IsValid() || !subnet.IsValid() || !subnet.Contains(ep.IPAddress) || ep.IPPrefixLen != subnet.Bits() || ep.IPAddress == subnet.Addr() {
			return false
		}
	}
	if nets == 0 {
		return h.NetworkMode == "none" && len(c.NetworkSettings.Networks) == 1 && c.NetworkSettings.Networks["none"] != nil && !c.NetworkSettings.Networks["none"].IPAddress.IsValid()
	}
	return nets == 1 && len(c.NetworkSettings.Networks) == 1
}

func readControlBoundaryObjects(ctx context.Context, api controlStorageReader, b controlStorageBinding, all map[string]container.InspectResponse, volumes []volume.Volume) (string, error) {
	fail := func() (string, error) { return "", ErrInvalidCodingInventory }
	nr, ok := api.(controlProfileNetworkReader)
	if !ok {
		return fail()
	}
	r := b.profileSource
	peers := map[string]container.InspectResponse{r.Control.Name: all[b.ControlID]}
	for _, c := range all {
		if p := b.boundaryPeer(c); p != nil {
			if _, exists := peers[p.Name]; exists {
				return fail()
			}
			peers[p.Name] = c
		}
	}
	if len(peers) != len(b.boundary.Consumers) {
		return fail()
	}
	objects := map[string]string{}
	for _, p := range b.boundary.Consumers {
		c, ok := peers[p.Name]
		if !ok || c.State == nil || !c.State.Running || !controlDiagnosticCarrier(c) {
			return fail()
		}
		created, ce := time.Parse(time.RFC3339Nano, c.Created)
		started, se := time.Parse(time.RFC3339Nano, c.State.StartedAt)
		if ce != nil || se != nil || created.IsZero() || started.Before(created) {
			return fail()
		}
		objects[p.Name] = executionDigest("boundary-consumer-session", struct {
			ID, Created, Started string
			Config               *container.Config
			Networks             any
		}{c.ID, c.Created, c.State.StartedAt, c.Config, c.NetworkSettings.Networks})
	}
	// These four inputs are the complete shared boundary. Volume/list equality
	// and aliases are checked in addition to container mount source equality.
	for _, m := range r.Control.Mounts {
		if m.Kind == "daemon_socket" || m.Kind == "persistent_ledger" || m.Kind == "control_source" {
			continue
		}
		name := b.profileVolume(m)
		v, e := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
		if e != nil || v.Volume.Name != name || v.Volume.Driver != "local" || v.Volume.Scope != "local" || len(v.Volume.Options) != 0 || v.Volume.ClusterVolume != nil || len(v.Volume.Status) != 0 || !maps.Equal(v.Volume.Labels, b.labels("input:"+m.StorageID)) || !safeStoragePath(v.Volume.Mountpoint) || !strings.HasSuffix(v.Volume.Mountpoint, "/volumes/"+name+"/_data") {
			return fail()
		}
		count := 0
		for _, other := range volumes {
			if other.Name == name {
				count++
				if !sameControlStorageVolume(other, v.Volume) {
					return fail()
				}
			} else if pathsOverlap(other.Mountpoint, v.Volume.Mountpoint) || pathsOverlap(other.Options["device"], v.Volume.Mountpoint) {
				return fail()
			}
		}
		if count != 1 {
			return fail()
		}
		objects[name] = executionDigest("boundary-volume", v.Volume)
	}
	for _, n := range r.Networks {
		name := b.profileNetwork(n.Network.Name)
		v, e := nr.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
		if e != nil {
			return fail()
		}
		net := v.Network
		if net.Name != name || !codingArchiveRuntimeID.MatchString(net.ID) || net.Driver != "bridge" || net.Scope != "local" || !net.Internal || net.EnableIPv6 || !net.EnableIPv4 || net.Attachable || net.Ingress || net.ConfigOnly || !maps.Equal(net.Labels, b.labels("network:"+n.Network.Name)) || !maps.Equal(net.Options, map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated", "com.docker.network.enable_ipv4": "true"}) || net.IPAM.Driver != "default" || len(net.IPAM.Options) != 0 || len(net.IPAM.Config) != 1 || net.IPAM.Config[0].Subnet.String() != n.Network.IPv4Subnet || net.IPAM.Config[0].Gateway.IsValid() || net.IPAM.Config[0].IPRange.IsValid() || len(net.IPAM.Config[0].AuxAddress) != 0 || len(net.Containers) != 2 {
			return fail()
		}
		provider := ""
		for _, end := range b.boundary.Endpoints {
			if end.Network == n.Network.Name {
				provider = end.ProviderDeployment
			}
		}
		for _, principal := range []string{r.Control.Name, provider} {
			c, ok := peers[principal]
			if !ok || c.NetworkSettings == nil {
				return fail()
			}
			ep := c.NetworkSettings.Networks[name]
			actual, ok := net.Containers[c.ID]
			if !ok || ep == nil || ep.NetworkID != net.ID || actual.Name != strings.TrimPrefix(c.Name, "/") || actual.EndpointID != ep.EndpointID || actual.IPv4Address.String() != fmt.Sprintf("%s/%d", ep.IPAddress, ep.IPPrefixLen) {
				return fail()
			}
		}
		objects[name] = executionDigest("boundary-network", net)
	}
	return executionDigest("control-consumer-boundary", objects), nil
}

// The held proof is deliberately about these diagnostic carriers. An arbitrary
// command in an approved image is not a legitimate Provider or TLS process.
func controlDiagnosticCarrier(c container.InspectResponse) bool {
	if c.Config == nil || c.HostConfig == nil || len(c.ID) != 64 {
		return false
	}
	v := c.Config
	h := c.HostConfig
	return slices.Equal(v.Entrypoint, []string{"/bin/sleep"}) && slices.Equal(v.Cmd, []string{"1800"}) && slices.Equal(v.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}) && v.WorkingDir == "/" && v.Hostname == c.ID[:12] && v.Domainname == "" && !v.Tty && !v.OpenStdin && !v.StdinOnce && len(v.ExposedPorts) == 0 && len(v.Volumes) == 0 && v.Healthcheck == nil && v.StopSignal == "" && h.Init == nil && !h.AutoRemove && (h.RestartPolicy.Name == "no" || h.RestartPolicy.Name == "") && h.RestartPolicy.MaximumRetryCount == 0
}
