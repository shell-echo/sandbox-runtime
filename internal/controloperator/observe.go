package controloperator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6process"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"io"
	"maps"
	"reflect"
	"slices"
	"time"
)

type daemonObservation struct {
	DaemonID    string                 `json:"daemon_id"`
	ContainerID string                 `json:"container_id"`
	Created     string                 `json:"created"`
	Image       string                 `json:"image"`
	PID         int                    `json:"pid"`
	StartedAt   string                 `json:"started_at"`
	Config      *container.Config      `json:"config"`
	HostConfig  *container.HostConfig  `json:"host_config"`
	Mounts      []container.MountPoint `json:"mounts"`
}

func inspect(ctx context.Context, cli *client.Client, a *inputs, running bool) (daemonObservation, error) {
	fail := controldelivery.ErrUnavailable
	info, e := cli.Info(ctx, client.InfoOptions{})
	if e != nil || info.Info.ID != a.input.DaemonID || info.Info.OSType != "linux" {
		return daemonObservation{}, fail
	}
	got, e := cli.ContainerInspect(ctx, a.input.ContainerID, client.ContainerInspectOptions{})
	if e != nil {
		return daemonObservation{}, fail
	}
	c := got.Container
	var backing []volume.Volume
	if phase6security.ControlObservesSource(a.review.Bootstrap.Target) {
		if a.review.Source == nil {
			return daemonObservation{}, fail
		}
		v, err := cli.VolumeInspect(ctx, "control-backing-"+a.review.Source.Source.Intent.Namespace, client.VolumeInspectOptions{})
		if err != nil {
			return daemonObservation{}, fail
		}
		backing = []volume.Volume{v.Volume}
	}
	if e = check(c, a, running, backing...); e != nil {
		return daemonObservation{}, e
	}
	// Both the index view and platform-selected view must retain the original
	// descriptor and exact config content-addressed identity from the OCI input.
	var baseRaw bytes.Buffer
	base, e := cli.ImageInspect(ctx, a.service.Principal.ImageDigest, client.ImageInspectWithRawResponse(&baseRaw))
	if e != nil || base.ID != a.service.Principal.ImageDigest {
		return daemonObservation{}, fail
	}
	image, e := cli.ImageInspect(ctx, a.service.Principal.ImageDigest, client.ImageInspectWithPlatform(a.selected.Platform))
	if e != nil || !reflect.DeepEqual(image.Descriptor, &a.selected) || image.Config == nil || image.Architecture != a.selected.Platform.Architecture || image.Os != a.selected.Platform.OS || !slices.Equal(image.RootFS.Layers, func() []string {
		out := make([]string, len(a.config.RootFS.DiffIDs))
		for i, d := range a.config.RootFS.DiffIDs {
			out[i] = d.String()
		}
		return out
	}()) {
		return daemonObservation{}, fail
	}
	principal := a.service.Principal
	array := func(b []byte) []byte { return append(append([]byte{'['}, b...), ']') }
	if _, e := phase6security.ObserveDockerRuntimeImage(array(got.Raw), array(baseRaw.Bytes()), principal.ImageLocation, principal.ImageIdentityKind, principal.ImageReference, principal.ImageDigest, principal.ImagePlatform, principal.ImageSelectedManifestDigest, principal.ImageConfigDigest, a.documents); e != nil {
		return daemonObservation{}, fail
	}
	if !slices.Equal(image.Config.Entrypoint, a.service.Entrypoint) || len(image.Config.Cmd) != 0 || image.Config.User != "65532:65532" || image.Config.WorkingDir != "/" || !slices.Equal(image.Config.Env, []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}) || len(image.Config.Volumes) != 0 || image.Config.Healthcheck != nil || len(image.Config.OnBuild) != 0 {
		return daemonObservation{}, fail
	}
	if phase6security.ControlObservesSource(a.service.Launch.Target) && !maps.Equal(image.Config.Labels, phase6security.ControlSourceImageLabels(a.service)) {
		return daemonObservation{}, fail
	}
	// Docker normalizes explicit OomKillDisable=false to null at start. Both
	// mean OOM handling enabled; true has already been rejected by check.
	host := *c.HostConfig
	host.OomKillDisable = nil
	return daemonObservation{info.Info.ID, c.ID, c.Created, c.Image, c.State.Pid, c.State.StartedAt, c.Config, &host, c.Mounts}, nil
}
func check(c container.InspectResponse, a *inputs, running bool, backing ...volume.Volume) error {
	fail := controldelivery.ErrUnavailable
	if c.Config == nil || c.HostConfig == nil || c.State == nil {
		return fail
	}
	h, cfg, st := c.HostConfig, c.Config, c.State
	p := a.service.Principal
	if cfg.Image != p.ImageReference || !reflect.DeepEqual(c.ImageManifestDescriptor, &a.selected) {
		return fail
	}
	if c.ID != a.input.ContainerID || c.Image != p.ImageDigest || c.Created == "" || c.RestartCount != 0 || st.Running != running || st.Paused || st.Restarting || st.OOMKilled || st.Dead || st.Error != "" || st.Health != nil {
		return fail
	}
	if running {
		if st.Status != "running" || st.Pid <= 0 || st.StartedAt == "" {
			return fail
		}
	} else if st.Status != "created" || st.Pid != 0 {
		return fail
	}
	if c.Path != "/bin/sh" || !slices.Equal(c.Args, a.service.Entrypoint[1:]) || !slices.Equal(cfg.Entrypoint, a.service.Entrypoint) || len(cfg.Cmd) != 0 || cfg.User != fmt.Sprintf("%d:%d", p.UID, p.GID) || cfg.WorkingDir != "/" || cfg.Hostname != c.ID[:12] || cfg.Domainname != "" || cfg.Tty || !cfg.OpenStdin || !cfg.StdinOnce || cfg.Healthcheck != nil || len(cfg.Volumes) != 0 || len(cfg.OnBuild) != 0 {
		return fail
	}
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "SR_PHASE6_FD_RUN_ID=" + a.envelope.RunID, "SR_PHASE6_FD_TARGET=" + a.envelope.Target, "SR_PHASE6_FD_NONCE=" + a.envelope.Nonce}
	actual := append([]string(nil), cfg.Env...)
	slices.Sort(env)
	slices.Sort(actual)
	if !slices.Equal(env, actual) {
		return fail
	}
	if h.OomKillDisable != nil && *h.OomKillDisable {
		return fail
	}
	if h.Runtime != "runc" {
		return fail
	}
	if phase6security.ControlObservesSource(a.review.Bootstrap.Target) {
		if len(backing) != 1 {
			return fail
		}
		binding := phase6fdloader.StartupBinding{Protocol: phase6fdloader.ControlStartupProtocol(a.envelope.Target), RunID: a.envelope.RunID, Nonce: a.envelope.Nonce, ContainerID: a.input.ContainerID, Target: a.envelope.Target}
		if dockercontrol.CheckSourceControlContainer(a.document, binding, c, backing[0], running) != nil {
			return fail
		}
		for _, m := range c.Mounts {
			if m.Destination == phase6security.Slice6PrivateConfigDirectory && m.Type == "volume" && m.Name == a.input.ConfigVolume {
				return nil
			}
		}
		return fail
	}
	if !h.ReadonlyRootfs || h.Privileged || h.NetworkMode != "none" || h.PidMode != "" || h.UTSMode != "" || h.UsernsMode != "" || h.CgroupnsMode != "private" || (h.IpcMode != "private" && h.IpcMode != "none") || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.CapAdd) != 0 || !slices.Equal(h.GroupAdd, []string{"0"}) || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges"}) || h.RestartPolicy.Name != "no" || h.AutoRemove || h.Init != nil && *h.Init {
		return fail
	}
	if len(h.Devices)+len(h.DeviceCgroupRules)+len(h.DeviceRequests)+len(h.Binds)+len(h.VolumesFrom)+len(h.Tmpfs)+len(h.Links)+len(h.PortBindings)+len(h.ExtraHosts)+len(h.Sysctls) != 0 || h.PublishAllPorts || h.PidsLimit == nil || *h.PidsLimit < 1 || *h.PidsLimit > 64 || h.Memory < 1 || h.Memory > 256<<20 || h.MemorySwap != h.Memory || h.NanoCPUs < 1 || h.NanoCPUs > 1e9 {
		return fail
	}
	// This narrow ceremony has exactly one read-only config volume. It has no
	// source/root volume, socket, device or business network to authorize.
	if len(c.Mounts) != 1 || len(h.Mounts) != 1 {
		return fail
	}
	m := c.Mounts[0]
	hm := h.Mounts[0]
	if m.Type != "volume" || m.Name != a.input.ConfigVolume || m.Destination != "/run/phase6/config" || m.RW || m.Driver != "local" || hm.Type != "volume" || hm.Source != m.Name || hm.Target != m.Destination || !hm.ReadOnly || hm.VolumeOptions == nil || !hm.VolumeOptions.NoCopy || hm.VolumeOptions.Subpath != "" {
		return fail
	}
	if c.NetworkSettings == nil || len(c.NetworkSettings.Networks) != 1 || c.NetworkSettings.Networks["none"] == nil {
		return fail
	}
	return nil
}
func observe(ctx context.Context, cli *client.Client, a *inputs, c controldelivery.Challenge) (daemonObservation, error) {
	observation, report, e := probe(ctx, cli, a, "role")
	if e != nil || !reflect.DeepEqual(report.Observation, c.Process) || report.Probe == nil || *report.Probe != c.Probe || !reflect.DeepEqual(report.Source, c.Source) {
		return daemonObservation{}, controldelivery.ErrUnavailable
	}
	return observation, nil
}
func probe(ctx context.Context, cli *client.Client, a *inputs, stage string) (observation daemonObservation, report phase6process.ProbeReport, err error) {
	fail := controldelivery.ErrUnavailable
	before, e := inspect(ctx, cli, a, true)
	if e != nil {
		return before, report, e
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := []string{phase6process.ProbePath, a.service.Principal.Name, stage}
	if phase6security.ControlObservesSource(a.service.Launch.Target) {
		command = append(command, a.envelope.RunID, a.envelope.Nonce, a.input.ContainerID)
	}
	exec, e := cli.ExecCreate(probeCtx, a.input.ContainerID, client.ExecCreateOptions{AttachStdin: true, AttachStdout: true, AttachStderr: true, User: fmt.Sprintf("%d:%d", a.service.Principal.UID, a.service.Principal.GID), WorkingDir: "/", Cmd: command})
	if e != nil {
		return before, report, fail
	}
	stream, e := cli.ExecAttach(probeCtx, exec.ID, client.ExecAttachOptions{})
	if e != nil {
		return before, report, fail
	}
	defer stream.Close()
	stop := context.AfterFunc(probeCtx, stream.Close)
	defer stop()
	if deadline, ok := probeCtx.Deadline(); ok {
		if stream.Conn.SetDeadline(deadline) != nil {
			return before, report, fail
		}
	}
	if _, e := io.Copy(stream.Conn, bytes.NewReader(a.document)); e != nil {
		return before, report, fail
	}
	cw, ok := stream.Conn.(client.CloseWriter)
	if !ok || cw.CloseWrite() != nil {
		return before, report, fail
	}
	demux := &dockerStdout{r: stream.Reader}
	b, e := io.ReadAll(io.LimitReader(demux, controldelivery.MaxFrame+1))
	if e != nil || len(b) > controldelivery.MaxFrame || len(demux.stderr) != 0 || len(b) == 0 || b[len(b)-1] != '\n' {
		return before, report, fail
	}

	if phase6fdloader.DecodeCanonical(b[:len(b)-1], &report) != nil || report.Admission != "held-not-a-permit" || report.ProfileBytesDigest != a.review.ProfileBytesDigest || report.Deployment != a.service.Principal.Name || report.Stage != stage || phase6process.Verify(report.Observation, a.service, stage) != nil || report.Probe == nil || report.Probe.Digest != a.service.Launch.ProbeDigest || report.Probe.Inode == 0 || report.Probe.Size <= 0 {
		return before, report, fail
	}
	if (!phase6security.ControlObservesSource(a.service.Launch.Target) || stage != "role") && report.Source != nil || phase6security.ControlObservesSource(a.service.Launch.Target) && stage == "role" && report.Source == nil {
		return before, report, fail
	}
	// Exit is checked explicitly; a partial valid-looking stdout is insufficient.
	status, e := cli.ExecInspect(probeCtx, exec.ID, client.ExecInspectOptions{})
	if e != nil || status.ID != exec.ID || status.ContainerID != a.input.ContainerID || status.Running || status.ExitCode != 0 {
		return before, report, fail
	}
	after, e := inspect(ctx, cli, a, true)
	if e != nil || !reflect.DeepEqual(before, after) {
		return before, report, fail
	}
	return after, report, nil
}

// Marshaled host observations remain private and are signed by digest only.
func observationDigest(observation daemonObservation) string {
	b, _ := json.Marshal(observation)
	return controldelivery.Digest(b)
}
