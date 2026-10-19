//go:build integration

package dockercontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This prospectively consumes the resource partition in real Docker create
// requests. It is not a new Profile, Coding image, dispatch/receipt authority,
// memory-pressure benchmark, daemon-restart gate, or release acceptance.
func TestCodingSharedScratchResourcesRealDaemon(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CODING_SHARED_SCRATCH") != "1" {
		t.Skip("explicit local shared-scratch experiment not enabled")
	}
	host := os.Getenv("SANDBOX_RUNTIME_CODING_EXEC_UNIX_ENDPOINT")
	path := strings.TrimPrefix(host, "unix://")
	resolved, err := filepath.EvalSymlinks(path)
	info, statErr := os.Lstat(path)
	if !strings.HasPrefix(host, "unix://") || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		err != nil || resolved != path || statErr != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("explicit no-symlink local Unix socket required")
	}
	sameEndpoint := func() bool {
		r, e := filepath.EvalSymlinks(path)
		v, se := os.Lstat(path)
		return e == nil && r == path && se == nil && v.Mode()&os.ModeSocket != 0 && os.SameFile(info, v)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if !sameEndpoint() {
			return nil, fmt.Errorf("fixture endpoint changed")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
		if err != nil {
			return nil, err
		}
		if !sameEndpoint() {
			_ = conn.Close()
			return nil, fmt.Errorf("fixture endpoint changed during dial")
		}
		return conn, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	api, err := client.New(client.WithHost(host), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{
		Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect denied") }}))
	if err != nil {
		t.Fatal("fixture client unavailable")
	}
	t.Cleanup(func() { _ = api.Close() })
	scope := digest([]byte("coding-shared-scratch-fixture\x00" + host))
	daemon, err := ObserveCodingDaemon(ctx, api, scope)
	if err != nil || daemon.Platform != "linux/arm64/v8" {
		t.Fatal("fixture requires Linux/arm64 daemon")
	}
	var raw bytes.Buffer
	index, err := api.ImageInspect(ctx, containmentImage, client.ImageInspectWithRawResponse(&raw))
	if err != nil || index.Descriptor == nil || index.Descriptor.Digest.String() != containmentIndex {
		t.Fatal("cached locked fixture missing; no pull allowed")
	}
	selected, err := api.ImageInspect(ctx, containmentImage, client.ImageInspectWithPlatform(&ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}))
	if err != nil || selected.Descriptor == nil || selected.Descriptor.Digest.String() != containmentManifest || selected.Config == nil || len(selected.Config.Volumes) != 1 || selected.Config.Healthcheck != nil {
		t.Fatal("fixture image descriptor/config drift")
	}
	if _, ok := selected.Config.Volumes["/var/lib/postgresql/data"]; !ok {
		t.Fatal("unexpected image VOLUME")
	}
	archive := filepath.Join(t.TempDir(), "scratch-fixture.oci.tar")
	if out, err := exec.CommandContext(ctx, "docker", "--host", host, "image", "save", "-o", archive, containmentImage).CombinedOutput(); err != nil {
		t.Fatalf("export cached image failed: %v (output bytes=%d)", err, len(out))
	}
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archive, "registry", phase6security.ImageIdentityOCIIndex,
		containmentImage, containmentIndex, "linux/arm64/v8", containmentManifest)
	if err != nil || phase6security.VerifyOCIArchiveLayers(archive, documents.Manifest, documents.Config) != nil {
		t.Fatal("cached OCI chain/layers failed")
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json"))
	if err != nil || digest(policy) != "sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("locked seccomp mismatch")
	}
	resources := codingidentity.ExecutionResources{Protocol: codingidentity.ExecutionResourcesProtocol,
		Total:        codingidentity.Limits{MemoryBytes: 256 << 20, CPUMillis: 500, PIDs: 64},
		Resident:     codingidentity.Limits{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16},
		Command:      codingidentity.Limits{MemoryBytes: 128 << 20, CPUMillis: 400, PIDs: 48},
		ScratchBytes: codingidentity.SharedScratchBytes, MaxPossibleCommands: 1}
	scratch := codingidentity.NewExecutionScratch()
	resourceDigest, err := resources.Digest()
	if err != nil || scratch.BindResources(resources) != nil {
		t.Fatal("unaccounted resource partition before any Docker mutation")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	p := &containmentProbe{t: t, ctx: ctx, api: api, run: run, volume: "sandbox-runtime-scratch-probe-" + run,
		policy: string(policy), config: proof.ConfigDigest, documents: documents, rawImage: raw.Bytes(), sameEndpoint: sameEndpoint}
	t.Logf("scratch-only run=%s resources=%s image=%s manifest=%s config=%s daemon=%s environment=%s",
		run, resourceDigest, containmentIndex, containmentManifest, proof.ConfigDigest, daemon.IdentityDigest, daemon.EnvironmentDigest)
	if _, err := api.VolumeInspect(ctx, p.volume, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("unique scratch name not absent")
	}
	t.Cleanup(p.cleanup)
	options, err := scratch.VolumeOptions(57000, 58000)
	if err != nil {
		t.Fatal("scratch policy invalid before mutation")
	}
	_, err = api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: p.volume, Driver: "local", DriverOpts: options, Labels: map[string]string{containmentLabel: run}})
	p.mutation(err)
	p.volumeCreated = true
	v, err := api.VolumeInspect(ctx, p.volume, client.VolumeInspectOptions{})
	if err != nil || v.Volume.Name != p.volume || v.Volume.Driver != "local" || v.Volume.Labels[containmentLabel] != run || !maps.Equal(v.Volume.Options, options) {
		t.Fatal("scratch definition drift")
	}

	resident := scratchCreate(p, "resident", resources.Resident)
	p.start(resident)
	scratchObserveMount(p, host, resident, scratch)
	scratchShell(p, host, resident, `set -eu; test "$(id -u)" = 57000; test "$(id -g)" = 58000; printf resident > /tmp/from-resident`)
	command := scratchCreate(p, "command", resources.Command)
	p.start(command)
	scratchObserveMount(p, host, command, scratch)
	scratchShell(p, host, command, `set -eu; test "$(cat /tmp/from-resident)" = resident; printf command > /tmp/from-command; printf '#!/bin/sh\nexit 0\n' > /tmp/noexec; chmod 700 /tmp/noexec; rc=0; /tmp/noexec >/tmp/noexec-out 2>/tmp/noexec-error || rc=$?; test "$rc" = 126; test "$(wc -c < /tmp/noexec-out)" = 0; grep -q 'Permission denied' /tmp/noexec-error`)
	scratchShell(p, host, resident, `set -eu; test "$(cat /tmp/from-command)" = command`)
	// Fixed bounded write: 33 MiB to a 32 MiB scratch. Both the errno text
	// and a near-capacity file distinguish capacity enforcement from EACCES.
	scratchShell(p, host, command, `set -eu; rc=0; message=$(dd if=/dev/zero of=/tmp/fill bs=1048576 count=33 2>&1) || rc=$?; test "$rc" = 1; printf '%s' "$message" | grep -q 'No space left on device'; n=$(stat -c %s /tmp/fill); test "$n" -ge 32505856; test "$n" -le 33554432; rm /tmp/fill; test "$(cat /tmp/from-resident)" = resident`)
	scratchMemorySample(p, host, command, "before-inodes", resources.Command.MemoryBytes)
	// A single awk process creates precisely the remaining empty inodes; no
	// shell/process per file or unbounded stress loop. Data blocks stay free.
	scratchShell(p, host, command, `set -eu; mkdir /tmp/inode-files; n=$(stat -f -c %d /tmp); test "$n" -gt 4000; test "$n" -lt 4096; awk -v n="$n" 'BEGIN {for(i=0;i<n;i++){p="/tmp/inode-files/f" i; printf "%s", "" >p; close(p)}}'; test "$(stat -f -c %d /tmp)" = 0; test "$(stat -f -c %f /tmp)" -gt 7000; rc=0; message=$(touch /tmp/inode-overflow 2>&1) || rc=$?; test "$rc" != 0; printf '%s' "$message" | grep -q 'No space left on device'; rc=0; message=$(mkdir /tmp/inode-overflow-dir 2>&1) || rc=$?; test "$rc" != 0; printf '%s' "$message" | grep -q 'No space left on device'; test "$(cat /tmp/from-resident)" = resident`)
	scratchMemorySample(p, host, command, "full-inodes", resources.Command.MemoryBytes)
	scratchShell(p, host, command, `set -eu; rm /tmp/inode-files/f0; test "$(stat -f -c %d /tmp)" = 1; mkdir /tmp/inode-dir; test "$(stat -f -c %d /tmp)" = 0; rmdir /tmp/inode-dir; rm /tmp/inode-files/*; rmdir /tmp/inode-files; test "$(stat -f -c %d /tmp)" -gt 4000; test "$(cat /tmp/from-command)" = command`)
	p.remove(command)
	// Releasing the command must not erase the sandbox's resident scratch.
	scratchShell(p, host, resident, `set -eu; test "$(cat /tmp/from-command)" = command`)
	successor := scratchCreate(p, "successor", resources.Command)
	p.start(successor)
	scratchShell(p, host, successor, `set -eu; test "$(cat /tmp/from-resident)" = resident; test "$(cat /tmp/from-command)" = command`)
	p.remove(successor)
	p.remove(resident)
	// This controlled full unmount/remount is NOT a Docker daemon restart.
	remounted := scratchCreate(p, "remounted", resources.Resident)
	p.start(remounted)
	scratchObserveMount(p, host, remounted, scratch)
	scratchShell(p, host, remounted, `set -eu; test ! -e /tmp/from-resident; test ! -e /tmp/from-command; test "$(ls -A /tmp | wc -l)" = 0`)
	p.remove(remounted)
	after, err := ObserveCodingDaemon(ctx, api, scope)
	if err != nil || after != daemon {
		t.Fatal("daemon identity/environment changed")
	}
	t.Log("shared tmpfs: actual 32MiB/4096-inode/type/flags/high UID/GID/mode; bidirectional visibility; noexec denial; data and inode ENOSPC; released inode reused by directory; command replacement retains data; full unmount/remount loses data; memory samples are not a kernel bound, daemon-restart or production claim")
}

func scratchCreate(p *containmentProbe, role string, limit codingidentity.Limits) string {
	p.t.Helper()
	if limit.Validate() != nil || !p.sameEndpoint() {
		p.t.Fatal("invalid pre-mutation fixture budget/endpoint")
	}
	name := p.volume + "-" + role
	if _, err := p.api.ContainerInspect(p.ctx, name, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		p.t.Fatal("unique container name not absent")
	}
	pids := limit.PIDs
	const fixtureCommand = "sleep 90"
	r, err := p.api.ContainerCreate(p.ctx, client.ContainerCreateOptions{Name: name,
		Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
		Config:   &container.Config{Image: containmentImage, User: containmentUser, Entrypoint: []string{"/bin/sh"}, Cmd: []string{"-c", fixtureCommand}, WorkingDir: "/tmp", Labels: map[string]string{containmentLabel: p.run}},
		HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + p.policy}, RestartPolicy: container.RestartPolicy{Name: "no"},
			Resources: container.Resources{Memory: limit.MemoryBytes, MemorySwap: limit.MemoryBytes, NanoCPUs: limit.CPUMillis * 1_000_000, PidsLimit: &pids},
			ShmSize:   16 << 20, Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: p.volume, Target: "/tmp", VolumeOptions: &mount.VolumeOptions{NoCopy: true}}},
			Tmpfs: map[string]string{"/var/lib/postgresql/data": "rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=57000,gid=58000"}}})
	p.mutation(err)
	if r.ID == "" || len(r.Warnings) != 0 {
		p.uncertain = true
		p.t.Fatal("invalid fixture create acknowledgement")
	}
	p.ids = append(p.ids, r.ID)
	observed := p.owned(r.ID)
	c, h := observed.Container, observed.Container.HostConfig
	if c.State == nil || c.State.Status != "created" || c.State.Running || c.State.Pid != 0 ||
		c.Config.User != containmentUser || !slices.Equal(c.Config.Entrypoint, []string{"/bin/sh"}) || !slices.Equal(c.Config.Cmd, []string{"-c", fixtureCommand}) ||
		h == nil || !h.ReadonlyRootfs || h.Privileged || h.PidMode != "" || h.IpcMode != "private" || h.NetworkMode != "none" || h.RestartPolicy.Name != "no" ||
		len(h.Binds) != 0 || len(h.CapAdd) != 0 || !slices.Equal(h.CapDrop, []string{"ALL"}) || !slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true", "seccomp=" + p.policy}) ||
		h.Memory != limit.MemoryBytes || h.MemorySwap != limit.MemoryBytes || h.NanoCPUs != limit.CPUMillis*1_000_000 || h.PidsLimit == nil || *h.PidsLimit != limit.PIDs || h.ShmSize != 16<<20 ||
		len(h.Mounts) != 1 || h.Mounts[0].VolumeOptions == nil || !h.Mounts[0].VolumeOptions.NoCopy || len(h.Tmpfs) != 1 {
		p.t.Fatal("resource/security create projection drift")
	}
	volumes := 0
	for _, m := range c.Mounts {
		if m.Type == mount.TypeVolume && m.Name == p.volume && m.Destination == "/tmp" && m.RW {
			volumes++
		} else if m.Type != mount.TypeTmpfs || m.Destination != "/var/lib/postgresql/data" {
			p.t.Fatal("unexpected fixture mount")
		}
	}
	if volumes != 1 {
		p.t.Fatal("missing scratch volume")
	}
	if _, err := phase6security.ObserveDockerRuntimeImage(codingProbeInspectArray(observed.Raw), codingProbeInspectArray(p.rawImage),
		"registry", phase6security.ImageIdentityOCIIndex, containmentImage, containmentIndex, "linux/arm64/v8", containmentManifest, p.config, p.documents); err != nil {
		p.t.Fatal("actual fixture image differs from verified OCI chain")
	}
	return r.ID
}

type scratchBoundedOutput struct{ bytes.Buffer }

func (b *scratchBoundedOutput) Write(v []byte) (int, error) {
	if b.Len()+len(v) > 16384 {
		return 0, fmt.Errorf("fixture output exceeds limit")
	}
	return b.Buffer.Write(v)
}

func scratchShell(p *containmentProbe, host, id, script string) string {
	p.t.Helper()
	p.owned(id)
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()
	r, err := p.api.ExecCreate(ctx, id, client.ExecCreateOptions{User: containmentUser, WorkingDir: "/tmp", Cmd: []string{"/bin/sh", "-c", script}, AttachStdout: true, AttachStderr: true})
	p.mutation(err)
	if r.ID == "" {
		p.uncertain = true
		p.t.Fatal("missing fixture exec ID")
	}
	stream, err := p.api.ExecAttach(ctx, r.ID, client.ExecAttachOptions{})
	p.mutation(err)
	defer stream.Close()
	stop := context.AfterFunc(ctx, stream.Close)
	defer stop()
	var out, errOut scratchBoundedOutput
	if _, err := stdcopy.StdCopy(&out, &errOut, stream.Reader); err != nil || ctx.Err() != nil || !p.sameEndpoint() {
		p.uncertain = true
		p.t.Fatalf("bounded fixture command failed/uncertain; retain exact resources (stdout bytes=%d stderr bytes=%d)", out.Len(), errOut.Len())
	}
	if status := p.execStopped(id, r.ID); status != 0 {
		p.t.Fatalf("fixed fixture assertion exit=%d (stdout=%q stderr=%q)", status, out.String(), errOut.String())
	}
	if errOut.Len() != 0 {
		p.t.Fatal("unexpected fixture stderr")
	}
	return out.String()
}

func scratchObserveMount(p *containmentProbe, host, id string, policy codingidentity.ExecutionScratch) {
	p.t.Helper()
	result := scratchShell(p, host, id, `set -eu; id -u; id -g; stat -c '%u %g %a' /tmp; stat -f -c '%T %s %b %c %d' /tmp; awk '$5=="/tmp" {print $6; for(i=1;i<=NF;i++) if($i=="-") {print $(i+1); print $(i+3)}}' /proc/self/mountinfo`)
	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 7 || lines[0] != "57000" || lines[1] != "58000" || lines[2] != "57000 58000 700" || lines[5] != "tmpfs" {
		p.t.Fatal("actual scratch identity/type differs")
	}
	fields := strings.Fields(lines[3])
	if len(fields) != 5 || fields[0] != "tmpfs" {
		p.t.Fatal("actual scratch filesystem type differs")
	}
	blockSize, e1 := strconv.ParseInt(fields[1], 10, 64)
	blocks, e2 := strconv.ParseInt(fields[2], 10, 64)
	if e1 != nil || e2 != nil || blockSize <= 0 || blocks <= 0 || blocks > policy.Bytes || blockSize > policy.Bytes || blocks*blockSize != policy.Bytes {
		p.t.Fatal("actual scratch capacity differs")
	}
	inodes, e3 := strconv.ParseInt(fields[3], 10, 64)
	freeInodes, e4 := strconv.ParseInt(fields[4], 10, 64)
	if e3 != nil || e4 != nil || inodes != policy.Inodes || freeInodes <= 0 || freeInodes >= inodes {
		p.t.Fatal("actual scratch inode capacity differs")
	}
	for _, flag := range []string{"rw", "nosuid", "nodev", "noexec"} {
		if !slices.Contains(strings.Split(lines[4], ","), flag) {
			p.t.Fatal("actual scratch mount lacks required flag")
		}
	}
	p.t.Logf("scratch actual tmpfs bytes=%d inodes=%d uid=57000 gid=58000 mode=700 rw/nosuid/nodev/noexec verified", policy.Bytes, policy.Inodes)
}

func scratchMemorySample(p *containmentProbe, host, id, phase string, wantLimit int64) {
	p.t.Helper()
	r := scratchShell(p, host, id, `set -eu; cat /sys/fs/cgroup/memory.max; cat /sys/fs/cgroup/memory.current; awk '$1=="shmem" || $1=="slab" {print $1, $2}' /sys/fs/cgroup/memory.stat`)
	lines := strings.Split(strings.TrimSpace(r), "\n")
	if len(lines) != 4 {
		p.t.Fatal("bounded cgroup memory sample unavailable")
	}
	limit, e1 := strconv.ParseInt(lines[0], 10, 64)
	current, e2 := strconv.ParseInt(lines[1], 10, 64)
	if e1 != nil || e2 != nil || limit != wantLimit || current < 0 {
		p.t.Fatal("cgroup limit/sample drift")
	}
	values := map[string]int64{}
	for _, line := range lines[2:] {
		f := strings.Fields(line)
		if len(f) != 2 || (f[0] != "shmem" && f[0] != "slab") {
			p.t.Fatal("unexpected cgroup counter")
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || v < 0 {
			p.t.Fatal("invalid cgroup counter")
		}
		values[f[0]] = v
	}
	if len(values) != 2 {
		p.t.Fatal("missing cgroup counter")
	}
	p.t.Logf("scratch memory sample %s: limit=%d current=%d shmem=%d slab=%d; not a host/kernel metadata bound", phase, limit, current, values["shmem"], values["slab"])
}
