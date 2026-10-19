//go:build integration

package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	containmentImage    = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	containmentIndex    = "sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	containmentManifest = "sha256:2c942175a1255a9abe0366e48c1b401d9f50f835b04dfea13f111609b5530df7"
	containmentLabel    = "io.github.shell-echo.sandbox-runtime.exec-containment-probe"
	containmentUser     = "57000:58000"
)

// This is a mechanism experiment, not a Coding image, Profile-v2, driver
// Cancel, or Control/PG release gate. It deliberately reproduces the legacy
// shell/PID-file algorithm without composing that legacy driver's host binds.
// A stopped container and a finite quiet window do not prove that previously
// uncertain Docker mutations cannot arrive later. No exec permit is produced.
func TestCodingExecContainmentRealDaemon(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CODING_EXEC_CONTAINMENT") != "1" {
		t.Skip("explicit local Docker containment probe not enabled")
	}
	host := os.Getenv("SANDBOX_RUNTIME_CODING_EXEC_UNIX_ENDPOINT")
	path := strings.TrimPrefix(host, "unix://")
	if !strings.HasPrefix(host, "unix://") || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("explicit local Unix endpoint required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		t.Fatal("fixture endpoint must have no symlink components")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatal("explicit local endpoint is not a socket")
	}
	sameEndpoint := func() bool {
		resolved, err := filepath.EvalSymlinks(path)
		current, statErr := os.Lstat(path)
		return err == nil && resolved == path && statErr == nil &&
			current.Mode()&os.ModeSocket != 0 && os.SameFile(info, current)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	transport := &http.Transport{Proxy: nil, MaxConnsPerHost: 1,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if !sameEndpoint() {
				return nil, fmt.Errorf("fixture socket changed before dial")
			}
			connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}
			if !sameEndpoint() {
				_ = connection.Close()
				return nil, fmt.Errorf("fixture socket changed during dial")
			}
			return connection, nil
		}}
	t.Cleanup(transport.CloseIdleConnections)
	api, err := client.New(client.WithHost(host), client.WithAPIVersion("1.55"),
		client.WithHTTPClient(&http.Client{Transport: transport, Timeout: 20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect denied") }}))
	if err != nil {
		t.Fatal("construct frozen fixture client")
	}
	t.Cleanup(func() { _ = api.Close() })
	scope := digest([]byte("exec-containment-fixture\x00" + host))
	daemon, err := ObserveCodingDaemon(ctx, api, scope)
	if err != nil || daemon.Platform != "linux/arm64/v8" {
		t.Fatal("fixture requires local Linux/arm64 Docker")
	}
	index, err := api.ImageInspect(ctx, containmentImage)
	if err != nil || index.Descriptor == nil || index.Descriptor.Digest.String() != containmentIndex {
		t.Fatal("cached locked PG fixture index missing; this test never pulls")
	}
	platform := &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	selected, err := api.ImageInspect(ctx, containmentImage, client.ImageInspectWithPlatform(platform))
	if err != nil || selected.Descriptor == nil || selected.Descriptor.Digest.String() != containmentManifest ||
		selected.Config == nil || len(selected.Config.Volumes) != 1 || selected.Config.Healthcheck != nil {
		t.Fatal("locked fixture manifest/config mismatch")
	}
	if _, ok := selected.Config.Volumes["/var/lib/postgresql/data"]; !ok {
		t.Fatal("unexpected fixture image volume")
	}
	// Verify cached original OCI bytes, including layers, before any mutation.
	archivePath := filepath.Join(t.TempDir(), "fixture.oci.tar")
	archiveCommand := exec.CommandContext(ctx, "docker", "--host", host, "image", "save", "-o", archivePath, containmentImage)
	if output, err := archiveCommand.CombinedOutput(); err != nil {
		t.Fatalf("export cached fixture: %v (output bytes=%d)", err, len(output))
	}
	if err := os.Chmod(archivePath, 0o600); err != nil {
		t.Fatal(err)
	}
	documents, proof, err := phase6security.ReadOCIArchiveDescriptorChain(archivePath,
		"registry", phase6security.ImageIdentityOCIIndex, containmentImage, containmentIndex,
		"linux/arm64/v8", containmentManifest)
	if err != nil || phase6security.VerifyOCIArchiveLayers(archivePath, documents.Manifest, documents.Config) != nil {
		t.Fatal("cached fixture OCI descriptor/config/layer chain failed")
	}
	binary := containmentBuild(t, ctx)
	policy, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json"))
	if err != nil || digest(policy) != "sha256:536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74" {
		t.Fatal("locked seccomp bytes differ")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	run := hex.EncodeToString(nonce[:])
	p := &containmentProbe{t: t, ctx: ctx, api: api, run: run,
		volume: "sandbox-runtime-exec-probe-" + run, policy: string(policy), config: proof.ConfigDigest,
		documents: documents, sameEndpoint: sameEndpoint}
	// Image observation additionally ties each actual container to the archive.
	var raw bytes.Buffer
	if _, err := api.ImageInspect(ctx, containmentImage, client.ImageInspectWithRawResponse(&raw)); err != nil {
		t.Fatal(err)
	}
	p.rawImage = raw.Bytes()
	t.Logf("mechanism-only run=%s index=%s manifest=%s config=%s binary=%s daemon=%s environment=%s uid_gid=%s seccomp=%s",
		run, containmentIndex, containmentManifest, proof.ConfigDigest, digest(binary), daemon.IdentityDigest,
		daemon.EnvironmentDigest, containmentUser, digest(policy))
	if _, err := api.VolumeInspect(ctx, p.volume, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("unique fixture volume already exists or cannot be observed")
	}
	t.Cleanup(p.cleanup)
	_, err = api.VolumeCreate(ctx, client.VolumeCreateOptions{Name: p.volume, Driver: "local", Labels: map[string]string{containmentLabel: run}})
	p.mutation(err)
	p.volumeCreated = true
	carrier := p.create("carrier", []string{"/bin/false"}, false)
	p.put(carrier, containmentArchive(t, binary), "/")
	// Never start the preparation carrier. All executable helper directories
	// are root-owned; only the three bounded case directories are writable.
	for _, name := range []string{"negative", "killed", "natural"} {
		b, header := p.read(carrier, "/probe/"+name, true)
		if len(b) != 0 || header.Uid != 57000 || header.Gid != 58000 || header.Mode != 0o700 {
			t.Fatal("case directory ownership/mode mismatch")
		}
	}
	gotBinary, header := p.read(carrier, "/probe/helper", false)
	if !bytes.Equal(gotBinary, binary) || header.Uid != 0 || header.Gid != 0 || header.Mode != 0o555 {
		t.Fatal("uploaded helper differs or is workload-writable")
	}
	_, rootHeader := p.read(carrier, "/probe", true)
	if rootHeader.Uid != 0 || rootHeader.Gid != 0 || rootHeader.Mode != 0o755 {
		t.Fatal("helper parent is workload-writable")
	}
	p.remove(carrier)

	negative := p.create("negative", []string{"/probe/helper", "park", "/probe/negative"}, true)
	p.start(negative)
	// Keep these shell strings equal to the legacy algorithm under review.
	wrapper := p.exec(negative, []string{"/bin/sh", "-c",
		`pid_file="$1"; shift; "$@" & child=$!; printf '%s\n' "$child" > "$pid_file" || exit 125; wait "$child"; status=$?; rm -f "$pid_file"; exit "$status"`,
		"sandbox-runtime-exec", "/tmp/probe.pid", "/probe/helper", "direct", "/probe/negative"})
	p.alive(negative, "negative")
	direct := p.identity(negative, "negative", "direct")
	checkPID := p.exec(negative, []string{"/bin/sh", "-c",
		`test "$(cat "$1")" = "$2" && kill -0 "$2"`, "check-direct", "/tmp/probe.pid", strconv.Itoa(direct.PID)})
	if p.execStopped(negative, checkPID) != 0 {
		t.Fatal("PID file is not the live direct child")
	}
	live, err := api.ExecInspect(ctx, wrapper, client.ExecInspectOptions{})
	if err != nil || !live.Running || live.ContainerID != negative {
		t.Fatal("wrapper stopped before cancellation")
	}
	killer := p.exec(negative, []string{"/bin/sh", "-c",
		`test -r "$1" || exit 3; pid=$(cat "$1") || exit 4; kill -TERM "$pid"`, "sandbox-runtime-cancel", "/tmp/probe.pid"})
	if exit := p.execStopped(negative, killer); exit != 0 {
		t.Fatalf("TERM did not succeed: %d", exit)
	}
	if exit := p.execStopped(negative, wrapper); exit != 143 {
		t.Fatalf("wrapper did not exit on child TERM: %d", exit)
	}
	before := p.counter(negative, "negative")
	p.pause(250 * time.Millisecond)
	after := p.counter(negative, "negative")
	if after <= before {
		t.Fatal("counterexample not reproduced: detached writer did not survive child TERM")
	}
	t.Logf("negative: TERM exit=0 wrapper exit=143 running=false; detached orphan counter still grew %d -> %d", before, after)
	p.remove(negative)

	for _, name := range []string{"killed", "natural"} {
		id := p.create(name, []string{"/probe/helper", "command", "/probe/" + name}, true)
		p.start(id)
		p.alive(id, name)
		parent := p.identity(id, name, "command")
		if parent.PID != 1 {
			t.Fatal("candidate command is not namespace PID 1")
		}
		code := 137
		if name == "killed" {
			p.owned(id)
			_, err := api.ContainerKill(ctx, id, client.ContainerKillOptions{Signal: "SIGKILL"})
			p.mutation(err)
		} else {
			code = 0
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			if err := tw.WriteHeader(&tar.Header{Name: "release", Mode: 0o600, Uid: 57000, Gid: 58000, Size: 0, Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			p.put(id, b.Bytes(), "/probe/"+name)
		}
		p.stopped(id, code)
		before := p.counter(id, name)
		for range 5 {
			p.pause(100 * time.Millisecond)
			if p.counter(id, name) != before {
				t.Fatal("writer changed state after exact container stopped")
			}
		}
		t.Logf("%s: exact container stopped PID=0 exit=%d; counter=%d unchanged in 500ms window (not late-mutation quiescence)", name, code, before)
		p.remove(id)
	}
	afterDaemon, err := ObserveCodingDaemon(ctx, api, scope)
	if err != nil || afterDaemon != daemon {
		t.Fatal("daemon identity/environment changed during probe")
	}
}

type containmentProbe struct {
	t                           *testing.T
	ctx                         context.Context
	api                         *client.Client
	run, volume, policy, config string
	documents                   phase6security.ImageDescriptorDocuments
	rawImage                    []byte
	ids                         []string
	volumeCreated, uncertain    bool
	sameEndpoint                func() bool
}

func containmentBuild(t *testing.T, ctx context.Context) []byte {
	t.Helper()
	version, err := exec.CommandContext(ctx, "go", "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "go version go1.26.8 ") {
		t.Fatal("fixture requires Go1.26.8")
	}
	source, err := os.ReadFile("testdata/execcontainment/main.go")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "helper")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-o", path, "./testdata/execcontainment")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline helper build: %v (output bytes=%d)", err, len(out))
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 || len(b) > 16<<20 {
		t.Fatal("invalid bounded fixture binary")
	}
	t.Logf("fixture source=%s compiler=%s target=linux/arm64 cgo=0", digest(source), strings.TrimSpace(string(version)))
	return b
}

func containmentArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range []*tar.Header{
		{Name: "probe/", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "probe/negative/", Mode: 0o700, Uid: 57000, Gid: 58000, Typeflag: tar.TypeDir},
		{Name: "probe/killed/", Mode: 0o700, Uid: 57000, Gid: 58000, Typeflag: tar.TypeDir},
		{Name: "probe/natural/", Mode: 0o700, Uid: 57000, Gid: 58000, Typeflag: tar.TypeDir},
		{Name: "probe/helper", Mode: 0o555, Size: int64(len(binary)), Typeflag: tar.TypeReg},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(binary); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func (p *containmentProbe) mutation(err error) {
	p.t.Helper()
	if err != nil {
		p.uncertain = true
		p.t.Fatal("Docker mutation uncertain; no retry or automatic cleanup; retain run-labelled resources")
	}
}

func (p *containmentProbe) create(role string, command []string, readonly bool) string {
	p.t.Helper()
	name := p.volume + "-" + role
	if _, err := p.api.ContainerInspect(p.ctx, name, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		p.t.Fatal("fixture name not absent")
	}
	pids := int64(64)
	r, err := p.api.ContainerCreate(p.ctx, client.ContainerCreateOptions{Name: name,
		Platform: &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
		Config: &container.Config{Image: containmentImage, Entrypoint: []string{command[0]}, Cmd: command[1:], User: containmentUser,
			WorkingDir: "/probe", Labels: map[string]string{containmentLabel: p.run}},
		HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: readonly, CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + p.policy}, RestartPolicy: container.RestartPolicy{Name: "no"},
			Resources: container.Resources{Memory: 256 << 20, MemorySwap: 256 << 20, NanoCPUs: 500_000_000, PidsLimit: &pids},
			Mounts:    []mount.Mount{{Type: mount.TypeVolume, Source: p.volume, Target: "/probe", VolumeOptions: &mount.VolumeOptions{NoCopy: true}}},
			Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=57000,gid=58000",
				"/var/lib/postgresql/data": "rw,noexec,nosuid,nodev,size=1048576,mode=0700,uid=57000,gid=58000"}}})
	p.mutation(err)
	if r.ID == "" || len(r.Warnings) != 0 {
		p.uncertain = true
		p.t.Fatal("invalid create acknowledgement")
	}
	p.ids = append(p.ids, r.ID)
	observed := p.owned(r.ID)
	c := observed.Container
	h := c.HostConfig
	if c.State == nil || c.State.Status != "created" || c.State.Running || c.State.Pid != 0 ||
		c.Config.User != containmentUser || c.Config.Image != containmentImage || !slices.Equal(c.Config.Entrypoint, command[:1]) || !slices.Equal(c.Config.Cmd, command[1:]) ||
		h == nil || h.Privileged || h.ReadonlyRootfs != readonly || h.NetworkMode != "none" || h.PidMode != "" || h.IpcMode != "private" ||
		h.RestartPolicy.Name != "no" || len(h.Binds) != 0 || len(h.CapAdd) != 0 || !slices.Equal(h.CapDrop, []string{"ALL"}) ||
		!slices.Equal(h.SecurityOpt, []string{"no-new-privileges:true", "seccomp=" + p.policy}) ||
		h.Memory != 256<<20 || h.MemorySwap != 256<<20 || h.NanoCPUs != 500_000_000 || h.PidsLimit == nil || *h.PidsLimit != 64 ||
		len(h.Mounts) != 1 || h.Mounts[0].VolumeOptions == nil || !h.Mounts[0].VolumeOptions.NoCopy || len(h.Tmpfs) != 2 {
		p.t.Fatal("closed fixture container configuration drift")
	}
	volumes := 0
	for _, m := range c.Mounts {
		if m.Type == mount.TypeVolume && m.Name == p.volume && m.Destination == "/probe" && m.RW {
			volumes++
		} else if m.Type != mount.TypeTmpfs || (m.Destination != "/tmp" && m.Destination != "/var/lib/postgresql/data") {
			p.t.Fatal("unexpected container mount")
		}
	}
	if volumes != 1 {
		p.t.Fatal("missing exact fixture volume")
	}
	image, err := phase6security.ObserveDockerRuntimeImage(codingProbeInspectArray(observed.Raw), codingProbeInspectArray(p.rawImage),
		"registry", phase6security.ImageIdentityOCIIndex, containmentImage, containmentIndex, "linux/arm64/v8", containmentManifest, p.config, p.documents)
	if err != nil || image.DescriptorProofDigest == "" {
		p.t.Fatal("actual container image differs from original cached OCI chain")
	}
	return r.ID
}

func (p *containmentProbe) owned(id string) client.ContainerInspectResult {
	p.t.Helper()
	if !p.sameEndpoint() {
		p.uncertain = true
		p.t.Fatal("fixture endpoint changed; retain owned resources")
	}
	r, err := p.api.ContainerInspect(p.ctx, id, client.ContainerInspectOptions{})
	if err != nil || r.Container.ID != id || r.Container.Config == nil || r.Container.Config.Labels[containmentLabel] != p.run {
		p.t.Fatal("exact fixture container ownership unavailable")
	}
	return r
}

func (p *containmentProbe) start(id string) {
	p.owned(id)
	_, err := p.api.ContainerStart(p.ctx, id, client.ContainerStartOptions{})
	p.mutation(err)
}

func (p *containmentProbe) put(id string, b []byte, dest string) {
	p.owned(id)
	_, err := p.api.CopyToContainer(p.ctx, id, client.CopyToContainerOptions{DestinationPath: dest, Content: bytes.NewReader(b), CopyUIDGID: false, AllowOverwriteDirWithFile: false})
	p.mutation(err)
}

func (p *containmentProbe) read(id, path string, directory bool) ([]byte, *tar.Header) {
	p.t.Helper()
	r, err := p.api.CopyFromContainer(p.ctx, id, client.CopyFromContainerOptions{SourcePath: path})
	if err != nil {
		p.t.Fatal("read bounded fixture artifact")
	}
	defer r.Content.Close()
	tr := tar.NewReader(io.LimitReader(r.Content, 17<<20))
	h, err := tr.Next()
	if err != nil || h.Size < 0 || h.Size > 16<<20 || (directory && h.Typeflag != tar.TypeDir) || (!directory && h.Typeflag != tar.TypeReg) {
		p.t.Fatal("invalid fixture archive entry")
	}
	if directory {
		return nil, h
	}
	b, err := io.ReadAll(tr)
	if err != nil || int64(len(b)) != h.Size {
		p.t.Fatal("incomplete fixture artifact")
	}
	return b, h
}

func (p *containmentProbe) exec(id string, command []string) string {
	p.owned(id)
	r, err := p.api.ExecCreate(p.ctx, id, client.ExecCreateOptions{User: containmentUser, WorkingDir: "/tmp", Cmd: command})
	p.mutation(err)
	if r.ID == "" {
		p.uncertain = true
		p.t.Fatal("missing exec acknowledgement")
	}
	_, err = p.api.ExecStart(p.ctx, r.ID, client.ExecStartOptions{Detach: true})
	p.mutation(err)
	return r.ID
}

func (p *containmentProbe) execStopped(id, execution string) int {
	p.t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		r, err := p.api.ExecInspect(p.ctx, execution, client.ExecInspectOptions{})
		if err != nil || r.ContainerID != id || r.ID != execution {
			p.t.Fatal("exact exec inspect failed")
		}
		if !r.Running {
			return r.ExitCode
		}
		p.pause(20 * time.Millisecond)
	}
	p.t.Fatal("exec did not stop within fixture deadline")
	return -1
}

type containmentIdentity struct {
	PID, PPID, SID, UID, GID int
	PIDNamespace             string
}

func (p *containmentProbe) identity(id, name, role string) containmentIdentity {
	p.t.Helper()
	b, _ := p.read(id, "/probe/"+name+"/"+role+".json", false)
	var r containmentIdentity
	if json.Unmarshal(b, &r) != nil || r.PID < 1 || r.UID != 57000 || r.GID != 58000 || !strings.HasPrefix(r.PIDNamespace, "pid:[") {
		p.t.Fatal("invalid fixture process identity")
	}
	return r
}

func (p *containmentProbe) alive(id, name string) {
	p.t.Helper()
	// Wait only for the fixed readiness file, not an execution mutation.
	until := time.Now().Add(5 * time.Second)
	for {
		r, err := p.api.ContainerStatPath(p.ctx, id, client.ContainerStatPathOptions{Path: "/probe/" + name + "/counter"})
		if err == nil && r.Stat.Size > 0 {
			break
		}
		if err != nil && !cerrdefs.IsNotFound(err) {
			p.t.Fatal("fixture readiness observation failed")
		}
		if time.Now().After(until) {
			p.t.Fatal("fixture writer did not become ready")
		}
		p.pause(20 * time.Millisecond)
	}
	leaf := p.identity(id, name, "leaf")
	if leaf.PID <= 1 || leaf.PPID != 1 || leaf.SID != leaf.PID {
		p.t.Fatal("writer did not detach and reparent to PID 1")
	}
	before := p.counter(id, name)
	p.pause(150 * time.Millisecond)
	if p.counter(id, name) <= before {
		p.t.Fatal("fixture writer was never observed advancing")
	}
}

func (p *containmentProbe) counter(id, name string) uint64 {
	p.t.Helper()
	b, _ := p.read(id, "/probe/"+name+"/counter", false)
	n, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil || n == 0 {
		p.t.Fatal("invalid fixture counter")
	}
	return n
}

func (p *containmentProbe) pause(d time.Duration) {
	select {
	case <-p.ctx.Done():
		p.t.Fatal("fixture deadline")
	case <-time.After(d):
	}
}

func (p *containmentProbe) stopped(id string, exit int) {
	p.t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		r := p.owned(id).Container
		if r.State != nil && !r.State.Running {
			if r.State.Status != "exited" || r.State.Pid != 0 || r.State.ExitCode != exit || r.State.OOMKilled || r.RestartCount != 0 {
				p.t.Fatal("candidate stopped for a different reason")
			}
			return
		}
		p.pause(20 * time.Millisecond)
	}
	p.t.Fatal("exact fixture container did not stop")
}

func (p *containmentProbe) remove(id string) {
	p.owned(id)
	_, err := p.api.ContainerRemove(p.ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: false})
	p.mutation(err)
	if _, err := p.api.ContainerInspect(p.ctx, id, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		p.t.Fatal("fixture removal not observed")
	}
	p.ids = slices.DeleteFunc(p.ids, func(v string) bool { return v == id })
}

func (p *containmentProbe) cleanup() {
	if p.uncertain || !p.sameEndpoint() {
		p.t.Logf("retained uncertain run=%s (helpers self-expire in 90s)", p.run)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := len(p.ids) - 1; i >= 0; i-- {
		id := p.ids[i]
		r, err := p.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil || r.Container.ID != id || r.Container.Config == nil || r.Container.Config.Labels[containmentLabel] != p.run {
			p.t.Error("cleanup refused container without exact ownership")
			return
		}
		if _, err := p.api.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: false}); err != nil {
			p.t.Error("cleanup container mutation uncertain; no retry")
			return
		}
	}
	if p.volumeCreated {
		r, err := p.api.VolumeInspect(ctx, p.volume, client.VolumeInspectOptions{})
		if err != nil || r.Volume.Name != p.volume || r.Volume.Labels[containmentLabel] != p.run || r.Volume.Driver != "local" {
			p.t.Error("cleanup refused volume without exact ownership")
			return
		}
		if _, err := p.api.VolumeRemove(ctx, p.volume, client.VolumeRemoveOptions{Force: false}); err != nil {
			p.t.Error("cleanup volume mutation uncertain; no retry")
			return
		}
		if _, err := p.api.VolumeInspect(ctx, p.volume, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			p.t.Error("fixture volume absence not observed")
			return
		}
	}
	p.t.Log("exact owned fixture cleanup completed")
}
