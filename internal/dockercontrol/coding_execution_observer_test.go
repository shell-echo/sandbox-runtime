//go:build darwin || linux

package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
	ocidigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingcandidate "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/candidate"
)

const executionFixturePolicy = "fixed-four-volume-test-policy"

type executionObserverFixture struct {
	observer        *executionUnixObserver
	Runtime         container.InspectResponse
	Volumes         [4]volume.Volume
	Info            system.Info
	Index, Selected image.InspectResponse
	ExtraContainer  bool
	ArchiveMutation func(int, *tar.Header)
	Before          func(*http.Request, int)
	Calls           []string
}

func newExecutionObserverFixture(b executionBinding, a executionCreate) (*executionObserverFixture, error) {
	manifest, configBytes, err := codingcandidate.DescriptorDocuments(b.Template.Image.Platform)
	if err != nil {
		return nil, err
	}
	docs := phase6security.ImageDescriptorDocuments{Manifest: manifest, Config: configBytes}
	labels, err := executionContainerLabels(b, a, "resident", docs)
	if err != nil {
		return nil, err
	}
	r := a.resources(b)
	tpl := b.Template
	platform, _ := codingOCIPlatform(tpl.Image.Platform)
	descriptor := &ocispec.Descriptor{Digest: ocidigest.Digest(tpl.Image.Descriptor.Digest), MediaType: "application/vnd.oci.image.manifest.v1+json", Size: tpl.Image.SelectedManifestSize, Platform: &platform}
	pids := tpl.Resources.Resident.PIDs
	init := false
	v := container.InspectResponse{ID: strings.Repeat("a", 64), Name: "/" + r.Resident, Image: tpl.Image.Descriptor.Digest, ImageManifestDescriptor: descriptor,
		State:  &container.State{Status: "running", Running: true, Pid: 123, StartedAt: a.IssuedAt.Format(time.RFC3339Nano)},
		Config: &container.Config{Image: tpl.Image.Reference, User: fmt.Sprintf("%d:%d", r.UID, r.GID), WorkingDir: tpl.WorkingDirectory, Cmd: slices.Clone(tpl.ResidentCommand), Env: slices.Clone(tpl.Environment), Labels: labels},
		HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, RestartPolicy: container.RestartPolicy{Name: "no"}, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + executionFixturePolicy}, Init: &init, LogConfig: container.LogConfig{Type: "none"}, ShmSize: tpl.PrivateShmBytes,
			Resources: container.Resources{Memory: tpl.Resources.Resident.MemoryBytes, MemorySwap: tpl.Resources.Resident.MemoryBytes, NanoCPUs: tpl.Resources.Resident.CPUMillis * 1_000_000, PidsLimit: &pids}},
		NetworkSettings: &container.NetworkSettings{Networks: map[string]*network.EndpointSettings{"none": {}}}}
	v.HostConfig.MaskedPaths, v.HostConfig.ReadonlyPaths = executionMaskedPaths(), executionReadonlyPaths()
	for _, m := range executionMounts(r) {
		v.HostConfig.Mounts = append(v.HostConfig.Mounts, mount.Mount{Type: mount.TypeVolume, Source: m.Name, Target: m.Target, ReadOnly: m.ReadOnly, VolumeOptions: &mount.VolumeOptions{NoCopy: true}})
		v.Mounts = append(v.Mounts, container.MountPoint{Type: mount.TypeVolume, Name: m.Name, Destination: m.Target, RW: !m.ReadOnly, Driver: "local"})
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
		Config struct {
			Cmd, Env         []string
			User, WorkingDir string
		} `json:"config"`
	}
	if json.Unmarshal(docs.Config, &config) != nil {
		return nil, ErrInvalidAuthority
	}
	f := &executionObserverFixture{Runtime: v, Info: codingInfoFixture(),
		Index:    image.InspectResponse{ID: tpl.Image.Descriptor.Digest, Descriptor: &ocispec.Descriptor{Digest: ocidigest.Digest(tpl.Image.Descriptor.Digest), MediaType: tpl.Image.Descriptor.MediaType, Size: tpl.Image.Descriptor.Size}, Os: "linux", Architecture: "arm64", Variant: "v8", RootFS: image.RootFS{Type: "layers", Layers: config.RootFS.DiffIDs}},
		Selected: image.InspectResponse{Os: "linux", Architecture: "arm64", Variant: "v8", ID: tpl.Image.Descriptor.Digest, Descriptor: descriptor, Config: &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{Env: config.Config.Env, Cmd: config.Config.Cmd, User: config.Config.User, WorkingDir: config.Config.WorkingDir}}}}
	for i, name := range r.Volumes {
		f.Volumes[i] = volume.Volume{Name: name, Driver: "local", Scope: "local", Labels: executionLabels(b, a, executionVolumeRoles[i]), Options: executionVolumeOptions(b, r, i)}
	}
	bounded := &executionObservationTransport{base: codingRoundTripFunc(f.respond), endpointHost: "/run/docker.sock", binding: b, create: a}
	api, err := client.New(client.WithHost("unix:///run/docker.sock"), client.WithAPIVersion("1.55"), client.WithHTTPClient(&http.Client{Transport: bounded, Timeout: maxCodingObservationRequestDuration}))
	if err != nil {
		return nil, err
	}
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	f.observer = &executionUnixObserver{gate: gate, api: api, bounded: bounded, binding: b, create: a, documents: docs, policy: []byte(executionFixturePolicy)}
	return f, nil
}
func (f *executionObserverFixture) respond(r *http.Request) (*http.Response, error) {
	f.Calls = append(f.Calls, r.URL.String())
	if f.Before != nil {
		f.Before(r, len(f.Calls))
	}
	encode := func(v any) (*http.Response, error) {
		d, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		return codingSDKResponse(200, string(d), "application/json"), nil
	}
	b, a := f.observer.binding, f.observer.create
	resources := a.resources(b)
	path := r.URL.Path
	switch path {
	case "/v1.55/info":
		return encode(f.Info)
	case "/v1.55/containers/" + resources.Preparation + "/json":
		return codingSDKResponse(404, `{"message":"absent"}`, "application/json"), nil
	case "/v1.55/containers/" + resources.Resident + "/json":
		return encode(f.Runtime)
	case "/v1.55/containers/json":
		items := []container.Summary{{ID: f.Runtime.ID, Names: []string{f.Runtime.Name}, Labels: f.Runtime.Config.Labels}}
		if f.ExtraContainer {
			items = append(items, items[0])
		}
		return encode(items)
	case "/v1.55/volumes":
		return encode(struct {
			Volumes  [4]volume.Volume
			Warnings []string
		}{Volumes: f.Volumes})
	case "/v1.55/images/" + b.Template.Image.Reference + "/json":
		if r.URL.RawQuery == "" {
			return encode(f.Index)
		}
		return encode(f.Selected)
	case "/v1.55/containers/" + f.Runtime.ID + "/archive":
		for i, target := range executionTargets {
			if r.URL.Query().Get("path") != target {
				continue
			}
			uid, gid, mode := executionRootOwner(resources, i)
			header := &tar.Header{Name: target[1:] + "/", Typeflag: tar.TypeDir, Uid: uid, Gid: gid, Mode: mode}
			if f.ArchiveMutation != nil {
				f.ArchiveMutation(i, header)
			}
			var out bytes.Buffer
			writer := tar.NewWriter(&out)
			if writer.WriteHeader(header) != nil || writer.Close() != nil {
				return nil, ErrInvalidAuthority
			}
			stat, _ := json.Marshal(container.PathStat{Name: target[1:], Mode: os.ModeDir | os.FileMode(mode)})
			response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(out.Bytes())), ContentLength: int64(out.Len())}
			response.Header.Set("Content-Type", "application/x-tar")
			response.Header.Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(stat))
			return response, nil
		}
	}
	for i, name := range resources.Volumes {
		if path == "/v1.55/volumes/"+name {
			return encode(f.Volumes[i])
		}
	}
	return nil, ErrInvalidCodingObservationTransport
}
func executionFixture(t *testing.T) (*executionObserverFixture, executionBinding, executionCreate) {
	t.Helper()
	l, _, a := executionTestLedger(t)
	f, err := newExecutionObserverFixture(l.binding, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.observer.CloseContext(context.Background()) })
	return f, l.binding, a
}
func observeExecutionFixture(f *executionObserverFixture, b executionBinding, a executionCreate) (executionCompletionObservation, error) {
	return f.observer.observeExecutionCreate(context.Background(), b, a, 2, executionTestDigest("f"))
}

func TestExecutionObserverCompleteFourVolumeBoundedSDKChain(t *testing.T) {
	f, b, a := executionFixture(t)
	proof, err := observeExecutionFixture(f, b, a)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 26 || f.observer.bounded.archiveID != "" || proof.validate(b, a, time.Now().UTC()) != nil {
		t.Fatal("incomplete bounded chain")
	}
	encoded, _ := json.Marshal(proof)
	for _, value := range []string{"/run/docker.sock", "/var/lib/docker", executionFixturePolicy} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatal("raw private source leaked into safe evidence")
		}
	}
	if len(encoded) > 64<<10 {
		t.Fatal("proof exceeds allocation reservation envelope")
	}
	for i, root := range proof.Physical.Roots {
		_, _, mode := executionRootOwner(proof.Resources, i)
		if root.ArchiveMode != mode {
			t.Fatal("wrong per-root mode")
		}
	}
}

func TestExecutionObserverRejectsDriftAndLegacyTopology(t *testing.T) {
	for name, mutate := range map[string]func(*executionObserverFixture){
		"legacy tmpfs": func(f *executionObserverFixture) {
			f.Runtime.HostConfig.Tmpfs = map[string]string{"/tmp": "rw,size=33554432"}
			f.Runtime.HostConfig.Mounts = f.Runtime.HostConfig.Mounts[:3]
			f.Runtime.Mounts = f.Runtime.Mounts[:3]
		},
		"missing scratch":                 func(f *executionObserverFixture) { f.Volumes[3].Name = "missing" },
		"scratch inode drift":             func(f *executionObserverFixture) { f.Volumes[3].Options["o"] = "size=33554432,nr_inodes=8192" },
		"scratch bind":                    func(f *executionObserverFixture) { f.Runtime.HostConfig.Mounts[3].Type = mount.TypeBind },
		"subpath":                         func(f *executionObserverFixture) { f.Runtime.HostConfig.Mounts[3].VolumeOptions.Subpath = "partial" },
		"foreign volume label":            func(f *executionObserverFixture) { f.Volumes[3].Labels[executionScopeLabel] = "foreign" },
		"extra container":                 func(f *executionObserverFixture) { f.ExtraContainer = true },
		"image rootfs":                    func(f *executionObserverFixture) { f.Index.RootFS.Layers[0] = executionTestDigest("f") },
		"image selection":                 func(f *executionObserverFixture) { f.Selected.Config.Env = []string{"WRONG=1"} },
		"selected missing OS":             func(f *executionObserverFixture) { f.Selected.Os = "" },
		"selected wrong arch":             func(f *executionObserverFixture) { f.Selected.Architecture = "amd64" },
		"selected wrong variant":          func(f *executionObserverFixture) { f.Selected.Variant = "v9" },
		"selected store/config confusion": func(f *executionObserverFixture) { f.Selected.ID = f.observer.binding.Template.Image.ConfigDigest },
		"container platform missing":      func(f *executionObserverFixture) { f.Runtime.ImageManifestDescriptor.Platform = nil },
		"container platform conflict":     func(f *executionObserverFixture) { f.Runtime.ImageManifestDescriptor.Platform.Architecture = "amd64" },
		"resident limits":                 func(f *executionObserverFixture) { f.Runtime.HostConfig.Memory = 1 << 30 },
		"shared PID":                      func(f *executionObserverFixture) { f.Runtime.HostConfig.PidMode = "host" },
		"init":                            func(f *executionObserverFixture) { v := true; f.Runtime.HostConfig.Init = &v },
		"logging":                         func(f *executionObserverFixture) { f.Runtime.HostConfig.LogConfig.Type = "json-file" },
		"shm":                             func(f *executionObserverFixture) { f.Runtime.HostConfig.ShmSize = 64 << 20 },
		"extra mount":                     func(f *executionObserverFixture) { f.Runtime.Mounts = append(f.Runtime.Mounts, f.Runtime.Mounts[0]) },
		"empty proc mask":                 func(f *executionObserverFixture) { f.Runtime.HostConfig.MaskedPaths = []string{} },
		"writable proc sys":               func(f *executionObserverFixture) { f.Runtime.HostConfig.ReadonlyPaths = nil },
		"scratch root mode": func(f *executionObserverFixture) {
			f.ArchiveMutation = func(i int, h *tar.Header) {
				if i == 3 {
					h.Mode = 0o770
				}
			}
		},
		"scratch root owner": func(f *executionObserverFixture) {
			f.ArchiveMutation = func(i int, h *tar.Header) {
				if i == 3 {
					h.Uid = 0
				}
			}
		},
		"daemon drift during read": func(f *executionObserverFixture) {
			f.Before = func(_ *http.Request, n int) {
				if n == 26 {
					f.Info.ID = "replacement"
				}
			}
		},
		"resident replacement": func(f *executionObserverFixture) {
			f.Before = func(r *http.Request, n int) {
				if n > 15 && strings.HasSuffix(r.URL.Path, "/json") && strings.Contains(r.URL.Path, "/containers/") {
					f.Runtime.ID = strings.Repeat("b", 64)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, b, a := executionFixture(t)
			mutate(f)
			if _, err := observeExecutionFixture(f, b, a); err == nil {
				t.Fatal("drift admitted")
			}
			if f.observer.bounded.archiveID != "" {
				t.Fatal("archive authority leaked")
			}
		})
	}
}

func TestExecutionObserverLocalManifestDescriptorMayOmitPlatform(t *testing.T) {
	f, b, a := executionFixture(t)
	d := *f.Selected.Descriptor
	d.Platform = nil
	f.Selected.Descriptor = &d
	if _, err := observeExecutionFixture(f, b, a); err != nil {
		t.Fatal("valid local manifest rejected", err)
	}
	// Missing descriptor platform cannot compensate for missing Docker OS/arch.
	f.Selected.Architecture = ""
	if _, err := observeExecutionFixture(f, b, a); err == nil {
		t.Fatal("missing platform authority accepted")
	}
}

func TestExecutionObserverRetainedProofRecheckedNotJustResealed(t *testing.T) {
	f, b, a := executionFixture(t)
	good, err := observeExecutionFixture(f, b, a)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*executionCompletionObservation){
		"options": func(o *executionCompletionObservation) {
			o.Physical.InitialInventory.Volumes[3].OptionsDigest = executionTestDigest("f")
			o.Physical.FinalInventory = o.Physical.InitialInventory
			o.InventoryEvidenceDigest = executionDigest("inventory", o.Physical.InitialInventory)
		},
		"root": func(o *executionCompletionObservation) { o.Physical.Roots[3].ArchiveGID = 0 },
		"runtime": func(o *executionCompletionObservation) {
			o.Physical.InitialRuntime.Init = true
			o.Physical.FinalRuntime = o.Physical.InitialRuntime
		},
		"image": func(o *executionCompletionObservation) {
			o.Physical.Image.OCIConfigDigest = executionTestDigest("f")
			o.ImageEvidenceDigest = executionDigest("image-evidence", struct {
				Image    phase6security.DockerImageObservation
				Selected string
			}{o.Physical.Image, o.Physical.SelectedImageDigest})
		},
		"descriptor source": func(o *executionCompletionObservation) { o.Physical.Documents.Config[0] = 'x' },
		"previous protocol": func(o *executionCompletionObservation) { o.Protocol = "sandbox-runtime.coding-isolated-receipts.v2" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneExecutionCompletion(good)
			mutate(&bad)
			if bad.validate(b, a, time.Now().UTC()) == nil {
				t.Fatal("resealed drift passed")
			}
		})
	}
}

func TestExecutionObserverReadOnlyTransportAndUnambiguousJSON(t *testing.T) {
	f, _, _ := executionFixture(t)
	transport := f.observer.bounded
	for _, path := range []string{"/v1.55/containers/json", "/v1.55/containers/other/json", "/v1.55/volumes/old-scratch", "/v1.55/info?extra=1", "/v1.55/containers/" + f.Runtime.ID + "/archive?path=%2Ftmp"} {
		u, _ := url.Parse("http://placeholder" + path)
		u.Host = transport.endpointHost
		r := &http.Request{Method: "GET", URL: u, Host: client.DummyHost}
		if _, err := transport.RoundTrip(r); err == nil {
			t.Fatal("unapproved GET")
		}
	}
	for _, method := range []string{"POST", "DELETE", "PUT", "HEAD"} {
		u := &url.URL{Scheme: "http", Host: transport.endpointHost, Path: "/v1.55/info"}
		if _, err := transport.RoundTrip(&http.Request{Method: method, URL: u, Host: client.DummyHost}); err == nil {
			t.Fatal("mutation admitted")
		}
	}
	if len(f.Calls) != 0 {
		t.Fatal("rejected request reached daemon")
	}
	for _, raw := range []string{`{"State":{"Running":true,"running":false}}`, `{"Volumes":[],"volumes":[]}`, strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)} {
		if executionJSONUnambiguous([]byte(raw)) {
			t.Fatal("ambiguous JSON admitted")
		}
	}
	if !executionJSONUnambiguous([]byte(`{"State":{"Running":true},"Mounts":[]}`)) {
		t.Fatal("normal JSON rejected")
	}
}

func TestExecutionObserverDeadlineAndSourceHold(t *testing.T) {
	f, b, a := executionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.observer.observeExecutionCreate(ctx, b, a, 2, executionTestDigest("f")); err == nil || len(f.Calls) != 0 {
		t.Fatal("cancelled collector performed reads")
	}
	<-f.observer.gate
	short, done := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer done()
	if _, err := f.observer.observeExecutionCreate(short, b, a, 2, executionTestDigest("f")); err == nil {
		t.Fatal("queue wait escaped deadline")
	}
	f.observer.gate <- struct{}{}
	if _, err := newExecutionUnixObserver(codingBoundUnixEndpoint{path: "/not/an/admitted/socket", scopeDigest: b.EndpointScopeDigest}, b, a, f.observer.documents, []byte(executionFixturePolicy)); err == nil {
		t.Fatal("unadmitted endpoint gained authority")
	}
}

func TestExecutionObserverSecondaryResourcesFailClosed(t *testing.T) {
	fields := reflect.TypeFor[container.Resources]()
	for i := range fields.NumField() {
		name := fields.Field(i).Name
		if slices.Contains([]string{"Memory", "MemorySwap", "NanoCPUs", "PidsLimit"}, name) {
			continue // independently covered exact limits
		}
		t.Run(name, func(t *testing.T) {
			f, b, a := executionFixture(t)
			v := reflect.ValueOf(&f.Runtime.HostConfig.Resources).Elem().Field(i)
			switch v.Kind() {
			case reflect.Int64:
				v.SetInt(1)
			case reflect.Uint16, reflect.Uint64:
				v.SetUint(1)
			case reflect.String:
				v.SetString("unapproved")
			case reflect.Slice:
				v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			case reflect.Pointer:
				v.Set(reflect.New(v.Type().Elem()))
				if v.Elem().Kind() == reflect.Bool {
					v.Elem().SetBool(true)
				} else {
					v.Elem().SetInt(1)
				}
			default:
				t.Fatalf("new resource field needs explicit test: %s", name)
			}
			if _, err := observeExecutionFixture(f, b, a); err == nil {
				t.Fatal("additional resource override admitted")
			}
		})
	}
	f, b, a := executionFixture(t)
	swappiness, oom := int64(-1), false
	f.Runtime.HostConfig.MemorySwappiness = &swappiness
	f.Runtime.HostConfig.OomKillDisable = &oom
	f.Runtime.HostConfig.Devices = []container.DeviceMapping{}
	if _, err := observeExecutionFixture(f, b, a); err != nil {
		t.Fatal("unset resource normalization rejected", err)
	}
	for name, change := range map[string]func(*container.HostConfig){
		"annotations": func(h *container.HostConfig) { h.Annotations = map[string]string{"runtime": "override"} },
		"dns":         func(h *container.HostConfig) { h.DNSOptions = []string{"rotate"} },
		"console":     func(h *container.HostConfig) { h.ConsoleSize[0] = 80 },
		"oom score":   func(h *container.HostConfig) { h.OomScoreAdj = -1000 },
		"isolation":   func(h *container.HostConfig) { h.Isolation = "hyperv" },
	} {
		t.Run(name, func(t *testing.T) {
			f, b, a := executionFixture(t)
			change(f.Runtime.HostConfig)
			if _, err := observeExecutionFixture(f, b, a); err == nil {
				t.Fatal("additional host option admitted")
			}
		})
	}
}

type executionStreamingTestBody struct {
	io.Reader
	onRead, onClose func()
	closed          bool
}

func (b *executionStreamingTestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if b.onRead != nil {
		b.onRead()
	}
	return n, err
}
func (b *executionStreamingTestBody) Close() error {
	b.closed = true
	if b.onClose != nil {
		b.onClose()
	}
	return nil
}

func TestExecutionObserverSocketAndCancellationCoverResponseBody(t *testing.T) {
	for _, mode := range []string{"stable", "before request", "during headers", "during body", "during close", "cancel during body"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _ := executionFixture(t)
			transport := f.observer.bounded
			stable, calls := mode != "before request", 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			body := &executionStreamingTestBody{Reader: strings.NewReader(`{"ok":true}`)}
			body.onRead = func() {
				if mode == "during body" {
					stable = false
				}
				if mode == "cancel during body" {
					cancel()
				}
			}
			body.onClose = func() {
				if mode == "during close" {
					stable = false
				}
			}
			check := func() bool { return stable }
			transport.checkSocket = check
			transport.base = executionSocketTransport{check: check, base: codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if mode == "during headers" {
					stable = false
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: -1, Body: body}, nil
			})}
			u := &url.URL{Scheme: "http", Host: transport.endpointHost, Path: "/v1.55/info"}
			r := (&http.Request{Method: "GET", URL: u, Host: client.DummyHost}).WithContext(ctx)
			response, err := transport.RoundTrip(r)
			if mode == "stable" {
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
			} else if err == nil || response != nil {
				t.Fatal("socket drift/cancellation admitted")
			}
			if mode == "before request" {
				if calls != 0 {
					t.Fatal("drifted socket dialed")
				}
			} else if calls != 1 || !body.closed {
				t.Fatal("response body not closed")
			}
		})
	}
}
