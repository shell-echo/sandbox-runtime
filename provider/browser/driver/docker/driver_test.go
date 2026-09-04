package docker

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- required by the RFC 6455 test handshake.
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

var browserDriverTestTime = time.Date(2026, 9, 3, 16, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Set(now time.Time) { c.mu.Lock(); c.now = now; c.mu.Unlock() }

type fakeProvenance struct {
	mu          sync.Mutex
	calls       int
	deadline    time.Time
	hasDeadline bool
	err         error
}

func (v *fakeProvenance) Verify(ctx context.Context, publication browserimage.Publication) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	v.deadline, v.hasDeadline = ctx.Deadline()
	if publication.Validate() != nil {
		return browserimage.ErrInvalidPublication
	}
	return v.err
}

type fakeNetwork struct {
	mu                     sync.Mutex
	readyCalls, acquires   int
	inspects, releases     int
	readyErr, acquireErr   error
	inspectErr, releaseErr error
	attachment             NetworkAttachment
}

func newFakeNetwork() *fakeNetwork {
	return &fakeNetwork{attachment: NetworkAttachment{
		DockerName: "browser-egress-network-1", GatewayContainer: "browser-egress-gateway-1", GatewayAddress: "10.88.0.2",
		LeaseID: "browser-network-lease-1", PolicyReference: "browser-egress-policy-1",
		PolicyDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", EgressGateway: true,
	}}
}
func (n *fakeNetwork) Ready(_ context.Context, policy string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.readyCalls++
	if policy != n.attachment.PolicyReference {
		return ErrNetworkUnavailable
	}
	return n.readyErr
}
func (n *fakeNetwork) Acquire(_ context.Context, request NetworkRequest) (NetworkAttachment, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.acquires++
	if request.PolicyReference != n.attachment.PolicyReference || request.SandboxID == "" || request.BrowserSessionID == "" {
		return NetworkAttachment{}, ErrNetworkUnavailable
	}
	return n.attachment, n.acquireErr
}
func (n *fakeNetwork) Inspect(_ context.Context, attachment NetworkAttachment) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.inspects++
	if attachment != n.attachment {
		return ErrNetworkUnavailable
	}
	return n.inspectErr
}
func (n *fakeNetwork) Release(_ context.Context, attachment NetworkAttachment) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.releases++
	if attachment != n.attachment {
		return ErrNetworkUnavailable
	}
	return n.releaseErr
}
func (n *fakeNetwork) counts() (int, int, int, int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.readyCalls, n.acquires, n.inspects, n.releases
}

type fakeEngine struct {
	mu             sync.Mutex
	image          imageInfo
	container      *containerInfo
	createRequests []createRequest
	attachRequests []*scriptedRelay
	pingErr        error
	ensureErr      error
	imageErr       error
	createErr      error
	inspectErr     error
	startErr       error
	removeErr      error
	attachErr      error
	closed         bool
}

const fakeContainerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func (e *fakeEngine) ping(context.Context) error                            { return e.pingErr }
func (e *fakeEngine) ensureImage(context.Context, string, PullPolicy) error { return e.ensureErr }
func (e *fakeEngine) inspectImage(context.Context, string) (imageInfo, error) {
	return e.image, e.imageErr
}
func (e *fakeEngine) create(_ context.Context, request createRequest) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.createRequests = append(e.createRequests, cloneCreateRequest(request))
	if e.createErr != nil {
		return "", e.createErr
	}
	if e.container != nil {
		return "", cerrdefs.ErrConflict
	}
	resolver := netip.MustParseAddr(request.dnsResolver)
	e.container = &containerInfo{
		id: fakeContainerID, imageID: e.image.id, imageReference: request.image,
		labels: cloneStrings(request.labels), user: request.user, workingDirectory: request.workingDirectory,
		entrypoint: append([]string(nil), e.image.entrypoint...), command: append([]string(nil), e.image.command...),
		environment: append([]string(nil), e.image.environment...), stopTimeout: request.stopTimeout, status: "created",
		readOnlyRoot: true, tmpfs: map[string]string{
			"/inputs":    fmt.Sprintf("ro,noexec,nosuid,nodev,size=%d,mode=0555", request.inputsBytes),
			"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=1777", request.tmpfsBytes),
			"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700", request.workspaceBytes),
			"/outputs":   fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700", request.outputsBytes),
		},
		dns: []netip.Addr{resolver}, capDrop: []string{"ALL"},
		securityOptions: []string{"no-new-privileges:true", "seccomp=" + request.seccompProfile},
		memoryBytes:     request.memoryBytes, memorySwap: request.memoryBytes, nanoCPUs: request.nanoCPUs, pidsLimit: request.pidsLimit,
		networkMode: request.networkName, restartPolicy: "no", logType: "local",
		logConfig: map[string]string{"max-size": "10m", "max-file": "3"},
		networks:  map[string]netip.Addr{request.networkName: netip.MustParseAddr("10.88.0.3")},
	}
	return e.container.id, nil
}
func (e *fakeEngine) inspect(_ context.Context, _ string) (containerInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inspectErr != nil {
		return containerInfo{}, e.inspectErr
	}
	if e.container == nil {
		return containerInfo{}, cerrdefs.ErrNotFound
	}
	result := *e.container
	result.labels = cloneStrings(e.container.labels)
	result.entrypoint = append([]string(nil), e.container.entrypoint...)
	result.command = append([]string(nil), e.container.command...)
	result.environment = append([]string(nil), e.container.environment...)
	result.tmpfs = cloneStrings(e.container.tmpfs)
	result.dns = append([]netip.Addr(nil), e.container.dns...)
	result.capAdd = append([]string(nil), e.container.capAdd...)
	result.capDrop = append([]string(nil), e.container.capDrop...)
	result.securityOptions = append([]string(nil), e.container.securityOptions...)
	result.logConfig = cloneStrings(e.container.logConfig)
	result.networks = make(map[string]netip.Addr, len(e.container.networks))
	for name, address := range e.container.networks {
		result.networks[name] = address
	}
	return result, nil
}
func (e *fakeEngine) start(context.Context, string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.startErr != nil {
		return e.startErr
	}
	e.container.status = "running"
	e.container.running = true
	return nil
}
func (e *fakeEngine) remove(context.Context, string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.removeErr != nil {
		return e.removeErr
	}
	e.container = nil
	return nil
}
func (e *fakeEngine) attachRelay(context.Context, string) (relayConnection, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.attachErr != nil {
		return nil, e.attachErr
	}
	stream := &scriptedRelay{}
	e.attachRequests = append(e.attachRequests, stream)
	return stream, nil
}
func (e *fakeEngine) close() error { e.closed = true; return nil }

func cloneCreateRequest(request createRequest) createRequest {
	request.labels = cloneStrings(request.labels)
	return request
}

type scriptedRelay struct {
	mu     sync.Mutex
	reader bytes.Buffer
	writes bytes.Buffer
	closed bool
}

func (s *scriptedRelay) Read(value []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reader.Read(value)
}
func (s *scriptedRelay) Write(value []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	s.writes.Write(value)
	request := string(value)
	switch {
	case strings.HasPrefix(request, "GET /json/version HTTP/1.1"):
		body := `{"Browser":"Chrome/151.0.7922.109","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/browser-id-1"}`
		_, _ = s.reader.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body)
	case strings.Contains(request, "Upgrade: websocket"):
		key := requestHeader(request, "Sec-WebSocket-Key")
		accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = s.reader.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(accept[:]) + "\r\n\r\n")
		_, _ = s.reader.Write([]byte{0x81, 0x02, 'o', 'k'})
	}
	return len(value), nil
}
func (s *scriptedRelay) Close() error                     { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }
func (s *scriptedRelay) SetReadDeadline(time.Time) error  { return nil }
func (s *scriptedRelay) SetWriteDeadline(time.Time) error { return nil }
func (s *scriptedRelay) written() string                  { s.mu.Lock(); defer s.mu.Unlock(); return s.writes.String() }

func requestHeader(request, name string) string {
	prefix := name + ":"
	for _, line := range strings.Split(request, "\r\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func validOptions(t *testing.T, root string, clock Clock) Options {
	t.Helper()
	imageRoot, err := filepath.Abs("../../../../profiles/browser/image")
	if err != nil {
		t.Fatal(err)
	}
	return Options{
		Image: browserimage.LockedPublication().Image(), PullPolicy: PullNever,
		MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
		InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 256 << 20,
		OperationTimeoutSeconds: 5, ProvenanceTimeoutSeconds: 120,
		PullTimeoutSeconds: 5, StopTimeoutSeconds: 10,
		DataRoot: root, ManifestPath: filepath.Join(imageRoot, "manifest.json"),
		SeccompPath: filepath.Join(imageRoot, "chromium-seccomp.json"),
		Namespace:   "browser-test", ControllerID: "controller-1",
		NetworkPolicyReference: "browser-egress-policy-1",
		MaxSessionsPerSandbox:  1, MaxSessionsPerController: 8, Clock: clock,
	}
}

func validImageInfo(t *testing.T) imageInfo {
	t.Helper()
	manifest, err := browserimage.Load("../../../../profiles/browser/image/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	publication := browserimage.LockedPublication()
	return imageInfo{
		id:                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		repositoryDigests: []string{publication.Image()}, descriptorDigest: publication.Digest,
		user: BrowserUser, entrypoint: []string{"/usr/local/bin/browser-runtime"}, workingDirectory: "/workspace",
		architecture: "amd64", operatingSystem: "linux",
		labels: map[string]string{
			"io.github.shell-echo.sandbox-runtime.profile":                  browserimage.ProfileID,
			"io.github.shell-echo.sandbox-runtime.browser-sandbox":          "user-namespace",
			"io.github.shell-echo.sandbox-runtime.seccomp-profile-digest":   browserimage.SeccompDigest,
			"io.github.shell-echo.sandbox-runtime.provenance.source-digest": manifest.Source.Manifests["linux/amd64"].Digest,
			"org.opencontainers.image.base.digest":                          manifest.Source.Manifests["linux/amd64"].Digest,
			"org.opencontainers.image.base.name":                            browserimage.SourceRepository,
			"org.opencontainers.image.revision":                             publication.SourceCommit,
			"org.opencontainers.image.source":                               "https://github.com/shell-echo/sandbox-runtime",
			"org.opencontainers.image.version":                              browserimage.ProfileID,
		},
	}
}

func TestRestartRejectsBrowserNetworkAndDNSDrift(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	root := t.TempDir()
	backend := &fakeEngine{}
	options := validOptions(t, root, clock)
	driver := testDriver(t, backend, newFakeNetwork(), options)
	want := allocation(clock.Now())
	if _, err := driver.Allocate(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.container.networks["bridge"] = netip.MustParseAddr("172.17.0.2")
	backend.mu.Unlock()
	restarted := testDriver(t, backend, newFakeNetwork(), options)
	if _, err := restarted.Allocate(context.Background(), want); !errors.Is(err, providerbrowser.ErrBrowserConflict) {
		t.Fatalf("extra network drift = %v", err)
	}
	backend.mu.Lock()
	delete(backend.container.networks, "bridge")
	backend.container.dns = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	backend.mu.Unlock()
	restarted = testDriver(t, backend, newFakeNetwork(), options)
	if _, err := restarted.Allocate(context.Background(), want); !errors.Is(err, providerbrowser.ErrBrowserConflict) {
		t.Fatalf("DNS drift = %v", err)
	}
}

func allocation(now time.Time) providerbrowser.Allocation {
	return providerbrowser.Allocation{
		Request: providerbrowser.AllocationRequest{
			SandboxID: "sandbox-1", BrowserSessionID: "browser-session-1",
			OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
			ExpectedGeneration:     1,
			RequestDigest:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			NetworkPolicyReference: "browser-egress-policy-1",
			ExpiresAt:              now.Add(5 * time.Minute),
		},
		AllocatedAt: now,
	}
}

func testDriver(t *testing.T, backend *fakeEngine, network *fakeNetwork, options Options) *Driver {
	t.Helper()
	backend.image = validImageInfo(t)
	driver, err := newDriver(context.Background(), backend, options, &fakeProvenance{}, network)
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func TestOptionsFailClosed(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	base := validOptions(t, t.TempDir(), clock)
	tests := map[string]func(*Options){
		"mutable image":       func(o *Options) { o.Image = browserimage.PublishedRepository + ":latest" },
		"unknown pull policy": func(o *Options) { o.PullPolicy = "sometimes" },
		"memory":              func(o *Options) { o.MemoryBytes = 0 },
		"cpu":                 func(o *Options) { o.NanoCPUs = 0 },
		"pids":                func(o *Options) { o.PidsLimit = maxPIDs + 1 },
		"inputs":              func(o *Options) { o.InputsBytes = 0 },
		"tmpfs":               func(o *Options) { o.TmpfsBytes = o.MemoryBytes + 1 },
		"workspace":           func(o *Options) { o.WorkspaceBytes = o.MemoryBytes + 1 },
		"outputs":             func(o *Options) { o.OutputsBytes = 0 },
		"timeout":             func(o *Options) { o.OperationTimeoutSeconds = 0 },
		"provenance timeout":  func(o *Options) { o.ProvenanceTimeoutSeconds = 0 },
		"relative manifest":   func(o *Options) { o.ManifestPath = "manifest.json" },
		"namespace":           func(o *Options) { o.Namespace = "unsafe/name" },
		"network policy":      func(o *Options) { o.NetworkPolicyReference = "" },
		"sandbox concurrency": func(o *Options) { o.MaxSessionsPerSandbox = 2 },
		"capacity":            func(o *Options) { o.MaxSessionsPerController = 0 },
		"clock":               func(o *Options) { o.Clock = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if err := options.validate(); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("validate = %v", err)
			}
		})
	}
	backend := &fakeEngine{image: validImageInfo(t)}
	if _, err := newDriver(context.Background(), backend, base, nil, newFakeNetwork()); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("missing provenance = %v", err)
	}
	if _, err := newDriver(context.Background(), backend, base, &fakeProvenance{}, nil); !errors.Is(err, ErrInvalidDriver) {
		t.Fatalf("missing network = %v", err)
	}
}

func TestNewDriverVerifiesPublicationNetworkAndImage(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	options := validOptions(t, t.TempDir(), clock)
	backend := &fakeEngine{image: validImageInfo(t)}
	provenance := &fakeProvenance{}
	network := newFakeNetwork()
	driver, err := newDriver(context.Background(), backend, options, provenance, network)
	if err != nil {
		t.Fatal(err)
	}
	if driver.publication.Validate() != nil || provenance.calls != 1 {
		t.Fatalf("publication was not verified: %#v calls=%d", driver.publication, provenance.calls)
	}
	if !provenance.hasDeadline || time.Until(provenance.deadline) < time.Minute {
		t.Fatalf("provenance deadline = %v, present=%v", provenance.deadline, provenance.hasDeadline)
	}
	ready, _, _, _ := network.counts()
	if ready != 1 {
		t.Fatalf("network readiness calls = %d", ready)
	}
	drifted := &fakeEngine{image: validImageInfo(t)}
	drifted.image.exposedPorts = 1
	if _, err := newDriver(context.Background(), drifted, validOptions(t, t.TempDir(), clock), &fakeProvenance{}, newFakeNetwork()); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("unsafe image = %v", err)
	}
	failing := &fakeProvenance{err: errors.New("signature mismatch: private detail")}
	if _, err := newDriver(context.Background(), &fakeEngine{image: validImageInfo(t)}, validOptions(t, t.TempDir(), clock), failing, newFakeNetwork()); !errors.Is(err, ErrInvalidProvenance) || strings.Contains(err.Error(), "private detail") {
		t.Fatalf("provenance error = %v", err)
	}
}

func TestNewDriverPreservesDependencyContextErrors(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	tests := map[string]struct {
		backend    *fakeEngine
		provenance *fakeProvenance
		network    *fakeNetwork
		want       error
	}{
		"engine ping": {
			backend: &fakeEngine{pingErr: context.Canceled}, provenance: &fakeProvenance{}, network: newFakeNetwork(), want: context.Canceled,
		},
		"network readiness": {
			backend: &fakeEngine{}, provenance: &fakeProvenance{}, network: func() *fakeNetwork {
				network := newFakeNetwork()
				network.readyErr = context.DeadlineExceeded
				return network
			}(), want: context.DeadlineExceeded,
		},
		"provenance": {
			backend: &fakeEngine{}, provenance: &fakeProvenance{err: context.Canceled}, network: newFakeNetwork(), want: context.Canceled,
		},
		"image pull": {
			backend: &fakeEngine{ensureErr: context.DeadlineExceeded}, provenance: &fakeProvenance{}, network: newFakeNetwork(), want: context.DeadlineExceeded,
		},
		"image inspection": {
			backend: &fakeEngine{imageErr: context.Canceled}, provenance: &fakeProvenance{}, network: newFakeNetwork(), want: context.Canceled,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.backend.image = validImageInfo(t)
			_, err := newDriver(context.Background(), test.backend, validOptions(t, t.TempDir(), clock), test.provenance, test.network)
			if !errors.Is(err, test.want) {
				t.Fatalf("newDriver error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestReadyRevalidatesRuntimeDependenciesAndHidesDetails(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	backend := &fakeEngine{image: validImageInfo(t)}
	provenance := &fakeProvenance{}
	network := newFakeNetwork()
	driver, err := newDriver(context.Background(), backend, validOptions(t, t.TempDir(), clock), provenance, network)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	readyCalls, _, _, _ := network.counts()
	if provenance.calls != 2 || readyCalls != 2 {
		t.Fatalf("revalidation calls provenance=%d network=%d", provenance.calls, readyCalls)
	}
	network.readyErr = errors.New("private network detail")
	if err := driver.Ready(context.Background()); !errors.Is(err, ErrNetworkUnavailable) || strings.Contains(err.Error(), "private network detail") {
		t.Fatalf("network readiness error = %v", err)
	}
	network.readyErr = nil
	provenance.err = errors.New("private signature detail")
	if err := driver.Ready(context.Background()); !errors.Is(err, ErrInvalidProvenance) || strings.Contains(err.Error(), "private signature detail") {
		t.Fatalf("provenance readiness error = %v", err)
	}
	provenance.err = nil
	backend.image.exposedPorts = 1
	if err := driver.Ready(context.Background()); !errors.Is(err, ErrInvalidRuntime) {
		t.Fatalf("image drift readiness error = %v", err)
	}
	if err := driver.Ready(nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context readiness = %v", err)
	}
}

func TestAllocateProjectsExactRuntimeAndReplays(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	backend := &fakeEngine{}
	network := newFakeNetwork()
	driver := testDriver(t, backend, network, validOptions(t, t.TempDir(), clock))
	wantAllocation := allocation(clock.Now())
	receipt, err := driver.Allocate(context.Background(), wantAllocation)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil || !receipt.Matches(wantAllocation.Request) || !receipt.AllocatedAt.Equal(wantAllocation.AllocatedAt) {
		t.Fatalf("receipt = %#v, %v", receipt, err)
	}
	backend.mu.Lock()
	if len(backend.createRequests) != 1 {
		backend.mu.Unlock()
		t.Fatalf("create requests = %d", len(backend.createRequests))
	}
	request := backend.createRequests[0]
	backend.mu.Unlock()
	if request.image != browserimage.LockedPublication().Image() || request.user != BrowserUser || request.workingDirectory != "/workspace" ||
		request.networkName != network.attachment.DockerName || request.memoryBytes <= 0 || request.nanoCPUs <= 0 || request.pidsLimit <= 0 ||
		request.dnsResolver != network.attachment.GatewayAddress ||
		!strings.Contains(request.seccompProfile, `"defaultAction": "SCMP_ACT_ERRNO"`) ||
		request.labels[ownerLabel] != providerOwner || request.labels[specDigestLabel] == "" {
		t.Fatalf("create request = %#v", request)
	}
	replay, err := driver.Allocate(context.Background(), wantAllocation)
	if err != nil || replay != receipt {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	backend.mu.Lock()
	creates := len(backend.createRequests)
	backend.mu.Unlock()
	_, acquires, _, _ := network.counts()
	if creates != 1 || acquires != 1 {
		t.Fatalf("replay duplicated create/acquire: %d/%d", creates, acquires)
	}
}

func TestAllocateUnknownOutcomeDoesNotLeakOrRedispatch(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	backend := &fakeEngine{createErr: errors.New("daemon secret diagnostic")}
	network := newFakeNetwork()
	driver := testDriver(t, backend, network, validOptions(t, t.TempDir(), clock))
	wantAllocation := allocation(clock.Now())
	_, err := driver.Allocate(context.Background(), wantAllocation)
	if !errors.Is(err, providerbrowser.ErrAllocationUnknown) || strings.Contains(err.Error(), "daemon secret") {
		t.Fatalf("allocate error = %v", err)
	}
	backend.createErr = nil
	_, err = driver.Allocate(context.Background(), wantAllocation)
	if !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("replay error = %v", err)
	}
	backend.mu.Lock()
	creates := len(backend.createRequests)
	backend.mu.Unlock()
	if creates != 1 {
		t.Fatalf("unknown allocation redispatched %d creates", creates)
	}
}

func TestAllocateRefusesForeignContainer(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	backend := &fakeEngine{createErr: cerrdefs.ErrConflict, container: &containerInfo{
		id: "foreign", status: "running", running: true, labels: map[string]string{ownerLabel: "someone-else"},
	}}
	driver := testDriver(t, backend, newFakeNetwork(), validOptions(t, t.TempDir(), clock))
	if _, err := driver.Allocate(context.Background(), allocation(clock.Now())); !errors.Is(err, providerbrowser.ErrBrowserConflict) {
		t.Fatalf("foreign allocation = %v", err)
	}
}

func TestAllocateRejectsUnsafeNetworkAndSecondSandboxSession(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	unsafeNetwork := newFakeNetwork()
	unsafeNetwork.attachment.DockerName = "container:foreign"
	driver := testDriver(t, &fakeEngine{}, unsafeNetwork, validOptions(t, t.TempDir(), clock))
	if _, err := driver.Allocate(context.Background(), allocation(clock.Now())); !errors.Is(err, providerbrowser.ErrBrowserUnsupported) {
		t.Fatalf("unsafe network allocation = %v", err)
	}
	_, _, _, releases := unsafeNetwork.counts()
	if releases != 1 {
		t.Fatalf("unsafe network releases = %d", releases)
	}

	backend := &fakeEngine{}
	network := newFakeNetwork()
	driver = testDriver(t, backend, network, validOptions(t, t.TempDir(), clock))
	if _, err := driver.Allocate(context.Background(), allocation(clock.Now())); err != nil {
		t.Fatal(err)
	}
	second := allocation(clock.Now())
	second.Request.BrowserSessionID = "browser-session-2"
	second.Request.OperationID = "operation-2"
	second.Request.AttemptID = "attempt-2"
	second.Request.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := driver.Allocate(context.Background(), second); !errors.Is(err, providerbrowser.ErrBrowserUnsupported) {
		t.Fatalf("second session allocation = %v", err)
	}
	_, acquires, _, _ := network.counts()
	if acquires != 1 {
		t.Fatalf("capacity check acquired %d networks", acquires)
	}
}

func TestAllocateRejectsNetworkPolicySubstitution(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	backend := &fakeEngine{}
	driver := testDriver(t, backend, newFakeNetwork(), validOptions(t, t.TempDir(), clock))
	want := allocation(clock.Now())
	want.Request.NetworkPolicyReference = "browser-egress-policy-other"
	if _, err := driver.Allocate(context.Background(), want); !errors.Is(err, providerbrowser.ErrBrowserUnsupported) {
		t.Fatalf("policy substitution error = %v", err)
	}
	if len(backend.createRequests) != 0 {
		t.Fatal("policy substitution reached Docker create")
	}
}

func TestRestartObserveAttachAndCleanup(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	root := t.TempDir()
	backend := &fakeEngine{}
	network := newFakeNetwork()
	options := validOptions(t, root, clock)
	driver := testDriver(t, backend, network, options)
	receipt, err := driver.Allocate(context.Background(), allocation(clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	restarted := testDriver(t, backend, network, options)
	observation, err := restarted.Observe(context.Background(), receipt)
	if err != nil || observation.State != providerbrowser.AllocationRunning {
		t.Fatalf("observation = %#v, %v", observation, err)
	}
	stream, err := restarted.Attach(context.Background(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4)
	if _, err := io.ReadFull(contextStreamReader{ctx: context.Background(), stream: stream}, frame); err != nil || !bytes.Equal(frame, []byte{0x81, 0x02, 'o', 'k'}) {
		t.Fatalf("websocket frame = %x, %v", frame, err)
	}
	if _, err := stream.Write(context.Background(), []byte{0x89, 0x00}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	lastRelay := backend.attachRequests[len(backend.attachRequests)-1]
	backend.mu.Unlock()
	if request := lastRelay.written(); !strings.HasPrefix(request, "GET /devtools/browser/browser-id-1 HTTP/1.1") || strings.Contains(request, "daemon") {
		t.Fatalf("websocket handshake = %q", request)
	}
	if err := restarted.Cleanup(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	_, _, _, releases := network.counts()
	if releases != 1 {
		t.Fatalf("network releases = %d", releases)
	}
	if observation, err := restarted.Observe(context.Background(), receipt); err != nil || observation.State != providerbrowser.AllocationAbsent {
		t.Fatalf("post-cleanup observation = %#v, %v", observation, err)
	}
}

func TestExpiryAndNetworkFailureFailClosed(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	backend := &fakeEngine{}
	network := newFakeNetwork()
	driver := testDriver(t, backend, network, validOptions(t, t.TempDir(), clock))
	receipt, err := driver.Allocate(context.Background(), allocation(clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	clock.Set(receipt.ExpiresAt.Add(time.Second))
	observation, err := driver.Observe(context.Background(), receipt)
	if err != nil || observation.State != providerbrowser.AllocationExpired {
		t.Fatalf("expired observation = %#v, %v", observation, err)
	}
	network.inspectErr = errors.New("gateway unavailable")
	clock.Set(browserDriverTestTime)
	if _, err := driver.Attach(context.Background(), receipt); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("attach with lost network = %v", err)
	}
}

func TestRuntimePreservesNetworkContextErrors(t *testing.T) {
	clock := &fakeClock{now: browserDriverTestTime}
	network := newFakeNetwork()
	driver := testDriver(t, &fakeEngine{}, network, validOptions(t, t.TempDir(), clock))
	network.acquireErr = context.Canceled
	if _, err := driver.Allocate(context.Background(), allocation(clock.Now())); !errors.Is(err, context.Canceled) {
		t.Fatalf("allocate error = %v", err)
	}

	network = newFakeNetwork()
	driver = testDriver(t, &fakeEngine{}, network, validOptions(t, t.TempDir(), clock))
	receipt, err := driver.Allocate(context.Background(), allocation(clock.Now()))
	if err != nil {
		t.Fatal(err)
	}
	network.inspectErr = context.DeadlineExceeded
	if _, err := driver.Observe(context.Background(), receipt); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("observe error = %v", err)
	}
}

func TestStreamHonorsCancelledContext(t *testing.T) {
	connection := &scriptedRelay{}
	stream := &browserStream{connection: connection, reader: connection}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stream.Read(cancelled, make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("read = %v", err)
	}
	if _, err := stream.Write(cancelled, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("write = %v", err)
	}
}
