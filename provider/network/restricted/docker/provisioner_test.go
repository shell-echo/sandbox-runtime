package docker

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
)

const testGatewayImage = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeEngine struct {
	mu                 sync.Mutex
	image              imageInfo
	networks           map[string]networkInfo
	containers         map[string]containerInfo
	networkCreates     int
	containerCreates   int
	connects, starts   int
	containerRemoves   int
	networkRemoves     int
	pingErr            error
	createNetworkErr   error
	createContainerErr error
	connectErr         error
	startErr           error
	healthAfterStart   string
}

func newFakeEngine(options Options) *fakeEngine {
	return &fakeEngine{
		image: validGatewayImage(),
		networks: map[string]networkInfo{
			options.UplinkNetwork: {
				id: "uplink-id", name: options.UplinkNetwork, driver: "bridge", scope: "local", enableIPv4: true,
				labels: map[string]string{managedLabel: "true", ownerLabel: UplinkRole, namespaceLabel: options.Namespace},
			},
		},
		containers:       map[string]containerInfo{},
		healthAfterStart: "healthy",
	}
}

func newBrowserTestProvisioner(ctx context.Context, backend engine, options Options) (*Provisioner, error) {
	return newProvisioner(ctx, backend, options, "browser", func(request Request) (restricted.Identity, error) {
		return restricted.BrowserIdentity(request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.Generation, request.Fence)
	})
}

func newDesktopTestProvisioner(ctx context.Context, backend engine, options Options) (*Provisioner, error) {
	return newProvisioner(ctx, backend, options, "desktop", func(request Request) (restricted.Identity, error) {
		return restricted.DesktopIdentity(request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.Generation, request.Fence)
	})
}

func (e *fakeEngine) ping(context.Context) error { return e.pingErr }
func (e *fakeEngine) inspectImage(context.Context, string) (imageInfo, error) {
	return e.image, nil
}
func (e *fakeEngine) inspectNetwork(_ context.Context, name string) (networkInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	value, ok := e.networks[name]
	if !ok {
		return networkInfo{}, cerrdefs.ErrNotFound
	}
	return cloneNetworkInfo(value), nil
}
func (e *fakeEngine) createNetwork(_ context.Context, request networkRequest) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.networkCreates++
	subnet, _ := netip.ParsePrefix(request.subnet)
	dockerGateway, _ := netip.ParseAddr(request.dockerGateway)
	e.networks[request.name] = networkInfo{
		id: "network-id", name: request.name, driver: "bridge", scope: "local", enableIPv4: true,
		internal: true, labels: cloneMap(request.labels), ipam: []ipamInfo{{subnet: subnet, gateway: dockerGateway}},
	}
	return e.createNetworkErr
}
func (e *fakeEngine) removeNetwork(_ context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.networkRemoves++
	delete(e.networks, name)
	return nil
}
func (e *fakeEngine) inspectContainer(_ context.Context, name string) (containerInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	value, ok := e.containers[name]
	if !ok {
		return containerInfo{}, cerrdefs.ErrNotFound
	}
	return cloneContainerInfo(value), nil
}
func (e *fakeEngine) createContainer(_ context.Context, request containerRequest) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.containerCreates++
	environment := []string{"PATH=" + GatewayPath}
	for key, value := range request.environment {
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)
	address := netip.MustParseAddr(request.internalAddress)
	e.containers[request.name] = containerInfo{
		id: "container-id", name: "/" + request.name, labels: cloneMap(request.labels),
		imageID: request.imageID, image: request.image,
		user: GatewayUser, entrypoint: []string{GatewayEntrypoint}, command: []string{"serve"}, workingDirectory: "/",
		stopTimeout: request.stopTimeout,
		environment: environment, readOnlyRoot: true, capDrop: []string{"ALL"},
		securityOptions: []string{"no-new-privileges:true"},
		tmpfs:           map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
		memoryBytes:     request.memoryBytes, nanoCPUs: request.nanoCPUs, pidsLimit: request.pidsLimit,
		networkMode: request.internalNetwork, restartPolicy: "no", logType: "local",
		logConfig: map[string]string{"max-size": "10m", "max-file": "3"},
		sysctls:   map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"},
		networks:  map[string]netip.Addr{request.internalNetwork: address},
	}
	network := e.networks[request.internalNetwork]
	network.containers = append(network.containers, endpointInfo{name: request.name, address: address})
	e.networks[request.internalNetwork] = network
	return e.createContainerErr
}
func (e *fakeEngine) connectNetwork(_ context.Context, networkName, containerName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.connects++
	if e.connectErr != nil {
		return e.connectErr
	}
	container := e.containers[containerName]
	container.networks[networkName] = netip.MustParseAddr("172.30.0.2")
	e.containers[containerName] = container
	return nil
}
func (e *fakeEngine) startContainer(_ context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.starts++
	if e.startErr != nil {
		return e.startErr
	}
	container := e.containers[name]
	container.running = true
	container.health = e.healthAfterStart
	e.containers[name] = container
	return nil
}
func (e *fakeEngine) removeContainer(_ context.Context, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.containerRemoves++
	container, ok := e.containers[name]
	if !ok {
		return cerrdefs.ErrNotFound
	}
	for networkName := range container.networks {
		network := e.networks[networkName]
		filtered := network.containers[:0]
		for _, endpoint := range network.containers {
			if endpoint.name != name {
				filtered = append(filtered, endpoint)
			}
		}
		network.containers = filtered
		e.networks[networkName] = network
	}
	delete(e.containers, name)
	return nil
}
func (e *fakeEngine) close() error { return nil }

func TestOptionsRejectUnsafeConfiguration(t *testing.T) {
	valid := validOptions()
	tests := map[string]func(*Options){
		"mutable image":      func(o *Options) { o.GatewayImage = "gateway:latest" },
		"default bridge":     func(o *Options) { o.UplinkNetwork = "bridge" },
		"missing namespace":  func(o *Options) { o.Namespace = "" },
		"missing controller": func(o *Options) { o.ControllerID = "" },
		"missing policy":     func(o *Options) { o.Policies = nil },
		"duplicate policy":   func(o *Options) { o.Policies = append(o.Policies, o.Policies[0]) },
		"unbounded memory":   func(o *Options) { o.MemoryBytes = 0 },
		"unbounded CPU":      func(o *Options) { o.NanoCPUs = 0 },
		"unbounded PIDs":     func(o *Options) { o.PidsLimit = 0 },
		"unbounded timeout":  func(o *Options) { o.OperationTimeoutSeconds = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := valid
			options.Policies = append([]restricted.Policy(nil), valid.Policies...)
			mutate(&options)
			if _, err := options.validate(); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestProvisionerValidatesGatewayImageAndOwnedUplink(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	if _, err := newBrowserTestProvisioner(t.Context(), backend, options); err != nil {
		t.Fatal(err)
	}
	backend.image.user = "0"
	if _, err := newBrowserTestProvisioner(t.Context(), backend, options); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatalf("root image error = %v", err)
	}
	backend.image = validGatewayImage()
	uplink := backend.networks[options.UplinkNetwork]
	uplink.internal = true
	backend.networks[options.UplinkNetwork] = uplink
	if _, err := newBrowserTestProvisioner(t.Context(), backend, options); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatalf("internal uplink error = %v", err)
	}
}

func TestAcquireInspectReplayAndRelease(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	provisioner, err := newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	request := validNetworkRequest(options)
	attachment, err := provisioner.Acquire(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !attachment.EgressGateway || attachment.Public || !netip.MustParseAddr(attachment.GatewayAddress).IsPrivate() ||
		attachment.PolicyReference != request.PolicyReference || attachment.PolicyDigest == "" {
		t.Fatalf("attachment = %#v", attachment)
	}
	attachFakeWorkload(t, backend, provisioner, request, attachment)
	if err := provisioner.Inspect(t.Context(), attachment); err != nil {
		t.Fatal(err)
	}
	container := backend.containers[attachment.GatewayContainer]
	container.imageID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	backend.containers[attachment.GatewayContainer] = container
	if err := provisioner.Inspect(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("gateway image drift = %v", err)
	}
	container.imageID = testGatewayImage
	backend.containers[attachment.GatewayContainer] = container
	replay, err := provisioner.Acquire(t.Context(), request)
	if err != nil || replay != attachment {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	if backend.networkCreates != 1 || backend.containerCreates != 1 || backend.connects != 1 || backend.starts != 1 {
		t.Fatalf("create counts = network %d container %d connect %d start %d", backend.networkCreates, backend.containerCreates, backend.connects, backend.starts)
	}
	detachFakeWorkload(backend, provisioner, request, attachment)
	if err := provisioner.Release(t.Context(), attachment); err != nil {
		t.Fatal(err)
	}
	if backend.containerRemoves != 1 || backend.networkRemoves != 1 {
		t.Fatalf("remove counts = container %d network %d", backend.containerRemoves, backend.networkRemoves)
	}
	if err := provisioner.Release(t.Context(), attachment); err != nil {
		t.Fatalf("idempotent release = %v", err)
	}
}

func TestAcquireRecoversCreateResponseLoss(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	backend.createNetworkErr = errors.New("lost network create response")
	backend.createContainerErr = errors.New("lost container create response")
	provisioner, err := newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.Acquire(t.Context(), validNetworkRequest(options)); err != nil {
		t.Fatalf("recovered allocation = %v", err)
	}
}

func TestAcquireFailsClosedOnOwnershipDriftAndUnhealthyGateway(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	provisioner, err := newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	request := validNetworkRequest(options)
	desired, networkRequest, _, err := provisioner.desired(request, options.Policies[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.createNetwork(t.Context(), networkRequest); err != nil {
		t.Fatal(err)
	}
	network := backend.networks[desired.DockerName]
	network.labels[ownerLabel] = "foreign"
	backend.networks[desired.DockerName] = network
	if _, err := provisioner.Acquire(t.Context(), request); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("ownership drift error = %v", err)
	}

	backend = newFakeEngine(options)
	backend.healthAfterStart = "unhealthy"
	provisioner, err = newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.Acquire(t.Context(), request); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatalf("unhealthy gateway error = %v", err)
	}
	if len(backend.containers) != 0 {
		t.Fatalf("unhealthy gateway containers = %#v", backend.containers)
	}
}

func TestAcquireRollsBackDefinitiveConnectFailure(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	backend.connectErr = cerrdefs.ErrPermissionDenied
	provisioner, err := newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.Acquire(t.Context(), validNetworkRequest(options)); !errors.Is(err, ErrNetworkUnavailable) {
		t.Fatalf("connect error = %v", err)
	}
	if len(backend.containers) != 0 {
		t.Fatalf("containers after rollback = %#v", backend.containers)
	}
}

func TestInspectAndReleaseRefuseForeignResources(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	provisioner, err := newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	request := validNetworkRequest(options)
	attachment, err := provisioner.Acquire(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	container := backend.containers[attachment.GatewayContainer]
	container.labels[ownerLabel] = "foreign"
	backend.containers[attachment.GatewayContainer] = container
	attachFakeWorkload(t, backend, provisioner, request, attachment)
	if err := provisioner.Inspect(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("inspect drift error = %v", err)
	}
	detachFakeWorkload(backend, provisioner, request, attachment)
	if err := provisioner.Release(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("release drift error = %v", err)
	}
	if len(backend.containers) != 1 {
		t.Fatal("foreign resource was removed")
	}
}

func TestPolicyAndCancellationFailClosed(t *testing.T) {
	options := validOptions()
	backend := newFakeEngine(options)
	provisioner, err := newBrowserTestProvisioner(t.Context(), backend, options)
	if err != nil {
		t.Fatal(err)
	}
	request := validNetworkRequest(options)
	request.PolicyReference = "unknown-policy"
	if _, err := provisioner.Acquire(t.Context(), request); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("unknown policy error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provisioner.Ready(cancelled, options.Policies[0].Reference); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ready = %v", err)
	}
}

func TestInspectRequiresOneExactRoleBoundWorkload(t *testing.T) {
	for _, role := range []string{"browser", "desktop"} {
		t.Run(role, func(t *testing.T) {
			options := validOptions()
			backend := newFakeEngine(options)
			request := validNetworkRequest(options)
			var provisioner *Provisioner
			var err error
			if role == "browser" {
				provisioner, err = newBrowserTestProvisioner(t.Context(), backend, options)
			} else {
				request.SessionID = "desktop-session-1"
				provisioner, err = newDesktopTestProvisioner(t.Context(), backend, options)
			}
			if err != nil {
				t.Fatal(err)
			}
			attachment, err := provisioner.Acquire(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := provisioner.Inspect(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
				t.Fatalf("missing workload error = %v", err)
			}
			attachFakeWorkload(t, backend, provisioner, request, attachment)
			if err := provisioner.Inspect(t.Context(), attachment); err != nil {
				t.Fatal(err)
			}

			identity, _ := provisioner.identity(request)
			for name, mutate := range map[string]func(map[string]string){
				"sandbox":    func(labels map[string]string) { labels[restricted.SandboxLabel] = "sandbox-other" },
				"session":    func(labels map[string]string) { labels[identity.SessionLabel()] = "session-other" },
				"generation": func(labels map[string]string) { labels[restricted.WorkloadGenerationLabel] = "99" },
				"fence":      func(labels map[string]string) { labels[restricted.WorkloadFenceLabel] = "99" },
				"name": func(labels map[string]string) {
					labels[restricted.WorkloadIdentityLabel] = "sha256:" + strings.Repeat("f", 64)
				},
			} {
				t.Run(name, func(t *testing.T) {
					backend.mu.Lock()
					workload := backend.containers[identity.WorkloadName()]
					original := cloneMap(workload.labels)
					mutate(workload.labels)
					backend.containers[identity.WorkloadName()] = workload
					backend.mu.Unlock()
					if err := provisioner.Inspect(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
						t.Fatalf("drift error = %v", err)
					}
					backend.mu.Lock()
					workload = backend.containers[identity.WorkloadName()]
					workload.labels = original
					backend.containers[identity.WorkloadName()] = workload
					backend.mu.Unlock()
				})
			}

			backend.mu.Lock()
			network := backend.networks[attachment.DockerName]
			network.containers = append(network.containers, endpointInfo{name: "foreign-workload", address: network.ipam[0].subnet.Addr().Next().Next().Next().Next()})
			backend.networks[attachment.DockerName] = network
			backend.mu.Unlock()
			if err := provisioner.Inspect(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
				t.Fatalf("extra workload error = %v", err)
			}
			backend.mu.Lock()
			network = backend.networks[attachment.DockerName]
			network.containers = network.containers[:len(network.containers)-1]
			backend.networks[attachment.DockerName] = network
			backend.mu.Unlock()

			replaceWithOppositeRoleWorkload(t, backend, provisioner, request, attachment)
			if err := provisioner.Inspect(t.Context(), attachment); !errors.Is(err, ErrOwnershipConflict) {
				t.Fatalf("opposite role error = %v", err)
			}
			removeAllFakeWorkloads(backend, attachment)
			if err := provisioner.Release(t.Context(), attachment); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func validOptions() Options {
	return Options{
		GatewayImage: testGatewayImage, UplinkNetwork: "sandbox-runtime-browser-uplink",
		Namespace: "test-namespace", ControllerID: "controller-1",
		Policies:    []restricted.Policy{{Reference: "browser-egress-policy-1", AllowedHosts: []string{"allowed.example"}}},
		MemoryBytes: 64 << 20, NanoCPUs: 250_000_000, PidsLimit: 32,
		OperationTimeoutSeconds: 5, StopTimeoutSeconds: 3,
	}
}

func validNetworkRequest(options Options) Request {
	return Request{
		SandboxID: "sandbox-1", SessionID: "browser-session-1", Generation: 1, Fence: 1,
		Namespace: options.Namespace, ControllerID: options.ControllerID,
		PolicyReference: options.Policies[0].Reference,
	}
}

func attachFakeWorkload(t *testing.T, backend *fakeEngine, provisioner *Provisioner, request Request, attachment Attachment) {
	t.Helper()
	identity, err := provisioner.identity(request)
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	network := backend.networks[attachment.DockerName]
	address := network.ipam[0].subnet.Addr().Next().Next().Next()
	backend.containers[identity.WorkloadName()] = containerInfo{
		id: "workload-id", name: "/" + identity.WorkloadName(), labels: identity.WorkloadLabels(attachment.LeaseID),
		networkMode: attachment.DockerName, networks: map[string]netip.Addr{attachment.DockerName: address},
	}
	network.containers = append(network.containers, endpointInfo{name: identity.WorkloadName(), address: address})
	backend.networks[attachment.DockerName] = network
}

func detachFakeWorkload(backend *fakeEngine, provisioner *Provisioner, request Request, attachment Attachment) {
	identity, _ := provisioner.identity(request)
	backend.mu.Lock()
	defer backend.mu.Unlock()
	delete(backend.containers, identity.WorkloadName())
	network := backend.networks[attachment.DockerName]
	filtered := network.containers[:0]
	for _, endpoint := range network.containers {
		if endpoint.name != identity.WorkloadName() {
			filtered = append(filtered, endpoint)
		}
	}
	network.containers = filtered
	backend.networks[attachment.DockerName] = network
}

func replaceWithOppositeRoleWorkload(t *testing.T, backend *fakeEngine, provisioner *Provisioner, request Request, attachment Attachment) {
	t.Helper()
	target, _ := provisioner.identity(request)
	var opposite restricted.Identity
	var err error
	if target.Role() == "browser" {
		opposite, err = restricted.DesktopIdentity(request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.Generation, request.Fence)
	} else {
		opposite, err = restricted.BrowserIdentity(request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.Generation, request.Fence)
	}
	if err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	delete(backend.containers, target.WorkloadName())
	network := backend.networks[attachment.DockerName]
	for index, endpoint := range network.containers {
		if endpoint.name == target.WorkloadName() {
			network.containers[index].name = opposite.WorkloadName()
			backend.containers[opposite.WorkloadName()] = containerInfo{id: "opposite-workload-id", name: "/" + opposite.WorkloadName(), labels: opposite.WorkloadLabels(attachment.LeaseID), networkMode: attachment.DockerName, networks: map[string]netip.Addr{attachment.DockerName: endpoint.address}}
		}
	}
	backend.networks[attachment.DockerName] = network
}

func removeAllFakeWorkloads(backend *fakeEngine, attachment Attachment) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	network := backend.networks[attachment.DockerName]
	filtered := network.containers[:0]
	for _, endpoint := range network.containers {
		if endpoint.name == attachment.GatewayContainer {
			filtered = append(filtered, endpoint)
			continue
		}
		delete(backend.containers, endpoint.name)
	}
	network.containers = filtered
	backend.networks[attachment.DockerName] = network
}

func validGatewayImage() imageInfo {
	return imageInfo{
		id: testGatewayImage, labels: map[string]string{gatewayImageLabel: GatewayComponent},
		user: GatewayUser, entrypoint: []string{GatewayEntrypoint}, command: []string{"serve"},
		workingDirectory: "/", environment: []string{"PATH=" + GatewayPath},
		healthcheck:    []string{"CMD", GatewayEntrypoint, "healthcheck"},
		healthInterval: 2 * time.Second, healthTimeout: 3 * time.Second,
		healthStart: 2 * time.Second, healthRetries: 5,
		operatingSystem: "linux", architecture: "arm64", variant: "v8",
	}
}

func cloneNetworkInfo(value networkInfo) networkInfo {
	value.labels = cloneMap(value.labels)
	value.ipam = append([]ipamInfo(nil), value.ipam...)
	value.containers = append([]endpointInfo(nil), value.containers...)
	return value
}

func cloneContainerInfo(value containerInfo) containerInfo {
	networks := value.networks
	value.labels = cloneMap(value.labels)
	value.environment = append([]string(nil), value.environment...)
	value.entrypoint = append([]string(nil), value.entrypoint...)
	value.command = append([]string(nil), value.command...)
	value.capAdd = append([]string(nil), value.capAdd...)
	value.capDrop = append([]string(nil), value.capDrop...)
	value.securityOptions = append([]string(nil), value.securityOptions...)
	value.tmpfs = cloneMap(value.tmpfs)
	value.sysctls = cloneMap(value.sysctls)
	value.logConfig = cloneMap(value.logConfig)
	value.networks = make(map[string]netip.Addr, len(networks))
	for name, address := range networks {
		value.networks[name] = address
	}
	return value
}
