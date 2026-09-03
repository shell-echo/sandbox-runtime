package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	browserdriver "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
)

const (
	managedLabel        = "io.github.shell-echo.sandbox-runtime.managed"
	ownerLabel          = "io.github.shell-echo.sandbox-runtime.owner"
	componentLabel      = "io.github.shell-echo.sandbox-runtime.component"
	namespaceLabel      = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel     = "io.github.shell-echo.sandbox-runtime.controller-id"
	sandboxLabel        = "io.github.shell-echo.sandbox-runtime.provider-sandbox-id"
	browserSessionLabel = "io.github.shell-echo.sandbox-runtime.browser-session-id"
	policyLabel         = "io.github.shell-echo.sandbox-runtime.network-policy"
	policyDigestLabel   = "io.github.shell-echo.sandbox-runtime.network-policy-digest"
	leaseLabel          = "io.github.shell-echo.sandbox-runtime.network-lease"
	subnetLabel         = "io.github.shell-echo.sandbox-runtime.network-subnet"
	gatewayAddressLabel = "io.github.shell-echo.sandbox-runtime.gateway-address"
	gatewayNameLabel    = "io.github.shell-echo.sandbox-runtime.gateway-container"
	browserNameLabel    = "io.github.shell-echo.sandbox-runtime.browser-container"
	networkOwner        = "provider-browser-restricted-egress"
	gatewayImageLabel   = "io.github.shell-echo.sandbox-runtime.component"

	probeInterval = 50 * time.Millisecond
)

type Provisioner struct {
	engine         engine
	options        Options
	policies       map[string]gateway.Policy
	gatewayImageID string
	mu             sync.Mutex
}

func New(ctx context.Context, options Options) (*Provisioner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	backend, err := newMobyEngine(options.Host)
	if err != nil {
		return nil, ErrNetworkUnavailable
	}
	provisioner, err := newProvisioner(ctx, backend, options)
	if err != nil {
		_ = backend.close()
		return nil, err
	}
	return provisioner, nil
}

func newProvisioner(ctx context.Context, backend engine, options Options) (*Provisioner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, ErrInvalidOptions
	}
	policies, err := options.validate()
	if err != nil {
		return nil, err
	}
	provisioner := &Provisioner{engine: backend, options: options, policies: policies}
	operationCtx, cancel := provisioner.operationContext(ctx)
	defer cancel()
	if err := backend.ping(operationCtx); err != nil {
		return nil, safeError(operationCtx, ErrNetworkUnavailable, err)
	}
	imageID, err := provisioner.validatePrerequisites(operationCtx)
	if err != nil {
		return nil, err
	}
	provisioner.gatewayImageID = imageID
	return provisioner, nil
}

func (p *Provisioner) Ready(ctx context.Context, policyReference string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if p == nil || p.engine == nil {
		return ErrNetworkUnavailable
	}
	if _, ok := p.policies[policyReference]; !ok {
		return ErrPolicyUnavailable
	}
	operationCtx, cancel := p.operationContext(ctx)
	defer cancel()
	return p.revalidatePrerequisites(operationCtx)
}

func (p *Provisioner) Acquire(ctx context.Context, request browserdriver.NetworkRequest) (browserdriver.NetworkAttachment, error) {
	if err := contextError(ctx); err != nil {
		return browserdriver.NetworkAttachment{}, err
	}
	if p == nil || p.engine == nil {
		return browserdriver.NetworkAttachment{}, ErrNetworkUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.policies[request.PolicyReference]
	if !ok || request.Namespace != p.options.Namespace || request.ControllerID != p.options.ControllerID ||
		!privateValuePattern.MatchString(request.SandboxID) || !privateValuePattern.MatchString(request.BrowserSessionID) {
		return browserdriver.NetworkAttachment{}, ErrPolicyUnavailable
	}
	desired, networkRequest, containerRequest, err := p.desired(request, policy)
	if err != nil {
		return browserdriver.NetworkAttachment{}, ErrPolicyUnavailable
	}
	operationCtx, cancel := p.operationContext(ctx)
	defer cancel()
	if err := p.revalidatePrerequisites(operationCtx); err != nil {
		return browserdriver.NetworkAttachment{}, err
	}

	networkCreated := false
	network, err := p.engine.inspectNetwork(operationCtx, desired.DockerName)
	if cerrdefs.IsNotFound(err) {
		if err := p.engine.createNetwork(operationCtx, networkRequest); err != nil {
			inspected, inspectErr := p.engine.inspectNetwork(operationCtx, desired.DockerName)
			if inspectErr != nil {
				return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
			}
			network = inspected
			if validateNetwork(network, networkRequest, desired, false) != nil {
				return browserdriver.NetworkAttachment{}, ErrOwnershipConflict
			}
		} else {
			networkCreated = true
			network, err = p.engine.inspectNetwork(operationCtx, desired.DockerName)
			if err != nil {
				return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
			}
		}
	} else if err != nil {
		return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
	}
	if validateNetwork(network, networkRequest, desired, false) != nil {
		return browserdriver.NetworkAttachment{}, ErrOwnershipConflict
	}

	container, err := p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
	if cerrdefs.IsNotFound(err) {
		if err := p.engine.createContainer(operationCtx, containerRequest); err != nil {
			inspected, inspectErr := p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
			if inspectErr != nil {
				if networkCreated {
					_ = p.engine.removeNetwork(operationCtx, desired.DockerName)
				}
				return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
			}
			container = inspected
		} else {
			container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
			if err != nil {
				return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
			}
		}
	} else if err != nil {
		return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
	}
	_, connected := container.networks[p.options.UplinkNetwork]
	if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, connected) != nil {
		return browserdriver.NetworkAttachment{}, ErrOwnershipConflict
	}

	if !connected {
		connectErr := p.engine.connectNetwork(operationCtx, p.options.UplinkNetwork, desired.GatewayContainer)
		container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
		if err != nil {
			return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, errors.Join(connectErr, err))
		}
		if _, connected := container.networks[p.options.UplinkNetwork]; !connected {
			_ = p.releaseOwned(operationCtx, desired)
			return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, connectErr)
		}
	}
	if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, true) != nil {
		return browserdriver.NetworkAttachment{}, ErrOwnershipConflict
	}

	if !container.running {
		startErr := p.engine.startContainer(operationCtx, desired.GatewayContainer)
		container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
		if err != nil || !container.running {
			return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, errors.Join(startErr, err))
		}
	}
	for {
		container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
		if err != nil {
			return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
		}
		if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, true) != nil {
			return browserdriver.NetworkAttachment{}, ErrOwnershipConflict
		}
		if container.health == "healthy" {
			break
		}
		if container.health == "unhealthy" || !container.running || container.paused || container.restarting || container.dead {
			_ = p.releaseOwned(operationCtx, desired)
			return browserdriver.NetworkAttachment{}, ErrNetworkUnavailable
		}
		if err := waitContext(operationCtx, probeInterval); err != nil {
			return browserdriver.NetworkAttachment{}, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	network, err = p.engine.inspectNetwork(operationCtx, desired.DockerName)
	if err != nil {
		return browserdriver.NetworkAttachment{}, classifyOperationError(operationCtx, err)
	}
	if validateNetwork(network, networkRequest, desired, true) != nil {
		return browserdriver.NetworkAttachment{}, ErrOwnershipConflict
	}
	return desired, nil
}

func (p *Provisioner) Inspect(ctx context.Context, attachment browserdriver.NetworkAttachment) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if p == nil || p.engine == nil {
		return ErrNetworkUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.policies[attachment.PolicyReference]
	if !ok {
		return ErrPolicyUnavailable
	}
	if !attachment.EgressGateway || attachment.Public || !validDockerName(attachment.DockerName) ||
		!validDockerName(attachment.GatewayContainer) || !privateValuePattern.MatchString(attachment.LeaseID) {
		return ErrOwnershipConflict
	}
	digest, err := policy.Digest()
	if err != nil || digest != attachment.PolicyDigest {
		return ErrOwnershipConflict
	}
	operationCtx, cancel := p.operationContext(ctx)
	defer cancel()
	network, err := p.engine.inspectNetwork(operationCtx, attachment.DockerName)
	if err != nil {
		return classifyOperationError(operationCtx, err)
	}
	networkRequest, containerRequest, err := p.requestsFromNetwork(network, attachment)
	if err != nil || validateNetwork(network, networkRequest, attachment, true) != nil {
		return ErrOwnershipConflict
	}
	container, err := p.engine.inspectContainer(operationCtx, attachment.GatewayContainer)
	if err != nil {
		return classifyOperationError(operationCtx, err)
	}
	if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, true) != nil {
		return ErrOwnershipConflict
	}
	if !container.running || container.health != "healthy" {
		return ErrNetworkUnavailable
	}
	return nil
}

func (p *Provisioner) Release(ctx context.Context, attachment browserdriver.NetworkAttachment) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if p == nil || p.engine == nil {
		return ErrNetworkUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	operationCtx, cancel := p.operationContext(ctx)
	defer cancel()
	return p.releaseOwned(operationCtx, attachment)
}

func (p *Provisioner) Close() error {
	if p == nil || p.engine == nil {
		return nil
	}
	return p.engine.close()
}

func (p *Provisioner) revalidatePrerequisites(ctx context.Context) error {
	imageID, err := p.validatePrerequisites(ctx)
	if err != nil {
		return err
	}
	if imageID != p.gatewayImageID {
		return ErrNetworkUnavailable
	}
	return nil
}

func (p *Provisioner) validatePrerequisites(ctx context.Context) (string, error) {
	image, err := p.engine.inspectImage(ctx, p.options.GatewayImage)
	if err != nil {
		return "", safeError(ctx, ErrNetworkUnavailable, err)
	}
	if validateGatewayImage(image, p.options.GatewayImage) != nil {
		return "", ErrNetworkUnavailable
	}
	uplink, err := p.engine.inspectNetwork(ctx, p.options.UplinkNetwork)
	if err != nil {
		return "", safeError(ctx, ErrNetworkUnavailable, err)
	}
	if uplink.name != p.options.UplinkNetwork || uplink.driver != "bridge" || uplink.scope != "local" ||
		uplink.internal || uplink.ingress || uplink.configOnly ||
		uplink.labels[managedLabel] != "true" || uplink.labels[ownerLabel] != UplinkRole ||
		uplink.labels[namespaceLabel] != p.options.Namespace {
		return "", ErrNetworkUnavailable
	}
	return image.id, nil
}

func validateGatewayImage(info imageInfo, reference string) error {
	bound := info.id == reference
	for _, digest := range info.repositoryDigests {
		if digest == reference {
			bound = true
			break
		}
	}
	if !bound || info.user != GatewayUser || strings.Join(info.entrypoint, "\x00") != GatewayEntrypoint ||
		strings.Join(info.command, "\x00") != "serve" || info.workingDirectory != "/" ||
		info.exposedPorts != 0 || info.volumes != 0 || strings.Join(info.environment, "\x00") != "PATH="+GatewayPath ||
		strings.Join(info.healthcheck, "\x00") != "CMD\x00"+GatewayEntrypoint+"\x00healthcheck" ||
		info.healthInterval != 2*time.Second || info.healthTimeout != 3*time.Second ||
		info.healthStart != 2*time.Second || info.healthRetries != 5 ||
		info.operatingSystem != "linux" ||
		(info.architecture != "amd64" && (info.architecture != "arm64" || (info.variant != "" && info.variant != "v8"))) ||
		info.labels[gatewayImageLabel] != GatewayComponent {
		return ErrNetworkUnavailable
	}
	return nil
}

func (p *Provisioner) desired(request browserdriver.NetworkRequest, policy gateway.Policy) (browserdriver.NetworkAttachment, networkRequest, containerRequest, error) {
	digest, err := policy.Digest()
	if err != nil {
		return browserdriver.NetworkAttachment{}, networkRequest{}, containerRequest{}, err
	}
	tokenBytes := sha256.Sum256([]byte(strings.Join([]string{
		request.Namespace, request.ControllerID, request.SandboxID, request.BrowserSessionID, request.PolicyReference, digest,
	}, "\x00")))
	token := hex.EncodeToString(tokenBytes[:16])
	networkName := "sandbox-runtime-browser-egress-" + token
	gatewayName := "sandbox-runtime-browser-gateway-" + token
	browserName := browserContainerName(request.SandboxID, request.BrowserSessionID)
	subnet, dockerGateway, gatewayAddress := privateSubnet(tokenBytes)
	lease := "browser-egress-" + token
	attachment := browserdriver.NetworkAttachment{
		DockerName: networkName, GatewayContainer: gatewayName, GatewayAddress: gatewayAddress.String(),
		LeaseID: lease, PolicyReference: policy.Reference, PolicyDigest: digest, EgressGateway: true, Public: false,
	}
	labels := map[string]string{
		managedLabel: "true", ownerLabel: networkOwner, componentLabel: GatewayComponent,
		namespaceLabel: request.Namespace, controllerLabel: request.ControllerID,
		sandboxLabel: request.SandboxID, browserSessionLabel: request.BrowserSessionID,
		policyLabel: policy.Reference, policyDigestLabel: digest, leaseLabel: lease,
		subnetLabel: subnet.String(), gatewayAddressLabel: gatewayAddress.String(),
		gatewayNameLabel: gatewayName, browserNameLabel: browserName,
	}
	encodedConfig, err := gateway.EncodeConfig(gateway.Config{GatewayAddress: gatewayAddress.String(), Policy: policy})
	if err != nil {
		return browserdriver.NetworkAttachment{}, networkRequest{}, containerRequest{}, err
	}
	return attachment,
		networkRequest{name: networkName, subnet: subnet.String(), dockerGateway: dockerGateway.String(), labels: labels},
		containerRequest{
			name: gatewayName, image: p.options.GatewayImage, imageID: p.gatewayImageID, internalNetwork: networkName,
			internalAddress: gatewayAddress.String(), labels: labels,
			environment: map[string]string{gateway.ConfigEnvironment: encodedConfig},
			memoryBytes: p.options.MemoryBytes, nanoCPUs: p.options.NanoCPUs,
			pidsLimit: p.options.PidsLimit, stopTimeout: p.options.StopTimeoutSeconds,
		}, nil
}

func (p *Provisioner) requestsFromNetwork(network networkInfo, attachment browserdriver.NetworkAttachment) (networkRequest, containerRequest, error) {
	labels := network.labels
	required := []string{namespaceLabel, controllerLabel, sandboxLabel, browserSessionLabel, policyLabel, policyDigestLabel, leaseLabel, subnetLabel, gatewayAddressLabel, gatewayNameLabel, browserNameLabel}
	for _, key := range required {
		if labels[key] == "" {
			return networkRequest{}, containerRequest{}, ErrOwnershipConflict
		}
	}
	if labels[namespaceLabel] != p.options.Namespace || labels[controllerLabel] != p.options.ControllerID ||
		labels[policyLabel] != attachment.PolicyReference || labels[policyDigestLabel] != attachment.PolicyDigest ||
		labels[leaseLabel] != attachment.LeaseID || labels[gatewayNameLabel] != attachment.GatewayContainer ||
		labels[gatewayAddressLabel] != attachment.GatewayAddress {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	subnet, err := netip.ParsePrefix(labels[subnetLabel])
	if err != nil || !subnet.Addr().Is4() || !subnet.Addr().IsPrivate() {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	dockerGateway := subnet.Addr().Next()
	policy, ok := p.policies[labels[policyLabel]]
	if !ok {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	encodedConfig, err := gateway.EncodeConfig(gateway.Config{
		GatewayAddress: labels[gatewayAddressLabel],
		Policy:         policy,
	})
	if err != nil {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	return networkRequest{name: network.name, subnet: subnet.String(), dockerGateway: dockerGateway.String(), labels: labels},
		containerRequest{
			name: labels[gatewayNameLabel], image: p.options.GatewayImage, imageID: p.gatewayImageID, internalNetwork: network.name,
			internalAddress: labels[gatewayAddressLabel], labels: labels,
			environment: map[string]string{gateway.ConfigEnvironment: encodedConfig},
			memoryBytes: p.options.MemoryBytes, nanoCPUs: p.options.NanoCPUs, pidsLimit: p.options.PidsLimit,
			stopTimeout: p.options.StopTimeoutSeconds,
		}, nil
}

func validateNetwork(info networkInfo, request networkRequest, attachment browserdriver.NetworkAttachment, requireGateway bool) error {
	if info.name != request.name || info.driver != "bridge" || info.scope != "local" || !info.enableIPv4 ||
		info.enableIPv6 || !info.internal || info.attachable || info.ingress || info.configOnly ||
		len(info.ipam) != 1 || info.ipam[0].subnet.String() != request.subnet ||
		info.ipam[0].gateway.String() != request.dockerGateway || !labelsMatch(info.labels, request.labels) {
		return ErrOwnershipConflict
	}
	allowed := map[string]bool{request.labels[gatewayNameLabel]: true, request.labels[browserNameLabel]: true}
	gatewayFound := false
	for _, endpoint := range info.containers {
		if !allowed[endpoint.name] {
			return ErrOwnershipConflict
		}
		if endpoint.name == attachment.GatewayContainer {
			gatewayFound = endpoint.address.String() == attachment.GatewayAddress
		}
	}
	if requireGateway && !gatewayFound {
		return ErrOwnershipConflict
	}
	return nil
}

func validateGatewayContainer(info containerInfo, request containerRequest, uplink string, requireUplink bool) error {
	expectedEnvironment := []string{"PATH=" + GatewayPath, gateway.ConfigEnvironment + "=" + request.environment[gateway.ConfigEnvironment]}
	sort.Strings(expectedEnvironment)
	actualEnvironment := append([]string(nil), info.environment...)
	sort.Strings(actualEnvironment)
	if strings.TrimPrefix(info.name, "/") != request.name || !labelsMatch(info.labels, request.labels) ||
		info.imageID != request.imageID || info.image != request.image ||
		info.user != GatewayUser || strings.Join(info.entrypoint, "\x00") != GatewayEntrypoint ||
		strings.Join(info.command, "\x00") != "serve" || info.workingDirectory != "/" ||
		info.stopTimeout != request.stopTimeout ||
		strings.Join(actualEnvironment, "\x00") != strings.Join(expectedEnvironment, "\x00") ||
		info.exposedPorts != 0 || info.privileged || info.autoRemove || !info.readOnlyRoot ||
		info.publishAllPorts || info.portBindings != 0 || info.binds != 0 || info.mounts != 0 ||
		len(info.capAdd) != 0 || strings.Join(info.capDrop, "\x00") != "ALL" ||
		strings.Join(info.securityOptions, "\x00") != "no-new-privileges:true" ||
		len(info.tmpfs) != 1 || info.tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=16777216,mode=1777" ||
		info.dns != 0 || info.extraHosts != 0 || info.memoryBytes != request.memoryBytes ||
		info.nanoCPUs != request.nanoCPUs || info.pidsLimit != request.pidsLimit ||
		info.networkMode != request.internalNetwork || !privateNamespaceMode(info.pidMode) || !privateNamespaceMode(info.ipcMode) ||
		len(info.sysctls) != 1 || info.sysctls["net.ipv4.ip_unprivileged_port_start"] != "0" ||
		(info.restartPolicy != "" && info.restartPolicy != "no") || info.logType != "local" ||
		info.logConfig["max-size"] != "10m" || info.logConfig["max-file"] != "3" ||
		len(info.networks) < 1 || len(info.networks) > 2 ||
		info.networks[request.internalNetwork].String() != request.internalAddress {
		return ErrOwnershipConflict
	}
	_, hasUplink := info.networks[uplink]
	if requireUplink != hasUplink {
		return ErrOwnershipConflict
	}
	for name := range info.networks {
		if name != request.internalNetwork && name != uplink {
			return ErrOwnershipConflict
		}
	}
	return nil
}

func privateNamespaceMode(value string) bool { return value == "" || value == "private" }

func (p *Provisioner) releaseOwned(ctx context.Context, attachment browserdriver.NetworkAttachment) error {
	container, containerErr := p.engine.inspectContainer(ctx, attachment.GatewayContainer)
	if containerErr == nil {
		if container.labels[managedLabel] != "true" || container.labels[ownerLabel] != networkOwner ||
			container.labels[leaseLabel] != attachment.LeaseID || container.labels[policyDigestLabel] != attachment.PolicyDigest ||
			container.labels[gatewayAddressLabel] != attachment.GatewayAddress {
			return ErrOwnershipConflict
		}
		if err := p.engine.removeContainer(ctx, attachment.GatewayContainer); err != nil && !cerrdefs.IsNotFound(err) {
			return classifyOperationError(ctx, err)
		}
	} else if !cerrdefs.IsNotFound(containerErr) {
		return classifyOperationError(ctx, containerErr)
	}
	network, networkErr := p.engine.inspectNetwork(ctx, attachment.DockerName)
	if networkErr == nil {
		if network.labels[managedLabel] != "true" || network.labels[ownerLabel] != networkOwner ||
			network.labels[leaseLabel] != attachment.LeaseID || network.labels[policyDigestLabel] != attachment.PolicyDigest ||
			network.labels[policyLabel] != attachment.PolicyReference ||
			network.labels[gatewayAddressLabel] != attachment.GatewayAddress ||
			network.labels[gatewayNameLabel] != attachment.GatewayContainer {
			return ErrOwnershipConflict
		}
		if len(network.containers) != 0 {
			return ErrOutcomeUnknown
		}
		if err := p.engine.removeNetwork(ctx, attachment.DockerName); err != nil && !cerrdefs.IsNotFound(err) {
			return classifyOperationError(ctx, err)
		}
	} else if !cerrdefs.IsNotFound(networkErr) {
		return classifyOperationError(ctx, networkErr)
	}
	return nil
}

func labelsMatch(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func privateSubnet(digest [32]byte) (netip.Prefix, netip.Addr, netip.Addr) {
	base := netip.AddrFrom4([4]byte{10, 128 + digest[16]%128, digest[17], digest[18] & 0xf0})
	return netip.PrefixFrom(base, 28), base.Next(), base.Next().Next()
}

func browserContainerName(sandboxID, browserSessionID string) string {
	digest := sha256.Sum256([]byte(sandboxID + "\x00" + browserSessionID))
	return "sandbox-runtime-browser-" + hex.EncodeToString(digest[:16])
}

func classifyOperationError(ctx context.Context, cause error) error {
	if err := contextError(ctx); err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if cerrdefs.IsInvalidArgument(cause) || cerrdefs.IsPermissionDenied(cause) || cerrdefs.IsNotFound(cause) {
		return ErrNetworkUnavailable
	}
	if cerrdefs.IsConflict(cause) {
		return ErrOwnershipConflict
	}
	return ErrOutcomeUnknown
}

func safeError(ctx context.Context, public, cause error) error {
	if err := contextError(ctx); err != nil {
		return errors.Join(public, err)
	}
	if errors.Is(cause, context.Canceled) {
		return errors.Join(public, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return errors.Join(public, context.DeadlineExceeded)
	}
	return public
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *Provisioner) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(p.options.OperationTimeoutSeconds)*time.Second)
}
