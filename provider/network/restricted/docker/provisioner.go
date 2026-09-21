package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
)

const (
	managedLabel        = restricted.ManagedLabel
	ownerLabel          = restricted.OwnerLabel
	componentLabel      = "io.github.shell-echo.sandbox-runtime.component"
	namespaceLabel      = restricted.NamespaceLabel
	controllerLabel     = restricted.ControllerLabel
	sandboxLabel        = restricted.SandboxLabel
	policyLabel         = "io.github.shell-echo.sandbox-runtime.network-policy"
	policyDigestLabel   = "io.github.shell-echo.sandbox-runtime.network-policy-digest"
	leaseLabel          = "io.github.shell-echo.sandbox-runtime.network-lease"
	subnetLabel         = "io.github.shell-echo.sandbox-runtime.network-subnet"
	gatewayAddressLabel = "io.github.shell-echo.sandbox-runtime.gateway-address"
	gatewayNameLabel    = "io.github.shell-echo.sandbox-runtime.gateway-container"
	workloadNameLabel   = "io.github.shell-echo.sandbox-runtime.workload-container"
	workloadRoleLabel   = restricted.WorkloadRoleLabel
	workloadIDLabel     = restricted.WorkloadIdentityLabel
	workloadGenLabel    = restricted.WorkloadGenerationLabel
	workloadFenceLabel  = restricted.WorkloadFenceLabel
	gatewayImageLabel   = "io.github.shell-echo.sandbox-runtime.component"

	probeInterval = 50 * time.Millisecond
)

type Provisioner struct {
	engine         engine
	options        Options
	policies       map[string]restricted.Policy
	identity       identityFactory
	role           string
	gatewayImageID string
	mu             sync.Mutex
}

type identityFactory func(Request) (restricted.Identity, error)

func NewBrowser(ctx context.Context, options Options) (*Provisioner, error) {
	return newWithEngine(ctx, options, "browser", func(request Request) (restricted.Identity, error) {
		return restricted.BrowserIdentity(request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.Generation, request.Fence)
	})
}

func NewDesktop(ctx context.Context, options Options) (*Provisioner, error) {
	return newWithEngine(ctx, options, "desktop", func(request Request) (restricted.Identity, error) {
		return restricted.DesktopIdentity(request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.Generation, request.Fence)
	})
}

func newWithEngine(ctx context.Context, options Options, role string, identity identityFactory) (*Provisioner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	backend, err := newMobyEngine(options.Host)
	if err != nil {
		return nil, ErrNetworkUnavailable
	}
	provisioner, err := newProvisioner(ctx, backend, options, role, identity)
	if err != nil {
		_ = backend.close()
		return nil, err
	}
	return provisioner, nil
}

func newProvisioner(ctx context.Context, backend engine, options Options, role string, identity identityFactory) (*Provisioner, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if backend == nil || identity == nil || role != "browser" && role != "desktop" {
		return nil, ErrInvalidOptions
	}
	policies, err := options.validate()
	if err != nil {
		return nil, err
	}
	provisioner := &Provisioner{engine: backend, options: options, policies: policies, identity: identity, role: role}
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

func (p *Provisioner) Acquire(ctx context.Context, request Request) (Attachment, error) {
	if err := contextError(ctx); err != nil {
		return Attachment{}, err
	}
	if p == nil || p.engine == nil {
		return Attachment{}, ErrNetworkUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	policy, ok := p.policies[request.PolicyReference]
	if !ok || request.Namespace != p.options.Namespace || request.ControllerID != p.options.ControllerID ||
		!privateValuePattern.MatchString(request.SandboxID) || !privateValuePattern.MatchString(request.SessionID) ||
		request.Generation < 1 || request.Fence < 1 {
		return Attachment{}, ErrPolicyUnavailable
	}
	desired, networkRequest, containerRequest, err := p.desired(request, policy)
	if err != nil {
		return Attachment{}, ErrPolicyUnavailable
	}
	operationCtx, cancel := p.operationContext(ctx)
	defer cancel()
	if err := p.revalidatePrerequisites(operationCtx); err != nil {
		return Attachment{}, err
	}

	networkCreated := false
	network, err := p.engine.inspectNetwork(operationCtx, desired.DockerName)
	if cerrdefs.IsNotFound(err) {
		if err := p.engine.createNetwork(operationCtx, networkRequest); err != nil {
			inspected, inspectErr := p.engine.inspectNetwork(operationCtx, desired.DockerName)
			if inspectErr != nil {
				return Attachment{}, classifyOperationError(operationCtx, err)
			}
			network = inspected
			if validateNetwork(network, networkRequest, desired, false, false) != nil {
				return Attachment{}, ErrOwnershipConflict
			}
		} else {
			networkCreated = true
			network, err = p.engine.inspectNetwork(operationCtx, desired.DockerName)
			if err != nil {
				return Attachment{}, classifyOperationError(operationCtx, err)
			}
		}
	} else if err != nil {
		return Attachment{}, classifyOperationError(operationCtx, err)
	}
	if validateNetwork(network, networkRequest, desired, false, false) != nil {
		return Attachment{}, ErrOwnershipConflict
	}

	container, err := p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
	if cerrdefs.IsNotFound(err) {
		if err := p.engine.createContainer(operationCtx, containerRequest); err != nil {
			inspected, inspectErr := p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
			if inspectErr != nil {
				if networkCreated {
					_ = p.engine.removeNetwork(operationCtx, desired.DockerName)
				}
				return Attachment{}, classifyOperationError(operationCtx, err)
			}
			container = inspected
		} else {
			container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
			if err != nil {
				return Attachment{}, classifyOperationError(operationCtx, err)
			}
		}
	} else if err != nil {
		return Attachment{}, classifyOperationError(operationCtx, err)
	}
	_, connected := container.networks[p.options.UplinkNetwork]
	if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, connected) != nil {
		return Attachment{}, ErrOwnershipConflict
	}

	if !connected {
		connectErr := p.engine.connectNetwork(operationCtx, p.options.UplinkNetwork, desired.GatewayContainer)
		container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
		if err != nil {
			return Attachment{}, classifyOperationError(operationCtx, errors.Join(connectErr, err))
		}
		if _, connected := container.networks[p.options.UplinkNetwork]; !connected {
			_ = p.releaseOwned(operationCtx, desired)
			return Attachment{}, classifyOperationError(operationCtx, connectErr)
		}
	}
	if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, true) != nil {
		return Attachment{}, ErrOwnershipConflict
	}

	if !container.running {
		startErr := p.engine.startContainer(operationCtx, desired.GatewayContainer)
		container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
		if err != nil || !container.running {
			return Attachment{}, classifyOperationError(operationCtx, errors.Join(startErr, err))
		}
	}
	for {
		container, err = p.engine.inspectContainer(operationCtx, desired.GatewayContainer)
		if err != nil {
			return Attachment{}, classifyOperationError(operationCtx, err)
		}
		if validateGatewayContainer(container, containerRequest, p.options.UplinkNetwork, true) != nil {
			return Attachment{}, ErrOwnershipConflict
		}
		if container.health == "healthy" {
			break
		}
		if container.health == "unhealthy" || !container.running || container.paused || container.restarting || container.dead {
			_ = p.releaseOwned(operationCtx, desired)
			return Attachment{}, ErrNetworkUnavailable
		}
		if err := waitContext(operationCtx, probeInterval); err != nil {
			return Attachment{}, errors.Join(ErrOutcomeUnknown, err)
		}
	}
	network, err = p.engine.inspectNetwork(operationCtx, desired.DockerName)
	if err != nil {
		return Attachment{}, classifyOperationError(operationCtx, err)
	}
	if validateNetwork(network, networkRequest, desired, true, false) != nil {
		return Attachment{}, ErrOwnershipConflict
	}
	return desired, nil
}

func (p *Provisioner) Inspect(ctx context.Context, attachment Attachment) error {
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
		!validDockerName(attachment.GatewayContainer) || !privateValuePattern.MatchString(attachment.LeaseID) ||
		!digestPattern.MatchString(attachment.WorkloadIdentityDigest) {
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
	if err != nil || validateNetwork(network, networkRequest, attachment, true, true) != nil {
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
	identity, err := p.identityFromLabels(network.labels)
	if err != nil || identity.Digest() != attachment.WorkloadIdentityDigest {
		return ErrOwnershipConflict
	}
	workload, err := p.engine.inspectContainer(operationCtx, identity.WorkloadName())
	if err != nil {
		return classifyOperationError(operationCtx, err)
	}
	if validateWorkloadContainer(workload, network, identity, attachment) != nil {
		return ErrOwnershipConflict
	}
	return nil
}

func (p *Provisioner) Release(ctx context.Context, attachment Attachment) error {
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

func (p *Provisioner) desired(request Request, policy restricted.Policy) (Attachment, networkRequest, containerRequest, error) {
	identity, err := p.identity(request)
	if err != nil {
		return Attachment{}, networkRequest{}, containerRequest{}, err
	}
	digest, err := policy.Digest()
	if err != nil {
		return Attachment{}, networkRequest{}, containerRequest{}, err
	}
	tokenBytes := sha256.Sum256([]byte(strings.Join([]string{
		request.Namespace, request.ControllerID, request.SandboxID, request.SessionID, request.PolicyReference, digest,
	}, "\x00")))
	token := hex.EncodeToString(tokenBytes[:16])
	networkName := identity.NetworkPrefix() + token
	gatewayName := identity.GatewayPrefix() + token
	workloadName := identity.WorkloadName()
	subnet, dockerGateway, gatewayAddress := privateSubnet(tokenBytes)
	lease := identity.LeasePrefix() + token
	attachment := Attachment{
		DockerName: networkName, GatewayContainer: gatewayName, GatewayAddress: gatewayAddress.String(),
		LeaseID: lease, PolicyReference: policy.Reference, PolicyDigest: digest,
		WorkloadIdentityDigest: identity.Digest(), EgressGateway: true, Public: false,
	}
	labels := map[string]string{
		managedLabel: "true", ownerLabel: networkOwner(identity.Role()), componentLabel: GatewayComponent,
		namespaceLabel: request.Namespace, controllerLabel: request.ControllerID,
		sandboxLabel: request.SandboxID, identity.SessionLabel(): request.SessionID,
		policyLabel: policy.Reference, policyDigestLabel: digest, leaseLabel: lease,
		subnetLabel: subnet.String(), gatewayAddressLabel: gatewayAddress.String(),
		gatewayNameLabel: gatewayName, workloadNameLabel: workloadName,
		workloadRoleLabel: identity.Role(), workloadIDLabel: identity.Digest(),
		workloadGenLabel: strconv.FormatInt(identity.Generation(), 10), workloadFenceLabel: strconv.FormatInt(identity.Fence(), 10),
	}
	encodedConfig, err := restricted.EncodeConfig(restricted.Config{GatewayAddress: gatewayAddress.String(), Policy: policy})
	if err != nil {
		return Attachment{}, networkRequest{}, containerRequest{}, err
	}
	return attachment,
		networkRequest{name: networkName, subnet: subnet.String(), dockerGateway: dockerGateway.String(), labels: labels},
		containerRequest{
			name: gatewayName, image: p.options.GatewayImage, imageID: p.gatewayImageID, internalNetwork: networkName,
			internalAddress: gatewayAddress.String(), labels: labels,
			environment: map[string]string{restricted.ConfigEnvironment: encodedConfig},
			memoryBytes: p.options.MemoryBytes, nanoCPUs: p.options.NanoCPUs,
			pidsLimit: p.options.PidsLimit, stopTimeout: p.options.StopTimeoutSeconds,
		}, nil
}

func (p *Provisioner) requestsFromNetwork(network networkInfo, attachment Attachment) (networkRequest, containerRequest, error) {
	if len(network.ipam) != 1 {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	labels := network.labels
	sessionLabel := restricted.BrowserSessionLabel
	if labels[workloadRoleLabel] == "desktop" {
		sessionLabel = restricted.DesktopSessionLabel
	}
	required := []string{namespaceLabel, controllerLabel, sandboxLabel, sessionLabel, policyLabel, policyDigestLabel, leaseLabel, subnetLabel, gatewayAddressLabel, gatewayNameLabel, workloadNameLabel, workloadRoleLabel, workloadIDLabel, workloadGenLabel, workloadFenceLabel}
	for _, key := range required {
		if labels[key] == "" {
			return networkRequest{}, containerRequest{}, ErrOwnershipConflict
		}
	}
	if labels[namespaceLabel] != p.options.Namespace || labels[controllerLabel] != p.options.ControllerID ||
		labels[policyLabel] != attachment.PolicyReference || labels[policyDigestLabel] != attachment.PolicyDigest ||
		labels[leaseLabel] != attachment.LeaseID || labels[gatewayNameLabel] != attachment.GatewayContainer ||
		labels[gatewayAddressLabel] != attachment.GatewayAddress || labels[workloadIDLabel] != attachment.WorkloadIdentityDigest {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	generation, generationErr := strconv.ParseInt(labels[workloadGenLabel], 10, 64)
	fence, fenceErr := strconv.ParseInt(labels[workloadFenceLabel], 10, 64)
	request := Request{SandboxID: labels[sandboxLabel], SessionID: labels[sessionLabel], Namespace: labels[namespaceLabel], ControllerID: labels[controllerLabel], PolicyReference: labels[policyLabel], Generation: generation, Fence: fence}
	identity, identityErr := p.identity(request)
	if generationErr != nil || fenceErr != nil || identityErr != nil || identity.Role() != labels[workloadRoleLabel] || identity.Digest() != attachment.WorkloadIdentityDigest || identity.WorkloadName() != labels[workloadNameLabel] {
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
	expectedAttachment, expectedNetwork, expectedContainer, err := p.desired(request, policy)
	if err != nil || expectedAttachment != attachment || network.name != expectedNetwork.name ||
		network.ipam[0].subnet.String() != expectedNetwork.subnet || network.ipam[0].gateway.String() != expectedNetwork.dockerGateway ||
		!stringMapEqual(labels, expectedNetwork.labels) {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	encodedConfig, err := restricted.EncodeConfig(restricted.Config{
		GatewayAddress: labels[gatewayAddressLabel],
		Policy:         policy,
	})
	if err != nil {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	if expectedContainer.name != labels[gatewayNameLabel] || expectedContainer.internalAddress != labels[gatewayAddressLabel] {
		return networkRequest{}, containerRequest{}, ErrOwnershipConflict
	}
	return networkRequest{name: network.name, subnet: subnet.String(), dockerGateway: dockerGateway.String(), labels: labels},
		containerRequest{
			name: labels[gatewayNameLabel], image: p.options.GatewayImage, imageID: p.gatewayImageID, internalNetwork: network.name,
			internalAddress: labels[gatewayAddressLabel], labels: labels,
			environment: map[string]string{restricted.ConfigEnvironment: encodedConfig},
			memoryBytes: p.options.MemoryBytes, nanoCPUs: p.options.NanoCPUs, pidsLimit: p.options.PidsLimit,
			stopTimeout: p.options.StopTimeoutSeconds,
		}, nil
}

func (p *Provisioner) identityFromLabels(labels map[string]string) (restricted.Identity, error) {
	sessionLabel := restricted.BrowserSessionLabel
	if labels[workloadRoleLabel] == "desktop" {
		sessionLabel = restricted.DesktopSessionLabel
	}
	generation, generationErr := strconv.ParseInt(labels[workloadGenLabel], 10, 64)
	fence, fenceErr := strconv.ParseInt(labels[workloadFenceLabel], 10, 64)
	if generationErr != nil || fenceErr != nil {
		return restricted.Identity{}, ErrOwnershipConflict
	}
	identity, err := p.identity(Request{SandboxID: labels[sandboxLabel], SessionID: labels[sessionLabel], Namespace: labels[namespaceLabel], ControllerID: labels[controllerLabel], PolicyReference: labels[policyLabel], Generation: generation, Fence: fence})
	if err != nil || identity.Role() != labels[workloadRoleLabel] || identity.Digest() != labels[workloadIDLabel] || identity.WorkloadName() != labels[workloadNameLabel] {
		return restricted.Identity{}, ErrOwnershipConflict
	}
	return identity, nil
}

func validateNetwork(info networkInfo, request networkRequest, attachment Attachment, requireGateway, requireWorkload bool) error {
	if info.name != request.name || info.driver != "bridge" || info.scope != "local" || !info.enableIPv4 ||
		info.enableIPv6 || !info.internal || info.attachable || info.ingress || info.configOnly ||
		len(info.ipam) != 1 || info.ipam[0].subnet.String() != request.subnet ||
		info.ipam[0].gateway.String() != request.dockerGateway || !labelsMatch(info.labels, request.labels) {
		return ErrOwnershipConflict
	}
	allowed := map[string]bool{request.labels[gatewayNameLabel]: true, request.labels[workloadNameLabel]: true}
	gatewayFound := false
	workloadFound := false
	for _, endpoint := range info.containers {
		if !allowed[endpoint.name] {
			return ErrOwnershipConflict
		}
		if endpoint.name == attachment.GatewayContainer {
			gatewayFound = endpoint.address.String() == attachment.GatewayAddress
		}
		if endpoint.name == request.labels[workloadNameLabel] {
			workloadFound = endpoint.address.IsValid() && endpoint.address.IsPrivate()
		}
	}
	if requireGateway && !gatewayFound || requireWorkload && !workloadFound {
		return ErrOwnershipConflict
	}
	return nil
}

func validateGatewayContainer(info containerInfo, request containerRequest, uplink string, requireUplink bool) error {
	expectedEnvironment := []string{"PATH=" + GatewayPath, restricted.ConfigEnvironment + "=" + request.environment[restricted.ConfigEnvironment]}
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

func validateWorkloadContainer(info containerInfo, network networkInfo, identity restricted.Identity, attachment Attachment) error {
	labels := identity.WorkloadLabels(attachment.LeaseID)
	address, attached := info.networks[attachment.DockerName]
	endpointFound := false
	for _, endpoint := range network.containers {
		if endpoint.name == identity.WorkloadName() {
			endpointFound = endpoint.address == address
		}
	}
	oppositeSessionLabel := restricted.DesktopSessionLabel
	if identity.Role() == "desktop" {
		oppositeSessionLabel = restricted.BrowserSessionLabel
	}
	if strings.TrimPrefix(info.name, "/") != identity.WorkloadName() || labels == nil || !labelsMatch(info.labels, labels) ||
		info.labels[oppositeSessionLabel] != "" || info.networkMode != attachment.DockerName || len(info.networks) != 1 ||
		!attached || !address.IsValid() || !address.IsPrivate() || !endpointFound {
		return ErrOwnershipConflict
	}
	return nil
}

func privateNamespaceMode(value string) bool { return value == "" || value == "private" }

func (p *Provisioner) releaseOwned(ctx context.Context, attachment Attachment) error {
	if !attachment.EgressGateway || attachment.Public || !validDockerName(attachment.DockerName) ||
		!validDockerName(attachment.GatewayContainer) || !privateValuePattern.MatchString(attachment.LeaseID) ||
		!digestPattern.MatchString(attachment.PolicyDigest) || !digestPattern.MatchString(attachment.WorkloadIdentityDigest) {
		return ErrOwnershipConflict
	}
	before, beforeErr := p.engine.inspectNetwork(ctx, attachment.DockerName)
	if beforeErr == nil {
		_, _, requestErr := p.requestsFromNetwork(before, attachment)
		if requestErr != nil ||
			before.labels[managedLabel] != "true" || before.labels[ownerLabel] != networkOwner(p.role) ||
			before.labels[leaseLabel] != attachment.LeaseID || before.labels[policyDigestLabel] != attachment.PolicyDigest ||
			before.labels[policyLabel] != attachment.PolicyReference || before.labels[gatewayAddressLabel] != attachment.GatewayAddress ||
			before.labels[gatewayNameLabel] != attachment.GatewayContainer {
			return ErrOwnershipConflict
		}
		for _, endpoint := range before.containers {
			if endpoint.name != attachment.GatewayContainer {
				return ErrOutcomeUnknown
			}
		}
	} else if !cerrdefs.IsNotFound(beforeErr) {
		return classifyOperationError(ctx, beforeErr)
	}
	container, containerErr := p.engine.inspectContainer(ctx, attachment.GatewayContainer)
	if containerErr == nil {
		if container.labels[managedLabel] != "true" || container.labels[ownerLabel] != networkOwner(p.role) ||
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
		if network.labels[managedLabel] != "true" || network.labels[ownerLabel] != networkOwner(p.role) ||
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

func stringMapEqual(left, right map[string]string) bool {
	return len(left) == len(right) && labelsMatch(left, right)
}

func privateSubnet(digest [32]byte) (netip.Prefix, netip.Addr, netip.Addr) {
	base := netip.AddrFrom4([4]byte{10, 128 + digest[16]%128, digest[17], digest[18] & 0xf0})
	return netip.PrefixFrom(base, 28), base.Next(), base.Next().Next()
}

func networkOwner(role string) string {
	if role == "browser" {
		return "provider-browser-restricted-egress"
	}
	if role == "desktop" {
		return "provider-desktop-restricted-egress"
	}
	return ""
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
