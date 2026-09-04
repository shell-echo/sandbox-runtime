package docker

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 is required by RFC 6455, not used for integrity.
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

const (
	connectTimeout       = 10 * time.Second
	browserReadyPoll     = 50 * time.Millisecond
	maxVersionBodyBytes  = 32 << 10
	maxWebSocketPathSize = 512
)

var (
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	webSocketPathPattern = regexp.MustCompile(`^/devtools/browser/[A-Za-z0-9._:-]{1,256}$`)
)

const (
	managedLabel        = "io.github.shell-echo.sandbox-runtime.managed"
	ownerLabel          = "io.github.shell-echo.sandbox-runtime.owner"
	sandboxLabel        = "io.github.shell-echo.sandbox-runtime.provider-sandbox-id"
	browserSessionLabel = "io.github.shell-echo.sandbox-runtime.browser-session-id"
	namespaceLabel      = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel     = "io.github.shell-echo.sandbox-runtime.controller-id"
	runtimeProfileLabel = "io.github.shell-echo.sandbox-runtime.runtime-profile"
	specDigestLabel     = "io.github.shell-echo.sandbox-runtime.browser-spec-digest"
	providerOwner       = "provider-browser-runtime"
)

type Driver struct {
	engine      engine
	options     Options
	dataRoot    string
	manifest    browserimage.Manifest
	publication browserimage.Publication
	image       imageInfo
	seccomp     string
	provenance  ProvenanceVerifier
	network     RestrictedNetwork
	mu          sync.Mutex
}

func New(ctx context.Context, options Options, provenance ProvenanceVerifier, network RestrictedNetwork) (*Driver, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	backend, err := newMobyEngine(options.Host)
	if err != nil {
		return nil, ErrInvalidDriver
	}
	driver, err := newDriver(ctx, backend, options, provenance, network)
	if err != nil {
		_ = backend.close()
		return nil, err
	}
	return driver, nil
}

func newDriver(ctx context.Context, backend engine, options Options, provenance ProvenanceVerifier, network RestrictedNetwork) (*Driver, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if backend == nil || provenance == nil || network == nil {
		return nil, ErrInvalidDriver
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	manifest, err := browserimage.Load(options.ManifestPath)
	if err != nil || manifest.ProfileID != BrowserRuntimeProfile {
		return nil, ErrInvalidOptions
	}
	if err := browserimage.VerifySeccompProfile(options.SeccompPath, manifest.Security.SeccompProfile.Digest); err != nil {
		return nil, ErrInvalidOptions
	}
	seccomp, err := os.ReadFile(filepath.Clean(options.SeccompPath))
	if err != nil || len(seccomp) == 0 || len(seccomp) > browserimage.MaxSeccompBytes {
		return nil, ErrInvalidOptions
	}
	publication := browserimage.LockedPublication()
	if err := publication.Validate(); err != nil || options.Image != publication.Image() {
		return nil, ErrInvalidProvenance
	}
	root, err := prepareDataRoot(options.DataRoot)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	pingCtx, pingCancel := context.WithTimeout(ctx, connectTimeout)
	if err := backend.ping(pingCtx); err != nil {
		result := safeContextError(ErrInvalidDriver, pingCtx, err)
		pingCancel()
		return nil, result
	}
	pingCancel()
	networkCtx, networkCancel := context.WithTimeout(ctx, connectTimeout)
	if err := network.Ready(networkCtx, options.NetworkPolicyReference); err != nil {
		result := safeContextError(ErrNetworkUnavailable, networkCtx, err)
		networkCancel()
		return nil, result
	}
	networkCancel()
	provenanceCtx, provenanceCancel := context.WithTimeout(ctx, time.Duration(options.ProvenanceTimeoutSeconds)*time.Second)
	if err := provenance.Verify(provenanceCtx, publication); err != nil {
		result := safeContextError(ErrInvalidProvenance, provenanceCtx, err)
		provenanceCancel()
		return nil, result
	}
	provenanceCancel()
	pullCtx, pullCancel := context.WithTimeout(ctx, time.Duration(options.PullTimeoutSeconds)*time.Second)
	err = backend.ensureImage(pullCtx, options.Image, options.PullPolicy)
	if err != nil {
		result := safeContextError(ErrInvalidRuntime, pullCtx, err)
		pullCancel()
		return nil, result
	}
	pullCancel()
	inspectCtx, inspectCancel := context.WithTimeout(ctx, time.Duration(options.OperationTimeoutSeconds)*time.Second)
	image, err := backend.inspectImage(inspectCtx, options.Image)
	if err != nil {
		result := safeContextError(ErrInvalidRuntime, inspectCtx, err)
		inspectCancel()
		return nil, result
	}
	inspectCancel()
	if validateImage(image, manifest, publication) != nil {
		return nil, ErrInvalidRuntime
	}
	return &Driver{
		engine: backend, options: options, dataRoot: root, manifest: manifest,
		publication: publication, image: image, seccomp: string(seccomp), provenance: provenance, network: network,
	}, nil
}

func validateImage(info imageInfo, manifest browserimage.Manifest, publication browserimage.Publication) error {
	bound := info.descriptorDigest == publication.Digest
	for _, repositoryDigest := range info.repositoryDigests {
		if repositoryDigest == publication.Image() {
			bound = true
			break
		}
	}
	if !bound || info.user != BrowserUser || info.workingDirectory != "/workspace" ||
		strings.Join(info.entrypoint, "\x00") != "/usr/local/bin/browser-runtime" || len(info.command) != 0 ||
		info.operatingSystem != "linux" || info.exposedPorts != 0 {
		return ErrInvalidRuntime
	}
	platform := "linux/" + info.architecture
	if info.architecture == "arm64" {
		if info.variant != "" && info.variant != "v8" {
			return ErrInvalidRuntime
		}
		platform = "linux/arm64/v8"
	} else if info.architecture != "amd64" || info.variant != "" {
		return ErrInvalidRuntime
	}
	source, ok := manifest.Source.Manifests[platform]
	labels := info.labels
	if !ok || labels["io.github.shell-echo.sandbox-runtime.profile"] != browserimage.ProfileID ||
		labels["io.github.shell-echo.sandbox-runtime.browser-sandbox"] != "user-namespace" ||
		labels["io.github.shell-echo.sandbox-runtime.seccomp-profile-digest"] != browserimage.SeccompDigest ||
		labels["io.github.shell-echo.sandbox-runtime.provenance.source-digest"] != source.Digest ||
		labels["org.opencontainers.image.base.digest"] != source.Digest ||
		labels["org.opencontainers.image.base.name"] != browserimage.SourceRepository ||
		labels["org.opencontainers.image.revision"] != publication.SourceCommit ||
		labels["org.opencontainers.image.source"] != "https://github.com/shell-echo/sandbox-runtime" ||
		labels["org.opencontainers.image.version"] != browserimage.ProfileID {
		return ErrInvalidRuntime
	}
	return nil
}

// Ready revalidates the runtime dependencies used by the Browser lifecycle
// readiness adapter. It performs no allocation and returns no backend detail.
func (d *Driver) Ready(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil || d.provenance == nil || d.network == nil {
		return ErrInvalidDriver
	}
	networkCtx, networkCancel := context.WithTimeout(ctx, connectTimeout)
	if err := d.network.Ready(networkCtx, d.options.NetworkPolicyReference); err != nil {
		result := safeContextError(ErrNetworkUnavailable, networkCtx, err)
		networkCancel()
		return result
	}
	networkCancel()
	provenanceCtx, provenanceCancel := context.WithTimeout(ctx, time.Duration(d.options.ProvenanceTimeoutSeconds)*time.Second)
	if err := d.provenance.Verify(provenanceCtx, d.publication); err != nil {
		result := safeContextError(ErrInvalidProvenance, provenanceCtx, err)
		provenanceCancel()
		return result
	}
	provenanceCancel()
	inspectCtx, inspectCancel := context.WithTimeout(ctx, time.Duration(d.options.OperationTimeoutSeconds)*time.Second)
	image, err := d.engine.inspectImage(inspectCtx, d.options.Image)
	if err != nil {
		result := safeContextError(ErrInvalidRuntime, inspectCtx, err)
		inspectCancel()
		return result
	}
	inspectCancel()
	if validateImage(image, d.manifest, d.publication) != nil {
		return ErrInvalidRuntime
	}
	return nil
}

func (d *Driver) Allocate(ctx context.Context, allocation providerbrowser.Allocation) (providerbrowser.AllocationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return providerbrowser.AllocationReceipt{}, err
	}
	if d == nil || d.engine == nil || d.network == nil {
		return providerbrowser.AllocationReceipt{}, ErrInvalidDriver
	}
	if err := allocation.Validate(); err != nil {
		return providerbrowser.AllocationReceipt{}, err
	}
	if allocation.Request.NetworkPolicyReference != d.options.NetworkPolicyReference {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserUnsupported
	}
	now := d.options.Clock.Now().UTC()
	if now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserExpired
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	directory, statePath, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.BrowserSessionID)
	if err != nil {
		return providerbrowser.AllocationReceipt{}, err
	}
	specDigest, err := d.specDigest(allocation)
	if err != nil {
		return providerbrowser.AllocationReceipt{}, err
	}
	state, err := loadBrowserState(statePath, d.options.NetworkPolicyReference)
	if err == nil {
		if !state.matchesAllocation(allocation) || state.SpecDigest != specDigest {
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
		}
		return d.recoverAllocation(ctx, statePath, state)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return providerbrowser.AllocationReceipt{}, err
	}
	if err := d.checkCapacity(directory); err != nil {
		return providerbrowser.AllocationReceipt{}, err
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	attachment, err := d.network.Acquire(operationCtx, NetworkRequest{
		SandboxID: allocation.Request.SandboxID, BrowserSessionID: allocation.Request.BrowserSessionID,
		Namespace: d.options.Namespace, ControllerID: d.options.ControllerID,
		PolicyReference: allocation.Request.NetworkPolicyReference,
	})
	if err != nil {
		if contextErr := allocationContextError(operationCtx, err); contextErr != nil {
			return providerbrowser.AllocationReceipt{}, contextErr
		}
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserUnsupported
	}
	if err := attachment.validate(d.options.NetworkPolicyReference); err != nil {
		if releaseErr := d.network.Release(operationCtx, attachment); releaseErr != nil {
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
		}
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserUnsupported
	}
	state = newBrowserState(allocation, attachment, specDigest)
	if err := persistBrowserState(statePath, state, d.options.NetworkPolicyReference); err != nil {
		_ = d.network.Release(operationCtx, attachment)
		return providerbrowser.AllocationReceipt{}, err
	}
	request := d.createRequest(state)
	if _, createErr := d.engine.create(operationCtx, request); createErr != nil {
		if cerrdefs.IsInvalidArgument(createErr) || cerrdefs.IsPermissionDenied(createErr) || cerrdefs.IsNotFound(createErr) {
			if rollbackErr := d.rollbackState(operationCtx, statePath, state); rollbackErr != nil {
				return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
			}
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserUnsupported
		}
		if !cerrdefs.IsConflict(createErr) {
			return providerbrowser.AllocationReceipt{}, allocationUnknown(operationCtx, createErr)
		}
	}
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		if errors.Is(err, ErrOwnershipConflict) {
			if rollbackErr := d.rollbackState(operationCtx, statePath, state); rollbackErr != nil {
				return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
			}
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
		}
		return providerbrowser.AllocationReceipt{}, err
	}
	if !found {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	state.BackendContainerID = info.id
	if err := persistBrowserState(statePath, state, d.options.NetworkPolicyReference); err != nil {
		return providerbrowser.AllocationReceipt{}, errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	return d.startAndProbe(operationCtx, statePath, state, info)
}

func (d *Driver) recoverAllocation(ctx context.Context, statePath string, state browserState) (providerbrowser.AllocationReceipt, error) {
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		if errors.Is(err, ErrOwnershipConflict) {
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
		}
		return providerbrowser.AllocationReceipt{}, err
	}
	if !found {
		if state.BackendContainerID == "" {
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
		}
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserNotFound
	}
	if state.BackendContainerID != "" && state.BackendContainerID != info.id {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
	}
	if state.BackendContainerID == "" {
		state.BackendContainerID = info.id
		if err := persistBrowserState(statePath, state, d.options.NetworkPolicyReference); err != nil {
			return providerbrowser.AllocationReceipt{}, errors.Join(providerbrowser.ErrAllocationUnknown, err)
		}
	}
	if err := d.network.Inspect(operationCtx, state.Network); err != nil {
		return providerbrowser.AllocationReceipt{}, allocationUnknown(operationCtx, err)
	}
	if state.Ready && (!info.running || info.status != "running") {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserNotFound
	}
	return d.startAndProbe(operationCtx, statePath, state, info)
}

func (d *Driver) startAndProbe(ctx context.Context, statePath string, state browserState, info containerInfo) (providerbrowser.AllocationReceipt, error) {
	if !info.running {
		if info.status != "created" || info.paused || info.restarting || info.dead {
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserNotFound
		}
		if err := d.engine.start(ctx, info.id); err != nil {
			return providerbrowser.AllocationReceipt{}, allocationUnknown(ctx, err)
		}
	}
	for {
		confirmed, found, err := d.inspectOwned(ctx, state)
		if err != nil {
			return providerbrowser.AllocationReceipt{}, err
		}
		if !found || !confirmed.running || confirmed.status != "running" || confirmed.paused || confirmed.restarting || confirmed.dead {
			return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
		}
		if _, err := d.browserWebSocketPath(ctx, state.BackendContainerID); err == nil {
			if !state.Ready {
				state.Ready = true
				if err := persistBrowserState(statePath, state, d.options.NetworkPolicyReference); err != nil {
					return providerbrowser.AllocationReceipt{}, errors.Join(providerbrowser.ErrAllocationUnknown, err)
				}
			}
			return state.Receipt, nil
		}
		if err := waitContext(ctx, browserReadyPoll); err != nil {
			return providerbrowser.AllocationReceipt{}, errors.Join(providerbrowser.ErrAllocationUnknown, err)
		}
	}
}

func (d *Driver) Observe(ctx context.Context, receipt providerbrowser.AllocationReceipt) (providerbrowser.AllocationObservation, error) {
	if err := contextError(ctx); err != nil {
		return providerbrowser.AllocationObservation{}, err
	}
	if d == nil || d.engine == nil || d.network == nil {
		return providerbrowser.AllocationObservation{}, ErrInvalidDriver
	}
	if err := receipt.Validate(); err != nil {
		return providerbrowser.AllocationObservation{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.options.Clock.Now().UTC()
	observation := providerbrowser.AllocationObservation{Receipt: receipt, ObservedAt: now}
	if now.IsZero() {
		return providerbrowser.AllocationObservation{}, ErrInvalidRuntime
	}
	if !receipt.ExpiresAt.After(now) {
		observation.State = providerbrowser.AllocationExpired
		return observation, observation.Validate()
	}
	_, statePath, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return providerbrowser.AllocationObservation{}, err
	}
	state, err := loadBrowserState(statePath, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		observation.State = providerbrowser.AllocationAbsent
		return observation, observation.Validate()
	}
	if err != nil {
		return providerbrowser.AllocationObservation{}, err
	}
	if !state.matchesReceipt(receipt) {
		return providerbrowser.AllocationObservation{}, providerbrowser.ErrBrowserConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		if contextErr := allocationContextError(operationCtx, err); contextErr != nil {
			return providerbrowser.AllocationObservation{}, contextErr
		}
		observation.State = providerbrowser.AllocationOutcomeUnknown
		return observation, observation.Validate()
	}
	if !found {
		observation.State = providerbrowser.AllocationAbsent
		return observation, observation.Validate()
	}
	if state.BackendContainerID != info.id {
		return providerbrowser.AllocationObservation{}, providerbrowser.ErrBrowserConflict
	}
	if err := d.network.Inspect(operationCtx, state.Network); err != nil {
		if contextErr := allocationContextError(operationCtx, err); contextErr != nil {
			return providerbrowser.AllocationObservation{}, contextErr
		}
		observation.State = providerbrowser.AllocationOutcomeUnknown
		return observation, observation.Validate()
	}
	if !info.running || info.status != "running" {
		observation.State = providerbrowser.AllocationOutcomeUnknown
		return observation, observation.Validate()
	}
	if _, err := d.browserWebSocketPath(operationCtx, state.BackendContainerID); err != nil {
		observation.State = providerbrowser.AllocationOutcomeUnknown
	} else {
		observation.State = providerbrowser.AllocationRunning
	}
	return observation, observation.Validate()
}

func (d *Driver) Attach(ctx context.Context, receipt providerbrowser.AllocationReceipt) (providerbrowser.Stream, error) {
	observation, err := d.Observe(ctx, receipt)
	if err != nil {
		return nil, err
	}
	switch observation.State {
	case providerbrowser.AllocationExpired:
		return nil, providerbrowser.ErrBrowserExpired
	case providerbrowser.AllocationAbsent:
		return nil, providerbrowser.ErrBrowserNotFound
	case providerbrowser.AllocationOutcomeUnknown:
		return nil, providerbrowser.ErrAllocationUnknown
	case providerbrowser.AllocationRunning:
	default:
		return nil, ErrInvalidRuntime
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, statePath, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return nil, err
	}
	state, err := loadBrowserState(statePath, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		return nil, providerbrowser.ErrBrowserNotFound
	}
	if err != nil {
		return nil, err
	}
	if !state.matchesReceipt(receipt) {
		return nil, providerbrowser.ErrBrowserConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	path, err := d.browserWebSocketPath(operationCtx, state.BackendContainerID)
	if err != nil {
		return nil, allocationUnknown(operationCtx, err)
	}
	connection, reader, err := d.attachWebSocket(operationCtx, state.BackendContainerID, path)
	if err != nil {
		return nil, allocationUnknown(operationCtx, err)
	}
	return &browserStream{connection: connection, reader: reader}, nil
}

func (d *Driver) Cleanup(ctx context.Context, receipt providerbrowser.AllocationReceipt) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil || d.network == nil {
		return ErrInvalidDriver
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	directory, statePath, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return err
	}
	state, err := loadBrowserState(statePath, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !state.matchesReceipt(receipt) {
		return providerbrowser.ErrBrowserConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		return err
	}
	if found {
		if state.BackendContainerID != "" && state.BackendContainerID != info.id {
			return providerbrowser.ErrBrowserConflict
		}
		if err := d.engine.remove(operationCtx, info.id); err != nil && !cerrdefs.IsNotFound(err) {
			return allocationUnknown(operationCtx, err)
		}
	}
	if err := d.network.Release(operationCtx, state.Network); err != nil {
		return allocationUnknown(operationCtx, err)
	}
	if err := os.Remove(statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(directoryFile.Sync(), directoryFile.Close())
}

func (d *Driver) Close() error {
	if d == nil || d.engine == nil {
		return nil
	}
	return d.engine.close()
}

func (d *Driver) inspectOwned(ctx context.Context, state browserState) (containerInfo, bool, error) {
	info, err := d.engine.inspect(ctx, containerName(state.Request.SandboxID, state.Request.BrowserSessionID))
	if cerrdefs.IsNotFound(err) {
		return containerInfo{}, false, nil
	}
	if err != nil {
		return containerInfo{}, false, allocationUnknown(ctx, err)
	}
	labels := info.labels
	if labels[managedLabel] != "true" || labels[ownerLabel] != providerOwner ||
		labels[sandboxLabel] != state.Request.SandboxID || labels[browserSessionLabel] != state.Request.BrowserSessionID ||
		labels[namespaceLabel] != d.options.Namespace || labels[controllerLabel] != d.options.ControllerID ||
		labels[runtimeProfileLabel] != BrowserRuntimeProfile || labels[specDigestLabel] != state.SpecDigest {
		return containerInfo{}, false, ErrOwnershipConflict
	}
	if validateContainerRuntime(info, d.createRequest(state), d.image) != nil {
		return containerInfo{}, false, ErrOwnershipConflict
	}
	return info, true, nil
}

func validateContainerRuntime(info containerInfo, request createRequest, image imageInfo) error {
	expectedTmpfs := map[string]string{
		"/inputs":    fmt.Sprintf("ro,noexec,nosuid,nodev,size=%d,mode=0555", request.inputsBytes),
		"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=1777", request.tmpfsBytes),
		"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700", request.workspaceBytes),
		"/outputs":   fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700", request.outputsBytes),
	}
	resolver, resolverErr := netip.ParseAddr(request.dnsResolver)
	address, attached := info.networks[request.networkName]
	validRuntimeAddress := attached && ((info.status == "created" && (!address.IsValid() || address.IsPrivate())) ||
		(address.IsValid() && address.IsPrivate()))
	if info.imageID != image.id || info.imageReference != request.image || info.user != request.user ||
		info.workingDirectory != request.workingDirectory || strings.Join(info.entrypoint, "\x00") != strings.Join(image.entrypoint, "\x00") ||
		strings.Join(info.command, "\x00") != strings.Join(image.command, "\x00") ||
		strings.Join(info.environment, "\x00") != strings.Join(image.environment, "\x00") ||
		info.stopTimeout != request.stopTimeout || info.exposedPorts != 0 || info.privileged || info.autoRemove ||
		!info.readOnlyRoot || info.publishAllPorts || info.portBindings != 0 || info.binds != 0 || info.mounts != 0 ||
		!stringMapEqual(info.tmpfs, expectedTmpfs) || resolverErr != nil || len(info.dns) != 1 || info.dns[0] != resolver ||
		len(info.capAdd) != 0 || strings.Join(info.capDrop, "\x00") != "ALL" || len(info.securityOptions) != 2 ||
		info.securityOptions[0] != "no-new-privileges:true" || info.securityOptions[1] != "seccomp="+request.seccompProfile ||
		info.memoryBytes != request.memoryBytes || info.memorySwap != request.memoryBytes || info.nanoCPUs != request.nanoCPUs ||
		info.pidsLimit != request.pidsLimit || info.networkMode != request.networkName || !privateNamespaceMode(info.pidMode) || !privateNamespaceMode(info.ipcMode) ||
		(info.restartPolicy != "" && info.restartPolicy != "no") || info.logType != "local" ||
		!stringMapEqual(info.logConfig, map[string]string{"max-size": "10m", "max-file": "3"}) ||
		len(info.networks) != 1 || !validRuntimeAddress {
		return ErrInvalidRuntime
	}
	return nil
}

func privateNamespaceMode(value string) bool { return value == "" || value == "private" }

func stringMapEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range right {
		if left[key] != value {
			return false
		}
	}
	return true
}

func (d *Driver) createRequest(state browserState) createRequest {
	return createRequest{
		name:  containerName(state.Request.SandboxID, state.Request.BrowserSessionID),
		image: d.options.Image, user: BrowserUser, workingDirectory: "/workspace",
		memoryBytes: d.options.MemoryBytes, nanoCPUs: d.options.NanoCPUs, pidsLimit: d.options.PidsLimit,
		inputsBytes: d.options.InputsBytes, tmpfsBytes: d.options.TmpfsBytes,
		workspaceBytes: d.options.WorkspaceBytes, outputsBytes: d.options.OutputsBytes,
		stopTimeout: d.options.StopTimeoutSeconds, networkName: state.Network.DockerName,
		dnsResolver: state.Network.GatewayAddress, seccompProfile: d.seccomp,
		labels: map[string]string{
			managedLabel: "true", ownerLabel: providerOwner,
			sandboxLabel: state.Request.SandboxID, browserSessionLabel: state.Request.BrowserSessionID,
			namespaceLabel: d.options.Namespace, controllerLabel: d.options.ControllerID,
			runtimeProfileLabel: BrowserRuntimeProfile, specDigestLabel: state.SpecDigest,
		},
	}
}

func (d *Driver) specDigest(allocation providerbrowser.Allocation) (string, error) {
	value := struct {
		Allocation       providerbrowser.Allocation
		Image            string
		User             string
		MemoryBytes      int64
		NanoCPUs         int64
		PidsLimit        int64
		InputsBytes      int64
		TmpfsBytes       int64
		WorkspaceBytes   int64
		OutputsBytes     int64
		StopTimeout      int
		SeccompDigest    string
		NetworkPolicy    string
		Namespace        string
		ControllerID     string
		RuntimeProfileID string
	}{
		Allocation: allocation, Image: d.options.Image, User: BrowserUser,
		MemoryBytes: d.options.MemoryBytes, NanoCPUs: d.options.NanoCPUs, PidsLimit: d.options.PidsLimit,
		InputsBytes: d.options.InputsBytes, TmpfsBytes: d.options.TmpfsBytes,
		WorkspaceBytes: d.options.WorkspaceBytes, OutputsBytes: d.options.OutputsBytes,
		StopTimeout:   d.options.StopTimeoutSeconds,
		SeccompDigest: d.manifest.Security.SeccompProfile.Digest,
		NetworkPolicy: allocation.Request.NetworkPolicyReference, Namespace: d.options.Namespace,
		ControllerID: d.options.ControllerID, RuntimeProfileID: BrowserRuntimeProfile,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (d *Driver) stateLocation(sandboxID, browserSessionID string) (string, string, error) {
	if !privateValuePattern.MatchString(sandboxID) || !privateValuePattern.MatchString(browserSessionID) {
		return "", "", providerbrowser.ErrInvalidRequest
	}
	directory := filepath.Join(d.dataRoot, sandboxToken(sandboxID), "browser")
	return directory, filepath.Join(directory, allocationToken(sandboxID, browserSessionID)+".json"), nil
}

func (d *Driver) checkCapacity(directory string) error {
	if err := ensureDirectory(filepath.Dir(directory), 0o700); err != nil {
		return err
	}
	if err := ensureDirectory(directory, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	sandboxCount := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if _, err := loadBrowserState(filepath.Join(directory, entry.Name()), d.options.NetworkPolicyReference); err != nil {
			return err
		}
		sandboxCount++
	}
	controllerCount, err := countBrowserStates(d.dataRoot, d.options.NetworkPolicyReference)
	if err != nil {
		return err
	}
	if sandboxCount >= d.options.MaxSessionsPerSandbox || controllerCount >= d.options.MaxSessionsPerController {
		return providerbrowser.ErrBrowserUnsupported
	}
	return nil
}

func (d *Driver) rollbackState(ctx context.Context, statePath string, state browserState) error {
	releaseErr := d.network.Release(ctx, state.Network)
	removeErr := os.Remove(statePath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(releaseErr, removeErr)
}

func (d *Driver) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(d.options.OperationTimeoutSeconds)*time.Second)
}

func (d *Driver) browserWebSocketPath(ctx context.Context, containerID string) (string, error) {
	connection, err := d.engine.attachRelay(ctx, containerID)
	if err != nil {
		return "", err
	}
	stream := &browserStream{connection: connection, reader: connection}
	defer stream.Close()
	request := "GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:9222\r\nConnection: close\r\n\r\n"
	if err := writeAll(ctx, stream, []byte(request)); err != nil {
		return "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(contextStreamReader{ctx: ctx, stream: stream}), &http.Request{Method: http.MethodGet})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrInvalidRuntime
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxVersionBodyBytes+1))
	if err != nil || len(body) > maxVersionBodyBytes {
		return "", ErrInvalidRuntime
	}
	var version struct {
		Browser              string `json:"Browser"`
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.Unmarshal(body, &version); err != nil || version.Browser != "Chrome/151.0.7922.109" {
		return "", ErrInvalidRuntime
	}
	endpoint, err := url.Parse(version.WebSocketDebuggerURL)
	if err != nil || endpoint.Scheme != "ws" || endpoint.Host != "127.0.0.1:9222" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil ||
		len(endpoint.EscapedPath()) > maxWebSocketPathSize || !webSocketPathPattern.MatchString(endpoint.EscapedPath()) {
		return "", ErrInvalidRuntime
	}
	return endpoint.EscapedPath(), nil
}

func (d *Driver) attachWebSocket(ctx context.Context, containerID, path string) (relayConnection, *bufio.Reader, error) {
	connection, err := d.engine.attachRelay(ctx, containerID)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := func(err error) (relayConnection, *bufio.Reader, error) {
		_ = connection.Close()
		return nil, nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return closeOnError(err)
	}
	key := base64.StdEncoding.EncodeToString(nonce)
	request := "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1:9222\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n"
	stream := &browserStream{connection: connection, reader: connection}
	if err := writeAll(ctx, stream, []byte(request)); err != nil {
		return closeOnError(err)
	}
	stop, fired := interruptOnCancellation(ctx, connection.SetReadDeadline)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	stopAndClearDeadline(stop, fired, connection.SetReadDeadline)
	if err != nil {
		return closeOnError(err)
	}
	if response.Body != nil {
		defer response.Body.Close()
	}
	wantAccept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(response.Header.Get("Connection"), "upgrade") ||
		response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(wantAccept[:]) {
		return closeOnError(ErrInvalidRuntime)
	}
	return connection, reader, nil
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func writeAll(ctx context.Context, stream providerbrowser.Stream, value []byte) error {
	for len(value) > 0 {
		count, err := stream.Write(ctx, value)
		if count > 0 {
			value = value[count:]
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type contextStreamReader struct {
	ctx    context.Context
	stream providerbrowser.Stream
}

func (r contextStreamReader) Read(value []byte) (int, error) { return r.stream.Read(r.ctx, value) }

type browserStream struct {
	connection relayConnection
	reader     io.Reader
	readMu     sync.Mutex
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (s *browserStream) Read(ctx context.Context, value []byte) (int, error) {
	if s == nil || s.connection == nil || s.reader == nil {
		return 0, net.ErrClosed
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	stop, fired := interruptOnCancellation(ctx, s.connection.SetReadDeadline)
	count, err := s.reader.Read(value)
	stopAndClearDeadline(stop, fired, s.connection.SetReadDeadline)
	if normalized := streamContextError(ctx, err); normalized != nil {
		return count, normalized
	}
	return count, err
}

func (s *browserStream) Write(ctx context.Context, value []byte) (int, error) {
	if s == nil || s.connection == nil {
		return 0, net.ErrClosed
	}
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	stop, fired := interruptOnCancellation(ctx, s.connection.SetWriteDeadline)
	count, err := s.connection.Write(value)
	stopAndClearDeadline(stop, fired, s.connection.SetWriteDeadline)
	if normalized := streamContextError(ctx, err); normalized != nil {
		return count, normalized
	}
	return count, err
}

func (s *browserStream) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { err = s.connection.Close() })
	return err
}

func interruptOnCancellation(ctx context.Context, setDeadline func(time.Time) error) (func() bool, <-chan struct{}) {
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(fired)
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = setDeadline(deadline)
	} else {
		_ = setDeadline(time.Time{})
	}
	return stop, fired
}

func stopAndClearDeadline(stop func() bool, fired <-chan struct{}, setDeadline func(time.Time) error) {
	if !stop() {
		<-fired
	}
	_ = setDeadline(time.Time{})
}

func streamContextError(ctx context.Context, streamErr error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var netErr net.Error
	if errors.As(streamErr, &netErr) && netErr.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return nil
}

var _ providerbrowser.Runtime = (*Driver)(nil)
