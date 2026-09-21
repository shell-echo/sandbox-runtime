package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
)

const (
	connectTimeout      = 10 * time.Second
	desktopReadyPoll    = 50 * time.Millisecond
	desktopBrokerPath   = desktopimage.BrokerPath
	desktopBrokerSocket = desktopimage.BrokerSocket
	maxBrokerExecBytes  = desktopbroker.MaxResponseBytes
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const (
	managedLabel        = "io.github.shell-echo.sandbox-runtime.managed"
	ownerLabel          = "io.github.shell-echo.sandbox-runtime.owner"
	sandboxLabel        = "io.github.shell-echo.sandbox-runtime.provider-sandbox-id"
	desktopSessionLabel = "io.github.shell-echo.sandbox-runtime.desktop-session-id"
	namespaceLabel      = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel     = "io.github.shell-echo.sandbox-runtime.controller-id"
	runtimeProfileLabel = "io.github.shell-echo.sandbox-runtime.runtime-profile"
	specDigestLabel     = "io.github.shell-echo.sandbox-runtime.desktop-spec-digest"
	providerOwner       = "provider-desktop-runtime"
)

type Driver struct {
	engine      engine
	options     Options
	dataRoot    string
	manifest    desktopimage.Manifest
	publication desktopimage.Publication
	candidate   *desktopcandidate.Manifest
	image       imageInfo
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

// NewLocalCandidate constructs the non-release Slice 4 integration adapter.
// The candidate digest is never promoted to the signed production lock.
func NewLocalCandidate(ctx context.Context, options Options, candidate desktopcandidate.Manifest, network RestrictedNetwork) (*Driver, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	backend, err := newMobyEngine(options.Host)
	if err != nil {
		return nil, ErrInvalidDriver
	}
	driver, err := newCandidateDriver(ctx, backend, options, candidate, network)
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
	manifest, err := desktopimage.Load(options.ManifestPath)
	if err != nil || manifest.ProfileID != DesktopRuntimeProfile {
		return nil, ErrInvalidOptions
	}
	publication := desktopimage.LockedPublication()
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
		publication: publication, image: image, provenance: provenance, network: network,
	}, nil
}

func newCandidateDriver(ctx context.Context, backend engine, options Options, candidate desktopcandidate.Manifest, network RestrictedNetwork) (*Driver, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if backend == nil || network == nil || options.validateCandidate(candidate) != nil {
		return nil, ErrInvalidDriver
	}
	manifest, err := desktopimage.Load(options.ManifestPath)
	if err != nil || manifest.ProfileID != DesktopRuntimeProfile {
		return nil, ErrInvalidOptions
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
	inspectCtx, inspectCancel := context.WithTimeout(ctx, time.Duration(options.OperationTimeoutSeconds)*time.Second)
	image, err := backend.inspectImage(inspectCtx, options.Image)
	if err != nil {
		result := safeContextError(ErrInvalidRuntime, inspectCtx, err)
		inspectCancel()
		return nil, result
	}
	inspectCancel()
	if validateCandidateImage(image, manifest, candidate) != nil {
		return nil, ErrInvalidRuntime
	}
	copyCandidate := candidate
	return &Driver{
		engine: backend, options: options, dataRoot: root, manifest: manifest,
		candidate: &copyCandidate, image: image, network: network,
	}, nil
}

func validateImage(info imageInfo, manifest desktopimage.Manifest, publication desktopimage.Publication) error {
	bound := info.descriptorDigest == publication.Digest
	for _, repositoryDigest := range info.repositoryDigests {
		if repositoryDigest == publication.Image() {
			bound = true
			break
		}
	}
	if !bound || info.user != DesktopUser || info.workingDirectory != "/workspace" ||
		strings.Join(info.entrypoint, "\x00") != "/usr/local/bin/desktop-runtime" || len(info.command) != 0 ||
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
	if !ok || labels["io.github.shell-echo.sandbox-runtime.profile"] != desktopimage.ProfileID ||
		labels["io.github.shell-echo.sandbox-runtime.desktop-broker-protocol"] != desktopimage.BrokerProtocol ||
		labels["io.github.shell-echo.sandbox-runtime.desktop-broker-path"] != desktopimage.BrokerPath ||
		labels["io.github.shell-echo.sandbox-runtime.package-archive-set-digest"] != source.PackageArchiveSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.installed-set-digest"] != source.InstalledSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.provenance.source-digest"] != source.Digest ||
		labels["org.opencontainers.image.base.digest"] != source.Digest ||
		labels["org.opencontainers.image.base.name"] != desktopimage.SourceRepository ||
		labels["org.opencontainers.image.revision"] != publication.SourceCommit ||
		labels["org.opencontainers.image.source"] != "https://github.com/shell-echo/sandbox-runtime" ||
		labels["org.opencontainers.image.version"] != desktopimage.ProfileID {
		return ErrInvalidRuntime
	}
	return nil
}

func validateCandidateImage(info imageInfo, manifest desktopimage.Manifest, candidate desktopcandidate.Manifest) error {
	if candidate.Validate() != nil || info.id != candidate.ImageDigest || candidate.ConfigDigest != candidate.ImageDigest ||
		info.user != DesktopUser || info.workingDirectory != "/workspace" ||
		strings.Join(info.entrypoint, "\x00") != "/usr/local/bin/desktop-runtime" || len(info.command) != 0 ||
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
	if !ok || platform != candidate.Platform || source.Digest != candidate.BaseImageDigest ||
		source.PackageArchiveSetDigest != candidate.PackageArchiveSetDigest || source.InstalledSetDigest != candidate.InstalledSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.profile"] != candidate.ProfileID ||
		labels["io.github.shell-echo.sandbox-runtime.desktop-broker-protocol"] != candidate.BrokerProtocol ||
		labels["io.github.shell-echo.sandbox-runtime.desktop-broker-path"] != desktopimage.BrokerPath ||
		labels["io.github.shell-echo.sandbox-runtime.package-archive-set-digest"] != candidate.PackageArchiveSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.installed-set-digest"] != candidate.InstalledSetDigest ||
		labels["io.github.shell-echo.sandbox-runtime.provenance.source-digest"] != candidate.BaseImageDigest ||
		labels["org.opencontainers.image.base.digest"] != candidate.BaseImageDigest ||
		labels["org.opencontainers.image.base.name"] != desktopimage.SourceRepository ||
		labels["org.opencontainers.image.revision"] != candidate.SourceRevision ||
		labels["org.opencontainers.image.source"] != "https://github.com/shell-echo/sandbox-runtime" ||
		labels["org.opencontainers.image.version"] != desktopimage.ProfileID {
		return ErrInvalidRuntime
	}
	return nil
}

// Ready revalidates the runtime dependencies used by the Desktop lifecycle
// readiness adapter. It performs no allocation and returns no backend detail.
func (d *Driver) Ready(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil || d.network == nil || (d.provenance == nil && d.candidate == nil) {
		return ErrInvalidDriver
	}
	networkCtx, networkCancel := context.WithTimeout(ctx, connectTimeout)
	if err := d.network.Ready(networkCtx, d.options.NetworkPolicyReference); err != nil {
		result := safeContextError(ErrNetworkUnavailable, networkCtx, err)
		networkCancel()
		return result
	}
	networkCancel()
	if d.candidate == nil {
		provenanceCtx, provenanceCancel := context.WithTimeout(ctx, time.Duration(d.options.ProvenanceTimeoutSeconds)*time.Second)
		if err := d.provenance.Verify(provenanceCtx, d.publication); err != nil {
			result := safeContextError(ErrInvalidProvenance, provenanceCtx, err)
			provenanceCancel()
			return result
		}
		provenanceCancel()
	}
	inspectCtx, inspectCancel := context.WithTimeout(ctx, time.Duration(d.options.OperationTimeoutSeconds)*time.Second)
	image, err := d.engine.inspectImage(inspectCtx, d.options.Image)
	if err != nil {
		result := safeContextError(ErrInvalidRuntime, inspectCtx, err)
		inspectCancel()
		return result
	}
	inspectCancel()
	if d.candidate != nil {
		if validateCandidateImage(image, d.manifest, *d.candidate) != nil {
			return ErrInvalidRuntime
		}
	} else if validateImage(image, d.manifest, d.publication) != nil {
		return ErrInvalidRuntime
	}
	return nil
}

func (d *Driver) Allocate(ctx context.Context, allocation providerdesktop.Allocation) (providerdesktop.AllocationReceipt, error) {
	if err := contextError(ctx); err != nil {
		return providerdesktop.AllocationReceipt{}, err
	}
	if d == nil || d.engine == nil || d.network == nil {
		return providerdesktop.AllocationReceipt{}, ErrInvalidDriver
	}
	if err := allocation.Validate(); err != nil {
		return providerdesktop.AllocationReceipt{}, err
	}
	if allocation.Request.NetworkPolicyReference != d.options.NetworkPolicyReference {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopUnsupported
	}
	now := d.options.Clock.Now().UTC()
	if now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopExpired
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	directory, statePath, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)
	if err != nil {
		return providerdesktop.AllocationReceipt{}, err
	}
	specDigest, err := d.specDigest(allocation)
	if err != nil {
		return providerdesktop.AllocationReceipt{}, err
	}
	state, err := loadDesktopState(statePath, d.options.NetworkPolicyReference)
	if err == nil {
		if !state.matchesAllocation(allocation) || state.SpecDigest != specDigest {
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
		}
		return d.recoverAllocation(ctx, statePath, state)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return providerdesktop.AllocationReceipt{}, err
	}
	if err := d.checkCapacity(directory); err != nil {
		return providerdesktop.AllocationReceipt{}, err
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	attachment, err := d.network.Acquire(operationCtx, NetworkRequest{
		SandboxID: allocation.Request.SandboxID, DesktopSessionID: allocation.Request.DesktopSessionID,
		Namespace: d.options.Namespace, ControllerID: d.options.ControllerID,
		PolicyReference: allocation.Request.NetworkPolicyReference, Generation: allocation.Request.ExpectedGeneration,
		FencingToken: allocation.Request.FencingToken,
	})
	if err != nil {
		if contextErr := allocationContextError(operationCtx, err); contextErr != nil {
			return providerdesktop.AllocationReceipt{}, contextErr
		}
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopUnsupported
	}
	if err := attachment.validate(d.options.NetworkPolicyReference); err != nil {
		if releaseErr := d.network.Release(operationCtx, attachment); releaseErr != nil {
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
		}
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopUnsupported
	}
	state = newDesktopState(allocation, attachment, specDigest)
	if err := persistDesktopState(statePath, state, d.options.NetworkPolicyReference); err != nil {
		_ = d.network.Release(operationCtx, attachment)
		return providerdesktop.AllocationReceipt{}, err
	}
	request := d.createRequest(state)
	if _, createErr := d.engine.create(operationCtx, request); createErr != nil {
		if cerrdefs.IsInvalidArgument(createErr) || cerrdefs.IsPermissionDenied(createErr) || cerrdefs.IsNotFound(createErr) {
			if rollbackErr := d.rollbackState(operationCtx, statePath, state); rollbackErr != nil {
				return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
			}
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopUnsupported
		}
		if !cerrdefs.IsConflict(createErr) {
			return providerdesktop.AllocationReceipt{}, allocationUnknown(operationCtx, createErr)
		}
	}
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		if errors.Is(err, ErrOwnershipConflict) {
			if rollbackErr := d.rollbackState(operationCtx, statePath, state); rollbackErr != nil {
				return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
			}
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
		}
		return providerdesktop.AllocationReceipt{}, err
	}
	if !found {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	state.BackendContainerID = info.id
	if err := persistDesktopState(statePath, state, d.options.NetworkPolicyReference); err != nil {
		return providerdesktop.AllocationReceipt{}, errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	return d.startAndProbe(operationCtx, statePath, state, info)
}

func (d *Driver) recoverAllocation(ctx context.Context, statePath string, state desktopState) (providerdesktop.AllocationReceipt, error) {
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		if errors.Is(err, ErrOwnershipConflict) {
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
		}
		return providerdesktop.AllocationReceipt{}, err
	}
	if !found {
		if state.BackendContainerID == "" {
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
		}
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopNotFound
	}
	if state.BackendContainerID != "" && state.BackendContainerID != info.id {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
	}
	if state.BackendContainerID == "" {
		state.BackendContainerID = info.id
		if err := persistDesktopState(statePath, state, d.options.NetworkPolicyReference); err != nil {
			return providerdesktop.AllocationReceipt{}, errors.Join(providerdesktop.ErrAllocationUnknown, err)
		}
	}
	if err := d.network.Inspect(operationCtx, state.Network); err != nil {
		return providerdesktop.AllocationReceipt{}, allocationUnknown(operationCtx, err)
	}
	if state.Ready && (!info.running || info.status != "running") {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopNotFound
	}
	return d.startAndProbe(operationCtx, statePath, state, info)
}

func (d *Driver) startAndProbe(ctx context.Context, statePath string, state desktopState, info containerInfo) (providerdesktop.AllocationReceipt, error) {
	if !info.running {
		if info.status != "created" || info.paused || info.restarting || info.dead {
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopNotFound
		}
		if err := d.engine.start(ctx, info.id); err != nil {
			return providerdesktop.AllocationReceipt{}, allocationUnknown(ctx, err)
		}
	}
	for {
		confirmed, found, err := d.inspectOwned(ctx, state)
		if err != nil {
			return providerdesktop.AllocationReceipt{}, err
		}
		if !found || !confirmed.running || confirmed.status != "running" || confirmed.paused || confirmed.restarting || confirmed.dead {
			return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
		}
		if _, err := d.brokerDescriptor(ctx, state.BackendContainerID); err == nil {
			if !state.Ready {
				state.Ready = true
				if err := persistDesktopState(statePath, state, d.options.NetworkPolicyReference); err != nil {
					return providerdesktop.AllocationReceipt{}, errors.Join(providerdesktop.ErrAllocationUnknown, err)
				}
			}
			return state.Receipt, nil
		}
		if err := waitContext(ctx, desktopReadyPoll); err != nil {
			return providerdesktop.AllocationReceipt{}, errors.Join(providerdesktop.ErrAllocationUnknown, err)
		}
	}
}

func (d *Driver) Observe(ctx context.Context, allocation providerdesktop.Allocation) (providerdesktop.AllocationObservation, error) {
	if err := contextError(ctx); err != nil {
		return providerdesktop.AllocationObservation{}, err
	}
	if d == nil || d.engine == nil || d.network == nil {
		return providerdesktop.AllocationObservation{}, ErrInvalidDriver
	}
	if err := allocation.Validate(); err != nil {
		return providerdesktop.AllocationObservation{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.options.Clock.Now().UTC()
	observation := providerdesktop.AllocationObservation{Request: allocation.Request, ObservedAt: now}
	if now.IsZero() || now.Before(allocation.AllocatedAt) {
		return providerdesktop.AllocationObservation{}, ErrInvalidRuntime
	}
	if !allocation.Request.ExpiresAt.After(now) {
		observation.State = providerdesktop.AllocationExpired
		return observation, observation.Validate(allocation)
	}
	_, statePath, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)
	if err != nil {
		return providerdesktop.AllocationObservation{}, err
	}
	state, err := loadDesktopState(statePath, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		observation.State = providerdesktop.AllocationAbsent
		return observation, observation.Validate(allocation)
	}
	if err != nil {
		return providerdesktop.AllocationObservation{}, err
	}
	if !state.matchesAllocation(allocation) {
		return providerdesktop.AllocationObservation{}, providerdesktop.ErrDesktopConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		if contextErr := allocationContextError(operationCtx, err); contextErr != nil {
			return providerdesktop.AllocationObservation{}, contextErr
		}
		observation.State = providerdesktop.AllocationOutcomeUnknown
		return observation, observation.Validate(allocation)
	}
	if !found {
		observation.State = providerdesktop.AllocationAbsent
		return observation, observation.Validate(allocation)
	}
	if state.BackendContainerID != info.id {
		return providerdesktop.AllocationObservation{}, providerdesktop.ErrDesktopConflict
	}
	if err := d.network.Inspect(operationCtx, state.Network); err != nil {
		if contextErr := allocationContextError(operationCtx, err); contextErr != nil {
			return providerdesktop.AllocationObservation{}, contextErr
		}
		observation.State = providerdesktop.AllocationOutcomeUnknown
		return observation, observation.Validate(allocation)
	}
	if !info.running || info.status != "running" || info.paused || info.restarting || info.dead {
		observation.State = providerdesktop.AllocationOutcomeUnknown
		return observation, observation.Validate(allocation)
	}
	if _, err := d.brokerDescriptor(operationCtx, state.BackendContainerID); err != nil {
		observation.State = providerdesktop.AllocationOutcomeUnknown
		return observation, observation.Validate(allocation)
	}
	receipt := state.Receipt
	observation.Receipt = &receipt
	observation.State = providerdesktop.AllocationRunning
	return observation, observation.Validate(allocation)
}

func (d *Driver) Attach(ctx context.Context, receipt providerdesktop.AllocationReceipt) (providerdesktop.Attachment, error) {
	if err := contextError(ctx); err != nil {
		return providerdesktop.Attachment{}, err
	}
	if d == nil || d.engine == nil || d.network == nil {
		return providerdesktop.Attachment{}, ErrInvalidDriver
	}
	if err := receipt.Validate(); err != nil {
		return providerdesktop.Attachment{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.options.Clock.Now().UTC()
	if now.IsZero() {
		return providerdesktop.Attachment{}, ErrInvalidRuntime
	}
	if !receipt.ExpiresAt.After(now) {
		return providerdesktop.Attachment{}, providerdesktop.ErrDesktopExpired
	}
	_, statePath, err := d.stateLocation(receipt.SandboxID, receipt.DesktopSessionID)
	if err != nil {
		return providerdesktop.Attachment{}, err
	}
	state, err := loadDesktopState(statePath, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		return providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	if err != nil {
		return providerdesktop.Attachment{}, err
	}
	if !state.matchesReceipt(receipt) {
		return providerdesktop.Attachment{}, providerdesktop.ErrDesktopConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		return providerdesktop.Attachment{}, err
	}
	if !found {
		return providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	if state.BackendContainerID != info.id {
		return providerdesktop.Attachment{}, providerdesktop.ErrDesktopConflict
	}
	if err := d.network.Inspect(operationCtx, state.Network); err != nil {
		return providerdesktop.Attachment{}, allocationUnknown(operationCtx, err)
	}
	if !info.running || info.status != "running" || info.paused || info.restarting || info.dead {
		return providerdesktop.Attachment{}, providerdesktop.ErrAllocationUnknown
	}
	descriptor, err := d.brokerDescriptor(operationCtx, state.BackendContainerID)
	if err != nil {
		return providerdesktop.Attachment{}, allocationUnknown(operationCtx, err)
	}
	attachedAt := d.options.Clock.Now().UTC()
	attachment := providerdesktop.Attachment{
		DesktopSessionID: receipt.DesktopSessionID, ConnectionGeneration: receipt.ConnectionGeneration,
		MediaProfileID: descriptor.MediaProfileID, ControlProfileID: descriptor.ControlProfileID,
		DisplayReference: descriptor.DisplayReference, Width: descriptor.Width, Height: descriptor.Height,
		Depth: descriptor.Depth, AudioOutput: descriptor.AudioOutput,
		PrivateInputModes: append([]string(nil), descriptor.PrivateInputModes...), AttachedAt: attachedAt,
	}
	if err := attachment.Validate(receipt); err != nil {
		return providerdesktop.Attachment{}, ErrInvalidRuntime
	}
	return attachment, nil
}

func (d *Driver) Cleanup(ctx context.Context, receipt providerdesktop.AllocationReceipt) error {
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
	directory, statePath, err := d.stateLocation(receipt.SandboxID, receipt.DesktopSessionID)
	if err != nil {
		return err
	}
	state, err := loadDesktopState(statePath, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !state.matchesReceipt(receipt) {
		return providerdesktop.ErrDesktopConflict
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operationCtx, state)
	if err != nil {
		return err
	}
	if found {
		if state.BackendContainerID != "" && state.BackendContainerID != info.id {
			return providerdesktop.ErrDesktopConflict
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

func (d *Driver) inspectOwned(ctx context.Context, state desktopState) (containerInfo, bool, error) {
	info, err := d.engine.inspect(ctx, containerName(state.Request.SandboxID, state.Request.DesktopSessionID))
	if cerrdefs.IsNotFound(err) {
		return containerInfo{}, false, nil
	}
	if err != nil {
		return containerInfo{}, false, allocationUnknown(ctx, err)
	}
	labels := info.labels
	if labels[managedLabel] != "true" || labels[ownerLabel] != providerOwner ||
		labels[sandboxLabel] != state.Request.SandboxID || labels[desktopSessionLabel] != state.Request.DesktopSessionID ||
		labels[namespaceLabel] != d.options.Namespace || labels[controllerLabel] != d.options.ControllerID ||
		labels[runtimeProfileLabel] != DesktopRuntimeProfile || labels[specDigestLabel] != state.SpecDigest {
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
		strings.Join(info.environment, "\x00") != strings.Join(request.environment, "\x00") ||
		info.stopTimeout != request.stopTimeout || info.exposedPorts != 0 || info.privileged || info.autoRemove ||
		!info.readOnlyRoot || info.publishAllPorts || info.portBindings != 0 || info.binds != 0 || info.mounts != 0 ||
		!stringMapEqual(info.tmpfs, expectedTmpfs) || resolverErr != nil || len(info.dns) != 1 || info.dns[0] != resolver ||
		len(info.capAdd) != 0 || strings.Join(info.capDrop, "\x00") != "ALL" || len(info.securityOptions) != 1 ||
		info.securityOptions[0] != "no-new-privileges:true" ||
		info.memoryBytes != request.memoryBytes || info.memorySwap != request.memoryBytes || info.nanoCPUs != request.nanoCPUs ||
		info.pidsLimit != request.pidsLimit || info.deviceMappings != 0 || info.deviceCgroupRules != 0 || info.deviceRequests != 0 ||
		info.dnsOptions != 0 || info.dnsSearch != 0 || info.extraHosts != 0 || info.groupAdd != 0 || info.links != 0 || info.sysctls != 0 ||
		info.networkMode != request.networkName || info.pidMode != "" || info.ipcMode != "private" || info.cgroupnsMode != "private" || info.usernsMode == "host" || info.utsMode == "host" ||
		(info.restartPolicy != "" && info.restartPolicy != "no") || info.logType != "local" ||
		!stringMapEqual(info.logConfig, map[string]string{"max-size": "10m", "max-file": "3"}) ||
		len(info.networks) != 1 || !validRuntimeAddress {
		return ErrInvalidRuntime
	}
	return nil
}

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

func (d *Driver) createRequest(state desktopState) createRequest {
	environment := append([]string(nil), d.image.environment...)
	sessionProtocol := desktopbroker.SessionProtocolID
	if d.options.BridgeKeyID != "" {
		sessionProtocol = desktopbroker.SessionProtocolV2ID
		environment = append(environment,
			"SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY="+base64.RawStdEncoding.EncodeToString(d.options.BridgePublicKey),
			"SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID="+d.options.BridgeKeyID)
	}
	environment = append(environment, desktopbroker.SessionProtocolEnv+"="+sessionProtocol)
	identity, _ := restricted.DesktopIdentity(d.options.Namespace, d.options.ControllerID, state.Request.SandboxID, state.Request.DesktopSessionID, state.Request.ExpectedGeneration, state.Request.FencingToken)
	labels := identity.WorkloadLabels(state.Network.LeaseID)
	labels[specDigestLabel] = state.SpecDigest
	return createRequest{
		name:  identity.WorkloadName(),
		image: d.options.Image, user: DesktopUser, workingDirectory: "/workspace",
		memoryBytes: d.options.MemoryBytes, nanoCPUs: d.options.NanoCPUs, pidsLimit: d.options.PidsLimit,
		inputsBytes: d.options.InputsBytes, tmpfsBytes: d.options.TmpfsBytes,
		workspaceBytes: d.options.WorkspaceBytes, outputsBytes: d.options.OutputsBytes,
		stopTimeout: d.options.StopTimeoutSeconds, networkName: state.Network.DockerName,
		dnsResolver: state.Network.GatewayAddress,
		labels:      labels,
		environment: environment,
	}
}

func (d *Driver) specDigest(allocation providerdesktop.Allocation) (string, error) {
	runtimeAuthorityDigest := d.publication.Digest
	if d.candidate != nil {
		runtimeAuthorityDigest = d.candidate.ManifestDigest
	}
	value := struct {
		Allocation       providerdesktop.Allocation
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
		SeccompPolicy    string
		NetworkPolicy    string
		BridgeKeyID      string
		BridgePublicKey  string
		Namespace        string
		ControllerID     string
		RuntimeProfileID string
		RuntimeAuthority string
	}{
		Allocation: allocation, Image: d.options.Image, User: DesktopUser,
		MemoryBytes: d.options.MemoryBytes, NanoCPUs: d.options.NanoCPUs, PidsLimit: d.options.PidsLimit,
		InputsBytes: d.options.InputsBytes, TmpfsBytes: d.options.TmpfsBytes,
		WorkspaceBytes: d.options.WorkspaceBytes, OutputsBytes: d.options.OutputsBytes,
		StopTimeout:   d.options.StopTimeoutSeconds,
		SeccompPolicy: d.manifest.Security.Seccomp,
		NetworkPolicy: allocation.Request.NetworkPolicyReference, Namespace: d.options.Namespace,
		ControllerID: d.options.ControllerID, RuntimeProfileID: DesktopRuntimeProfile,
		RuntimeAuthority: runtimeAuthorityDigest,
		BridgeKeyID:      d.options.BridgeKeyID, BridgePublicKey: base64.RawStdEncoding.EncodeToString(d.options.BridgePublicKey),
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (d *Driver) stateLocation(sandboxID, desktopSessionID string) (string, string, error) {
	if !privateValuePattern.MatchString(sandboxID) || !privateValuePattern.MatchString(desktopSessionID) {
		return "", "", providerdesktop.ErrInvalidRequest
	}
	directory := filepath.Join(d.dataRoot, sandboxToken(sandboxID), "desktop")
	return directory, filepath.Join(directory, allocationToken(sandboxID, desktopSessionID)+".json"), nil
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
		if _, err := loadDesktopState(filepath.Join(directory, entry.Name()), d.options.NetworkPolicyReference); err != nil {
			return err
		}
		sandboxCount++
	}
	controllerCount, err := countDesktopStates(d.dataRoot, d.options.NetworkPolicyReference)
	if err != nil {
		return err
	}
	if sandboxCount >= d.options.MaxSessionsPerSandbox || controllerCount >= d.options.MaxSessionsPerController {
		return providerdesktop.ErrDesktopUnsupported
	}
	return nil
}

func (d *Driver) rollbackState(ctx context.Context, statePath string, state desktopState) error {
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

func (d *Driver) brokerDescriptor(ctx context.Context, containerID string) (desktopbroker.Descriptor, error) {
	output, err := d.engine.describe(ctx, containerID)
	if err != nil || len(output) == 0 || len(output) > maxBrokerExecBytes {
		return desktopbroker.Descriptor{}, ErrInvalidRuntime
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var response desktopbroker.Response
	if err := decoder.Decode(&response); err != nil {
		return desktopbroker.Descriptor{}, ErrInvalidRuntime
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return desktopbroker.Descriptor{}, ErrInvalidRuntime
	}
	if err := response.Validate(); err != nil || response.Status != "ok" || response.Descriptor == nil {
		return desktopbroker.Descriptor{}, ErrInvalidRuntime
	}
	return *response.Descriptor, nil
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

var _ providerdesktop.Runtime = (*Driver)(nil)
