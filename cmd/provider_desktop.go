package cmd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	browserdriver "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	browsernetworkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	browsernetworkgateway "github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktopdocker "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/docker"
	desktoplifecycle "github.com/shell-echo/sandbox-runtime/provider/desktop/lifecycle"
	desktopprovenance "github.com/shell-echo/sandbox-runtime/provider/desktop/provenance/ghcli"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
	desktopusage "github.com/shell-echo/sandbox-runtime/provider/desktop/usage"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	"github.com/shell-echo/sandbox-runtime/providerapi"
	providerprocess "github.com/shell-echo/sandbox-runtime/providerapi/process"
)

func newProductionDesktopProvider(ctx context.Context, cfg *config.ProviderProcessConfig, state *providerpostgres.Store, pool *pgxpool.Pool) (*productionProviderComposition, error) { //nolint:cyclop
	stack := &providerCloseStack{}
	fail := func(err error) (*productionProviderComposition, error) { return nil, errors.Join(err, stack.close()) }
	desktopConfig := cfg.Desktop
	policies := make([]browsernetworkgateway.Policy, len(desktopConfig.RestrictedNetwork.Policies))
	for index, policy := range desktopConfig.RestrictedNetwork.Policies {
		policies[index] = browsernetworkgateway.Policy{Reference: policy.Reference, AllowedHosts: append([]string(nil), policy.AllowedHosts...)}
	}
	network, err := browsernetworkdocker.New(ctx, browsernetworkdocker.Options{
		Host: desktopConfig.RestrictedNetwork.Host, GatewayImage: desktopConfig.RestrictedNetwork.GatewayImage,
		UplinkNetwork: desktopConfig.RestrictedNetwork.UplinkNetwork, Namespace: desktopConfig.RestrictedNetwork.Namespace,
		ControllerID: desktopConfig.RestrictedNetwork.ControllerID, Policies: policies,
		MemoryBytes: desktopConfig.RestrictedNetwork.MemoryBytes, NanoCPUs: desktopConfig.RestrictedNetwork.NanoCPUs,
		PidsLimit: desktopConfig.RestrictedNetwork.PidsLimit, OperationTimeoutSeconds: desktopConfig.RestrictedNetwork.OperationTimeoutSeconds,
		StopTimeoutSeconds: desktopConfig.RestrictedNetwork.StopTimeoutSeconds,
	})
	if err != nil {
		return fail(fmt.Errorf("construct production Desktop restricted network: %w", err))
	}
	stack.add(network.Close)
	verifier, err := desktopprovenance.New(desktopprovenance.Options{ExecutablePath: desktopConfig.Provenance.ExecutablePath, ExecutableDigest: desktopConfig.Provenance.ExecutableDigest})
	if err != nil {
		return fail(fmt.Errorf("construct production Desktop provenance verifier: %w", err))
	}
	dockerConfig := desktopConfig.Docker
	desktopRuntime, err := desktopdocker.New(ctx, desktopdocker.Options{
		Host: dockerConfig.Host, Image: dockerConfig.Image, PullPolicy: desktopdocker.PullPolicy(dockerConfig.PullPolicy),
		MemoryBytes: dockerConfig.MemoryBytes, NanoCPUs: dockerConfig.NanoCPUs, PidsLimit: dockerConfig.PidsLimit,
		InputsBytes: dockerConfig.InputsBytes, TmpfsBytes: dockerConfig.TmpfsBytes, WorkspaceBytes: dockerConfig.WorkspaceBytes, OutputsBytes: dockerConfig.OutputsBytes,
		OperationTimeoutSeconds: dockerConfig.OperationTimeoutSeconds, ProvenanceTimeoutSeconds: dockerConfig.ProvenanceTimeoutSeconds,
		PullTimeoutSeconds: dockerConfig.PullTimeoutSeconds, StopTimeoutSeconds: dockerConfig.StopTimeoutSeconds,
		DataRoot: dockerConfig.DataRoot, ManifestPath: dockerConfig.ManifestPath, Namespace: dockerConfig.Namespace, ControllerID: dockerConfig.ControllerID,
		NetworkPolicyReference: dockerConfig.NetworkPolicyReference, MaxSessionsPerSandbox: dockerConfig.MaxSessionsPerSandbox,
		MaxSessionsPerController: dockerConfig.MaxSessionsPerController, Clock: systemAdmissionClock{},
	}, verifier, desktopRestrictedNetwork{network: network})
	if err != nil {
		return fail(fmt.Errorf("construct production Desktop runtime: %w", err))
	}
	stack.add(desktopRuntime.Close)
	lifecycleDriver, err := desktoplifecycle.New(desktopRuntime, dockerConfig.NetworkPolicyReference)
	if err != nil {
		return fail(err)
	}
	lifecycleRepo, err := providerpostgres.NewLifecycleRepository(state)
	if err != nil {
		return fail(err)
	}
	lifecycleApp, err := lifecycleapplication.New(lifecycleRepo, lifecycleDriver, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	stack.add(lifecycleApp.Close)
	if err := lifecycleApp.Recover(ctx); err != nil {
		return fail(fmt.Errorf("recover production Desktop lifecycle: %w", err))
	}
	desktopRepo, err := providerpostgres.NewDesktopRepository(state)
	if err != nil {
		return fail(err)
	}
	references, err := providerpostgres.NewDesktopReferenceStore(state)
	if err != nil {
		return fail(err)
	}
	registrar, err := desktopreference.NewRegistrar(references, systemAdmissionClock{}, nil)
	if err != nil {
		return fail(err)
	}
	vertical, err := desktopapplication.NewVerticalWithHandoffLifecycle(desktopRepo, desktopRuntime, lifecycleApp,
		desktopapplication.DesktopProfile{RuntimeProfileID: lifecycle.DesktopRuntimeProfile, CapabilityProfileID: providerdesktop.CapabilityProfileID}, registrar, registrar, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	if _, err := vertical.Recover(ctx); err != nil {
		return fail(fmt.Errorf("recover production Desktop sessions: %w", err))
	}
	desktopApp := &productionDesktopApplication{Vertical: vertical, authority: desktopRepo, runtime: desktopRuntime, references: references, cleanupTimeout: time.Duration(desktopConfig.ShutdownCleanupSeconds) * time.Second}
	stack.add(desktopApp.Close)
	usageRepo, err := providerpostgres.NewUsageRepository(state, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	usageReader, err := desktopusage.NewReader(desktopRepo, usageRepo, time.Duration(desktopConfig.UsageRetentionSeconds)*time.Second)
	if err != nil {
		return fail(err)
	}
	protected, err := newProductionProviderAdmission(cfg, state)
	if err != nil {
		return fail(err)
	}
	protected.Application = lifecycleApp
	protected.DesktopApplication = desktopApp
	protected.UsageEvidenceReader = usageReader
	lifecycleReader, err := provideroperation.NewLifecycleReader(lifecycleApp)
	if err != nil {
		return fail(err)
	}
	desktopReader, err := provideroperation.NewDesktopSessionReader(desktopApp)
	if err != nil {
		return fail(err)
	}
	operationReader, err := provideroperation.NewAggregator(lifecycleReader, desktopReader)
	if err != nil {
		return fail(err)
	}
	protected.OperationReader = operationReader
	source, err := newDesktopCapabilitySource(cfg)
	if err != nil {
		return fail(err)
	}
	providerServer, err := newProductionProviderTransport(ctx, cfg, protected, source)
	if err != nil {
		return fail(err)
	}
	reconciler, err := providerprocess.NewReconciler(time.Duration(cfg.Reconciliation.IntervalSeconds)*time.Second, time.Duration(cfg.Reconciliation.TimeoutSeconds)*time.Second,
		func(runCtx context.Context) error { return lifecycleApp.Recover(runCtx) },
		func(runCtx context.Context) error { _, err := vertical.Recover(runCtx); return err },
	)
	if err != nil {
		return fail(err)
	}
	probe, err := providerprocess.NewServer(cfg.Probe, providerReadinessChecker{state: state, pool: pool, reconciler: reconciler})
	if err != nil {
		return fail(err)
	}
	return &productionProviderComposition{provider: providerServer, probe: probe, reconciler: reconciler, close: stack.close}, nil
}

type desktopRestrictedNetwork struct {
	network *browsernetworkdocker.Provisioner
}

func (n desktopRestrictedNetwork) Ready(ctx context.Context, policy string) error {
	return n.network.Ready(ctx, policy)
}
func (n desktopRestrictedNetwork) Acquire(ctx context.Context, request desktopdocker.NetworkRequest) (desktopdocker.NetworkAttachment, error) {
	attachment, err := n.network.Acquire(ctx, browserdriver.NetworkRequest{SandboxID: request.SandboxID, BrowserSessionID: request.DesktopSessionID, Namespace: request.Namespace, ControllerID: request.ControllerID, PolicyReference: request.PolicyReference})
	return desktopNetworkAttachment(attachment), err
}
func (n desktopRestrictedNetwork) Inspect(ctx context.Context, attachment desktopdocker.NetworkAttachment) error {
	return n.network.Inspect(ctx, browserNetworkAttachment(attachment))
}
func (n desktopRestrictedNetwork) Release(ctx context.Context, attachment desktopdocker.NetworkAttachment) error {
	return n.network.Release(ctx, browserNetworkAttachment(attachment))
}
func desktopNetworkAttachment(value browserdriver.NetworkAttachment) desktopdocker.NetworkAttachment {
	return desktopdocker.NetworkAttachment{DockerName: value.DockerName, GatewayContainer: value.GatewayContainer, GatewayAddress: value.GatewayAddress, LeaseID: value.LeaseID, PolicyReference: value.PolicyReference, PolicyDigest: value.PolicyDigest, EgressGateway: value.EgressGateway, Public: value.Public}
}
func browserNetworkAttachment(value desktopdocker.NetworkAttachment) browserdriver.NetworkAttachment {
	return browserdriver.NetworkAttachment{DockerName: value.DockerName, GatewayContainer: value.GatewayContainer, GatewayAddress: value.GatewayAddress, LeaseID: value.LeaseID, PolicyReference: value.PolicyReference, PolicyDigest: value.PolicyDigest, EgressGateway: value.EgressGateway, Public: value.Public}
}

type productionDesktopApplication struct {
	*desktopapplication.Vertical
	authority interface {
		ListOpen(context.Context) ([]providerdesktop.Record, error)
	}
	runtime        providerdesktop.Runtime
	references     desktopreference.Store
	cleanupTimeout time.Duration
	closeOnce      sync.Once
	closeErr       error
}

func (a *productionDesktopApplication) Close() error {
	a.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), a.cleanupTimeout)
		defer cancel()
		records, err := a.authority.ListOpen(ctx)
		if err != nil {
			a.closeErr = err
			return
		}
		now := time.Now().UTC()
		for _, record := range records {
			if record.Allocation == nil {
				continue
			}
			if record.Handoff != nil {
				if revokeErr := a.references.Revoke(ctx, record.Handoff.InternalEndpointReference, now); revokeErr != nil && !errors.Is(revokeErr, desktopreference.ErrNotFound) {
					a.closeErr = errors.Join(a.closeErr, revokeErr)
				}
			}
			if cleanupErr := a.runtime.Cleanup(ctx, record.Allocation.Receipt); cleanupErr != nil && !errors.Is(cleanupErr, providerdesktop.ErrDesktopNotFound) {
				a.closeErr = errors.Join(a.closeErr, cleanupErr)
			}
		}
	})
	return a.closeErr
}

func newDesktopCapabilitySource(cfg *config.ProviderProcessConfig) (*provider.StaticCapabilitySource, error) {
	profiles := make([]provider.SnapshotRestoreProfile, len(cfg.Capability.SnapshotRestoreProfiles))
	for index, profile := range cfg.Capability.SnapshotRestoreProfiles {
		profiles[index] = provider.SnapshotRestoreProfile{ProfileID: profile.ProfileID, Level: provider.SnapshotLevel(profile.Level), SuiteID: provider.CompatibilitySuiteID(profile.SuiteID), SuiteVersion: profile.SuiteVersion, SuiteDigest: provider.SHA256Digest(profile.SuiteDigest)}
	}
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(cfg.Capability.ProviderRevisionID, provider.Limits{
		MaxCPUMillis: cfg.Capability.Limits.MaxCPUMillis, MaxMemoryBytes: cfg.Capability.Limits.MaxMemoryBytes,
		MaxEphemeralStorageBytes: cfg.Capability.Limits.MaxEphemeralStorageBytes, MaxWorkspaceBytes: cloneOptionalInt64(cfg.Capability.Limits.MaxWorkspaceBytes),
		MaxGPUCount: cloneOptionalInt64(cfg.Capability.Limits.MaxGPUCount), MaxLeaseSeconds: cfg.Capability.Limits.MaxLeaseSeconds, MaxExecSeconds: cfg.Capability.Limits.MaxExecSeconds,
	}, []provider.Capability{{ID: "sandbox.desktop", Versions: []string{"1.0.0"}, Profiles: []string{providerdesktop.CapabilityProfileID}}},
		[]provider.RuntimeProfile{{ID: lifecycle.DesktopRuntimeProfile, IsolationClass: "container", RuntimeClassName: desktopimage.RuntimeClassName, Architecture: []string{cfg.Desktop.Architecture}, CapabilityProfileIDs: []string{providerdesktop.CapabilityProfileID}}}, profiles)
	if err != nil {
		return nil, fmt.Errorf("construct production Desktop capability snapshot: %w", err)
	}
	return provider.NewStaticCapabilitySource(snapshot)
}

var _ desktopdocker.RestrictedNetwork = desktopRestrictedNetwork{}
var _ providerapi.DesktopApplication = (*productionDesktopApplication)(nil)
var _ usage.EvidenceReader = (*desktopusage.Reader)(nil)
