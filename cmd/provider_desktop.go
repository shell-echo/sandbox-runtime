package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktopdocker "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/docker"
	desktopremote "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/remote"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/gateway"
	desktoplifecycle "github.com/shell-echo/sandbox-runtime/provider/desktop/lifecycle"
	desktopnetworkdocker "github.com/shell-echo/sandbox-runtime/provider/desktop/network/docker"
	desktopprovenance "github.com/shell-echo/sandbox-runtime/provider/desktop/provenance/ghcli"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
	desktopusage "github.com/shell-echo/sandbox-runtime/provider/desktop/usage"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	"github.com/shell-echo/sandbox-runtime/providerapi"
	providerprocess "github.com/shell-echo/sandbox-runtime/providerapi/process"
	"github.com/shell-echo/sandbox-runtime/server"
)

func newProductionDesktopProvider(ctx context.Context, cfg *config.ProviderProcessConfig, state *providerpostgres.Store, pool *pgxpool.Pool) (*productionProviderComposition, error) { //nolint:cyclop
	stack := &providerCloseStack{}
	fail := func(err error) (*productionProviderComposition, error) { return nil, errors.Join(err, stack.close()) }
	desktopConfig := cfg.Desktop
	policies := make([]restricted.Policy, len(desktopConfig.RestrictedNetwork.Policies))
	for index, policy := range desktopConfig.RestrictedNetwork.Policies {
		policies[index] = restricted.Policy{Reference: policy.Reference, AllowedHosts: append([]string(nil), policy.AllowedHosts...)}
	}
	network, err := desktopnetworkdocker.New(ctx, desktopnetworkdocker.Options{
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
	dockerConfig := desktopConfig.Docker
	var bridgePrivateKey ed25519.PrivateKey
	var bridgePublicKey ed25519.PublicKey
	if desktopConfig.ExecutorURL != "" {
		bridgePrivateKey, err = loadDesktopBridgePrivateKey(desktopConfig.ExecutorBridgePrivateKeyFile)
		if err != nil {
			return fail(fmt.Errorf("load production Desktop bridge signing key: %w", err))
		}
		bridgePublicKey = append(ed25519.PublicKey(nil), bridgePrivateKey.Public().(ed25519.PublicKey)...)
	}
	runtimeOptions := desktopdocker.Options{
		Host: dockerConfig.Host, Image: dockerConfig.Image, PullPolicy: desktopdocker.PullPolicy(dockerConfig.PullPolicy),
		MemoryBytes: dockerConfig.MemoryBytes, NanoCPUs: dockerConfig.NanoCPUs, PidsLimit: dockerConfig.PidsLimit,
		InputsBytes: dockerConfig.InputsBytes, TmpfsBytes: dockerConfig.TmpfsBytes, WorkspaceBytes: dockerConfig.WorkspaceBytes, OutputsBytes: dockerConfig.OutputsBytes,
		OperationTimeoutSeconds: dockerConfig.OperationTimeoutSeconds, ProvenanceTimeoutSeconds: dockerConfig.ProvenanceTimeoutSeconds,
		PullTimeoutSeconds: dockerConfig.PullTimeoutSeconds, StopTimeoutSeconds: dockerConfig.StopTimeoutSeconds,
		DataRoot: dockerConfig.DataRoot, ManifestPath: dockerConfig.ManifestPath, Namespace: dockerConfig.Namespace, ControllerID: dockerConfig.ControllerID,
		NetworkPolicyReference: dockerConfig.NetworkPolicyReference, MaxSessionsPerSandbox: dockerConfig.MaxSessionsPerSandbox,
		MaxSessionsPerController: dockerConfig.MaxSessionsPerController, Clock: systemAdmissionClock{}, BridgeKeyID: desktopConfig.ExecutorBridgeKeyID, BridgePublicKey: bridgePublicKey,
	}
	var desktopRuntime *desktopdocker.Driver
	if cfg.DeploymentLevel == config.ProviderLocalCandidateLevel {
		candidate, candidateErr := desktopcandidate.Load(desktopConfig.LocalCandidateManifestFile)
		if candidateErr != nil || candidate.ImageDigest != dockerConfig.Image || candidate.Platform != "linux/"+desktopConfig.Architecture && !(desktopConfig.Architecture == "arm64" && candidate.Platform == "linux/arm64/v8") {
			return fail(errors.New("load Phase 6 local Desktop candidate authority"))
		}
		desktopRuntime, err = desktopdocker.NewLocalCandidate(ctx, runtimeOptions, candidate, network)
	} else {
		verifier, verifierErr := desktopprovenance.New(desktopprovenance.Options{ExecutablePath: desktopConfig.Provenance.ExecutablePath, ExecutableDigest: desktopConfig.Provenance.ExecutableDigest})
		if verifierErr != nil {
			return fail(fmt.Errorf("construct production Desktop provenance verifier: %w", verifierErr))
		}
		desktopRuntime, err = desktopdocker.New(ctx, runtimeOptions, verifier, network)
	}
	if err != nil {
		return fail(fmt.Errorf("construct Desktop runtime: %w", err))
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
	resolver, err := desktopreference.NewResolver(references, desktopRepo, desktopRuntime, systemAdmissionClock{})
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
	mediaRuntime := providerdesktop.MediaRuntime(desktopRuntime)
	if desktopConfig.ExecutorURL != "" {
		executorClient, clientErr := desktopremote.NewHTTPClient(desktopConfig.ExecutorURL, desktopConfig.ExecutorCABundleFile, desktopConfig.ExecutorCertificateFile, desktopConfig.ExecutorPrivateKeyFile)
		if clientErr != nil {
			return fail(fmt.Errorf("construct production Desktop executor client: %w", clientErr))
		}
		executorRuntime, runtimeErr := desktopremote.New(desktopremote.Options{URL: desktopConfig.ExecutorURL, HTTPClient: executorClient, OperationTimeout: time.Duration(dockerConfig.OperationTimeoutSeconds) * time.Second, BridgeKeyID: desktopConfig.ExecutorBridgeKeyID, ExecutorIdentity: desktopConfig.ExecutorIdentity, BridgePrivateKey: bridgePrivateKey})
		if runtimeErr != nil {
			return fail(fmt.Errorf("construct production Desktop executor runtime: %w", runtimeErr))
		}
		mediaRuntime = executorRuntime
	}
	privateServer, err := newProductionProviderPrivateDesktopServer(ctx, cfg, resolver, registrar, mediaRuntime)
	if err != nil {
		return fail(err)
	}
	var brokerMux server.Server
	if desktopConfig.ExecutorURL != "" {
		muxAuthority := &productionDesktopBrokerAuthority{resolver: resolver, executorIdentity: desktopConfig.ExecutorIdentity, bridgeKeyID: desktopConfig.ExecutorBridgeKeyID, bridgePrivateKey: bridgePrivateKey}
		brokerMux, err = desktopdocker.NewBrokerMux(desktopRuntime, desktopdocker.BrokerMuxOptions{SocketPath: desktopConfig.BrokerMuxSocketPath, MaxSessions: dockerConfig.MaxSessionsPerController, OperationTimeout: 10 * time.Second, Authority: muxAuthority})
		if err != nil {
			return fail(fmt.Errorf("construct Provider Desktop broker mux: %w", err))
		}
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
	return &productionProviderComposition{provider: providerServer, private: privateServer, brokerMux: brokerMux, probe: probe, reconciler: reconciler, close: stack.close}, nil
}

type productionDesktopBrokerAuthority struct {
	resolver interface {
		Resolve(context.Context, string) (desktopreference.Endpoint, error)
	}
	executorIdentity string
	bridgeKeyID      string
	bridgePrivateKey ed25519.PrivateKey
	mu               sync.Mutex
	lastVerifiedOpen *desktopbroker.SessionOpen
}

func (a *productionDesktopBrokerAuthority) Authorize(ctx context.Context, open desktopbroker.SessionOpen) error {
	if a == nil || a.resolver == nil || ctx == nil || open.Bridge == nil || open.Bridge.Statement.ExecutorIdentity != a.executorIdentity || open.Bridge.Statement.KeyID != a.bridgeKeyID {
		return errors.New("Desktop broker authority is unavailable")
	}
	endpoint, err := a.resolver.Resolve(ctx, open.HandoffReference)
	if err != nil || endpoint.Binding == nil {
		return errors.New("Desktop broker authority is unavailable")
	}
	binding := endpoint.Binding
	authorityExpiry, authorityErr := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	handoffExpiry, handoffErr := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	if authorityErr != nil || handoffErr != nil ||
		endpoint.Reference != open.HandoffReference || endpoint.ProviderRevisionID != open.ProviderRevisionID || endpoint.SandboxID != open.SandboxID ||
		endpoint.DesktopSessionID != open.DesktopSessionID || endpoint.AllocationReference != open.AllocationReference || endpoint.CapabilityProfileID != open.CapabilityProfileID ||
		endpoint.ConnectionGeneration != open.ConnectionGeneration || endpoint.TenantBindingDigest != open.TenantBindingDigest || !endpoint.ExpiresAt.Equal(handoffExpiry) ||
		binding.TenantBindingDigest != open.TenantBindingDigest || binding.ProviderRevisionID != open.ProviderRevisionID || binding.SandboxID != open.SandboxID ||
		binding.DesktopSessionID != open.DesktopSessionID || binding.HandoffReference != open.HandoffReference || binding.ConnectionGeneration != open.ConnectionGeneration ||
		binding.ConnectionEpoch != open.ConnectionEpoch || binding.ControllerFence != open.Fence || !binding.AuthorityExpiresAt.Equal(authorityExpiry) ||
		!binding.HandoffExpiresAt.Equal(handoffExpiry) || binding.MediaPolicy != open.MediaPolicy {
		return errors.New("Desktop broker authority drift")
	}
	copy := open
	bridge := *open.Bridge
	copy.Bridge = &bridge
	a.mu.Lock()
	a.lastVerifiedOpen = &copy
	a.mu.Unlock()
	return nil
}

func (a *productionDesktopBrokerAuthority) Probe(ctx context.Context) (desktopbroker.SessionOpen, error) {
	if a == nil || ctx == nil || len(a.bridgePrivateKey) != ed25519.PrivateKeySize {
		return desktopbroker.SessionOpen{}, errors.New("Desktop broker probe authority is unavailable")
	}
	a.mu.Lock()
	if a.lastVerifiedOpen == nil {
		a.mu.Unlock()
		return desktopbroker.SessionOpen{}, errors.New("Desktop broker has no verified candidate allocation")
	}
	open := *a.lastVerifiedOpen
	a.mu.Unlock()
	if err := a.Authorize(ctx, open); err != nil {
		return desktopbroker.SessionOpen{}, err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return desktopbroker.SessionOpen{}, errors.New("generate Desktop broker probe authority")
	}
	nonce := "probe-" + hex.EncodeToString(nonceBytes)
	open.RequestID = "broker-" + hex.EncodeToString(nonceBytes)
	statement := open.Bridge.Statement
	statement.NotBefore = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	statement.Nonce = nonce
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, a.bridgePrivateKey)
	if err != nil {
		return desktopbroker.SessionOpen{}, errors.New("sign Desktop broker probe authority")
	}
	open.Bridge = &bridge
	return open, nil
}

func loadDesktopBridgePrivateKey(path string) (ed25519.PrivateKey, error) {
	document, err := secretfile.Read(path, ed25519.PrivateKeySize)
	if err != nil || len(document) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Desktop bridge signing key")
	}
	key := ed25519.PrivateKey(append([]byte(nil), document...))
	clear(document)
	return key, nil
}

type productionDesktopMediaSource struct{ runtime providerdesktop.MediaRuntime }

func (s productionDesktopMediaSource) OpenBound(ctx context.Context, open desktophandoff.OpenRequest, endpoint desktopreference.Endpoint, attachment providerdesktop.Attachment) (desktopgateway.Session, error) {
	if s.runtime == nil || open.Validate(time.Now().UTC()) != nil {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	authorityExpiry, authorityErr := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	handoffExpiry, handoffErr := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	if authorityErr != nil || handoffErr != nil ||
		endpoint.Reference != open.HandoffReference || endpoint.ProviderRevisionID != open.ProviderRevisionID || endpoint.SandboxID != open.SandboxID ||
		endpoint.DesktopSessionID != open.DesktopSessionID || endpoint.CapabilityProfileID != open.CapabilityProfileID ||
		endpoint.ConnectionGeneration != open.ConnectionGeneration || !endpoint.ExpiresAt.Equal(handoffExpiry) ||
		endpoint.TenantBindingDigest != open.TenantBindingDigest || endpoint.AllocationReference == "" ||
		attachment.DesktopSessionID != open.DesktopSessionID || attachment.ConnectionGeneration != open.ConnectionGeneration ||
		attachment.MediaProfileID != providerdesktop.MediaProfileID || attachment.ControlProfileID != providerdesktop.ControlProfileID {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	return s.runtime.OpenMedia(ctx, providerdesktop.MediaAuthority{
		TenantBindingDigest: open.TenantBindingDigest, ProviderRevisionID: open.ProviderRevisionID, SandboxID: open.SandboxID,
		DesktopSessionID: open.DesktopSessionID, HandoffReference: open.HandoffReference, HandoffReferenceDigest: open.HandoffDigest,
		AllocationReference: endpoint.AllocationReference, ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch,
		ControllerFence: open.ControllerFence, MediaProfileID: open.MediaProfileID, ControlProfileID: open.ControlProfileID,
		AuthorityDigest: open.AuthorityDigest, RequestDigest: open.RequestDigest, AuthorityExpiresAt: authorityExpiry, HandoffExpiresAt: handoffExpiry}, attachment, open.MediaPolicy)
}

func newProductionProviderPrivateDesktopServer(ctx context.Context, cfg *config.ProviderProcessConfig, resolver desktopgateway.Resolver, registrar desktopgateway.BindingRegistrar, runtime providerdesktop.MediaRuntime) (server.Server, error) {
	if cfg == nil || !cfg.Transport.Private.Enabled {
		return nil, nil
	}
	allowed := false
	for _, route := range cfg.Transport.Private.RoutePolicy {
		if route == config.ProviderPrivateRouteDesktop {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("Provider private transport route policy does not authorize Desktop")
	}
	handler, err := desktopgateway.New(desktopgateway.Options{Resolver: resolver, BoundMedia: productionDesktopMediaSource{runtime: runtime}, BindingRegistrar: registrar, PeerAuthorizer: providerPrivatePeerAuthorizer{}, MaxMessageBytes: cfg.Transport.Private.MaxBodyBytes, OperationTimeout: time.Duration(cfg.Transport.Private.ReadTimeoutMillis) * time.Millisecond})
	if err != nil {
		return nil, fmt.Errorf("construct Provider private Desktop handler: %w", err)
	}
	private := cfg.Transport.Private
	return providerapi.NewPrivateServer(ctx, providerapi.PrivateTransportOptions{Address: private.Address, ServerCertificateFile: private.ServerCertificateFile, ServerPrivateKeyFile: private.ServerPrivateKeyFile, ClientCABundleFile: private.ClientCABundleFile, AllowedClientURIIdentities: append([]string(nil), private.AllowedClientURIIdentities...), Handler: handler, ReadHeaderTimeout: time.Duration(private.ReadHeaderTimeoutMillis) * time.Millisecond, ReadTimeout: time.Duration(private.ReadTimeoutMillis) * time.Millisecond, WriteTimeout: time.Duration(private.WriteTimeoutMillis) * time.Millisecond, IdleTimeout: time.Duration(private.IdleTimeoutMillis) * time.Millisecond, MaxHeaderBytes: private.MaxHeaderBytes, MaxBodyBytes: private.MaxBodyBytes})
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

var _ providerapi.DesktopApplication = (*productionDesktopApplication)(nil)
var _ usage.EvidenceReader = (*desktopusage.Reader)(nil)
