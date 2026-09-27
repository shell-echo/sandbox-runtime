package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	browserremote "github.com/shell-echo/sandbox-runtime/provider/browser/driver/remote"
	browsergateway "github.com/shell-echo/sandbox-runtime/provider/browser/gateway"
	browserlifecycle "github.com/shell-echo/sandbox-runtime/provider/browser/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/browser/mux"
	browsernetworkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	browsernetworkgateway "github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
	browserprovenance "github.com/shell-echo/sandbox-runtime/provider/browser/provenance/ghcli"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	browserusage "github.com/shell-echo/sandbox-runtime/provider/browser/usage"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	"github.com/shell-echo/sandbox-runtime/providerapi"
	providerprocess "github.com/shell-echo/sandbox-runtime/providerapi/process"
	"github.com/shell-echo/sandbox-runtime/server"
)

// This graph is deliberately not selected by provider serve until the
// independent action-ingress/Redis/witness command and its process gate exist.
// It contains no file-backed Browser authority or static executor TLS path.
func newProductionBrowserProvider(ctx context.Context, cfg *config.ProviderProcessConfig, state *providerpostgres.Store,
	pool *pgxpool.Pool, registry *secretref.Registry) (*productionProviderComposition, error) { //nolint:cyclop
	if cfg == nil || cfg.Profile != config.ProviderProcessBrowserProfile || cfg.SchemaVersion != config.ProviderProductionSchemaV3 ||
		state == nil || pool == nil || registry == nil {
		return nil, errors.New("Browser Provider production dependencies are unavailable")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate Browser Provider production authority: %w", err)
	}
	stack := &providerCloseStack{}
	fail := func(err error) (*productionProviderComposition, error) { return nil, errors.Join(err, stack.close()) }
	profile, err := loadProviderSecurityProfile(cfg)
	if err != nil {
		return fail(err)
	}
	roleDocument, err := phase6security.VerifyPeerCRLRoleFile(cfg.Transport.PeerCRLRoleFile, profile,
		cfg.Transport.PeerCRLSourceMappingDigest, cfg.Transport.PeerCRLRoleDigest)
	if err != nil {
		return fail(errors.New("Browser Provider peer CRL role binding mismatch"))
	}
	browserConfig := cfg.Browser
	policies := make([]browsernetworkgateway.Policy, len(browserConfig.RestrictedNetwork.Policies))
	for index, policy := range browserConfig.RestrictedNetwork.Policies {
		policies[index] = browsernetworkgateway.Policy{Reference: policy.Reference, AllowedHosts: append([]string(nil), policy.AllowedHosts...)}
	}
	network, err := browsernetworkdocker.New(ctx, browsernetworkdocker.Options{
		Host: browserConfig.RestrictedNetwork.Host, GatewayImage: browserConfig.RestrictedNetwork.GatewayImage,
		UplinkNetwork: browserConfig.RestrictedNetwork.UplinkNetwork, Namespace: browserConfig.RestrictedNetwork.Namespace,
		ControllerID: browserConfig.RestrictedNetwork.ControllerID, Policies: policies,
		MemoryBytes: browserConfig.RestrictedNetwork.MemoryBytes, NanoCPUs: browserConfig.RestrictedNetwork.NanoCPUs,
		PidsLimit: browserConfig.RestrictedNetwork.PidsLimit, OperationTimeoutSeconds: browserConfig.RestrictedNetwork.OperationTimeoutSeconds,
		StopTimeoutSeconds: browserConfig.RestrictedNetwork.StopTimeoutSeconds,
	})
	if err != nil {
		return fail(fmt.Errorf("construct Browser restricted network: %w", err))
	}
	stack.add(network.Close)
	verifier, err := browserprovenance.New(browserprovenance.Options{
		ExecutablePath: browserConfig.Provenance.ExecutablePath, ExecutableDigest: browserConfig.Provenance.ExecutableDigest})
	if err != nil {
		return fail(fmt.Errorf("construct Browser image verifier: %w", err))
	}
	dockerConfig := browserConfig.Docker
	identityPlan, err := profile.ProjectSandboxIdentityPlan("browser-sandbox-runtime", "provider-browser-runtime",
		dockerConfig.MaxSessionsPerController)
	if err != nil {
		return fail(errors.New("Browser identity plan does not match the production profile"))
	}
	identityLedger, err := providerpostgres.NewBrowserBoundIdentityRepository(ctx, state, identityPlan)
	if err != nil {
		return fail(errors.New("Browser identity ledger authority is unavailable"))
	}
	if _, err := identityLedger.Reservations(ctx); err != nil {
		return fail(errors.New("Browser identity ledger is uninitialized or unavailable"))
	}
	runtimeAuthority, err := identityPlan.ProjectRuntimeAuthority()
	if err != nil {
		return fail(errors.New("Browser runtime identity projection is unavailable"))
	}
	runtime, err := browserdocker.NewBound(ctx, browserdocker.Options{
		Host: dockerConfig.Host, Image: dockerConfig.Image, PullPolicy: browserdocker.PullPolicy(dockerConfig.PullPolicy),
		MemoryBytes: dockerConfig.MemoryBytes, NanoCPUs: dockerConfig.NanoCPUs, PidsLimit: dockerConfig.PidsLimit,
		InputsBytes: dockerConfig.InputsBytes, TmpfsBytes: dockerConfig.TmpfsBytes, WorkspaceBytes: dockerConfig.WorkspaceBytes,
		OutputsBytes: dockerConfig.OutputsBytes, OperationTimeoutSeconds: dockerConfig.OperationTimeoutSeconds,
		ProvenanceTimeoutSeconds: dockerConfig.ProvenanceTimeoutSeconds, PullTimeoutSeconds: dockerConfig.PullTimeoutSeconds,
		StopTimeoutSeconds: dockerConfig.StopTimeoutSeconds, DataRoot: dockerConfig.DataRoot, ManifestPath: dockerConfig.ManifestPath,
		SeccompPath: dockerConfig.SeccompPath, Namespace: dockerConfig.Namespace, ControllerID: dockerConfig.ControllerID,
		NetworkPolicyReference: dockerConfig.NetworkPolicyReference, MaxSessionsPerSandbox: dockerConfig.MaxSessionsPerSandbox,
		MaxSessionsPerController: dockerConfig.MaxSessionsPerController, Clock: systemAdmissionClock{},
	}, verifier, network, runtimeAuthority)
	if err != nil {
		return fail(fmt.Errorf("construct Browser Docker runtime: %w", err))
	}
	stack.add(runtime.Close)
	identityRuntime, err := browserapplication.NewBrowserIdentityRuntime(identityLedger, runtime, systemAdmissionClock{})
	if err != nil {
		return fail(errors.New("Browser identity runtime composition is unavailable"))
	}
	lifecycleDriver, err := browserlifecycle.New(runtime, dockerConfig.NetworkPolicyReference)
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
		return fail(fmt.Errorf("recover Browser Provider lifecycle: %w", err))
	}
	sessions, err := providerpostgres.NewBrowserRepository(state)
	if err != nil {
		return fail(err)
	}
	references, err := providerpostgres.NewBrowserReferenceStore(state)
	if err != nil {
		return fail(err)
	}
	registrar, err := browserreference.NewRegistrar(references, systemAdmissionClock{}, nil)
	if err != nil {
		return fail(err)
	}
	vertical, err := browserapplication.NewVerticalWithHandoffRegistrar(sessions, identityRuntime, lifecycleApp,
		browserapplication.BrowserProfile{RuntimeProfileID: lifecycle.BrowserRuntimeProfile, CapabilityProfileID: providerbrowser.CapabilityProfileID},
		providerBrowserHandoffRegistrar{registrar: registrar}, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	if _, err := vertical.Recover(ctx); err != nil {
		return fail(fmt.Errorf("recover Browser Provider sessions: %w", err))
	}
	application := &productionBrowserApplication{Vertical: vertical, sessions: sessions, references: references, runtime: identityRuntime,
		cleanupTimeout: time.Duration(browserConfig.ShutdownCleanupSeconds) * time.Second}
	stack.add(application.Close)
	usageRepo, err := providerpostgres.NewUsageRepository(state, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	usageReader, err := browserusage.NewReader(sessions, usageRepo, time.Duration(browserConfig.UsageRetentionSeconds)*time.Second)
	if err != nil {
		return fail(err)
	}
	protected, err := newProductionProviderAdmission(ctx, cfg, state, registry)
	if err != nil {
		return fail(err)
	}
	protected.Application = lifecycleApp
	protected.BrowserApplication = application
	protected.UsageEvidenceReader = usageReader
	lifecycleReader, err := provideroperation.NewLifecycleReader(lifecycleApp)
	if err != nil {
		return fail(err)
	}
	browserReader, err := provideroperation.NewBrowserSessionReader(application)
	if err != nil {
		return fail(err)
	}
	protected.OperationReader, err = provideroperation.NewAggregator(lifecycleReader, browserReader)
	if err != nil {
		return fail(err)
	}
	source, err := newBrowserCapabilitySource(cfg, runtime.ImageArchitecture())
	if err != nil {
		return fail(err)
	}
	contractServer, contractProbe, err := newProductionProviderTransport(ctx, cfg, protected, source, registry)
	if err != nil {
		return fail(err)
	}
	executorTransport, executorGuard, err := phase6tls.ProviderPrivateRoleClient(profile, phase6tls.ProviderPrivateRoleClientAuthority{
		Role: "browser", Origin: browserConfig.ExecutorURL, PeerCRLRole: roleDocument,
		AgentSocket: cfg.Transport.AgentSocket, AgentUID: cfg.Transport.AgentUID, AgentGID: cfg.Transport.AgentGID,
		OperationTimeout: time.Duration(cfg.Transport.OperationTimeoutMillis) * time.Millisecond})
	if err != nil || executorGuard.Bootstrap(ctx) != nil {
		return fail(errors.New("Browser executor TLS authority is unavailable"))
	}
	stopExecutorPoll, err := executorGuard.StartPolling(ctx)
	if err != nil {
		return fail(errors.New("Browser executor revocation polling is unavailable"))
	}
	stack.add(func() error { stopExecutorPoll(); return nil })
	executorClient := &http.Client{Transport: executorTransport, Timeout: time.Duration(min(dockerConfig.OperationTimeoutSeconds, 30)) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Browser executor redirect denied") }}
	attacher, err := browserremote.New(browserremote.Options{URL: browserConfig.ExecutorURL, HTTPClient: executorClient,
		OperationTimeout: time.Duration(min(dockerConfig.OperationTimeoutSeconds, 30)) * time.Second, ConnectionStore: references})
	if err != nil {
		return fail(err)
	}
	resolver, err := browserreference.NewResolver(references, sessions, attacher, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	privateServer, privateProbe, err := newProductionProviderPrivateBrowserServer(ctx, cfg, profile, roleDocument, resolver, references)
	if err != nil {
		return fail(err)
	}
	muxAuthority, err := mux.NewProviderAuthority(sessions, references, state)
	if err != nil {
		return fail(err)
	}
	providerPrincipal, backendPrincipal, err := browserMuxPrincipals(profile)
	if err != nil {
		return fail(err)
	}
	allocationMux, err := mux.New(mux.Options{SocketPath: browserConfig.MuxSocketPath,
		Layout: restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
			OwnerUID: providerPrincipal.UID, DirectoryGID: backendPrincipal.GID},
		AllowedPeerUID: backendPrincipal.UID, MaxSessions: dockerConfig.MaxSessionsPerController,
		OperationTimeout: 10 * time.Second, AuthorityPollInterval: 100 * time.Millisecond,
		Authority: muxAuthority, Runtime: identityRuntime})
	if err != nil {
		return fail(fmt.Errorf("construct Browser allocation mux: %w", err))
	}
	reconciler, err := providerprocess.NewReconciler(time.Duration(cfg.Reconciliation.IntervalSeconds)*time.Second,
		time.Duration(cfg.Reconciliation.TimeoutSeconds)*time.Second,
		func(runCtx context.Context) error { return lifecycleApp.Recover(runCtx) },
		func(runCtx context.Context) error { _, recoverErr := vertical.Recover(runCtx); return recoverErr })
	if err != nil {
		return fail(err)
	}
	executorProbe := func(probeCtx context.Context) error {
		if err := executorGuard.Bootstrap(probeCtx); err != nil || !executorGuard.Ready() {
			return phase6tls.ErrPeerCRLUnavailable
		}
		return nil
	}
	probe, err := providerprocess.NewServer(cfg.Probe, providerReadinessChecker{state: state, pool: pool, reconciler: reconciler,
		registry: registry, config: cfg, tlsProbes: []func(context.Context) error{contractProbe, privateProbe, executorProbe},
		dependencyProbes: []func(context.Context) error{runtime.Ready, allocationMux.Ready}})
	if err != nil {
		return fail(err)
	}
	return &productionProviderComposition{provider: contractServer, private: privateServer, brokerMux: allocationMux,
		probe: probe, reconciler: reconciler, close: stack.close}, nil
}

func browserMuxPrincipals(profile phase6security.Profile) (phase6security.Principal, phase6security.Principal, error) {
	if profile.Validate() != nil {
		return phase6security.Principal{}, phase6security.Principal{}, errors.New("Browser mux profile is invalid")
	}
	var providerPrincipal, backendPrincipal phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "provider-browser-runtime":
			providerPrincipal = principal
		case "browser-executor-backend":
			backendPrincipal = principal
		}
	}
	if providerPrincipal.UID == 0 || backendPrincipal.UID == 0 || providerPrincipal.UID == backendPrincipal.UID ||
		uint32(os.Getuid()) != providerPrincipal.UID || uint32(os.Getgid()) != providerPrincipal.GID {
		return phase6security.Principal{}, phase6security.Principal{}, errors.New("Browser mux principals do not match the process")
	}
	return providerPrincipal, backendPrincipal, nil
}

type productionBrowserApplication struct {
	*browserapplication.Vertical
	sessions interface {
		ListOpen(context.Context) ([]providerbrowser.Record, error)
	}
	references     browserreference.Store
	runtime        providerbrowser.Runtime
	cleanupTimeout time.Duration
	closeOnce      sync.Once
	closeErr       error
}

func (a *productionBrowserApplication) Close() error {
	a.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), a.cleanupTimeout)
		defer cancel()
		records, err := a.sessions.ListOpen(ctx)
		if err != nil {
			a.closeErr = err
			return
		}
		now := time.Now().UTC()
		for _, record := range records {
			if record.Allocation == nil || !browserRecordNeedsShutdownCleanup(record, now) {
				continue
			}
			if revokeErr := revokeProviderBrowserHandoff(ctx, a.references, record, now); revokeErr != nil {
				a.closeErr = errors.Join(a.closeErr, revokeErr)
			}
			if cleanupErr := a.runtime.Cleanup(ctx, record.Allocation.Receipt); cleanupErr != nil &&
				!errors.Is(cleanupErr, providerbrowser.ErrBrowserNotFound) {
				a.closeErr = errors.Join(a.closeErr, cleanupErr)
			}
		}
	})
	return a.closeErr
}

func newProductionProviderPrivateBrowserServer(ctx context.Context, cfg *config.ProviderProcessConfig, profile phase6security.Profile,
	roleDocument phase6security.PeerCRLRoleDocument, resolver *browserreference.Resolver,
	references *providerpostgres.BrowserReferenceStore) (server.Server, func(context.Context) error, error) {
	private := cfg.Transport.Private
	edge, ingress, _, _, _, err := profile.BrowserActionIngressProviderBoundary("wss://" + private.Address.Addr() + browsergateway.PrivateV2Path)
	if err != nil || edge.TargetAddress != private.Address.Addr() || !slices.Equal(private.AllowedClientURIIdentities, []string{ingress.TLS.URI}) {
		return nil, nil, errors.New("Browser Provider private ingress boundary does not match profile")
	}
	handler, err := browsergateway.NewV2(browsergateway.V2Options{Resolver: resolver, Store: references,
		ExpectedPeerURI: ingress.TLS.URI, ExpectedHost: private.Address.Addr(),
		MaxSessions:           cfg.Browser.Docker.MaxSessionsPerController,
		OperationTimeout:      time.Duration(min(private.ReadTimeoutMillis, 30_000)) * time.Millisecond,
		AuthorityPollInterval: 100 * time.Millisecond})
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, tlsProbe, peerURI, peerMonitor, err := phase6tls.ProviderServer(profile, phase6tls.ProviderServerAuthority{
		EdgeID: phase6security.BrowserActionIngressProviderPrivateEdgeID, ListenAddress: private.Address.Addr(),
		PeerCRLRole: roleDocument, AgentSocket: cfg.Transport.AgentSocket,
		AgentUID: cfg.Transport.AgentUID, AgentGID: cfg.Transport.AgentGID,
		OperationTimeout: time.Duration(cfg.Transport.OperationTimeoutMillis) * time.Millisecond})
	if err != nil || peerURI != ingress.TLS.URI {
		return nil, nil, errors.New("Browser Provider private TLS authority is unavailable")
	}
	result, err := providerapi.NewPrivateServer(ctx, providerapi.PrivateTransportOptions{Address: private.Address,
		TLSConfig: tlsConfig, PeerRevocationMonitor: peerMonitor,
		ConnectionMaxAge:           time.Duration(edge.MaxConnectionSeconds) * time.Second,
		AllowedClientURIIdentities: append([]string(nil), private.AllowedClientURIIdentities...), Handler: handler,
		ReadHeaderTimeout: time.Duration(private.ReadHeaderTimeoutMillis) * time.Millisecond,
		ReadTimeout:       time.Duration(private.ReadTimeoutMillis) * time.Millisecond,
		WriteTimeout:      time.Duration(private.WriteTimeoutMillis) * time.Millisecond,
		IdleTimeout:       time.Duration(private.IdleTimeoutMillis) * time.Millisecond,
		MaxHeaderBytes:    private.MaxHeaderBytes, MaxBodyBytes: private.MaxBodyBytes})
	return result, tlsProbe, err
}

func newBrowserCapabilitySource(cfg *config.ProviderProcessConfig, architecture string) (*provider.StaticCapabilitySource, error) {
	if cfg == nil || cfg.Profile != config.ProviderProcessBrowserProfile ||
		(architecture != "amd64" && architecture != "arm64") {
		return nil, errors.New("Browser Provider image architecture is unavailable")
	}
	profiles := make([]provider.SnapshotRestoreProfile, len(cfg.Capability.SnapshotRestoreProfiles))
	for index, profile := range cfg.Capability.SnapshotRestoreProfiles {
		profiles[index] = provider.SnapshotRestoreProfile{ProfileID: profile.ProfileID,
			Level: provider.SnapshotLevel(profile.Level), SuiteID: provider.CompatibilitySuiteID(profile.SuiteID),
			SuiteVersion: profile.SuiteVersion, SuiteDigest: provider.SHA256Digest(profile.SuiteDigest)}
	}
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(cfg.Capability.ProviderRevisionID, provider.Limits{
		MaxCPUMillis: cfg.Capability.Limits.MaxCPUMillis, MaxMemoryBytes: cfg.Capability.Limits.MaxMemoryBytes,
		MaxEphemeralStorageBytes: cfg.Capability.Limits.MaxEphemeralStorageBytes,
		MaxWorkspaceBytes:        cloneOptionalInt64(cfg.Capability.Limits.MaxWorkspaceBytes),
		MaxGPUCount:              cloneOptionalInt64(cfg.Capability.Limits.MaxGPUCount),
		MaxLeaseSeconds:          cfg.Capability.Limits.MaxLeaseSeconds, MaxExecSeconds: cfg.Capability.Limits.MaxExecSeconds,
	}, []provider.Capability{{ID: "sandbox.browser", Versions: []string{"1.0.0"}, Profiles: []string{providerbrowser.CapabilityProfileID}}},
		[]provider.RuntimeProfile{{ID: lifecycle.BrowserRuntimeProfile, IsolationClass: "container",
			RuntimeClassName: browserimage.RuntimeClassName, Architecture: []string{architecture},
			CapabilityProfileIDs: []string{providerbrowser.CapabilityProfileID}}}, profiles)
	if err != nil {
		return nil, fmt.Errorf("construct Browser capability snapshot: %w", err)
	}
	return provider.NewStaticCapabilitySource(snapshot)
}

var _ providerapi.BrowserApplication = (*productionBrowserApplication)(nil)
var _ usage.EvidenceReader = (*browserusage.Reader)(nil)
