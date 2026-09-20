package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
	artifactapplication "github.com/shell-echo/sandbox-runtime/provider/artifact/application"
	artifactstaging "github.com/shell-echo/sandbox-runtime/provider/artifact/staging"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	execapplication "github.com/shell-echo/sandbox-runtime/provider/exec/application"
	execcoordinator "github.com/shell-echo/sandbox-runtime/provider/exec/coordinator"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	lifecycledocker "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/docker"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	usageapplication "github.com/shell-echo/sandbox-runtime/provider/usage/application"
	"github.com/shell-echo/sandbox-runtime/providerapi"
	providerprocess "github.com/shell-echo/sandbox-runtime/providerapi/process"
	"github.com/shell-echo/sandbox-runtime/server"
	"github.com/spf13/cobra"
)

const maxProviderPostgresDSNBytes int64 = 8 << 10

var providerCmd = &cobra.Command{Use: "provider", Short: "Operate the independent Provider process"}
var providerServeCmd = &cobra.Command{Use: "serve", Short: "Start the independent Provider control plane", SilenceUsage: true, RunE: runProviderServe}

func runProviderServe(cmd *cobra.Command, _ []string) (result error) {
	providerConfig := config.ProviderProcess
	if providerConfig == nil || !providerConfig.Enabled {
		return errors.New("provider_process.enabled must be true for provider serve")
	}
	if config.Application == nil || config.Application.Mode != config.ApplicationProductionMode {
		return errors.New("provider serve requires application.mode=production")
	}
	if config.ProductProcess != nil && config.ProductProcess.Enabled {
		return errors.New("Product and Provider process authorities cannot share one command")
	}
	if config.Server != nil && config.Server.Provider.Transport.Enabled {
		return errors.New("server.provider belongs to root serve and must be disabled for provider serve")
	}
	if err := providerConfig.Validate(); err != nil {
		return err
	}
	startupContext, cancelStartup := context.WithTimeout(cmd.Context(), time.Duration(providerConfig.Postgres.StartupTimeoutSeconds)*time.Second)
	defer cancelStartup()
	migrationPool, err := openProviderPostgresFile(startupContext, providerConfig.Postgres.MigrationDSNFile, providerConfig.Postgres.MigrationMaxConnections, 0)
	if err != nil {
		return fmt.Errorf("open Provider migration database: %w", err)
	}
	defer migrationPool.Close()
	if err := providerpostgres.ApplyMigrations(startupContext, migrationPool); err != nil {
		return fmt.Errorf("apply Provider database migrations: %w", err)
	}
	runtimePool, err := openProviderPostgresFile(startupContext, providerConfig.Postgres.RuntimeDSNFile, providerConfig.Postgres.MaxConnections, providerConfig.Postgres.MinConnections)
	if err != nil {
		return fmt.Errorf("open Provider runtime database: %w", err)
	}
	defer runtimePool.Close()
	if err := runtimePool.Ping(startupContext); err != nil {
		return errors.New("Provider runtime database is unavailable at startup")
	}
	if err := providerpostgres.VerifySeparatedRoles(startupContext, migrationPool, runtimePool, providerConfig.Postgres.MigrationRole, providerConfig.Postgres.RuntimeRole); err != nil {
		return fmt.Errorf("verify Provider database authority: %w", err)
	}
	if err := providerpostgres.VerifySchemaCompatibility(startupContext, runtimePool); err != nil {
		return fmt.Errorf("verify Provider database schema: %w", err)
	}
	migrationPool.Close()
	state, err := providerpostgres.New(runtimePool, time.Duration(providerConfig.Postgres.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return errors.New("construct Provider transactional state")
	}
	composition, err := newProductionProvider(cmd.Context(), providerConfig, state, runtimePool)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, composition.close()) }()
	return server.RunE(map[string]server.Server{
		"provider":                composition.provider,
		"provider-probe":          composition.probe,
		"provider-reconciliation": composition.reconciler,
	})
}

type productionProviderComposition struct {
	provider   server.Server
	probe      server.Server
	reconciler server.Server
	close      func() error
}

func newProductionProvider(ctx context.Context, cfg *config.ProviderProcessConfig, state *providerpostgres.Store, pool *pgxpool.Pool) (*productionProviderComposition, error) {
	if cfg.Profile == config.ProviderProcessDesktopProfile {
		return newProductionDesktopProvider(ctx, cfg, state, pool)
	}
	return newProductionCodingProvider(ctx, cfg, state, pool)
}

type providerCloseStack struct{ closers []func() error }

func (s *providerCloseStack) add(closer func() error) {
	if closer != nil {
		s.closers = append(s.closers, closer)
	}
}
func (s *providerCloseStack) close() error {
	var result error
	for index := len(s.closers) - 1; index >= 0; index-- {
		result = errors.Join(result, s.closers[index]())
	}
	return result
}

func newProductionCodingProvider(ctx context.Context, cfg *config.ProviderProcessConfig, state *providerpostgres.Store, pool *pgxpool.Pool) (*productionProviderComposition, error) { //nolint:cyclop
	stack := &providerCloseStack{}
	fail := func(err error) (*productionProviderComposition, error) { return nil, errors.Join(err, stack.close()) }
	lifecycleRepo, err := providerpostgres.NewLifecycleRepository(state)
	if err != nil {
		return fail(err)
	}
	dockerConfig := cfg.Coding.Lifecycle
	runtime, err := lifecycledocker.New(ctx, lifecycledocker.Options{
		Host: dockerConfig.Host, Image: dockerConfig.Image, PullPolicy: lifecycledocker.PullPolicy(dockerConfig.PullPolicy),
		MemoryBytes: dockerConfig.MemoryBytes, NanoCPUs: dockerConfig.NanoCPUs, PidsLimit: dockerConfig.PidsLimit, TmpfsBytes: dockerConfig.TmpfsBytes,
		OperationTimeoutSeconds: dockerConfig.OperationTimeoutSeconds, PullTimeoutSeconds: dockerConfig.PullTimeoutSeconds, StopTimeoutSeconds: dockerConfig.StopTimeoutSeconds,
		User: dockerConfig.User, Command: append([]string(nil), dockerConfig.Command...), DataRoot: dockerConfig.DataRoot,
		Namespace: dockerConfig.Namespace, ControllerID: dockerConfig.ControllerID,
	})
	if err != nil {
		return fail(fmt.Errorf("construct production Provider lifecycle runtime: %w", err))
	}
	stack.add(runtime.Close)
	lifecycleApp, err := lifecycleapplication.New(lifecycleRepo, runtime, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	stack.add(lifecycleApp.Close)
	if err := lifecycleApp.Recover(ctx); err != nil {
		return fail(fmt.Errorf("recover production Provider lifecycle: %w", err))
	}
	usageRepo, err := providerpostgres.NewUsageRepository(state, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	usageCollector, err := usageapplication.NewResultCollector(usageRepo, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	execRepo, err := providerpostgres.NewExecRepository(state)
	if err != nil {
		return fail(err)
	}
	execCoordinator, err := execcoordinator.NewWithRuntimeAndResultObserver(execRepo, runtime, runtime, runtime, runtime, usageCollector, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	execApp, err := execapplication.NewVerticalWithSupport(execCoordinator, lifecycleApp, runtime, systemAdmissionClock{})
	if err != nil {
		return fail(err)
	}
	if err := execApp.Recover(ctx); err != nil {
		return fail(fmt.Errorf("recover production Provider exec: %w", err))
	}
	terminalApp, err := newProductionProviderTerminal(ctx, cfg.Coding.Terminal, state, lifecycleApp, runtime)
	if err != nil {
		return fail(err)
	}
	stack.add(terminalApp.Close)
	artifactApp, err := newProductionProviderArtifact(ctx, cfg.Coding.Artifact, state, lifecycleApp, runtime)
	if err != nil {
		return fail(err)
	}
	stack.add(artifactApp.Close)
	usageReader, err := usageapplication.NewReader(usageRepo, execApp, usageCollector)
	if err != nil {
		return fail(err)
	}
	protected, err := newProductionProviderAdmission(cfg, state)
	if err != nil {
		return fail(err)
	}
	protected.Application = lifecycleApp
	protected.ExecApplication = execApp
	protected.SessionApplication = terminalApp
	protected.SessionConnector = terminalApp
	protected.ArtifactApplication = artifactApp
	protected.UsageEvidenceReader = usageReader
	operationReader, err := newProviderOperationReader(lifecycleApp, execApp, terminalApp, artifactApp, nil)
	if err != nil {
		return fail(err)
	}
	protected.OperationReader = operationReader
	readiness := providerCapabilityReadiness{
		ProtectedAdmission: true, MutationGuard: true, LifecyclePersistence: true, RuntimeLifecycle: true,
		LifecycleControl: true, LeaseExpiry: true, LifecycleEventReads: true, StableMounts: true,
		ExecAcceptance: true, ExecExecutor: true, ExecCancellation: true, ExecResultRetention: true, ExecReconciliation: true,
		UsageCollection: true, TerminalAuthority: true, TerminalAllocator: true, OpaqueHandoff: true, TerminalControl: true, TerminalWebSocket: true,
		ArtifactAcceptance: true, OutputStaging: true, ContentChecks: true, RetainedEvidence: true, OperationAggregation: true,
	}
	source, err := newProviderCapabilitySource(providerProcessCapability(cfg, true), readiness)
	if err != nil {
		return fail(err)
	}
	providerServer, err := newProductionProviderTransport(ctx, cfg, protected, source)
	if err != nil {
		return fail(err)
	}
	reconciler, err := providerprocess.NewReconciler(time.Duration(cfg.Reconciliation.IntervalSeconds)*time.Second, time.Duration(cfg.Reconciliation.TimeoutSeconds)*time.Second,
		func(runCtx context.Context) error { return lifecycleApp.Recover(runCtx) },
		func(runCtx context.Context) error { return execApp.Recover(runCtx) },
		func(runCtx context.Context) error { _, err := terminalApp.vertical.Recover(runCtx); return err },
		func(runCtx context.Context) error { _, err := artifactApp.Recover(runCtx); return err },
	)
	if err != nil {
		return fail(err)
	}
	checker := providerReadinessChecker{state: state, pool: pool, reconciler: reconciler}
	probe, err := providerprocess.NewServer(cfg.Probe, checker)
	if err != nil {
		return fail(err)
	}
	return &productionProviderComposition{provider: providerServer, probe: probe, reconciler: reconciler, close: stack.close}, nil
}

func newProductionProviderTerminal(ctx context.Context, terminalConfig config.ProviderTerminalConfig, state *providerpostgres.Store, lifecycleApp *lifecycleapplication.Application, runtime *lifecycledocker.Driver) (*providerTerminalApplication, error) {
	sessions, err := providerpostgres.NewSessionRepository(state)
	if err != nil {
		return nil, err
	}
	references, err := providerpostgres.NewSessionReferenceStore(state)
	if err != nil {
		return nil, err
	}
	terminalRuntime, err := lifecycledocker.NewTerminalRuntime(runtime, lifecycledocker.TerminalOptions{BrokerPath: terminalConfig.BrokerPath, ShellPath: terminalConfig.ShellPath, MaxSessionsPerSandbox: terminalConfig.MaxSessionsPerSandbox, MaxSessionsPerController: terminalConfig.MaxSessionsPerController, Clock: systemAdmissionClock{}})
	if err != nil {
		return nil, err
	}
	registrar, err := sessionreference.NewRegistrar(references, systemAdmissionClock{}, nil)
	if err != nil {
		return nil, err
	}
	handoff := providerTerminalHandoffRegistrar{registrar: registrar, store: references}
	vertical, err := sessionapplication.NewVerticalWithHandoffLifecycle(sessions, terminalRuntime, lifecycleApp, sessionapplication.TerminalProfile{RuntimeProfileID: config.ProviderCodingShellRuntimeProfileID, CapabilityProfileID: config.ProviderCodingShellTerminalProfileID, WorkingDirectory: "/workspace"}, handoff, handoff, systemAdmissionClock{})
	if err != nil {
		return nil, err
	}
	resolver, err := sessionreference.NewResolver(references, sessions, terminalRuntime, systemAdmissionClock{})
	if err != nil {
		return nil, err
	}
	application := &providerTerminalApplication{vertical: vertical, resolver: resolver, authority: sessions, runtime: terminalRuntime, references: references, clock: systemAdmissionClock{}, shutdownCleanup: time.Duration(terminalConfig.ShutdownCleanupSeconds) * time.Second, closeSession: sessions.Close, closeReferences: func() error { return nil }}
	if _, err := vertical.Recover(ctx); err != nil {
		return nil, errors.Join(err, application.Close())
	}
	return application, nil
}

func newProductionProviderArtifact(ctx context.Context, artifactConfig config.ProviderArtifactConfig, state *providerpostgres.Store, lifecycleApp *lifecycleapplication.Application, runtime *lifecycledocker.Driver) (*artifactapplication.Vertical, error) {
	repository, err := providerpostgres.NewArtifactRepository(state)
	if err != nil {
		return nil, err
	}
	activeContent, err := artifactstaging.NewCommandChecker(artifactConfig.ActiveContentCommand)
	if err != nil {
		return nil, err
	}
	malware, err := artifactstaging.NewCommandChecker(artifactConfig.MalwareCommand)
	if err != nil {
		return nil, err
	}
	stager, err := artifactstaging.New(runtime, providerArtifactTenantChecker{sandboxes: lifecycleApp, clock: systemAdmissionClock{}}, activeContent, malware, artifactConfig.StagingRoot, systemAdmissionClock{})
	if err != nil {
		return nil, err
	}
	application, err := artifactapplication.NewVertical(repository, stager, lifecycleApp, stager, systemAdmissionClock{})
	if err != nil {
		return nil, err
	}
	if _, err := application.Recover(ctx); err != nil {
		return nil, errors.Join(err, application.Close())
	}
	return application, nil
}

func newProductionProviderAdmission(cfg *config.ProviderProcessConfig, state *providerpostgres.Store) (*providerapi.ProtectedTransportOptions, error) {
	authority, err := admission.NewAdmissionAuthority(cfg.ProtectedAdmission.Issuer, cfg.Capability.ProviderRevisionID, cfg.ProtectedAdmission.ProviderInstanceAudience)
	if err != nil {
		return nil, err
	}
	files := make([]admissionfile.TrustedKeyFile, len(cfg.ProtectedAdmission.TrustedVerificationKeys))
	for index, key := range cfg.ProtectedAdmission.TrustedVerificationKeys {
		files[index] = admissionfile.TrustedKeyFile{ID: admission.KeyID(key.ID), Algorithm: admission.Algorithm(key.Algorithm), Path: key.PublicKeyFile}
	}
	keys, err := admissionfile.LoadTrustedKeySource(files)
	if err != nil {
		return nil, fmt.Errorf("load production Provider verification keys: %w", err)
	}
	guard, err := providerpostgres.NewAdmissionGuard(state, systemAdmissionClock{})
	if err != nil {
		return nil, err
	}
	gate, err := admission.NewProtectedOperationGate(keys, authority, systemAdmissionClock{}, guard)
	if err != nil {
		return nil, err
	}
	return &providerapi.ProtectedTransportOptions{Gate: gate}, nil
}

func providerProcessCapability(cfg *config.ProviderProcessConfig, coding bool) config.ProviderCapabilityConfig {
	return config.ProviderCapabilityConfig{CodingShellEnabled: coding, ProviderRevisionID: cfg.Capability.ProviderRevisionID, Limits: cfg.Capability.Limits, SnapshotRestoreProfiles: append([]config.ProviderCompatibilityProfile(nil), cfg.Capability.SnapshotRestoreProfiles...)}
}

func newProductionProviderTransport(ctx context.Context, cfg *config.ProviderProcessConfig, protected *providerapi.ProtectedTransportOptions, source provider.CapabilityReader) (*providerapi.Server, error) {
	transport := cfg.Transport
	return providerapi.NewServer(ctx, providerapi.TransportOptions{Address: transport.Address, ServerCertificateFile: transport.ServerCertificateFile, ServerPrivateKeyFile: transport.ServerPrivateKeyFile, ClientCABundleFile: transport.ClientCABundleFile, AllowedClientURIIdentities: append([]string(nil), transport.AllowedClientURIIdentities...), Protected: protected}, source)
}

type providerReadinessChecker struct {
	state      *providerpostgres.Store
	pool       *pgxpool.Pool
	reconciler interface{ Ready(context.Context) error }
}

func (c providerReadinessChecker) Ready(ctx context.Context) error {
	if c.state == nil || c.pool == nil || c.reconciler == nil {
		return providerpostgres.ErrUnavailable
	}
	if err := c.state.Ping(ctx); err != nil {
		return err
	}
	if err := providerpostgres.VerifySchemaCompatibility(ctx, c.pool); err != nil {
		return err
	}
	return c.reconciler.Ready(ctx)
}

func openProviderPostgresFile(ctx context.Context, path string, maxConnections, minConnections int32) (*pgxpool.Pool, error) {
	raw, err := secretfile.Read(path, maxProviderPostgresDSNBytes)
	if err != nil {
		return nil, errors.New("load Provider PostgreSQL connection secret")
	}
	defer clear(raw)
	dsn := strings.TrimSuffix(string(raw), "\n")
	if dsn == "" || strings.TrimSpace(dsn) != dsn || strings.ContainsAny(dsn, "\x00\r\n") {
		return nil, errors.New("invalid Provider PostgreSQL connection secret")
	}
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" || parsed.User == nil {
		return nil, errors.New("invalid Provider PostgreSQL connection secret")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid Provider PostgreSQL connection secret")
	}
	poolConfig.MaxConns, poolConfig.MinConns = maxConnections, minConnections
	poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime, poolConfig.HealthCheckPeriod = 30*time.Minute, 5*time.Minute, 30*time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("open Provider PostgreSQL pool")
	}
	return pool, nil
}

func init() {
	providerCmd.AddCommand(providerServeCmd)
	rootCmd.AddCommand(providerCmd)
}

var _ providerexec.ResultObserver = (*usageapplication.ResultCollector)(nil)
var _ usage.Store = (*providerpostgres.UsageRepository)(nil)
var _ provideroperation.Reader = (*execapplication.Vertical)(nil)
