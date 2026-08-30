package cmd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/shell-echo/sandbox-runtime/config"
	dockerdriver "github.com/shell-echo/sandbox-runtime/driver/docker"
	"github.com/shell-echo/sandbox-runtime/driver/fake"
	"github.com/shell-echo/sandbox-runtime/instance"
	instancefile "github.com/shell-echo/sandbox-runtime/instance/file"
	"github.com/shell-echo/sandbox-runtime/instance/memory"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	artifactapplication "github.com/shell-echo/sandbox-runtime/provider/artifact/application"
	artifactfile "github.com/shell-echo/sandbox-runtime/provider/artifact/repository/file"
	artifactstaging "github.com/shell-echo/sandbox-runtime/provider/artifact/staging"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	execapplication "github.com/shell-echo/sandbox-runtime/provider/exec/application"
	execcoordinator "github.com/shell-echo/sandbox-runtime/provider/exec/coordinator"
	execrepository "github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	execfile "github.com/shell-echo/sandbox-runtime/provider/exec/repository/file"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	lifecycledocker "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/docker"
	lifecyclefake "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/fake"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	lifecyclefile "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/file"
	lifecyclememory "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/memory"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
	sessionreferencefile "github.com/shell-echo/sandbox-runtime/provider/session/reference/repository/file"
	sessionfile "github.com/shell-echo/sandbox-runtime/provider/session/repository/file"
	providerterminal "github.com/shell-echo/sandbox-runtime/provider/terminal"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	usageapplication "github.com/shell-echo/sandbox-runtime/provider/usage/application"
	usagefile "github.com/shell-echo/sandbox-runtime/provider/usage/repository/file"
	"github.com/shell-echo/sandbox-runtime/providerapi"
	"github.com/shell-echo/sandbox-runtime/server"
	"github.com/shell-echo/sandbox-runtime/server/api"
	"github.com/spf13/cobra"
)

// serveCmd starts the long-running servers. Configuration and the logger have
// already been initialised by the root command's PersistentPreRunE.
var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the server",
	SilenceUsage: true,
	RunE:         runServe,
}

func runServe(cmd *cobra.Command, _ []string) (result error) {
	if err := validateServeConfiguration(config.Application, config.Server, config.Runtime, config.Repository); err != nil {
		return err
	}
	providerServer, closeProvider, err := newProviderServer(cmd.Context(), config.Server.Provider)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeProvider()) }()
	runtimeDriver, closeRuntime, err := newRuntimeDriver(cmd.Context(), config.Runtime)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeRuntime()) }()

	repository, err := newInstanceRepository(config.Repository)
	if err != nil {
		return err
	}
	if closer, ok := repository.(interface{ Close() error }); ok {
		defer func() { result = errors.Join(result, closer.Close()) }()
	}
	instances, err := instance.NewService(repository, runtimeDriver)
	if err != nil {
		return err
	}
	if err := instances.Recover(cmd.Context()); err != nil {
		return fmt.Errorf("recover instances: %w", err)
	}
	apiServer, err := api.NewServer(config.Application.IsDevelopment(), config.Server.API, instances)
	if err != nil {
		return err
	}
	return server.RunE(enabledServers(apiServer, providerServer))
}

func enabledServers(apiServer, providerServer server.Server) map[string]server.Server {
	servers := map[string]server.Server{"api": apiServer}
	if providerServer != nil {
		servers["provider"] = providerServer
	}
	return servers
}

func newProviderServer(ctx context.Context, providerConfig config.ProviderConfig) (server.Server, func() error, error) {
	if !providerConfig.Transport.Enabled {
		return nil, noOpProviderClose, nil
	}
	if err := providerConfig.Validate(); err != nil {
		return nil, noOpProviderClose, fmt.Errorf("validate Provider configuration: %w", err)
	}
	lifecycleApp, execRuntime, closeLifecycle, err := newProviderLifecycleRuntime(ctx, providerConfig.Lifecycle)
	if err != nil {
		return nil, noOpProviderClose, err
	}

	protected, closeProtected, err := newProviderProtectedTransportOptions(providerConfig.ProtectedAdmission, systemAdmissionClock{})
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeLifecycle())
	}
	usageStore, usageCollector, closeUsage, err := newProviderUsageCollector(providerConfig.Usage)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeProtected(), closeLifecycle())
	}
	execApp, closeExec, err := newProviderExecApplication(ctx, providerConfig.Exec, lifecycleApp, execRuntime, usageCollector)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeUsage(), closeProtected(), closeLifecycle())
	}
	usageReader, err := newProviderUsageReader(providerConfig.Usage, usageStore, usageCollector, execApp)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeExec(), closeUsage(), closeProtected(), closeLifecycle())
	}
	terminalApp, closeTerminal, err := newProviderTerminalApplication(ctx, providerConfig.Terminal, lifecycleApp, execRuntime)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeExec(), closeUsage(), closeProtected(), closeLifecycle())
	}
	artifactApp, closeArtifact, err := newProviderArtifactApplication(ctx, providerConfig.Artifact, lifecycleApp, execRuntime)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeTerminal(), closeExec(), closeUsage(), closeProtected(), closeLifecycle())
	}
	var operationReader provideroperation.Reader
	var readerErr error
	if protected != nil {
		protected.Application = lifecycleApp
		protected.ExecApplication = execApp
		protected.SessionApplication = terminalApp
		protected.ArtifactApplication = artifactApp
		protected.UsageEvidenceReader = usageReader
		operationReader, readerErr = newProviderOperationReader(lifecycleApp, execApp, terminalApp, artifactApp)
		if readerErr != nil {
			return nil, noOpProviderClose, errors.Join(readerErr, closeArtifact(), closeTerminal(), closeExec(), closeUsage(), closeProtected(), closeLifecycle())
		}
		protected.OperationReader = operationReader
	}
	readiness := providerCapabilityReadiness{
		ProtectedAdmission:   protected != nil && protected.Gate != nil,
		MutationGuard:        protected != nil && protected.Gate != nil,
		LifecyclePersistence: lifecycleApp != nil && providerConfig.Lifecycle.Repository.Driver == config.ProviderLifecycleFileRepository,
		RuntimeLifecycle:     execRuntime != nil,
		StableMounts:         execRuntime != nil,
		ExecAcceptance:       execApp != nil,
		ExecExecutor:         execApp != nil && execRuntime != nil,
		ExecCancellation:     execApp != nil,
		ExecResultRetention:  execApp != nil,
		ExecReconciliation:   execApp != nil,
		UsageCollection:      usageCollector != nil && usageReader != nil,
		TerminalAuthority:    terminalApp != nil,
		TerminalAllocator:    terminalApp != nil,
		OpaqueHandoff:        terminalApp != nil,
		TerminalWebSocket:    false, // f4 is not command-composed; the caller owns the Gateway edge.
		GatewayBoundary:      false, // f5 requires caller-owned authorization, revocation, and recording.
		ArtifactAcceptance:   artifactApp != nil,
		OutputStaging:        artifactApp != nil && execRuntime != nil,
		ContentChecks:        artifactApp != nil,
		RetainedEvidence:     artifactApp != nil && usageReader != nil,
		OperationAggregation: operationReader != nil,
	}
	source, err := newProviderCapabilitySource(providerConfig.Capability, readiness)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeArtifact(), closeTerminal(), closeExec(), closeUsage(), closeProtected(), closeLifecycle())
	}
	transport := providerConfig.Transport
	providerServer, err := providerapi.NewServer(ctx, providerapi.TransportOptions{
		Address:                    transport.Address,
		ServerCertificateFile:      transport.ServerCertificateFile,
		ServerPrivateKeyFile:       transport.ServerPrivateKeyFile,
		ClientCABundleFile:         transport.ClientCABundleFile,
		AllowedClientURIIdentities: append([]string(nil), transport.AllowedClientURIIdentities...),
		Protected:                  protected,
	}, source)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("construct Provider API server: %w", err), closeArtifact(), closeTerminal(), closeExec(), closeUsage(), closeProtected(), closeLifecycle())
	}
	return providerServer, func() error {
		return errors.Join(closeArtifact(), closeTerminal(), closeExec(), closeUsage(), closeProtected(), closeLifecycle())
	}, nil
}

// newProviderOperationReader composes only the operation families whose
// application boundaries were explicitly injected. Usage evidence remains a
// read sidecar correlated to exec operations rather than a separate operation
// family.
func newProviderOperationReader(lifecycleApp providerapi.LifecycleApplication, execApp provideroperation.Reader, sessionApp *providerTerminalApplication, artifactApp providerapi.ArtifactApplication) (provideroperation.Reader, error) {
	readers := make([]provideroperation.Reader, 0, 4)
	if lifecycleApp != nil {
		reader, err := provideroperation.NewLifecycleReader(lifecycleApp)
		if err != nil {
			return nil, err
		}
		readers = append(readers, reader)
	}
	if execApp != nil {
		readers = append(readers, execApp)
	}
	if sessionApp != nil {
		reader, err := provideroperation.NewSessionReader(sessionApp)
		if err != nil {
			return nil, err
		}
		readers = append(readers, reader)
	}
	if artifactApp != nil {
		reader, err := provideroperation.NewArtifactReader(artifactApp)
		if err != nil {
			return nil, err
		}
		readers = append(readers, reader)
	}
	if len(readers) == 0 {
		return nil, nil
	}
	return provideroperation.NewAggregator(readers...)
}

func newProviderLifecycleApplication(ctx context.Context, lifecycleConfig config.ProviderLifecycleConfig) (*lifecycleapplication.Application, func() error, error) {
	application, _, closeApplication, err := newProviderLifecycleRuntime(ctx, lifecycleConfig)
	return application, closeApplication, err
}

func newProviderLifecycleRuntime(ctx context.Context, lifecycleConfig config.ProviderLifecycleConfig) (*lifecycleapplication.Application, *lifecycledocker.Driver, func() error, error) {
	if !lifecycleConfig.Enabled {
		return nil, nil, noOpProviderClose, nil
	}
	if err := lifecycleConfig.Validate(); err != nil {
		return nil, nil, noOpProviderClose, fmt.Errorf("validate Provider lifecycle configuration: %w", err)
	}
	var lifecycleRepo lifecyclerepository.Repository
	switch lifecycleConfig.Repository.Driver {
	case config.ProviderLifecycleMemoryRepository:
		lifecycleRepo = lifecyclememory.NewRepository()
	case config.ProviderLifecycleFileRepository:
		repo, err := lifecyclefile.NewRepository(lifecycleConfig.Repository.File.Path)
		if err != nil {
			return nil, nil, noOpProviderClose, fmt.Errorf("open Provider lifecycle repository: %w", err)
		}
		lifecycleRepo = repo
	default:
		return nil, nil, noOpProviderClose, fmt.Errorf("unsupported Provider lifecycle repository %q", lifecycleConfig.Repository.Driver)
	}
	var driver lifecyclecoordinator.Driver
	var execRuntime *lifecycledocker.Driver
	closeDriver := noOpProviderClose
	switch lifecycleConfig.Driver {
	case config.ProviderLifecycleFakeDriver:
		driver = lifecyclefake.New()
	case config.ProviderLifecycleDockerDriver:
		cfg := lifecycleConfig.Docker
		dockerDriver, err := lifecycledocker.New(ctx, lifecycledocker.Options{
			Host: cfg.Host, Image: cfg.Image, PullPolicy: lifecycledocker.PullPolicy(cfg.PullPolicy),
			MemoryBytes: cfg.MemoryBytes, NanoCPUs: cfg.NanoCPUs, PidsLimit: cfg.PidsLimit,
			TmpfsBytes: cfg.TmpfsBytes, OperationTimeoutSeconds: cfg.OperationTimeoutSeconds,
			PullTimeoutSeconds: cfg.PullTimeoutSeconds, StopTimeoutSeconds: cfg.StopTimeoutSeconds,
			User: cfg.User, Command: append([]string(nil), cfg.Command...), DataRoot: cfg.DataRoot,
			Namespace: cfg.Namespace, ControllerID: cfg.ControllerID,
		})
		if err != nil {
			_ = lifecycleRepo.Close()
			return nil, nil, noOpProviderClose, fmt.Errorf("construct Provider Docker lifecycle driver: %w", err)
		}
		driver = dockerDriver
		execRuntime = dockerDriver
		closeDriver = dockerDriver.Close
	default:
		_ = lifecycleRepo.Close()
		return nil, nil, noOpProviderClose, fmt.Errorf("unsupported Provider lifecycle driver %q", lifecycleConfig.Driver)
	}
	application, err := lifecycleapplication.New(lifecycleRepo, driver, systemAdmissionClock{})
	if err != nil {
		_ = errors.Join(closeDriver(), lifecycleRepo.Close())
		return nil, nil, noOpProviderClose, fmt.Errorf("construct Provider lifecycle application: %w", err)
	}
	if err := application.Recover(ctx); err != nil {
		return nil, nil, noOpProviderClose, errors.Join(fmt.Errorf("recover Provider lifecycle: %w", err), application.Close(), closeDriver(), lifecycleRepo.Close())
	}
	return application, execRuntime, func() error { return errors.Join(application.Close(), closeDriver(), lifecycleRepo.Close()) }, nil
}

func newProviderExecApplication(ctx context.Context, execConfig config.ProviderExecConfig, lifecycleApp *lifecycleapplication.Application, runtime *lifecycledocker.Driver, resultSink providerexec.ResultObserver) (*execapplication.Vertical, func() error, error) {
	if !execConfig.Enabled {
		return nil, noOpProviderClose, nil
	}
	if err := execConfig.Validate(); err != nil {
		return nil, noOpProviderClose, fmt.Errorf("validate Provider exec configuration: %w", err)
	}
	if lifecycleApp == nil || runtime == nil {
		return nil, noOpProviderClose, errors.New("Provider exec requires a composed Docker lifecycle runtime")
	}
	repo, err := execfile.NewRepository(execConfig.RepositoryFile)
	if err != nil {
		return nil, noOpProviderClose, fmt.Errorf("open Provider exec repository: %w", err)
	}
	var repository execrepository.Repository = repo
	coordinator, err := execcoordinator.NewWithRuntimeAndResultObserver(repository, runtime, runtime, runtime, runtime, resultSink, systemAdmissionClock{})
	if err != nil {
		_ = repo.Close()
		return nil, noOpProviderClose, fmt.Errorf("construct Provider exec coordinator: %w", err)
	}
	application, err := execapplication.NewVerticalWithSupport(coordinator, lifecycleApp, runtime, systemAdmissionClock{})
	if err != nil {
		_ = repo.Close()
		return nil, noOpProviderClose, fmt.Errorf("construct Provider exec application: %w", err)
	}
	if err := application.Recover(ctx); err != nil {
		_ = repo.Close()
		return nil, noOpProviderClose, fmt.Errorf("recover Provider exec operations: %w", err)
	}
	return application, repo.Close, nil
}

func newProviderUsageCollector(usageConfig config.ProviderUsageConfig) (usage.Store, *usageapplication.ResultCollector, func() error, error) {
	if !usageConfig.Enabled {
		return nil, nil, noOpProviderClose, nil
	}
	if err := usageConfig.Validate(); err != nil {
		return nil, nil, noOpProviderClose, fmt.Errorf("validate Provider usage configuration: %w", err)
	}
	repository, err := usagefile.NewRepository(usageConfig.RepositoryFile, systemAdmissionClock{})
	if err != nil {
		return nil, nil, noOpProviderClose, fmt.Errorf("open Provider usage repository: %w", err)
	}
	collector, err := usageapplication.NewResultCollector(repository, systemAdmissionClock{})
	if err != nil {
		_ = repository.Close()
		return nil, nil, noOpProviderClose, fmt.Errorf("construct Provider usage collector: %w", err)
	}
	return repository, collector, repository.Close, nil
}

func newProviderUsageReader(usageConfig config.ProviderUsageConfig, store usage.Store, collector *usageapplication.ResultCollector, execApp *execapplication.Vertical) (usage.EvidenceReader, error) {
	if !usageConfig.Enabled {
		return nil, nil
	}
	if store == nil || collector == nil || execApp == nil {
		return nil, errors.New("Provider usage requires a composed exec result source")
	}
	reader, err := usageapplication.NewReader(store, execApp, collector)
	if err != nil {
		return nil, fmt.Errorf("construct Provider usage reader: %w", err)
	}
	return reader, nil
}

type providerArtifactTenantChecker struct {
	sandboxes *lifecycleapplication.Application
	clock     systemAdmissionClock
}

func (c providerArtifactTenantChecker) CheckTenantBinding(ctx context.Context, request artifact.Request) (artifact.CheckStatus, error) {
	if c.sandboxes == nil {
		return artifact.CheckNotRun, artifact.ErrUnsupportedChecks
	}
	sandbox, err := c.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return artifact.CheckNotRun, err
	}
	if err := sandbox.Validate(); err != nil || sandbox.ID != request.SandboxID || sandbox.Generation > math.MaxInt64 || int64(sandbox.Generation) != request.ExpectedGeneration {
		return artifact.CheckNotRun, artifact.ErrGenerationConflict
	}
	if sandbox.TenantID != request.TenantID {
		return artifact.CheckFailed, nil
	}
	if sandbox.DesiredState != lifecycle.DesiredReady || sandbox.ObservedState != lifecycle.ObservedReady || sandbox.ObservedGeneration != sandbox.Generation || !sandbox.LeaseExpiresAt.After(c.clock.Now()) {
		return artifact.CheckNotRun, artifact.ErrSandboxNotReady
	}
	return artifact.CheckPassed, nil
}

func newProviderArtifactApplication(ctx context.Context, artifactConfig config.ProviderArtifactConfig, lifecycleApp *lifecycleapplication.Application, runtime *lifecycledocker.Driver) (*artifactapplication.Vertical, func() error, error) {
	if !artifactConfig.Enabled {
		return nil, noOpProviderClose, nil
	}
	if err := artifactConfig.Validate(); err != nil {
		return nil, noOpProviderClose, fmt.Errorf("validate Provider artifact configuration: %w", err)
	}
	if lifecycleApp == nil || runtime == nil {
		return nil, noOpProviderClose, errors.New("Provider artifact staging requires a composed Docker lifecycle runtime")
	}
	repository, err := artifactfile.NewRepository(artifactConfig.RepositoryFile)
	if err != nil {
		return nil, noOpProviderClose, fmt.Errorf("open Provider artifact repository: %w", err)
	}
	activeContent, err := artifactstaging.NewCommandChecker(artifactConfig.ActiveContentCommand)
	if err != nil {
		_ = repository.Close()
		return nil, noOpProviderClose, fmt.Errorf("construct Provider active-content checker: %w", err)
	}
	malware, err := artifactstaging.NewCommandChecker(artifactConfig.MalwareCommand)
	if err != nil {
		_ = repository.Close()
		return nil, noOpProviderClose, fmt.Errorf("construct Provider malware checker: %w", err)
	}
	tenant := providerArtifactTenantChecker{sandboxes: lifecycleApp, clock: systemAdmissionClock{}}
	stager, err := artifactstaging.New(runtime, tenant, activeContent, malware, artifactConfig.StagingRoot, systemAdmissionClock{})
	if err != nil {
		_ = repository.Close()
		return nil, noOpProviderClose, fmt.Errorf("construct Provider artifact stager: %w", err)
	}
	application, err := artifactapplication.NewVertical(repository, stager, lifecycleApp, stager, systemAdmissionClock{})
	if err != nil {
		_ = repository.Close()
		return nil, noOpProviderClose, fmt.Errorf("construct Provider artifact application: %w", err)
	}
	if _, err := application.Recover(ctx); err != nil {
		_ = errors.Join(application.Close(), repository.Close())
		return nil, noOpProviderClose, fmt.Errorf("recover Provider artifact operations: %w", err)
	}
	return application, func() error { return errors.Join(application.Close(), repository.Close()) }, nil
}

// providerTerminalApplication owns development-only process composition around
// the otherwise provider-neutral session vertical. It is intentionally not a
// Gateway: no caller authorization, public listener, or capability
// advertisement is supplied here.
type providerTerminalApplication struct {
	vertical   *sessionapplication.Vertical
	authority  session.CoordinationAuthority
	runtime    providerterminal.Runtime
	references sessionreference.Store
	clock      systemAdmissionClock

	shutdownCleanup time.Duration
	closeSession    func() error
	closeReferences func() error
	closeOnce       sync.Once
	closeErr        error
}

type providerTerminalHandoffRegistrar struct{ registrar *sessionreference.Registrar }

func (r providerTerminalHandoffRegistrar) RegisterHandoff(ctx context.Context, source session.Record) (session.EndpointEvidence, error) {
	if r.registrar == nil {
		return session.EndpointEvidence{}, sessionreference.ErrUnavailable
	}
	registration, err := r.registrar.Register(ctx, source)
	if err != nil {
		return session.EndpointEvidence{}, err
	}
	return registration.Evidence, nil
}

func newProviderTerminalApplication(ctx context.Context, terminalConfig config.ProviderTerminalConfig, lifecycleApp *lifecycleapplication.Application, runtime *lifecycledocker.Driver) (*providerTerminalApplication, func() error, error) {
	if !terminalConfig.Enabled {
		return nil, noOpProviderClose, nil
	}
	if err := terminalConfig.Validate(); err != nil {
		return nil, noOpProviderClose, fmt.Errorf("validate Provider terminal configuration: %w", err)
	}
	if lifecycleApp == nil || runtime == nil {
		return nil, noOpProviderClose, errors.New("Provider terminal requires a composed Docker lifecycle runtime")
	}
	sessions, err := sessionfile.NewRepository(terminalConfig.SessionRepositoryFile)
	if err != nil {
		return nil, noOpProviderClose, fmt.Errorf("open Provider terminal session repository: %w", err)
	}
	references, err := sessionreferencefile.NewRegistry(terminalConfig.ReferenceRegistryFile)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("open Provider terminal reference registry: %w", err), sessions.Close())
	}
	terminalRuntime, err := lifecycledocker.NewTerminalRuntime(runtime, lifecycledocker.TerminalOptions{
		BrokerPath: terminalConfig.BrokerPath, ShellPath: terminalConfig.ShellPath,
		MaxSessionsPerSandbox: terminalConfig.MaxSessionsPerSandbox, MaxSessionsPerController: terminalConfig.MaxSessionsPerController,
		Clock: systemAdmissionClock{},
	})
	if err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("construct Provider Docker terminal runtime: %w", err), references.Close(), sessions.Close())
	}
	registrar, err := sessionreference.NewRegistrar(references, systemAdmissionClock{}, nil)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("construct Provider terminal handoff registrar: %w", err), references.Close(), sessions.Close())
	}
	vertical, err := sessionapplication.NewVerticalWithHandoffRegistrar(
		sessions, terminalRuntime, lifecycleApp,
		sessionapplication.TerminalProfile{RuntimeProfileID: terminalConfig.RuntimeProfileID, CapabilityProfileID: terminalConfig.CapabilityProfileID, WorkingDirectory: "/workspace"},
		providerTerminalHandoffRegistrar{registrar: registrar}, systemAdmissionClock{},
	)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("construct Provider terminal application: %w", err), references.Close(), sessions.Close())
	}
	application := &providerTerminalApplication{
		vertical: vertical, authority: sessions, runtime: terminalRuntime, references: references, clock: systemAdmissionClock{},
		shutdownCleanup: time.Duration(terminalConfig.ShutdownCleanupSeconds) * time.Second,
		closeSession:    sessions.Close, closeReferences: references.Close,
	}
	if _, err := application.vertical.Recover(ctx); err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("recover Provider terminal sessions: %w", err), application.Close())
	}
	return application, application.Close, nil
}

func (a *providerTerminalApplication) Open(ctx context.Context, request session.OpenRequest) (sessionapplication.Operation, error) {
	if a == nil || a.vertical == nil {
		return sessionapplication.Operation{}, sessionapplication.ErrInvalidApplication
	}
	return a.vertical.Open(ctx, request)
}

func (a *providerTerminalApplication) GetHandoff(ctx context.Context, operationID string) (sessionapplication.Handoff, error) {
	if a == nil || a.vertical == nil {
		return sessionapplication.Handoff{}, sessionapplication.ErrInvalidApplication
	}
	return a.vertical.GetHandoff(ctx, operationID)
}

func (a *providerTerminalApplication) GetOperation(ctx context.Context, operationID string) (sessionapplication.Operation, error) {
	if a == nil || a.vertical == nil {
		return sessionapplication.Operation{}, sessionapplication.ErrInvalidApplication
	}
	return a.vertical.GetOperation(ctx, operationID)
}

// Close runs after server.RunE has stopped the Provider listener. It revokes
// any registered running handoff before identity-bound broker cleanup, so a
// concurrent resolver cannot attach while the terminal is being removed.
func (a *providerTerminalApplication) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		a.closeErr = a.shutdown()
	})
	return a.closeErr
}

func (a *providerTerminalApplication) shutdown() error {
	var result error
	cleanupContext, cancel := context.WithTimeout(context.Background(), a.shutdownCleanup)
	defer cancel()
	if a.authority == nil || a.runtime == nil || a.references == nil || a.clock.Now().IsZero() {
		result = errors.Join(result, sessionapplication.ErrInvalidApplication)
	} else {
		records, err := a.authority.ListOpen(cleanupContext)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("list Provider terminal sessions for shutdown: %w", err))
		} else {
			for _, record := range records {
				if record.Status != session.StatusRunning || record.Allocation == nil {
					continue
				}
				registration, findErr := a.references.FindRunning(cleanupContext, record)
				if findErr == nil {
					if revokeErr := a.references.Revoke(cleanupContext, registration.Reference, a.clock.Now()); revokeErr != nil {
						result = errors.Join(result, fmt.Errorf("revoke Provider terminal handoff: %w", revokeErr))
					}
				} else if !errors.Is(findErr, sessionreference.ErrNotFound) {
					result = errors.Join(result, fmt.Errorf("find Provider terminal handoff for shutdown: %w", findErr))
				}
				if cleanupErr := a.runtime.Cleanup(cleanupContext, providerTerminalReceipt(record.Allocation.Receipt)); cleanupErr != nil {
					result = errors.Join(result, fmt.Errorf("cleanup Provider terminal allocation: %w", cleanupErr))
				}
			}
		}
	}
	if a.closeReferences != nil {
		result = errors.Join(result, a.closeReferences())
	}
	if a.closeSession != nil {
		result = errors.Join(result, a.closeSession())
	}
	return result
}

func providerTerminalReceipt(receipt session.AllocationReceipt) providerterminal.Receipt {
	return providerterminal.Receipt{
		Reference: providerterminal.Reference(receipt.Reference), SandboxID: receipt.SandboxID,
		RuntimeSessionID: receipt.RuntimeSessionID, OperationID: receipt.OperationID, AttemptID: receipt.AttemptID,
		FencingToken: receipt.FencingToken, ExpectedGeneration: receipt.ExpectedGeneration,
		ConnectionGeneration: receipt.ConnectionGeneration, AllocatedAt: receipt.AllocatedAt.UTC(), ExpiresAt: receipt.ExpiresAt.UTC(),
	}
}

func noOpProviderClose() error { return nil }

// systemAdmissionClock is chosen at the process composition boundary. The
// admission package still receives only its narrow Clock port.
type systemAdmissionClock struct{}

func (systemAdmissionClock) Now() time.Time { return time.Now().UTC() }

func newProviderProtectedTransportOptions(protectedConfig config.ProviderProtectedAdmissionConfig, clock admission.Clock) (*providerapi.ProtectedTransportOptions, func() error, error) {
	if !protectedConfig.Enabled {
		return nil, noOpProviderClose, nil
	}

	files := make([]admissionfile.TrustedKeyFile, len(protectedConfig.TrustedVerificationKeys))
	for index, key := range protectedConfig.TrustedVerificationKeys {
		files[index] = admissionfile.TrustedKeyFile{
			ID:        admission.KeyID(key.ID),
			Algorithm: admission.Algorithm(key.Algorithm),
			Path:      key.PublicKeyFile,
		}
	}
	keys, err := admissionfile.LoadTrustedKeySource(files)
	if err != nil {
		return nil, noOpProviderClose, fmt.Errorf("load Provider trusted verification keys: %w", err)
	}
	guard, err := admissionfile.NewGuard(protectedConfig.GuardStateFile, clock)
	if err != nil {
		return nil, noOpProviderClose, fmt.Errorf("open Provider admission guard: %w", err)
	}
	gate, err := admission.NewProtectedOperationGate(keys, clock, guard)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("construct Provider admission gate: %w", err), guard.Close())
	}
	return &providerapi.ProtectedTransportOptions{Gate: gate}, guard.Close, nil
}

// providerCapabilityReadiness is the command-root dependency graph for the
// canonical coding/shell profile. A configured capability is not advertised
// until every node is backed by a composed application or adapter.
type providerCapabilityReadiness struct {
	ProtectedAdmission   bool
	MutationGuard        bool
	LifecyclePersistence bool
	RuntimeLifecycle     bool
	StableMounts         bool
	ExecAcceptance       bool
	ExecExecutor         bool
	ExecCancellation     bool
	ExecResultRetention  bool
	ExecReconciliation   bool
	UsageCollection      bool
	TerminalAuthority    bool
	TerminalAllocator    bool
	OpaqueHandoff        bool
	TerminalWebSocket    bool
	GatewayBoundary      bool
	ArtifactAcceptance   bool
	OutputStaging        bool
	ContentChecks        bool
	RetainedEvidence     bool
	OperationAggregation bool
}

func (r providerCapabilityReadiness) missingDependencies() []string {
	checks := []struct {
		name  string
		ready bool
	}{
		{"protected mTLS/JWS admission", r.ProtectedAdmission},
		{"durable mutation guard", r.MutationGuard},
		{"lifecycle persistence", r.LifecyclePersistence},
		{"real runtime lifecycle adapter", r.RuntimeLifecycle},
		{"stable /inputs,/workspace,/outputs,/tmp mounts", r.StableMounts},
		{"durable exec acceptance", r.ExecAcceptance},
		{"exec executor", r.ExecExecutor},
		{"exec cancellation", r.ExecCancellation},
		{"exec result retention", r.ExecResultRetention},
		{"exec reconciliation", r.ExecReconciliation},
		{"usage collection", r.UsageCollection},
		{"terminal authority", r.TerminalAuthority},
		{"terminal allocator", r.TerminalAllocator},
		{"opaque terminal handoff", r.OpaqueHandoff},
		{"concrete terminal WebSocket data plane", r.TerminalWebSocket},
		{"trusted caller-owned Gateway boundary", r.GatewayBoundary},
		{"artifact acceptance", r.ArtifactAcceptance},
		{"real output staging", r.OutputStaging},
		{"bounded artifact content checks", r.ContentChecks},
		{"retained artifact/usage evidence", r.RetainedEvidence},
		{"operation-family aggregation", r.OperationAggregation},
	}
	missing := make([]string, 0)
	for _, check := range checks {
		if !check.ready {
			missing = append(missing, check.name)
		}
	}
	return missing
}

// newProviderCapabilitySource derives the immutable startup advertisement
// from the composed dependency graph. The optional argument keeps the helper
// useful for the pre-readiness empty snapshot tests; command startup always
// supplies the graph explicitly.
func newProviderCapabilitySource(capability config.ProviderCapabilityConfig, graph ...providerCapabilityReadiness) (*provider.StaticCapabilitySource, error) {
	if len(graph) > 1 {
		return nil, errors.New("construct Provider capability source: at most one readiness graph is allowed")
	}
	var readiness providerCapabilityReadiness
	if len(graph) == 1 {
		readiness = graph[0]
	}
	profiles := make([]provider.SnapshotRestoreProfile, len(capability.SnapshotRestoreProfiles))
	for index, profile := range capability.SnapshotRestoreProfiles {
		profiles[index] = provider.SnapshotRestoreProfile{
			ProfileID:    profile.ProfileID,
			Level:        provider.SnapshotLevel(profile.Level),
			SuiteID:      provider.CompatibilitySuiteID(profile.SuiteID),
			SuiteVersion: profile.SuiteVersion,
			SuiteDigest:  provider.SHA256Digest(profile.SuiteDigest),
		}
	}
	var capabilities []provider.Capability
	var runtimeProfiles []provider.RuntimeProfile
	if capability.CodingShellEnabled {
		if missing := readiness.missingDependencies(); len(missing) != 0 {
			return nil, fmt.Errorf("coding/shell profile enabled but dependency graph is incomplete: %s", strings.Join(missing, ", "))
		}
		capabilities = []provider.Capability{
			{ID: "sandbox.exec", Versions: []string{config.ProviderCodingShellCapabilityVersion}, Profiles: []string{config.ProviderCodingShellExecProfileID}},
			{ID: "sandbox.terminal", Versions: []string{config.ProviderCodingShellCapabilityVersion}, Profiles: []string{config.ProviderCodingShellTerminalProfileID}},
		}
		runtimeProfiles = []provider.RuntimeProfile{{
			ID:                   config.ProviderCodingShellRuntimeProfileID,
			IsolationClass:       "container",
			RuntimeClassName:     config.ProviderCodingShellRuntimeClassName,
			Architecture:         []string{"amd64"},
			CapabilityProfileIDs: []string{config.ProviderCodingShellExecProfileID, config.ProviderCodingShellTerminalProfileID},
		}}
	}
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(capability.ProviderRevisionID, provider.Limits{
		MaxCPUMillis:             capability.Limits.MaxCPUMillis,
		MaxMemoryBytes:           capability.Limits.MaxMemoryBytes,
		MaxEphemeralStorageBytes: capability.Limits.MaxEphemeralStorageBytes,
		MaxWorkspaceBytes:        cloneOptionalInt64(capability.Limits.MaxWorkspaceBytes),
		MaxGPUCount:              cloneOptionalInt64(capability.Limits.MaxGPUCount),
		MaxLeaseSeconds:          capability.Limits.MaxLeaseSeconds,
		MaxExecSeconds:           capability.Limits.MaxExecSeconds,
	}, capabilities, runtimeProfiles, profiles)
	if err != nil {
		return nil, fmt.Errorf("construct Provider capability snapshot: %w", err)
	}
	source, err := provider.NewStaticCapabilitySource(snapshot)
	if err != nil {
		return nil, fmt.Errorf("construct Provider capability source: %w", err)
	}
	return source, nil
}

func cloneOptionalInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func validateServeConfiguration(application *config.ApplicationConfig, serverConfig *config.ServerConfig, runtimeConfig *config.RuntimeConfig, repositoryConfig *config.RepositoryConfig) error {
	if application == nil || serverConfig == nil || runtimeConfig == nil || repositoryConfig == nil {
		return errors.New("application, server, runtime, and repository configuration are required")
	}
	if err := serverConfig.Provider.Validate(); err != nil {
		return fmt.Errorf("validate Provider configuration: %w", err)
	}
	if serverConfig.Provider.Transport.Enabled && serverConfig.API.Port == serverConfig.Provider.Transport.Address.Port {
		return errors.New("server.api and server.provider transport must use different ports")
	}
	if application.Mode == config.ApplicationProductionMode && runtimeConfig.Driver == config.RuntimeFakeDriver {
		return errors.New("production mode requires a real runtime driver")
	}
	if application.Mode == config.ApplicationProductionMode && repositoryConfig.Driver == config.RepositoryMemoryDriver {
		return errors.New("production mode requires a persistent repository")
	}
	if application.Mode == config.ApplicationProductionMode && (serverConfig.Provider.Lifecycle.Enabled || serverConfig.Provider.Exec.Enabled || serverConfig.Provider.Terminal.Enabled || serverConfig.Provider.Artifact.Enabled || serverConfig.Provider.Usage.Enabled) {
		return errors.New("production mode rejects Provider lifecycle, exec, terminal, artifact, and usage drivers until production-capable adapters pass their release gates")
	}
	if runtimeConfig.Driver == config.RuntimeDockerDriver && repositoryConfig.Driver == config.RepositoryMemoryDriver {
		return errors.New("docker runtime requires a persistent repository")
	}
	if application.Mode == config.ApplicationProductionMode {
		if !isLoopbackHost(serverConfig.API.Host) {
			return errors.New("production mode requires server.api.host to be a loopback address until API authentication is implemented")
		}
		if runtimeConfig.Driver == config.RuntimeDockerDriver {
			if !isSHA256PinnedImage(runtimeConfig.Docker.Image) {
				return errors.New("production mode requires runtime.docker.image pinned by sha256 digest")
			}
			if err := validateProductionDockerHost(runtimeConfig.Docker.Host); err != nil {
				return err
			}
		}
	}
	return nil
}

func isSHA256PinnedImage(image string) bool {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false
	}
	digested, ok := named.(reference.Digested)
	return ok && digested.Digest().Algorithm() == digest.SHA256 && digested.Digest().Validate() == nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateProductionDockerHost(configuredHost string) error {
	host := configuredHost
	if host == "" {
		host = os.Getenv("DOCKER_HOST")
	}
	if host == "" || strings.HasPrefix(host, "unix://") {
		return nil
	}
	if strings.HasPrefix(host, "https://") || strings.HasPrefix(host, "ssh://") {
		return nil
	}
	if strings.HasPrefix(host, "tcp://") && os.Getenv("DOCKER_TLS_VERIFY") != "" && os.Getenv("DOCKER_CERT_PATH") != "" {
		return nil
	}
	return fmt.Errorf("production mode rejects Docker host %q without an authenticated encrypted transport", host)
}

func newRuntimeDriver(ctx context.Context, runtimeConfig *config.RuntimeConfig) (instance.Driver, func() error, error) {
	if runtimeConfig == nil {
		return nil, nil, errors.New("runtime config is required")
	}
	switch runtimeConfig.Driver {
	case config.RuntimeFakeDriver:
		return fake.NewDriver(), func() error { return nil }, nil
	case config.RuntimeDockerDriver:
		cfg := runtimeConfig.Docker
		driver, err := dockerdriver.New(ctx, dockerdriver.Options{
			Host:                    cfg.Host,
			Image:                   cfg.Image,
			PullPolicy:              dockerdriver.PullPolicy(cfg.PullPolicy),
			MemoryBytes:             cfg.MemoryBytes,
			NanoCPUs:                cfg.NanoCPUs,
			PidsLimit:               cfg.PidsLimit,
			OperationTimeoutSeconds: cfg.OperationTimeoutSeconds,
			PullTimeoutSeconds:      cfg.PullTimeoutSeconds,
			StopTimeoutSeconds:      cfg.StopTimeoutSeconds,
			User:                    cfg.User,
			Command:                 append([]string(nil), cfg.Command...),
			Namespace:               cfg.Namespace,
			ControllerID:            cfg.ControllerID,
		})
		if err != nil {
			return nil, nil, err
		}
		return driver, driver.Close, nil
	default:
		return nil, nil, errors.New("unsupported runtime driver")
	}
}

func newInstanceRepository(repositoryConfig *config.RepositoryConfig) (instance.Repository, error) {
	if repositoryConfig == nil {
		return nil, errors.New("repository config is required")
	}
	switch repositoryConfig.Driver {
	case config.RepositoryMemoryDriver:
		return memory.NewRepository(), nil
	case config.RepositoryFileDriver:
		repository, err := instancefile.NewRepository(repositoryConfig.File.Path)
		if err != nil {
			return nil, fmt.Errorf("open instance repository: %w", err)
		}
		return repository, nil
	default:
		return nil, errors.New("unsupported repository driver")
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
