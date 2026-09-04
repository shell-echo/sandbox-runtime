package stack

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/option"
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
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	lifecyclefile "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/file"
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
)

type clock struct{}

func (clock) Now() time.Time { return time.Now().UTC() }

type Stack struct {
	provider *providerapi.Server
	gateway  interface {
		Startup(context.Context) error
		Shutdown(context.Context) error
	}
	closers []func() error
}

func Open(ctx context.Context, config Config) (_ *Stack, result error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Profile == ProfileBrowser {
		return openBrowser(ctx, config)
	}
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		return nil, err
	}
	if err := verifyRuntimeImage(ctx, config.RuntimeImage); err != nil {
		return nil, err
	}
	stack := &Stack{}
	defer func() {
		if result != nil {
			result = errors.Join(result, stack.Close())
		}
	}()

	lifecycleRepo, err := lifecyclefile.NewRepository(filepath.Join(config.StateRoot, "lifecycle.json"))
	if err != nil {
		return nil, err
	}
	stack.addCloser(lifecycleRepo.Close)
	runtimeUID, runtimeGID := os.Getuid(), os.Getgid()
	if runtimeUID == 0 {
		runtimeUID = 65532
	}
	if runtimeGID == 0 {
		runtimeGID = 65532
	}
	runtime, err := lifecycledocker.New(ctx, lifecycledocker.Options{
		Image: config.RuntimeImage, PullPolicy: lifecycledocker.PullNever,
		MemoryBytes: 256 << 20, NanoCPUs: 500_000_000, PidsLimit: 128, TmpfsBytes: 64 << 20,
		OperationTimeoutSeconds: 30, PullTimeoutSeconds: 90, StopTimeoutSeconds: 5,
		User: fmt.Sprintf("%d:%d", runtimeUID, runtimeGID), Command: []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
		DataRoot: config.RuntimeDataRoot, Namespace: "reference-e2e", ControllerID: config.RuntimeControllerID,
	})
	if err != nil {
		return nil, err
	}
	stack.addCloser(runtime.Close)
	var lifecycleDriver lifecyclecoordinator.Driver = runtime
	var lifecycleAuthority lifecyclerepository.Repository = lifecycleRepo
	lifecycleApp, err := lifecycleapplication.New(lifecycleAuthority, lifecycleDriver, clock{})
	if err != nil {
		return nil, err
	}
	stack.addCloser(lifecycleApp.Close)
	if err := lifecycleApp.Recover(ctx); err != nil {
		return nil, err
	}

	usageRepo, err := usagefile.NewRepository(filepath.Join(config.StateRoot, "usage.json"), clock{})
	if err != nil {
		return nil, err
	}
	stack.addCloser(usageRepo.Close)
	usageCollector, err := usageapplication.NewResultCollector(usageRepo, clock{})
	if err != nil {
		return nil, err
	}
	execRepo, err := execfile.NewRepository(filepath.Join(config.StateRoot, "exec.json"))
	if err != nil {
		return nil, err
	}
	stack.addCloser(execRepo.Close)
	var execAuthority execrepository.Repository = execRepo
	execCoordinator, err := execcoordinator.NewWithRuntimeAndResultObserver(execAuthority, runtime, runtime, runtime, runtime, usageCollector, clock{})
	if err != nil {
		return nil, err
	}
	execApp, err := execapplication.NewVerticalWithSupport(execCoordinator, lifecycleApp, runtime, clock{})
	if err != nil {
		return nil, err
	}
	if err := execApp.Recover(ctx); err != nil {
		return nil, err
	}
	usageReader, err := usageapplication.NewReader(usageRepo, execApp, usageCollector)
	if err != nil {
		return nil, err
	}

	terminalApp, resolver, terminalClosers, err := openTerminal(ctx, config, lifecycleApp, runtime)
	if err != nil {
		return nil, err
	}
	for _, closer := range terminalClosers {
		stack.addCloser(closer)
	}

	artifactRepo, err := artifactfile.NewRepository(filepath.Join(config.StateRoot, "artifacts.json"))
	if err != nil {
		return nil, err
	}
	stack.addCloser(artifactRepo.Close)
	activeContent, err := artifactstaging.NewCommandChecker([]string{"/usr/bin/true"})
	if err != nil {
		return nil, err
	}
	malware, err := artifactstaging.NewCommandChecker([]string{"/usr/bin/true"})
	if err != nil {
		return nil, err
	}
	stager, err := artifactstaging.New(runtime, tenantChecker{sandboxes: lifecycleApp}, activeContent, malware, filepath.Join(config.StateRoot, "staging"), clock{})
	if err != nil {
		return nil, err
	}
	artifactApp, err := artifactapplication.NewVertical(artifactRepo, stager, lifecycleApp, stager, clock{})
	if err != nil {
		return nil, err
	}
	stack.addCloser(artifactApp.Close)
	if _, err := artifactApp.Recover(ctx); err != nil {
		return nil, err
	}

	operationReader, err := aggregateOperations(lifecycleApp, execApp, terminalApp, artifactApp)
	if err != nil {
		return nil, err
	}
	protected, closeAdmission, err := protectedOptions(config)
	if err != nil {
		return nil, err
	}
	stack.addCloser(closeAdmission)
	protected.Application = lifecycleApp
	protected.ExecApplication = execApp
	protected.SessionApplication = terminalApp
	protected.ArtifactApplication = artifactApp
	protected.UsageEvidenceReader = usageReader
	protected.OperationReader = operationReader

	capabilities, err := capabilitySource(config.ProviderRevisionID)
	if err != nil {
		return nil, err
	}
	providerHost, providerPort, err := splitAddress(config.ProviderAddress)
	if err != nil {
		return nil, err
	}
	providerServer, err := providerapi.NewServer(ctx, providerapi.TransportOptions{
		Address:               option.HTTP{Host: providerHost, Port: providerPort},
		ServerCertificateFile: config.ProviderCertificateFile, ServerPrivateKeyFile: config.ProviderPrivateKeyFile,
		ClientCABundleFile: config.ClientCAFile, AllowedClientURIIdentities: append([]string(nil), config.AllowedClientURIs...),
		Protected: protected,
	}, capabilities)
	if err != nil {
		return nil, err
	}
	stack.provider = providerServer

	referenceGateway, err := newReferenceGateway(config, resolver, nil)
	if err != nil {
		return nil, err
	}
	stack.addCloser(referenceGateway.Close)
	stack.gateway, err = newPublicGatewayServer(config, referenceGateway.Handler())
	if err != nil {
		return nil, err
	}
	return stack, nil
}

func (s *Stack) Run(ctx context.Context) error {
	if s == nil || s.provider == nil || s.gateway == nil {
		return errors.New("reference stack is unavailable")
	}
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- s.provider.Startup(ctx) }()
	go func() { errorsChannel <- s.gateway.Startup(ctx) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return errors.Join(s.gateway.Shutdown(shutdown), s.provider.Shutdown(shutdown))
	case err := <-errorsChannel:
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return errors.Join(err, s.gateway.Shutdown(shutdown), s.provider.Shutdown(shutdown))
	}
}

func (s *Stack) Close() error {
	if s == nil {
		return nil
	}
	var result error
	for index := len(s.closers) - 1; index >= 0; index-- {
		result = errors.Join(result, s.closers[index]())
	}
	s.closers = nil
	return result
}

func (s *Stack) addCloser(closer func() error) { s.closers = append(s.closers, closer) }

type terminalRegistrar struct{ registrar *sessionreference.Registrar }

func (r terminalRegistrar) RegisterHandoff(ctx context.Context, source session.Record) (session.EndpointEvidence, error) {
	registration, err := r.registrar.Register(ctx, source)
	return registration.Evidence, err
}

func openTerminal(ctx context.Context, config Config, sandboxes *lifecycleapplication.Application, runtime *lifecycledocker.Driver) (*sessionapplication.Vertical, *sessionreference.Resolver, []func() error, error) {
	sessions, err := sessionfile.NewRepository(filepath.Join(config.StateRoot, "sessions.json"))
	if err != nil {
		return nil, nil, nil, err
	}
	references, err := sessionreferencefile.NewRegistry(filepath.Join(config.StateRoot, "references.json"))
	if err != nil {
		_ = sessions.Close()
		return nil, nil, nil, err
	}
	terminalRuntime, err := lifecycledocker.NewTerminalRuntime(runtime, lifecycledocker.TerminalOptions{
		BrokerPath: config.TerminalBrokerPath, ShellPath: "/bin/e2e-shell",
		MaxSessionsPerSandbox: 4, MaxSessionsPerController: 16, Clock: clock{},
	})
	if err != nil {
		_ = errors.Join(references.Close(), sessions.Close())
		return nil, nil, nil, err
	}
	registrar, err := sessionreference.NewRegistrar(references, clock{}, nil)
	if err != nil {
		_ = errors.Join(references.Close(), sessions.Close())
		return nil, nil, nil, err
	}
	vertical, err := sessionapplication.NewVerticalWithHandoffRegistrar(sessions, terminalRuntime, sandboxes, sessionapplication.TerminalProfile{
		RuntimeProfileID: "sandbox-runtime-coding-shell-v1", CapabilityProfileID: "terminal-v1", WorkingDirectory: "/workspace",
	}, terminalRegistrar{registrar: registrar}, clock{})
	if err != nil {
		_ = errors.Join(references.Close(), sessions.Close())
		return nil, nil, nil, err
	}
	if _, err := vertical.Recover(ctx); err != nil {
		_ = errors.Join(references.Close(), sessions.Close())
		return nil, nil, nil, err
	}
	resolver, err := sessionreference.NewResolver(references, sessions, terminalRuntime, clock{})
	if err != nil {
		_ = errors.Join(references.Close(), sessions.Close())
		return nil, nil, nil, err
	}
	return vertical, resolver, []func() error{sessions.Close, references.Close}, nil
}

type tenantChecker struct {
	sandboxes *lifecycleapplication.Application
}

func (c tenantChecker) CheckTenantBinding(ctx context.Context, request artifact.Request) (artifact.CheckStatus, error) {
	sandbox, err := c.sandboxes.GetSandbox(ctx, request.SandboxID)
	if err != nil {
		return artifact.CheckNotRun, err
	}
	if sandbox.Generation > math.MaxInt64 || int64(sandbox.Generation) != request.ExpectedGeneration {
		return artifact.CheckNotRun, artifact.ErrGenerationConflict
	}
	if sandbox.TenantID != request.TenantID {
		return artifact.CheckFailed, nil
	}
	if sandbox.ObservedState != lifecycle.ObservedReady || sandbox.ObservedGeneration != sandbox.Generation || !sandbox.LeaseExpiresAt.After(clock{}.Now()) {
		return artifact.CheckNotRun, artifact.ErrSandboxNotReady
	}
	return artifact.CheckPassed, nil
}

func aggregateOperations(lifecycleApp *lifecycleapplication.Application, execApp *execapplication.Vertical, sessionApp *sessionapplication.Vertical, artifactApp *artifactapplication.Vertical) (provideroperation.Reader, error) {
	lifecycleReader, err := provideroperation.NewLifecycleReader(lifecycleApp)
	if err != nil {
		return nil, err
	}
	artifactReader, err := provideroperation.NewArtifactReader(artifactApp)
	if err != nil {
		return nil, err
	}
	sessionReader, err := provideroperation.NewSessionReader(sessionApp)
	if err != nil {
		return nil, err
	}
	return provideroperation.NewAggregator(lifecycleReader, execApp, sessionReader, artifactReader)
}

func protectedOptions(config Config) (*providerapi.ProtectedTransportOptions, func() error, error) {
	files := make([]admissionfile.TrustedKeyFile, len(config.TrustedJWSKeys))
	for index, key := range config.TrustedJWSKeys {
		files[index] = admissionfile.TrustedKeyFile{ID: admission.KeyID(key.ID), Algorithm: admission.Algorithm(key.Algorithm), Path: key.Path}
	}
	keys, err := admissionfile.LoadTrustedKeySource(files)
	if err != nil {
		return nil, nil, err
	}
	guard, err := admissionfile.NewGuard(filepath.Join(config.StateRoot, "admission.json"), clock{})
	if err != nil {
		return nil, nil, err
	}
	gate, err := admission.NewProtectedOperationGate(keys, clock{}, guard)
	if err != nil {
		_ = guard.Close()
		return nil, nil, err
	}
	return &providerapi.ProtectedTransportOptions{Gate: gate}, guard.Close, nil
}

func capabilitySource(providerRevisionID string) (*provider.StaticCapabilitySource, error) {
	workspace := int64(1 << 30)
	gpu := int64(0)
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(providerRevisionID, provider.Limits{
		MaxCPUMillis: 1000, MaxMemoryBytes: 1 << 30, MaxEphemeralStorageBytes: 1 << 30,
		MaxWorkspaceBytes: &workspace, MaxGPUCount: &gpu, MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
	}, []provider.Capability{
		{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}},
		{ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}},
	}, []provider.RuntimeProfile{{
		ID: "sandbox-runtime-coding-shell-v1", IsolationClass: "container", RuntimeClassName: "sandbox-runtime-coding-shell",
		Architecture: []string{"amd64"}, CapabilityProfileIDs: []string{"exec-v1", "terminal-v1"},
	}}, []provider.SnapshotRestoreProfile{{
		ProfileID: "sandbox-snapshot-workspace-v1", Level: provider.SnapshotLevelWorkspace,
		SuiteID: provider.CompatibilitySuiteSandboxProvider, SuiteVersion: "1.0.0",
		SuiteDigest: provider.SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}})
	if err != nil {
		return nil, err
	}
	return provider.NewStaticCapabilitySource(snapshot)
}

func splitAddress(address string) (string, int, error) {
	host, encodedPort, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, errors.New("invalid loopback address")
	}
	port, err := strconv.Atoi(encodedPort)
	if err != nil {
		return "", 0, errors.New("invalid loopback port")
	}
	if host != "127.0.0.1" || port < 1 || port > 65535 {
		return "", 0, errors.New("reference stack requires a bounded IPv4 loopback address")
	}
	return host, port, nil
}

func verifyRuntimeImage(ctx context.Context, image string) error {
	apiClient, err := client.New(client.FromEnv)
	if err != nil {
		return fmt.Errorf("create Docker image verifier: %w", err)
	}
	defer apiClient.Close()
	inspection, err := apiClient.ImageInspect(ctx, image)
	if err != nil {
		return fmt.Errorf("inspect runtime image %q: %w", image, err)
	}
	if inspection.Os != "linux" || inspection.Architecture != "amd64" {
		return fmt.Errorf("runtime image %q platform = %s/%s, want linux/amd64", image, inspection.Os, inspection.Architecture)
	}
	return nil
}

var _ usage.EvidenceReader = (*usageapplication.Reader)(nil)
var _ providerexec.ResultObserver = (*usageapplication.ResultCollector)(nil)
var _ providerterminal.Runtime = (*lifecycledocker.TerminalRuntime)(nil)
