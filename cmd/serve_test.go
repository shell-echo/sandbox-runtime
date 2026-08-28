package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
	artifactfile "github.com/shell-echo/sandbox-runtime/provider/artifact/repository/file"
	execfile "github.com/shell-echo/sandbox-runtime/provider/exec/repository/file"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	lifecycledocker "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/docker"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
	sessionreferencefile "github.com/shell-echo/sandbox-runtime/provider/session/reference/repository/file"
	sessionreferencememory "github.com/shell-echo/sandbox-runtime/provider/session/reference/repository/memory"
	sessionfile "github.com/shell-echo/sandbox-runtime/provider/session/repository/file"
	providerterminal "github.com/shell-echo/sandbox-runtime/provider/terminal"
	usagefile "github.com/shell-echo/sandbox-runtime/provider/usage/repository/file"
)

// TestServeCmdRegistered confirms the serve subcommand is wired onto the root
// command.
func TestServeCmdRegistered(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "serve" {
			return
		}
	}
	t.Error("serve command not registered on rootCmd")
}

func TestNewRuntimeDriverDocker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_ping" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("API-Version", "1.55")
		w.Header().Set("OSType", "linux")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runtimeConfig := &config.RuntimeConfig{
		Driver: config.RuntimeDockerDriver,
		Docker: config.RuntimeDockerConfig{
			Host:                    server.URL,
			Image:                   "example/shell:v1",
			PullPolicy:              config.DockerPullNever,
			MemoryBytes:             256 << 20,
			NanoCPUs:                500_000_000,
			PidsLimit:               128,
			OperationTimeoutSeconds: 2,
			PullTimeoutSeconds:      2,
			StopTimeoutSeconds:      5,
			User:                    "65532:65532",
			Command:                 []string{"/bin/sh", "-c", "sleep 3600"},
			Namespace:               "test",
			ControllerID:            "controller-test",
		},
	}
	driver, closeDriver, err := newRuntimeDriver(context.Background(), runtimeConfig)
	if err != nil || driver == nil || closeDriver == nil {
		t.Fatalf("newRuntimeDriver = %T, %v", driver, err)
	}
	if err := closeDriver(); err != nil {
		t.Fatalf("close docker driver: %v", err)
	}
}

func TestNewRuntimeDriverFake(t *testing.T) {
	driver, closeDriver, err := newRuntimeDriver(context.Background(), &config.RuntimeConfig{Driver: config.RuntimeFakeDriver})
	if err != nil || driver == nil || closeDriver == nil {
		t.Fatalf("newRuntimeDriver = %T, %v", driver, err)
	}
	if err := closeDriver(); err != nil {
		t.Fatalf("close fake driver: %v", err)
	}
}

func TestNewRuntimeDriverRejectsInvalidConfig(t *testing.T) {
	if _, _, err := newRuntimeDriver(context.Background(), nil); err == nil {
		t.Fatal("expected nil config error")
	}
	if _, _, err := newRuntimeDriver(context.Background(), &config.RuntimeConfig{Driver: "unknown"}); err == nil {
		t.Fatal("expected unsupported driver error")
	}
}

func TestValidateServeConfigurationRejectsFakeProduction(t *testing.T) {
	application := &config.ApplicationConfig{Mode: config.ApplicationProductionMode}
	serverConfig := &config.ServerConfig{API: option.HTTP{Host: "127.0.0.1", Port: 8080}}
	runtimeConfig := &config.RuntimeConfig{Driver: config.RuntimeFakeDriver}
	repositoryConfig := &config.RepositoryConfig{Driver: config.RepositoryMemoryDriver}
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("expected fake production configuration error")
	}
	application.Mode = config.ApplicationDevelopmentMode
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err != nil {
		t.Fatalf("development fake configuration: %v", err)
	}
	runtimeConfig.Driver = config.RuntimeDockerDriver
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("expected Docker memory repository error")
	}
}

func TestValidateServeConfigurationProductionBoundaries(t *testing.T) {
	t.Setenv("DOCKER_HOST", "")
	application := &config.ApplicationConfig{Mode: config.ApplicationProductionMode}
	serverConfig := &config.ServerConfig{API: option.HTTP{Host: "127.0.0.1", Port: 8080}}
	runtimeConfig := &config.RuntimeConfig{Driver: config.RuntimeDockerDriver, Docker: config.RuntimeDockerConfig{
		Image: "example/shell@sha256:" + strings.Repeat("a", 64),
	}}
	repositoryConfig := &config.RepositoryConfig{Driver: config.RepositoryFileDriver, File: config.RepositoryFileConfig{Path: "state.json"}}
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err != nil {
		t.Fatalf("secure production config: %v", err)
	}
	serverConfig.API.Host = "0.0.0.0"
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("expected public unauthenticated listener rejection")
	}
	serverConfig.API.Host = "127.0.0.1"
	runtimeConfig.Docker.Image = "example/shell:latest"
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("expected mutable image rejection")
	}
	runtimeConfig.Docker.Image = "example/shell@sha256:" + strings.Repeat("a", 64)
	runtimeConfig.Docker.Host = "tcp://docker.example:2375"
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("expected plaintext remote Docker rejection")
	}
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", "/run/secrets/docker")
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err != nil {
		t.Fatalf("TLS-protected Docker host: %v", err)
	}
}

func TestValidateServeConfigurationRejectsDevelopmentProviderLifecycleInProduction(t *testing.T) {
	application := &config.ApplicationConfig{Mode: config.ApplicationProductionMode}
	serverConfig := &config.ServerConfig{API: option.HTTP{Host: "127.0.0.1", Port: 8080}, Provider: validProviderConfigForServeTest()}
	serverConfig.Provider.ProtectedAdmission = validProtectedAdmissionConfigForServeTest()
	serverConfig.Provider.Lifecycle = config.ProviderLifecycleConfig{
		Enabled: true,
		Driver:  config.ProviderLifecycleFakeDriver,
		Repository: config.ProviderLifecycleRepositoryConfig{
			Driver: config.ProviderLifecycleFileRepository,
			File:   config.ProviderLifecycleRepositoryFileConfig{Path: "provider-lifecycle.json"},
		},
	}
	runtimeConfig := &config.RuntimeConfig{Driver: config.RuntimeDockerDriver, Docker: config.RuntimeDockerConfig{Image: "example/shell@sha256:" + strings.Repeat("a", 64)}}
	repositoryConfig := &config.RepositoryConfig{Driver: config.RepositoryFileDriver, File: config.RepositoryFileConfig{Path: "instances.json"}}
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("production accepted the Provider fake lifecycle driver")
	}
	serverConfig.Provider.Lifecycle.Driver = config.ProviderLifecycleDockerDriver
	serverConfig.Provider.Lifecycle.Docker = config.ProviderLifecycleDockerConfig{
		Image: "example/shell@sha256:" + strings.Repeat("a", 64), PullPolicy: "if_not_present",
		MemoryBytes: 512 << 20, NanoCPUs: 1_000_000_000, PidsLimit: 256, TmpfsBytes: 64 << 20,
		OperationTimeoutSeconds: 30, PullTimeoutSeconds: 300, StopTimeoutSeconds: 10,
		User: "65532:65532", Command: []string{"sleep", "3600"}, DataRoot: "provider-runtime",
		Namespace: "provider-dev", ControllerID: "controller-one",
	}
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("production accepted the Provider Docker development lifecycle driver")
	}
}

func TestNewProviderLifecycleApplicationUsesIndependentComposition(t *testing.T) {
	lifecycleConfig := config.ProviderLifecycleConfig{
		Enabled: true,
		Driver:  config.ProviderLifecycleFakeDriver,
		Repository: config.ProviderLifecycleRepositoryConfig{
			Driver: config.ProviderLifecycleMemoryRepository,
		},
	}
	application, closeApplication, err := newProviderLifecycleApplication(context.Background(), lifecycleConfig)
	if err != nil || application == nil || closeApplication == nil {
		t.Fatalf("newProviderLifecycleApplication() = %T, %t, %v", application, closeApplication != nil, err)
	}
	if err := closeApplication(); err != nil {
		t.Fatalf("close Provider lifecycle application: %v", err)
	}
}

func TestNewProviderExecApplicationRequiresDependenciesAndReleasesRepository(t *testing.T) {
	disabled, closeDisabled, err := newProviderExecApplication(context.Background(), config.ProviderExecConfig{}, nil, nil, nil)
	if err != nil || disabled != nil || closeDisabled == nil {
		t.Fatalf("disabled exec composition = %T, %t, %v", disabled, closeDisabled != nil, err)
	}
	if err := closeDisabled(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider-exec.json")
	enabled := config.ProviderExecConfig{Enabled: true, RepositoryFile: path}
	if application, closeApplication, err := newProviderExecApplication(context.Background(), enabled, nil, nil, nil); err == nil || application != nil {
		t.Fatalf("missing dependencies = %T, %v", application, err)
	} else if closeErr := closeApplication(); closeErr != nil {
		t.Fatalf("close missing-dependency composition: %v", closeErr)
	}
	application, closeApplication, err := newProviderExecApplication(context.Background(), enabled, &lifecycleapplication.Application{}, &lifecycledocker.Driver{}, nil)
	if err != nil || application == nil || closeApplication == nil {
		t.Fatalf("exec composition = %T, %t, %v", application, closeApplication != nil, err)
	}
	if _, err := execfile.NewRepository(path); err == nil {
		t.Fatal("exec composition did not retain the single-controller repository lock")
	}
	if err := closeApplication(); err != nil {
		t.Fatal(err)
	}
	reopened, err := execfile.NewRepository(path)
	if err != nil {
		t.Fatalf("reopen released exec repository: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewProviderUsageCompositionRequiresExecAndReleasesRepository(t *testing.T) {
	store, collector, closeDisabled, err := newProviderUsageCollector(config.ProviderUsageConfig{})
	if err != nil || store != nil || collector != nil || closeDisabled == nil {
		t.Fatalf("disabled usage composition = %T, %T, %t, %v", store, collector, closeDisabled != nil, err)
	}
	if err := closeDisabled(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "provider-usage.json")
	enabled := config.ProviderUsageConfig{Enabled: true, RepositoryFile: path}
	store, collector, closeUsage, err := newProviderUsageCollector(enabled)
	if err != nil || store == nil || collector == nil || closeUsage == nil {
		t.Fatalf("usage collector composition = %T, %T, %t, %v", store, collector, closeUsage != nil, err)
	}
	if reader, err := newProviderUsageReader(enabled, store, collector, nil); err == nil || reader != nil {
		t.Fatalf("usage reader without exec = %T, %v", reader, err)
	}
	if _, err := usagefile.NewRepository(path, systemAdmissionClock{}); err == nil {
		t.Fatal("usage composition did not retain the single-controller repository lock")
	}
	if err := closeUsage(); err != nil {
		t.Fatal(err)
	}
	reopened, err := usagefile.NewRepository(path, systemAdmissionClock{})
	if err != nil {
		t.Fatalf("reopen released usage repository: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewProviderArtifactApplicationRequiresDependenciesAndReleasesRepository(t *testing.T) {
	disabled, closeDisabled, err := newProviderArtifactApplication(context.Background(), config.ProviderArtifactConfig{}, nil, nil)
	if err != nil || disabled != nil || closeDisabled == nil {
		t.Fatalf("disabled artifact composition = %T, %t, %v", disabled, closeDisabled != nil, err)
	}
	if err := closeDisabled(); err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	enabled := config.ProviderArtifactConfig{
		Enabled: true, RepositoryFile: filepath.Join(directory, "provider-artifacts.json"), StagingRoot: filepath.Join(directory, "staging"),
		ActiveContentCommand: []string{"true"}, MalwareCommand: []string{"true"},
	}
	if application, closeApplication, err := newProviderArtifactApplication(context.Background(), enabled, nil, nil); err == nil || application != nil {
		t.Fatalf("artifact application without runtime = %T, %v", application, err)
	} else if closeErr := closeApplication(); closeErr != nil {
		t.Fatalf("close missing-dependency composition: %v", closeErr)
	}

	missingScanner := enabled
	missingScanner.ActiveContentCommand = []string{filepath.Join(directory, "missing-scanner")}
	if application, closeApplication, err := newProviderArtifactApplication(context.Background(), missingScanner, &lifecycleapplication.Application{}, &lifecycledocker.Driver{}); err == nil || application != nil {
		t.Fatalf("artifact application with missing scanner = %T, %v", application, err)
	} else if closeErr := closeApplication(); closeErr != nil {
		t.Fatalf("close failed scanner composition: %v", closeErr)
	}

	application, closeApplication, err := newProviderArtifactApplication(context.Background(), enabled, &lifecycleapplication.Application{}, &lifecycledocker.Driver{})
	if err != nil || application == nil || closeApplication == nil {
		t.Fatalf("artifact application composition = %T, %t, %v", application, closeApplication != nil, err)
	}
	if _, err := artifactfile.NewRepository(enabled.RepositoryFile); err == nil {
		t.Fatal("artifact composition did not retain the single-controller repository lock")
	}
	if err := closeApplication(); err != nil {
		t.Fatal(err)
	}
	reopened, err := artifactfile.NewRepository(enabled.RepositoryFile)
	if err != nil {
		t.Fatalf("reopen released artifact repository: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewProviderTerminalApplicationRecoversBeforeReturningAndReleasesLocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/_ping" {
			http.NotFound(response, request)
			return
		}
		response.Header().Set("API-Version", "1.55")
		response.Header().Set("OSType", "linux")
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	driver, err := lifecycledocker.New(context.Background(), lifecycledocker.Options{
		Host: server.URL, Image: "example/shell@sha256:" + strings.Repeat("a", 64), PullPolicy: lifecycledocker.PullNever,
		MemoryBytes: 256 << 20, NanoCPUs: 500_000_000, PidsLimit: 128, TmpfsBytes: 32 << 20,
		OperationTimeoutSeconds: 2, PullTimeoutSeconds: 2, StopTimeoutSeconds: 1, User: "65532:65532",
		Command: []string{"sleep", "3600"}, DataRoot: filepath.Join(t.TempDir(), "runtime"), Namespace: "test", ControllerID: "controller-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	directory := t.TempDir()
	terminalConfig := config.ProviderTerminalConfig{
		Enabled: true, SessionRepositoryFile: filepath.Join(directory, "sessions.json"), ReferenceRegistryFile: filepath.Join(directory, "references.json"),
		RuntimeProfileID: "coding-shell-v1", CapabilityProfileID: "coding-shell-terminal-v1",
		BrokerPath: "/workspace/.sandbox-runtime/terminal-broker", ShellPath: "/bin/sh",
		MaxSessionsPerSandbox: 2, MaxSessionsPerController: 4, ShutdownCleanupSeconds: 1,
	}
	application, closeApplication, err := newProviderTerminalApplication(context.Background(), terminalConfig, &lifecycleapplication.Application{}, driver)
	if err != nil || application == nil || closeApplication == nil {
		t.Fatalf("newProviderTerminalApplication() = %T, closer %t, %v", application, closeApplication != nil, err)
	}
	if _, err := sessionfile.NewRepository(terminalConfig.SessionRepositoryFile); err == nil {
		t.Fatal("terminal composition did not retain the session repository lock")
	}
	if _, err := sessionreferencefile.NewRegistry(terminalConfig.ReferenceRegistryFile); err == nil {
		t.Fatal("terminal composition did not retain the reference registry lock")
	}
	if err := closeApplication(); err != nil {
		t.Fatal(err)
	}
	sessions, err := sessionfile.NewRepository(terminalConfig.SessionRepositoryFile)
	if err != nil {
		t.Fatalf("reopen terminal session repository: %v", err)
	}
	if err := sessions.Close(); err != nil {
		t.Fatal(err)
	}
	references, err := sessionreferencefile.NewRegistry(terminalConfig.ReferenceRegistryFile)
	if err != nil {
		t.Fatalf("reopen terminal reference registry: %v", err)
	}
	if err := references.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderTerminalApplicationShutdownRevokesBeforeIdentityBoundCleanup(t *testing.T) {
	now := time.Now().UTC()
	request := session.OpenRequest{
		SandboxID: "sandbox-terminal-close", ProviderRevisionID: "provider-revision-terminal-close",
		OperationID: "operation-terminal-close", AttemptID: "attempt-terminal-close", FencingToken: 1,
		IdempotencyKey: "terminal-close-key", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline: now.Add(time.Minute), ExpectedGeneration: 1, RuntimeSessionID: "session-terminal-close",
		RuntimeType: session.RuntimeTerminal, CapabilityProfileID: "terminal-v1", ExpiresAt: now.Add(30 * time.Second),
	}
	running, err := session.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	running, err = session.AttachAllocation(running, session.AllocationReceipt{
		Reference: "ref:terminal/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: now, ExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := sessionreferencememory.NewRegistry()
	registered, err := sessionreference.NewRecord("ref:session:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", running, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Create(context.Background(), registered); err != nil {
		t.Fatal(err)
	}
	order := make([]string, 0, 4)
	application := &providerTerminalApplication{
		authority:  &terminalShutdownAuthority{records: []session.Record{running}},
		runtime:    &terminalShutdownRuntime{order: &order},
		references: &terminalShutdownReferenceStore{Store: registry, order: &order},
		clock:      systemAdmissionClock{}, shutdownCleanup: time.Second,
		closeReferences: func() error { order = append(order, "references-close"); return registry.Close() },
		closeSession:    func() error { order = append(order, "sessions-close"); return nil },
	}
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}
	if err := application.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got, want := strings.Join(order, ","), "revoke,cleanup,references-close,sessions-close"; got != want {
		t.Fatalf("shutdown order = %q, want %q", got, want)
	}
}

func TestValidateServeConfigurationRejectsProviderPortCollision(t *testing.T) {
	application := &config.ApplicationConfig{Mode: config.ApplicationDevelopmentMode}
	serverConfig := &config.ServerConfig{
		API:      option.HTTP{Host: "127.0.0.1", Port: 8080},
		Provider: validProviderConfigForServeTest(),
	}
	serverConfig.Provider.Transport.Address = option.HTTP{Host: "127.0.0.2", Port: 8080}
	runtimeConfig := &config.RuntimeConfig{Driver: config.RuntimeFakeDriver}
	repositoryConfig := &config.RepositoryConfig{Driver: config.RepositoryMemoryDriver}
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("same local and Provider port accepted")
	}

	serverConfig.Provider.Transport.Address.Port = 8443
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err != nil {
		t.Fatalf("distinct listener ports rejected: %v", err)
	}

	serverConfig.Provider.Transport.Enabled = false
	serverConfig.Provider.Transport.Address.Port = serverConfig.API.Port
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err != nil {
		t.Fatalf("disabled Provider port placeholder rejected: %v", err)
	}
}

func TestNewInstanceRepository(t *testing.T) {
	if _, err := newInstanceRepository(nil); err == nil {
		t.Fatal("expected nil repository config error")
	}
	if _, err := newInstanceRepository(&config.RepositoryConfig{Driver: "unknown"}); err == nil {
		t.Fatal("expected unsupported repository error")
	}
	path := t.TempDir() + "/instances.json"
	repository, err := newInstanceRepository(&config.RepositoryConfig{
		Driver: config.RepositoryFileDriver,
		File:   config.RepositoryFileConfig{Path: path},
	})
	if err != nil || repository == nil {
		t.Fatalf("new file repository = %T, %v", repository, err)
	}
}

func TestNewProviderServerDisabledIsInert(t *testing.T) {
	providerServer, closeProvider, err := newProviderServer(context.Background(), config.ProviderConfig{})
	if err != nil || providerServer != nil || closeProvider == nil {
		t.Fatalf("newProviderServer() = %T, closer present %t, %v; want nil, non-nil closer, nil", providerServer, closeProvider != nil, err)
	}
	if err := closeProvider(); err != nil {
		t.Fatalf("close disabled Provider server: %v", err)
	}
}

func TestValidateServeConfigurationFailsClosedForInvalidProtectedAdmission(t *testing.T) {
	application := &config.ApplicationConfig{Mode: config.ApplicationProductionMode}
	serverConfig := &config.ServerConfig{API: option.HTTP{Host: "127.0.0.1", Port: 8080}, Provider: validProviderConfigForServeTest()}
	serverConfig.Provider.ProtectedAdmission = config.ProviderProtectedAdmissionConfig{Enabled: true}
	runtimeConfig := &config.RuntimeConfig{Driver: config.RuntimeDockerDriver, Docker: config.RuntimeDockerConfig{
		Image: "example/shell@sha256:" + strings.Repeat("a", 64),
	}}
	repositoryConfig := &config.RepositoryConfig{Driver: config.RepositoryFileDriver, File: config.RepositoryFileConfig{Path: "instances.json"}}
	if err := validateServeConfiguration(application, serverConfig, runtimeConfig, repositoryConfig); err == nil {
		t.Fatal("validateServeConfiguration accepted incomplete protected admission")
	}
}

func TestNewProviderProtectedTransportOptionsIsOptInAndReleasesGuard(t *testing.T) {
	clock := fixedAdmissionClock{now: time.Unix(1_000, 0).UTC()}
	disabled, closeDisabled, err := newProviderProtectedTransportOptions(config.ProviderProtectedAdmissionConfig{}, clock)
	if err != nil || disabled != nil {
		t.Fatalf("disabled protected transport = %#v, %v", disabled, err)
	}
	if err := closeDisabled(); err != nil {
		t.Fatalf("close disabled protected transport: %v", err)
	}

	directory := t.TempDir()
	keyPath := writeTrustedPublicKeyForServeTest(t, directory)
	statePath := filepath.Join(directory, "guard", "admission.json")
	protected := config.ProviderProtectedAdmissionConfig{
		Enabled:        true,
		GuardStateFile: statePath,
		TrustedVerificationKeys: []config.ProviderTrustedVerificationKeyConfig{{
			ID: "agent-platform-ed25519", Algorithm: "EdDSA", PublicKeyFile: keyPath,
		}},
	}
	options, closeProtected, err := newProviderProtectedTransportOptions(protected, clock)
	if err != nil || options == nil || options.Gate == nil || closeProtected == nil {
		t.Fatalf("newProviderProtectedTransportOptions() = %#v, closer present %t, %v", options, closeProtected != nil, err)
	}
	if _, err := admissionfile.NewGuard(statePath, clock); err == nil {
		t.Fatal("protected transport did not retain the single-controller guard lock")
	}
	if err := closeProtected(); err != nil {
		t.Fatalf("close protected transport: %v", err)
	}
	reopened, err := admissionfile.NewGuard(statePath, clock)
	if err != nil {
		t.Fatalf("reopen released guard: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened guard: %v", err)
	}
}

func TestNewProviderProtectedTransportOptionsFailsClosed(t *testing.T) {
	clock := fixedAdmissionClock{now: time.Unix(1_000, 0).UTC()}
	protected := config.ProviderProtectedAdmissionConfig{
		Enabled:        true,
		GuardStateFile: filepath.Join(t.TempDir(), "admission.json"),
		TrustedVerificationKeys: []config.ProviderTrustedVerificationKeyConfig{{
			ID: "agent-platform-ed25519", Algorithm: "EdDSA", PublicKeyFile: "missing.pem",
		}},
	}
	if options, closeProtected, err := newProviderProtectedTransportOptions(protected, clock); err == nil || options != nil {
		t.Fatalf("missing trusted key = %#v, %v", options, err)
	} else if closeErr := closeProtected(); closeErr != nil {
		t.Fatalf("close failed protected transport: %v", closeErr)
	}

	directory := t.TempDir()
	protected.TrustedVerificationKeys[0].PublicKeyFile = writeTrustedPublicKeyForServeTest(t, directory)
	protected.GuardStateFile = directory
	if options, closeProtected, err := newProviderProtectedTransportOptions(protected, clock); err == nil || options != nil {
		t.Fatalf("invalid guard state = %#v, %v", options, err)
	} else if closeErr := closeProtected(); closeErr != nil {
		t.Fatalf("close failed protected transport: %v", closeErr)
	}
}

func TestEnabledServersKeepsProviderSeparate(t *testing.T) {
	apiServer := &testLifecycleServer{}
	withoutProvider := enabledServers(apiServer, nil)
	if len(withoutProvider) != 1 || withoutProvider["api"] != apiServer {
		t.Fatalf("disabled server set = %#v", withoutProvider)
	}

	providerServer := &testLifecycleServer{}
	withProvider := enabledServers(apiServer, providerServer)
	if len(withProvider) != 2 || withProvider["api"] != apiServer || withProvider["provider"] != providerServer {
		t.Fatalf("enabled server set = %#v", withProvider)
	}
}

func TestNewProviderCapabilitySourceMapsAndFreezesConfiguration(t *testing.T) {
	workspace := int64(4096)
	gpu := int64(0)
	capability := validProviderCapabilityConfig(&workspace, &gpu)
	source, err := newProviderCapabilitySource(capability)
	if err != nil {
		t.Fatalf("newProviderCapabilitySource: %v", err)
	}

	workspace = 1
	gpu = 2
	capability.SnapshotRestoreProfiles[0].ProfileID = "mutated"
	snapshot, err := source.CapabilitySnapshot(context.Background())
	if err != nil {
		t.Fatalf("CapabilitySnapshot: %v", err)
	}
	if snapshot.ProviderRevisionID != "revision-1" || snapshot.APIVersion != provider.APIVersionV1 {
		t.Fatalf("snapshot identity = %#v", snapshot)
	}
	if snapshot.Limits.MaxWorkspaceBytes == nil || *snapshot.Limits.MaxWorkspaceBytes != 4096 ||
		snapshot.Limits.MaxGPUCount == nil || *snapshot.Limits.MaxGPUCount != 0 {
		t.Fatalf("snapshot optional limits = %#v", snapshot.Limits)
	}
	if len(snapshot.SnapshotRestoreProfiles) != 1 || snapshot.SnapshotRestoreProfiles[0].ProfileID != "profile-1" {
		t.Fatalf("snapshot profiles = %#v", snapshot.SnapshotRestoreProfiles)
	}
}

func TestNewProviderCapabilitySourceRejectsInvalidModel(t *testing.T) {
	capability := validProviderCapabilityConfig(nil, nil)
	capability.ProviderRevisionID = ""
	if _, err := newProviderCapabilitySource(capability); err == nil {
		t.Fatal("newProviderCapabilitySource() error = nil")
	}
}

func validProviderCapabilityConfig(workspace, gpu *int64) config.ProviderCapabilityConfig {
	return config.ProviderCapabilityConfig{
		ProviderRevisionID: "revision-1",
		Limits: config.ProviderLimitsConfig{
			MaxCPUMillis:             1000,
			MaxMemoryBytes:           1 << 30,
			MaxEphemeralStorageBytes: 1 << 30,
			MaxWorkspaceBytes:        workspace,
			MaxGPUCount:              gpu,
			MaxLeaseSeconds:          3600,
			MaxExecSeconds:           300,
		},
		SnapshotRestoreProfiles: []config.ProviderCompatibilityProfile{{
			ProfileID:    "profile-1",
			Level:        "workspace",
			SuiteID:      "sandbox-provider",
			SuiteVersion: "1.0.0",
			SuiteDigest:  "sha256:" + strings.Repeat("a", 64),
		}},
	}
}

type testLifecycleServer struct{}

func (*testLifecycleServer) Startup(context.Context) error  { return nil }
func (*testLifecycleServer) Shutdown(context.Context) error { return nil }

type terminalShutdownAuthority struct {
	session.CoordinationAuthority
	records []session.Record
}

func (a *terminalShutdownAuthority) ListOpen(context.Context) ([]session.Record, error) {
	result := make([]session.Record, len(a.records))
	for index, record := range a.records {
		result[index] = record.Clone()
	}
	return result, nil
}

type terminalShutdownReferenceStore struct {
	sessionreference.Store
	order *[]string
	mu    sync.Mutex
}

func (s *terminalShutdownReferenceStore) Revoke(ctx context.Context, value string, when time.Time) error {
	s.mu.Lock()
	*s.order = append(*s.order, "revoke")
	s.mu.Unlock()
	return s.Store.Revoke(ctx, value, when)
}

type terminalShutdownRuntime struct {
	order   *[]string
	receipt providerterminal.Receipt
	mu      sync.Mutex
}

func (*terminalShutdownRuntime) Allocate(context.Context, providerterminal.Allocation) (providerterminal.Receipt, error) {
	return providerterminal.Receipt{}, providerterminal.ErrTerminalUnsupported
}

func (*terminalShutdownRuntime) Observe(context.Context, providerterminal.Receipt) (providerterminal.Observation, error) {
	return providerterminal.Observation{}, providerterminal.ErrTerminalUnsupported
}

func (*terminalShutdownRuntime) Attach(context.Context, providerterminal.Receipt) (providerterminal.Stream, error) {
	return nil, providerterminal.ErrTerminalUnsupported
}

func (r *terminalShutdownRuntime) Cleanup(_ context.Context, receipt providerterminal.Receipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.receipt = receipt
	*r.order = append(*r.order, "cleanup")
	return nil
}

type fixedAdmissionClock struct{ now time.Time }

func (clock fixedAdmissionClock) Now() time.Time { return clock.now }

func validProviderConfigForServeTest() config.ProviderConfig {
	return config.ProviderConfig{
		Transport: config.ProviderTransportConfig{
			Enabled:                    true,
			Address:                    option.HTTP{Host: "127.0.0.1", Port: 8443},
			ServerCertificateFile:      "provider.crt",
			ServerPrivateKeyFile:       "provider.key",
			ClientCABundleFile:         "client-ca.pem",
			AllowedClientURIIdentities: []string{"spiffe://agent-platform/provider-client"},
		},
		Capability: config.ProviderCapabilityConfig{
			ProviderRevisionID: "provider-revision-1",
			Limits: config.ProviderLimitsConfig{
				MaxCPUMillis: 1000, MaxMemoryBytes: 1 << 30, MaxEphemeralStorageBytes: 1 << 30,
				MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
			},
			SnapshotRestoreProfiles: []config.ProviderCompatibilityProfile{{
				ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0",
				SuiteDigest: "sha256:" + strings.Repeat("a", 64),
			}},
		},
	}
}

func validProtectedAdmissionConfigForServeTest() config.ProviderProtectedAdmissionConfig {
	return config.ProviderProtectedAdmissionConfig{
		Enabled: true, GuardStateFile: "provider-admission.json",
		TrustedVerificationKeys: []config.ProviderTrustedVerificationKeyConfig{{ID: "key-1", Algorithm: "EdDSA", PublicKeyFile: "key.pem"}},
	}
}

func writeTrustedPublicKeyForServeTest(t *testing.T, directory string) string {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "trusted-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var _ admission.Clock = fixedAdmissionClock{}
var _ session.CoordinationAuthority = (*terminalShutdownAuthority)(nil)
var _ sessionreference.Store = (*terminalShutdownReferenceStore)(nil)
var _ providerterminal.Runtime = (*terminalShutdownRuntime)(nil)
