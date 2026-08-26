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
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
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
