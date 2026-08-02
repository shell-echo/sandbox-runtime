package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
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

func TestValidateServeConfigurationRejectsProviderPortCollision(t *testing.T) {
	application := &config.ApplicationConfig{Mode: config.ApplicationDevelopmentMode}
	serverConfig := &config.ServerConfig{
		API: option.HTTP{Host: "127.0.0.1", Port: 8080},
		Provider: config.ProviderConfig{Transport: config.ProviderTransportConfig{
			Enabled: true,
			Address: option.HTTP{Host: "127.0.0.2", Port: 8080},
		}},
	}
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
	providerServer, err := newProviderServer(context.Background(), config.ProviderConfig{})
	if err != nil || providerServer != nil {
		t.Fatalf("newProviderServer() = %T, %v; want nil, nil", providerServer, err)
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
