package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/option"
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
