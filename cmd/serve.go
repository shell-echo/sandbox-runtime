package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/shell-echo/sandbox-runtime/config"
	dockerdriver "github.com/shell-echo/sandbox-runtime/driver/docker"
	"github.com/shell-echo/sandbox-runtime/driver/fake"
	"github.com/shell-echo/sandbox-runtime/instance"
	instancefile "github.com/shell-echo/sandbox-runtime/instance/file"
	"github.com/shell-echo/sandbox-runtime/instance/memory"
	"github.com/shell-echo/sandbox-runtime/provider"
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
	providerServer, err := newProviderServer(cmd.Context(), config.Server.Provider)
	if err != nil {
		return err
	}
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

func newProviderServer(ctx context.Context, providerConfig config.ProviderConfig) (server.Server, error) {
	if !providerConfig.Transport.Enabled {
		return nil, nil
	}
	if err := providerConfig.Validate(); err != nil {
		return nil, fmt.Errorf("validate Provider configuration: %w", err)
	}

	source, err := newProviderCapabilitySource(providerConfig.Capability)
	if err != nil {
		return nil, err
	}
	transport := providerConfig.Transport
	providerServer, err := providerapi.NewServer(ctx, providerapi.TransportOptions{
		Address:                    transport.Address,
		ServerCertificateFile:      transport.ServerCertificateFile,
		ServerPrivateKeyFile:       transport.ServerPrivateKeyFile,
		ClientCABundleFile:         transport.ClientCABundleFile,
		AllowedClientURIIdentities: append([]string(nil), transport.AllowedClientURIIdentities...),
	}, source)
	if err != nil {
		return nil, fmt.Errorf("construct Provider API server: %w", err)
	}
	return providerServer, nil
}

func newProviderCapabilitySource(capability config.ProviderCapabilityConfig) (*provider.StaticCapabilitySource, error) {
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
	snapshot, err := provider.NewCapabilitySnapshot(capability.ProviderRevisionID, provider.Limits{
		MaxCPUMillis:             capability.Limits.MaxCPUMillis,
		MaxMemoryBytes:           capability.Limits.MaxMemoryBytes,
		MaxEphemeralStorageBytes: capability.Limits.MaxEphemeralStorageBytes,
		MaxWorkspaceBytes:        cloneOptionalInt64(capability.Limits.MaxWorkspaceBytes),
		MaxGPUCount:              cloneOptionalInt64(capability.Limits.MaxGPUCount),
		MaxLeaseSeconds:          capability.Limits.MaxLeaseSeconds,
		MaxExecSeconds:           capability.Limits.MaxExecSeconds,
	}, profiles)
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
	if serverConfig.Provider.Transport.Enabled && serverConfig.API.Port == serverConfig.Provider.Transport.Address.Port {
		return errors.New("server.api and server.provider transport must use different ports")
	}
	if application.Mode == config.ApplicationProductionMode && runtimeConfig.Driver == config.RuntimeFakeDriver {
		return errors.New("production mode requires a real runtime driver")
	}
	if application.Mode == config.ApplicationProductionMode && repositoryConfig.Driver == config.RepositoryMemoryDriver {
		return errors.New("production mode requires a persistent repository")
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
