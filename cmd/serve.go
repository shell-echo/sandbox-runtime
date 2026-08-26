package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
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
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	lifecyclecoordinator "github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	lifecycledocker "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/docker"
	lifecyclefake "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/fake"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	lifecyclefile "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/file"
	lifecyclememory "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/memory"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
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
	lifecycleApp, closeLifecycle, err := newProviderLifecycleApplication(ctx, providerConfig.Lifecycle)
	if err != nil {
		return nil, noOpProviderClose, err
	}

	source, err := newProviderCapabilitySource(providerConfig.Capability)
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeLifecycle())
	}
	protected, closeProtected, err := newProviderProtectedTransportOptions(providerConfig.ProtectedAdmission, systemAdmissionClock{})
	if err != nil {
		return nil, noOpProviderClose, errors.Join(err, closeLifecycle())
	}
	if protected != nil {
		protected.Application = lifecycleApp
		operationReader, readerErr := newProviderOperationReader(lifecycleApp, nil)
		if readerErr != nil {
			return nil, noOpProviderClose, errors.Join(readerErr, closeProtected(), closeLifecycle())
		}
		protected.OperationReader = operationReader
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
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("construct Provider API server: %w", err), closeProtected(), closeLifecycle())
	}
	return providerServer, func() error { return errors.Join(closeProtected(), closeLifecycle()) }, nil
}

// newProviderOperationReader composes only the operation families whose
// application boundaries were explicitly injected. Artifact and usage
// dependencies remain absent from the default composition root until a real
// source/stager and collector are configured; the transport then fails closed
// rather than exposing a partial or synthetic operation surface.
func newProviderOperationReader(lifecycleApp providerapi.LifecycleApplication, artifactApp providerapi.ArtifactApplication) (provideroperation.Reader, error) {
	readers := make([]provideroperation.Reader, 0, 2)
	if lifecycleApp != nil {
		reader, err := provideroperation.NewLifecycleReader(lifecycleApp)
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
	if !lifecycleConfig.Enabled {
		return nil, noOpProviderClose, nil
	}
	if err := lifecycleConfig.Validate(); err != nil {
		return nil, noOpProviderClose, fmt.Errorf("validate Provider lifecycle configuration: %w", err)
	}
	var lifecycleRepo lifecyclerepository.Repository
	switch lifecycleConfig.Repository.Driver {
	case config.ProviderLifecycleMemoryRepository:
		lifecycleRepo = lifecyclememory.NewRepository()
	case config.ProviderLifecycleFileRepository:
		repo, err := lifecyclefile.NewRepository(lifecycleConfig.Repository.File.Path)
		if err != nil {
			return nil, noOpProviderClose, fmt.Errorf("open Provider lifecycle repository: %w", err)
		}
		lifecycleRepo = repo
	default:
		return nil, noOpProviderClose, fmt.Errorf("unsupported Provider lifecycle repository %q", lifecycleConfig.Repository.Driver)
	}
	var driver lifecyclecoordinator.Driver
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
			return nil, noOpProviderClose, fmt.Errorf("construct Provider Docker lifecycle driver: %w", err)
		}
		driver = dockerDriver
		closeDriver = dockerDriver.Close
	default:
		_ = lifecycleRepo.Close()
		return nil, noOpProviderClose, fmt.Errorf("unsupported Provider lifecycle driver %q", lifecycleConfig.Driver)
	}
	application, err := lifecycleapplication.New(lifecycleRepo, driver, systemAdmissionClock{})
	if err != nil {
		_ = errors.Join(closeDriver(), lifecycleRepo.Close())
		return nil, noOpProviderClose, fmt.Errorf("construct Provider lifecycle application: %w", err)
	}
	if err := application.Recover(ctx); err != nil {
		return nil, noOpProviderClose, errors.Join(fmt.Errorf("recover Provider lifecycle: %w", err), closeDriver(), lifecycleRepo.Close())
	}
	return application, func() error { return errors.Join(closeDriver(), lifecycleRepo.Close()) }, nil
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
	if application.Mode == config.ApplicationProductionMode && serverConfig.Provider.Lifecycle.Enabled {
		return errors.New("production mode rejects Provider lifecycle drivers until a production-capable adapter passes its release gates")
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
