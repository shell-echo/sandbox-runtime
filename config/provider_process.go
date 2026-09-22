package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/option"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/spf13/viper"
)

const (
	defaultProviderProcessHost = "127.0.0.1"
	defaultProviderProcessPort = 8444
)

type ProviderProcessProfile string

type ProviderDeploymentLevel string

const (
	ProviderProductionLevel           ProviderDeploymentLevel = "production"
	ProviderLocalCandidateLevel       ProviderDeploymentLevel = "local_candidate"
	ProviderProcessCodingShellProfile ProviderProcessProfile  = "coding_shell"
	ProviderProcessDesktopProfile     ProviderProcessProfile  = "desktop"
)

// ProviderProcessConfig is the independent production Provider role. It has
// no local /instances listener, local repository, Product identity, or public
// Gateway configuration.
type ProviderProcessConfig struct {
	Enabled            bool                            `mapstructure:"enabled"`
	DeploymentLevel    ProviderDeploymentLevel         `mapstructure:"deployment_level"`
	Profile            ProviderProcessProfile          `mapstructure:"profile"`
	Transport          ProviderTransportConfig         `mapstructure:"transport"`
	Probe              option.HTTP                     `mapstructure:"probe"`
	Capability         ProviderProcessCapabilityConfig `mapstructure:"capability"`
	ProtectedAdmission ProviderProcessAdmissionConfig  `mapstructure:"protected_admission"`
	Postgres           ProviderPostgresConfig          `mapstructure:"postgres"`
	Coding             ProviderProcessCodingConfig     `mapstructure:"coding"`
	Desktop            ProviderProcessDesktopConfig    `mapstructure:"desktop"`
	Reconciliation     ProviderReconciliationConfig    `mapstructure:"reconciliation"`
}

type ProviderProcessCapabilityConfig struct {
	ProviderRevisionID      string                         `mapstructure:"provider_revision_id"`
	Limits                  ProviderLimitsConfig           `mapstructure:"limits"`
	SnapshotRestoreProfiles []ProviderCompatibilityProfile `mapstructure:"snapshot_restore_profiles"`
}

type ProviderProcessAdmissionConfig struct {
	Issuer                   string                                 `mapstructure:"issuer"`
	ProviderInstanceAudience string                                 `mapstructure:"provider_instance_audience"`
	TrustedVerificationKeys  []ProviderTrustedVerificationKeyConfig `mapstructure:"trusted_verification_keys"`
}

type ProviderPostgresConfig struct {
	MigrationDSNFile        string `mapstructure:"migration_dsn_file"`
	RuntimeDSNFile          string `mapstructure:"runtime_dsn_file"`
	MigrationRole           string `mapstructure:"migration_role"`
	RuntimeRole             string `mapstructure:"runtime_role"`
	StartupTimeoutSeconds   int    `mapstructure:"startup_timeout_seconds"`
	OperationTimeoutSeconds int    `mapstructure:"operation_timeout_seconds"`
	MigrationMaxConnections int32  `mapstructure:"migration_max_connections"`
	MaxConnections          int32  `mapstructure:"max_connections"`
	MinConnections          int32  `mapstructure:"min_connections"`
}

type ProviderProcessCodingConfig struct {
	Lifecycle ProviderLifecycleDockerConfig `mapstructure:"lifecycle"`
	Terminal  ProviderTerminalConfig        `mapstructure:"terminal"`
	Artifact  ProviderArtifactConfig        `mapstructure:"artifact"`
}

type ProviderProcessDesktopConfig struct {
	Architecture                 string                          `mapstructure:"architecture"`
	ExecutorURL                  string                          `mapstructure:"executor_url"`
	BrokerMuxSocketPath          string                          `mapstructure:"broker_mux_socket_path"`
	ExecutorCABundleFile         string                          `mapstructure:"executor_ca_bundle_file"`
	ExecutorCertificateFile      string                          `mapstructure:"executor_certificate_file"`
	ExecutorPrivateKeyFile       string                          `mapstructure:"executor_private_key_file"`
	ExecutorIdentity             string                          `mapstructure:"executor_identity"`
	ExecutorBridgeKeyID          string                          `mapstructure:"executor_bridge_key_id"`
	ExecutorBridgePrivateKeyFile string                          `mapstructure:"executor_bridge_private_key_file"`
	LocalCandidateManifestFile   string                          `mapstructure:"local_candidate_manifest_file"`
	UsageRetentionSeconds        int                             `mapstructure:"usage_retention_seconds"`
	ShutdownCleanupSeconds       int                             `mapstructure:"shutdown_cleanup_seconds"`
	Docker                       ProviderDesktopDockerConfig     `mapstructure:"docker"`
	Provenance                   ProviderBrowserProvenanceConfig `mapstructure:"provenance"`
	RestrictedNetwork            ProviderBrowserNetworkConfig    `mapstructure:"restricted_network"`
}

type ProviderDesktopDockerConfig struct {
	Host                     string `mapstructure:"host"`
	Image                    string `mapstructure:"image"`
	PullPolicy               string `mapstructure:"pull_policy"`
	MemoryBytes              int64  `mapstructure:"memory_bytes"`
	NanoCPUs                 int64  `mapstructure:"nano_cpus"`
	PidsLimit                int64  `mapstructure:"pids_limit"`
	InputsBytes              int64  `mapstructure:"inputs_bytes"`
	TmpfsBytes               int64  `mapstructure:"tmpfs_bytes"`
	WorkspaceBytes           int64  `mapstructure:"workspace_bytes"`
	OutputsBytes             int64  `mapstructure:"outputs_bytes"`
	OperationTimeoutSeconds  int    `mapstructure:"operation_timeout_seconds"`
	ProvenanceTimeoutSeconds int    `mapstructure:"provenance_timeout_seconds"`
	PullTimeoutSeconds       int    `mapstructure:"pull_timeout_seconds"`
	StopTimeoutSeconds       int    `mapstructure:"stop_timeout_seconds"`
	DataRoot                 string `mapstructure:"data_root"`
	ProductionManifestPath   string `mapstructure:"production_release_manifest_path"`
	CandidateManifestPath    string `mapstructure:"local_candidate_image_manifest_path"`
	Namespace                string `mapstructure:"namespace"`
	ControllerID             string `mapstructure:"controller_id"`
	NetworkPolicyReference   string `mapstructure:"network_policy_reference"`
	MaxSessionsPerSandbox    int    `mapstructure:"max_sessions_per_sandbox"`
	MaxSessionsPerController int    `mapstructure:"max_sessions_per_controller"`
}

type ProviderReconciliationConfig struct {
	IntervalSeconds int `mapstructure:"interval_seconds"`
	TimeoutSeconds  int `mapstructure:"timeout_seconds"`
}

func defaultProviderProcessConfig() *ProviderProcessConfig {
	return &ProviderProcessConfig{
		DeploymentLevel: ProviderProductionLevel,
		Transport:       ProviderTransportConfig{Address: providerDefaultHTTP(defaultProviderProcessHost, defaultProviderProcessPort)},
		Probe:           providerDefaultHTTP("127.0.0.1", 8084),
		Postgres:        ProviderPostgresConfig{StartupTimeoutSeconds: 10, OperationTimeoutSeconds: 3, MigrationMaxConnections: 1, MaxConnections: 12, MinConnections: 1},
		Coding: ProviderProcessCodingConfig{
			Lifecycle: defaultServerConfig().Provider.Lifecycle.Docker,
			Terminal:  defaultServerConfig().Provider.Terminal,
			Artifact:  defaultServerConfig().Provider.Artifact,
		},
		Desktop: ProviderProcessDesktopConfig{
			UsageRetentionSeconds: 3600, ShutdownCleanupSeconds: 10,
			Docker: ProviderDesktopDockerConfig{PullPolicy: "if_not_present", MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
				InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
				OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
				Namespace: "default", MaxSessionsPerSandbox: 1, MaxSessionsPerController: 16,
			},
			RestrictedNetwork: ProviderBrowserNetworkConfig{Namespace: "default", MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64, OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10},
		},
		Reconciliation: ProviderReconciliationConfig{IntervalSeconds: 1, TimeoutSeconds: 5},
	}
}

// optionHTTP is kept local to avoid exporting another configuration default.
func providerDefaultHTTP(host string, port int) option.HTTP {
	return option.HTTP{Host: host, Port: port}
}

func (c *ProviderProcessConfig) Validate() error { //nolint:cyclop
	if c == nil {
		return errors.New("provider_process configuration is required")
	}
	if !c.Enabled {
		return nil
	}
	if c.DeploymentLevel != ProviderProductionLevel && c.DeploymentLevel != ProviderLocalCandidateLevel {
		return errors.New("provider_process requires deployment_level=production or local_candidate")
	}
	if !c.Transport.Enabled {
		return errors.New("provider_process transport must be enabled")
	}
	if err := c.Transport.validateEnabled(); err != nil {
		return fmt.Errorf("provider_process.transport: %w", err)
	}
	if net.ParseIP(c.Transport.Address.Host) == nil {
		return errors.New("provider_process.transport.address.host must be an explicit IP address")
	}
	if err := c.Probe.Validate(); err != nil || !exactLoopbackIP(c.Probe.Host) || c.Probe.Port == c.Transport.Address.Port {
		return errors.New("provider_process.probe must use a distinct explicit loopback address")
	}
	capability := ProviderCapabilityConfig{ProviderRevisionID: c.Capability.ProviderRevisionID, Limits: c.Capability.Limits, SnapshotRestoreProfiles: c.Capability.SnapshotRestoreProfiles}
	if err := capability.validateEnabled(); err != nil {
		return fmt.Errorf("provider_process.capability: %w", err)
	}
	if err := c.validateAdmission(); err != nil {
		return err
	}
	if err := c.validatePostgres(); err != nil {
		return err
	}
	if c.Reconciliation.IntervalSeconds < 1 || c.Reconciliation.IntervalSeconds > 60 || c.Reconciliation.TimeoutSeconds < 1 || c.Reconciliation.TimeoutSeconds > 30 || c.Reconciliation.TimeoutSeconds > c.Reconciliation.IntervalSeconds*5 {
		return errors.New("provider_process reconciliation bounds are invalid")
	}
	switch c.Profile {
	case ProviderProcessCodingShellProfile:
		if c.DeploymentLevel != ProviderProductionLevel {
			return errors.New("coding_shell Provider profile requires deployment_level=production")
		}
		if err := c.validateCoding(); err != nil {
			return err
		}
		if c.Desktop.Architecture != "" || c.Desktop.Docker.Image != "" {
			return errors.New("Desktop runtime authority is forbidden for the coding_shell Provider profile")
		}
	case ProviderProcessDesktopProfile:
		if err := c.validateDesktop(); err != nil {
			return err
		}
		if c.Coding.Lifecycle.Image != "" {
			return errors.New("coding runtime authority is forbidden for the desktop Provider profile")
		}
	default:
		return fmt.Errorf("provider_process.profile %q is invalid", c.Profile)
	}
	return c.validateAuthorityPaths()
}

func (c *ProviderProcessConfig) validateAdmission() error {
	if _, err := admission.NewAdmissionAuthority(c.ProtectedAdmission.Issuer, c.Capability.ProviderRevisionID, c.ProtectedAdmission.ProviderInstanceAudience); err != nil {
		return fmt.Errorf("provider_process.protected_admission: %w", err)
	}
	keys := c.ProtectedAdmission.TrustedVerificationKeys
	if len(keys) < 1 || len(keys) > 32 {
		return errors.New("provider_process protected admission requires 1..32 trusted verification keys")
	}
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if strings.TrimSpace(key.ID) == "" || len(key.ID) > 128 || (key.Algorithm != "EdDSA" && key.Algorithm != "ES256") {
			return errors.New("provider_process trusted verification key is invalid")
		}
		if _, exists := seen[key.ID]; exists {
			return errors.New("provider_process trusted verification key IDs must be unique")
		}
		seen[key.ID] = struct{}{}
	}
	return nil
}

func (c *ProviderProcessConfig) validatePostgres() error {
	p := c.Postgres
	if p.StartupTimeoutSeconds < 1 || p.StartupTimeoutSeconds > 60 || p.OperationTimeoutSeconds < 1 || p.OperationTimeoutSeconds > 30 || p.MigrationMaxConnections < 1 || p.MigrationMaxConnections > 4 || p.MaxConnections < 1 || p.MaxConnections > 64 || p.MinConnections < 0 || p.MinConnections > p.MaxConnections {
		return errors.New("provider_process PostgreSQL connection bounds are invalid")
	}
	if !postgresRolePattern.MatchString(p.MigrationRole) || !postgresRolePattern.MatchString(p.RuntimeRole) || p.MigrationRole == p.RuntimeRole {
		return errors.New("provider_process migration and runtime PostgreSQL roles must be distinct explicit identifiers")
	}
	return nil
}

func (c *ProviderProcessConfig) validateCoding() error {
	lifecycleConfig := ProviderLifecycleConfig{Enabled: true, Driver: ProviderLifecycleDockerDriver, Repository: ProviderLifecycleRepositoryConfig{Driver: ProviderLifecycleFileRepository, File: ProviderLifecycleRepositoryFileConfig{Path: "unused"}}, Docker: c.Coding.Lifecycle}
	if err := lifecycleConfig.Validate(); err != nil {
		return fmt.Errorf("provider_process.coding.lifecycle: %w", err)
	}
	if !filepath.IsAbs(c.Coding.Lifecycle.DataRoot) {
		return errors.New("provider_process.coding.lifecycle.data_root must be absolute")
	}
	terminal := c.Coding.Terminal
	terminal.Enabled, terminal.ConnectEnabled = true, true
	terminal.SessionRepositoryFile, terminal.ReferenceRegistryFile = "sessions", "references"
	if err := terminal.Validate(); err != nil {
		return fmt.Errorf("provider_process.coding.terminal: %w", err)
	}
	artifact := c.Coding.Artifact
	artifact.Enabled, artifact.RepositoryFile = true, "artifacts"
	if err := artifact.Validate(); err != nil {
		return fmt.Errorf("provider_process.coding.artifact: %w", err)
	}
	if !filepath.IsAbs(artifact.StagingRoot) {
		return errors.New("provider_process.coding.artifact.staging_root must be absolute")
	}
	return nil
}

func (c *ProviderProcessConfig) validateDesktop() error {
	d := c.Desktop
	if d.Architecture != "amd64" && d.Architecture != "arm64" || d.UsageRetentionSeconds < 60 || d.UsageRetentionSeconds > 2_592_000 || d.ShutdownCleanupSeconds < 1 || d.ShutdownCleanupSeconds > 300 {
		return errors.New("provider_process Desktop architecture or duration is invalid")
	}
	o := d.Docker
	validImage := c.DeploymentLevel == ProviderProductionLevel && o.Image == desktopimage.LockedPublication().Image() && providerPinnedImagePattern.MatchString(o.Image) && (o.PullPolicy == "never" || o.PullPolicy == "if_not_present" || o.PullPolicy == "always")
	validManifest := c.DeploymentLevel == ProviderProductionLevel && filepath.IsAbs(o.ProductionManifestPath) && o.CandidateManifestPath == ""
	if c.DeploymentLevel == ProviderLocalCandidateLevel {
		validImage = providerSHA256Pattern.MatchString(o.Image) && o.PullPolicy == "never" && filepath.IsAbs(d.LocalCandidateManifestFile)
		validManifest = filepath.IsAbs(o.CandidateManifestPath) && o.ProductionManifestPath == ""
	}
	if !validImage || !validManifest || !filepath.IsAbs(o.DataRoot) || !providerOwnershipPattern.MatchString(o.Namespace) || !providerOwnershipPattern.MatchString(o.ControllerID) || !providerProfileIDPattern.MatchString(o.NetworkPolicyReference) || o.MaxSessionsPerSandbox != 1 || o.MaxSessionsPerController < 1 || o.MaxSessionsPerController > 1000 {
		return errors.New("provider_process Desktop image, paths, ownership, policy, or capacity is invalid")
	}
	const maxBytes = int64(64 << 30)
	for _, value := range []int64{o.MemoryBytes, o.InputsBytes, o.TmpfsBytes, o.WorkspaceBytes, o.OutputsBytes} {
		if value <= 0 || value > maxBytes {
			return errors.New("provider_process Desktop byte limits are invalid")
		}
	}
	if o.NanoCPUs <= 0 || o.NanoCPUs > 64_000_000_000 || o.PidsLimit <= 0 || o.PidsLimit > 4096 || o.OperationTimeoutSeconds < 1 || o.OperationTimeoutSeconds > 600 || o.ProvenanceTimeoutSeconds < 1 || o.ProvenanceTimeoutSeconds > 600 || o.PullTimeoutSeconds < 1 || o.PullTimeoutSeconds > 600 || o.StopTimeoutSeconds < 0 || o.StopTimeoutSeconds > 600 {
		return errors.New("provider_process Desktop resources or timeouts are invalid")
	}
	if c.DeploymentLevel == ProviderProductionLevel {
		if !filepath.IsAbs(d.Provenance.ExecutablePath) || !providerSHA256Pattern.MatchString(d.Provenance.ExecutableDigest) || d.LocalCandidateManifestFile != "" {
			return errors.New("provider_process Desktop production provenance or candidate boundary is invalid")
		}
	} else if d.Provenance.ExecutablePath != "" || d.Provenance.ExecutableDigest != "" {
		return errors.New("provider_process local candidate cannot claim production provenance")
	}
	if err := d.RestrictedNetwork.validate(o.NetworkPolicyReference); err != nil {
		return fmt.Errorf("provider_process.desktop.restricted_network: %w", err)
	}
	if d.RestrictedNetwork.Namespace != o.Namespace || d.RestrictedNetwork.ControllerID != o.ControllerID || strings.TrimSpace(d.RestrictedNetwork.Host) != strings.TrimSpace(o.Host) {
		return errors.New("provider_process Desktop runtime and restricted-network ownership must match")
	}
	if d.ExecutorURL != "" {
		if c.DeploymentLevel == ProviderProductionLevel {
			return errors.New("provider_process production Desktop executor requires the Slice 7 published v2 runtime")
		}
		parsed, err := url.Parse(d.ExecutorURL)
		if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("provider_process Desktop executor_url is invalid")
		}
		if !providerProfileIDPattern.MatchString(d.ExecutorIdentity) || !providerProfileIDPattern.MatchString(d.ExecutorBridgeKeyID) {
			return errors.New("provider_process Desktop executor identity or bridge key ID is invalid")
		}
		for name, path := range map[string]string{"executor CA": d.ExecutorCABundleFile, "executor certificate": d.ExecutorCertificateFile, "executor key": d.ExecutorPrivateKeyFile, "executor bridge key": d.ExecutorBridgePrivateKeyFile} {
			if err := validateAbsoluteSecretPath("provider_process Desktop "+name, path); err != nil {
				return err
			}
		}
		if !filepath.IsAbs(d.BrokerMuxSocketPath) || filepath.Clean(d.BrokerMuxSocketPath) != d.BrokerMuxSocketPath || !providerDesktopBrokerMuxSocketPattern.MatchString(filepath.Base(d.BrokerMuxSocketPath)) {
			return errors.New("provider_process Desktop broker mux socket path is invalid")
		}
	} else if c.DeploymentLevel == ProviderLocalCandidateLevel {
		return errors.New("provider_process local candidate requires the Desktop executor")
	} else if d.ExecutorCABundleFile != "" || d.ExecutorCertificateFile != "" || d.ExecutorPrivateKeyFile != "" || d.ExecutorIdentity != "" || d.ExecutorBridgeKeyID != "" || d.ExecutorBridgePrivateKeyFile != "" || d.BrokerMuxSocketPath != "" {
		return errors.New("provider_process Desktop executor credentials require executor_url")
	}
	return nil
}

func (c *ProviderProcessConfig) validateAuthorityPaths() error {
	paths := []struct{ name, value string }{
		{"transport certificate", c.Transport.ServerCertificateFile}, {"transport key", c.Transport.ServerPrivateKeyFile},
		{"client CA", c.Transport.ClientCABundleFile}, {"migration DSN", c.Postgres.MigrationDSNFile}, {"runtime DSN", c.Postgres.RuntimeDSNFile},
	}
	if c.Transport.Private.Enabled {
		paths = append(paths,
			struct{ name, value string }{"private transport certificate", c.Transport.Private.ServerCertificateFile},
			struct{ name, value string }{"private transport key", c.Transport.Private.ServerPrivateKeyFile},
			struct{ name, value string }{"private client CA", c.Transport.Private.ClientCABundleFile},
		)
	}
	if c.Desktop.ExecutorURL != "" {
		paths = append(paths,
			struct{ name, value string }{"Desktop executor CA", c.Desktop.ExecutorCABundleFile},
			struct{ name, value string }{"Desktop executor certificate", c.Desktop.ExecutorCertificateFile},
			struct{ name, value string }{"Desktop executor key", c.Desktop.ExecutorPrivateKeyFile},
			struct{ name, value string }{"Desktop executor bridge key", c.Desktop.ExecutorBridgePrivateKeyFile},
		)
	}
	if c.DeploymentLevel == ProviderLocalCandidateLevel {
		paths = append(paths, struct{ name, value string }{"Desktop local candidate manifest", c.Desktop.LocalCandidateManifestFile})
	}
	for index, key := range c.ProtectedAdmission.TrustedVerificationKeys {
		paths = append(paths, struct{ name, value string }{fmt.Sprintf("trusted verification key %d", index), key.PublicKeyFile})
	}
	seen := make(map[string]struct{}, len(paths))
	for _, item := range paths {
		if err := validateAbsoluteSecretPath("provider_process "+item.name, item.value); err != nil {
			return err
		}
		clean := filepath.Clean(item.value)
		if _, exists := seen[clean]; exists {
			return errors.New("provider_process authority files must use distinct paths")
		}
		seen[clean] = struct{}{}
	}
	return nil
}

var ProviderProcess = defaultProviderProcessConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		if err := bindEnvDefaults(v, "provider_process", defaultProviderProcessConfig()); err != nil {
			return nil, fmt.Errorf("bind config %q: %w", "provider_process", err)
		}
		section := v.Sub("provider_process")
		if section == nil {
			return nil, errors.New("parse config \"provider_process\": section unavailable")
		}
		candidate := &ProviderProcessConfig{}
		if err := section.UnmarshalExact(candidate); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", "provider_process", err)
		}
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		return func() error { ProviderProcess = candidate; return nil }, nil
	})
}
