package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/internal/provideridentity"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

// Defaults for the server section, used when the config omits values.
const (
	defaultServerAPIHost = "127.0.0.1"
	defaultServerAPIPort = 8080
)

// ServerConfig is the parsed server section. The local API and Provider API are
// independent sibling listeners.
type ServerConfig struct {
	API      option.HTTP    `mapstructure:"api"`
	Provider ProviderConfig `mapstructure:"provider"`
}

// ProviderConfig keeps the Provider listener transport separate from the
// application capability document it serves.
type ProviderConfig struct {
	Transport          ProviderTransportConfig          `mapstructure:"transport"`
	Capability         ProviderCapabilityConfig         `mapstructure:"capability"`
	ProtectedAdmission ProviderProtectedAdmissionConfig `mapstructure:"protected_admission"`
	Lifecycle          ProviderLifecycleConfig          `mapstructure:"lifecycle"`
	Exec               ProviderExecConfig               `mapstructure:"exec"`
	Terminal           ProviderTerminalConfig           `mapstructure:"terminal"`
	Artifact           ProviderArtifactConfig           `mapstructure:"artifact"`
	Usage              ProviderUsageConfig              `mapstructure:"usage"`
	Browser            ProviderBrowserConfig            `mapstructure:"browser"`
}

// ProviderLifecycleDriver identifies a Provider-local runtime implementation.
// It is intentionally separate from the local instance runtime driver.
type ProviderLifecycleDriver string

const (
	ProviderLifecycleFakeDriver    ProviderLifecycleDriver = "fake"
	ProviderLifecycleDockerDriver  ProviderLifecycleDriver = "docker"
	ProviderLifecycleBrowserDriver ProviderLifecycleDriver = "browser"
)

// ProviderLifecycleRepositoryDriver identifies Provider-local persistence.
type ProviderLifecycleRepositoryDriver string

const (
	ProviderLifecycleMemoryRepository ProviderLifecycleRepositoryDriver = "memory"
	ProviderLifecycleFileRepository   ProviderLifecycleRepositoryDriver = "file"
)

type ProviderLifecycleRepositoryFileConfig struct {
	Path string `mapstructure:"path"`
}

// ProviderLifecycleRepositoryConfig is independent from the /instances
// repository configuration and its durability claims.
type ProviderLifecycleRepositoryConfig struct {
	Driver ProviderLifecycleRepositoryDriver     `mapstructure:"driver"`
	File   ProviderLifecycleRepositoryFileConfig `mapstructure:"file"`
}

// ProviderLifecycleDockerConfig is intentionally independent from the local
// runtime.docker configuration. It configures only Provider-owned resources.
type ProviderLifecycleDockerConfig struct {
	Host                    string   `mapstructure:"host"`
	Image                   string   `mapstructure:"image"`
	PullPolicy              string   `mapstructure:"pull_policy"`
	MemoryBytes             int64    `mapstructure:"memory_bytes"`
	NanoCPUs                int64    `mapstructure:"nano_cpus"`
	PidsLimit               int64    `mapstructure:"pids_limit"`
	TmpfsBytes              int64    `mapstructure:"tmpfs_bytes"`
	OperationTimeoutSeconds int      `mapstructure:"operation_timeout_seconds"`
	PullTimeoutSeconds      int      `mapstructure:"pull_timeout_seconds"`
	StopTimeoutSeconds      int      `mapstructure:"stop_timeout_seconds"`
	User                    string   `mapstructure:"user"`
	Command                 []string `mapstructure:"command"`
	DataRoot                string   `mapstructure:"data_root"`
	Namespace               string   `mapstructure:"namespace"`
	ControllerID            string   `mapstructure:"controller_id"`
}

// ProviderLifecycleConfig controls composition of the authorized Provider
// lifecycle application. Disabled configuration is inert.
type ProviderLifecycleConfig struct {
	Enabled    bool                              `mapstructure:"enabled"`
	Driver     ProviderLifecycleDriver           `mapstructure:"driver"`
	Repository ProviderLifecycleRepositoryConfig `mapstructure:"repository"`
	Docker     ProviderLifecycleDockerConfig     `mapstructure:"docker"`
}

// ProviderExecConfig enables the P2.5e single-controller exec vertical. Its
// ledger is independent from lifecycle and local /instances persistence.
type ProviderExecConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	RepositoryFile string `mapstructure:"repository_file"`
}

// ProviderTerminalConfig enables the single-controller development terminal
// vertical. It never configures a public Gateway, caller identity, or
// capability advertisement.
type ProviderTerminalConfig struct {
	Enabled                  bool   `mapstructure:"enabled"`
	SessionRepositoryFile    string `mapstructure:"session_repository_file"`
	ReferenceRegistryFile    string `mapstructure:"reference_registry_file"`
	RuntimeProfileID         string `mapstructure:"runtime_profile_id"`
	CapabilityProfileID      string `mapstructure:"capability_profile_id"`
	BrokerPath               string `mapstructure:"broker_path"`
	ShellPath                string `mapstructure:"shell_path"`
	MaxSessionsPerSandbox    int    `mapstructure:"max_sessions_per_sandbox"`
	MaxSessionsPerController int    `mapstructure:"max_sessions_per_controller"`
	ShutdownCleanupSeconds   int    `mapstructure:"shutdown_cleanup_seconds"`
}

// ProviderArtifactConfig enables provider-local /outputs staging. Scanner
// commands are direct argv arrays; content is supplied only through stdin.
type ProviderArtifactConfig struct {
	Enabled              bool     `mapstructure:"enabled"`
	RepositoryFile       string   `mapstructure:"repository_file"`
	StagingRoot          string   `mapstructure:"staging_root"`
	ActiveContentCommand []string `mapstructure:"active_content_command"`
	MalwareCommand       []string `mapstructure:"malware_command"`
}

// ProviderUsageConfig enables durable evidence derived from composed exec
// results. It does not configure pricing, accounting, or billing.
type ProviderUsageConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	RepositoryFile string `mapstructure:"repository_file"`
}

// ProviderBrowserConfig controls the default-disabled development Browser
// vertical. It contains Provider-local runtime inputs only; caller identity,
// authorization, revocation, audit, and the public Gateway remain outside this
// configuration surface.
type ProviderBrowserConfig struct {
	Enabled                bool                            `mapstructure:"enabled"`
	SessionRepositoryFile  string                          `mapstructure:"session_repository_file"`
	ReferenceRegistryFile  string                          `mapstructure:"reference_registry_file"`
	ShutdownCleanupSeconds int                             `mapstructure:"shutdown_cleanup_seconds"`
	UsageRetentionSeconds  int                             `mapstructure:"usage_retention_seconds"`
	Docker                 ProviderBrowserDockerConfig     `mapstructure:"docker"`
	Provenance             ProviderBrowserProvenanceConfig `mapstructure:"provenance"`
	RestrictedNetwork      ProviderBrowserNetworkConfig    `mapstructure:"restricted_network"`
}

type ProviderBrowserDockerConfig struct {
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
	ManifestPath             string `mapstructure:"manifest_path"`
	SeccompPath              string `mapstructure:"seccomp_path"`
	Namespace                string `mapstructure:"namespace"`
	ControllerID             string `mapstructure:"controller_id"`
	NetworkPolicyReference   string `mapstructure:"network_policy_reference"`
	MaxSessionsPerSandbox    int    `mapstructure:"max_sessions_per_sandbox"`
	MaxSessionsPerController int    `mapstructure:"max_sessions_per_controller"`
}

type ProviderBrowserProvenanceConfig struct {
	ExecutablePath   string `mapstructure:"executable_path"`
	ExecutableDigest string `mapstructure:"executable_digest"`
}

type ProviderBrowserNetworkPolicyConfig struct {
	Reference    string   `mapstructure:"reference"`
	AllowedHosts []string `mapstructure:"allowed_hosts"`
}

type ProviderBrowserNetworkConfig struct {
	Host                    string                               `mapstructure:"host"`
	GatewayImage            string                               `mapstructure:"gateway_image"`
	UplinkNetwork           string                               `mapstructure:"uplink_network"`
	Namespace               string                               `mapstructure:"namespace"`
	ControllerID            string                               `mapstructure:"controller_id"`
	Policies                []ProviderBrowserNetworkPolicyConfig `mapstructure:"policies"`
	MemoryBytes             int64                                `mapstructure:"memory_bytes"`
	NanoCPUs                int64                                `mapstructure:"nano_cpus"`
	PidsLimit               int64                                `mapstructure:"pids_limit"`
	OperationTimeoutSeconds int                                  `mapstructure:"operation_timeout_seconds"`
	StopTimeoutSeconds      int                                  `mapstructure:"stop_timeout_seconds"`
}

// ProviderTransportConfig configures the dedicated, mTLS-only Provider
// listener. TLS policy is fixed by the transport implementation, not exposed as
// a downgradeable configuration value.
type ProviderTransportConfig struct {
	Enabled                    bool        `mapstructure:"enabled"`
	Address                    option.HTTP `mapstructure:"address"`
	ServerCertificateFile      string      `mapstructure:"server_certificate_file"`
	ServerPrivateKeyFile       string      `mapstructure:"server_private_key_file"`
	ClientCABundleFile         string      `mapstructure:"client_ca_bundle_file"`
	AllowedClientURIIdentities []string    `mapstructure:"allowed_client_uri_identities"`
}

// ProviderCapabilityConfig is the application-owned startup capability
// configuration. Compatibility profiles are metadata only and do not
// advertise or authorize a runtime capability.
type ProviderCapabilityConfig struct {
	// CodingShellEnabled explicitly requests the canonical coding/shell
	// capability profile. Advertisement is still gated by the command
	// composition readiness graph; this flag must never be treated as proof
	// that the dependency graph is complete.
	CodingShellEnabled      bool                           `mapstructure:"coding_shell_enabled"`
	ProviderRevisionID      string                         `mapstructure:"provider_revision_id"`
	Limits                  ProviderLimitsConfig           `mapstructure:"limits"`
	SnapshotRestoreProfiles []ProviderCompatibilityProfile `mapstructure:"snapshot_restore_profiles"`
}

// Provider coding/shell identifiers are locked by the repository-owned
// Provider v1 Contract. They are not operator-selectable advertisement IDs.
const (
	ProviderCodingShellRuntimeProfileID  = "sandbox-runtime-coding-shell-v1"
	ProviderCodingShellRuntimeClassName  = "sandbox-runtime-coding-shell"
	ProviderCodingShellExecProfileID     = "exec-v1"
	ProviderCodingShellTerminalProfileID = "terminal-v1"
	ProviderCodingShellCapabilityVersion = "1.0.0"
)

// ProviderProtectedAdmissionConfig controls the opt-in protected-operation
// boundary. It is independent from mTLS-only capability discovery so an
// omitted or disabled section cannot accidentally expose protected routes.
type ProviderProtectedAdmissionConfig struct {
	Enabled                 bool                                   `mapstructure:"enabled"`
	GuardStateFile          string                                 `mapstructure:"guard_state_file"`
	TrustedVerificationKeys []ProviderTrustedVerificationKeyConfig `mapstructure:"trusted_verification_keys"`
}

// ProviderTrustedVerificationKeyConfig identifies one operator-managed SPKI
// public-key file. It never accepts or configures private key material.
type ProviderTrustedVerificationKeyConfig struct {
	ID            string `mapstructure:"id"`
	Algorithm     string `mapstructure:"algorithm"`
	PublicKeyFile string `mapstructure:"public_key_file"`
}

// ProviderLimitsConfig declares hard limits for the Provider revision.
type ProviderLimitsConfig struct {
	MaxCPUMillis             int64  `mapstructure:"max_cpu_millis"`
	MaxMemoryBytes           int64  `mapstructure:"max_memory_bytes"`
	MaxEphemeralStorageBytes int64  `mapstructure:"max_ephemeral_storage_bytes"`
	MaxWorkspaceBytes        *int64 `mapstructure:"max_workspace_bytes"`
	MaxGPUCount              *int64 `mapstructure:"max_gpu_count"`
	MaxLeaseSeconds          int64  `mapstructure:"max_lease_seconds"`
	MaxExecSeconds           int64  `mapstructure:"max_exec_seconds"`
}

// ProviderCompatibilityProfile describes content-addressed snapshot/restore
// compatibility evidence without claiming that the capability is implemented.
type ProviderCompatibilityProfile struct {
	ProfileID    string `mapstructure:"profile_id"`
	Level        string `mapstructure:"level"`
	SuiteID      string `mapstructure:"suite_id"`
	SuiteVersion string `mapstructure:"suite_version"`
	SuiteDigest  string `mapstructure:"suite_digest"`
}

var (
	providerSuiteVersionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	providerSuiteDigestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	providerPinnedImagePattern    = regexp.MustCompile(`^.+@sha256:[0-9a-f]{64}$`)
	providerImmutableImagePattern = regexp.MustCompile(`^(?:sha256:[0-9a-f]{64}|.+@sha256:[0-9a-f]{64})$`)
	providerOwnershipPattern      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)
	providerProfileIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	providerDockerNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	providerSHA256Pattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// load registers the section's defaults and env bindings, unmarshals the merged
// (default < file < env) configuration over the receiver, and validates it.
func (c *ServerConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "server", defaultServerConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "server", err)
	}

	var wrap struct {
		Server ServerConfig `mapstructure:"server"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "server", err)
	}
	*c = wrap.Server

	if err := c.API.Validate(); err != nil {
		return fmt.Errorf("server.api %w", err)
	}
	if err := c.Provider.Validate(); err != nil {
		return fmt.Errorf("server.provider %w", err)
	}
	if c.Provider.Transport.Enabled && c.API.Port == c.Provider.Transport.Address.Port {
		return errors.New("server.api and server.provider transport must use different ports")
	}
	return nil
}

// Validate applies the conditional Provider configuration policy. Disabled
// configuration is inert and may retain template placeholders.
func (c *ProviderConfig) Validate() error {
	if !c.Transport.Enabled {
		if c.Capability.CodingShellEnabled || c.Lifecycle.Enabled || c.Exec.Enabled || c.Terminal.Enabled || c.Artifact.Enabled || c.Usage.Enabled || c.Browser.Enabled {
			return errors.New("lifecycle, exec, terminal, artifact, usage, and browser require Provider transport to be enabled")
		}
		return nil
	}
	if err := c.Transport.validateEnabled(); err != nil {
		return fmt.Errorf("transport %w", err)
	}
	if err := c.Capability.validateEnabled(); err != nil {
		return fmt.Errorf("capability %w", err)
	}
	if err := c.ProtectedAdmission.validateEnabled(); err != nil {
		return fmt.Errorf("protected admission %w", err)
	}
	if err := c.Lifecycle.validateEnabled(); err != nil {
		return fmt.Errorf("lifecycle %w", err)
	}
	if err := c.Exec.validateEnabled(); err != nil {
		return fmt.Errorf("exec %w", err)
	}
	if err := c.Terminal.validateEnabled(); err != nil {
		return fmt.Errorf("terminal %w", err)
	}
	if err := c.Artifact.validateEnabled(); err != nil {
		return fmt.Errorf("artifact %w", err)
	}
	if err := c.Usage.validateEnabled(); err != nil {
		return fmt.Errorf("usage %w", err)
	}
	if err := c.Browser.validateEnabled(); err != nil {
		return fmt.Errorf("browser %w", err)
	}
	if c.Lifecycle.Enabled && !c.ProtectedAdmission.Enabled {
		return errors.New("lifecycle requires protected admission to be enabled")
	}
	if c.Exec.Enabled {
		if !c.ProtectedAdmission.Enabled {
			return errors.New("exec requires protected admission to be enabled")
		}
		if !c.Lifecycle.Enabled || c.Lifecycle.Driver != ProviderLifecycleDockerDriver || c.Lifecycle.Repository.Driver != ProviderLifecycleFileRepository {
			return errors.New("exec requires the Docker Provider lifecycle and its file repository")
		}
	}
	if c.Terminal.Enabled {
		if !c.ProtectedAdmission.Enabled {
			return errors.New("terminal requires protected admission to be enabled")
		}
		if !c.Lifecycle.Enabled || c.Lifecycle.Driver != ProviderLifecycleDockerDriver || c.Lifecycle.Repository.Driver != ProviderLifecycleFileRepository {
			return errors.New("terminal requires the Docker Provider lifecycle and its file repository")
		}
	}
	if c.Artifact.Enabled {
		if !c.ProtectedAdmission.Enabled {
			return errors.New("artifact requires protected admission to be enabled")
		}
		if !c.Lifecycle.Enabled || c.Lifecycle.Driver != ProviderLifecycleDockerDriver || c.Lifecycle.Repository.Driver != ProviderLifecycleFileRepository {
			return errors.New("artifact requires the Docker Provider lifecycle and its file repository")
		}
	}
	if c.Browser.Enabled {
		if !c.ProtectedAdmission.Enabled {
			return errors.New("browser requires protected admission to be enabled")
		}
		if !c.Lifecycle.Enabled || c.Lifecycle.Driver != ProviderLifecycleBrowserDriver || c.Lifecycle.Repository.Driver != ProviderLifecycleFileRepository {
			return errors.New("browser requires the Browser lifecycle readiness driver and its file repository")
		}
		if !c.Usage.Enabled {
			return errors.New("browser requires durable usage evidence storage")
		}
	}
	if c.Usage.Enabled {
		if !c.ProtectedAdmission.Enabled || (!c.Exec.Enabled && !c.Browser.Enabled) {
			return errors.New("usage requires protected admission and a composed exec or Browser vertical")
		}
	}
	if c.Capability.CodingShellEnabled {
		if !c.Exec.Enabled || !c.Terminal.Enabled || !c.Artifact.Enabled || !c.Usage.Enabled {
			return errors.New("coding/shell profile requires exec, terminal, artifact, and usage to be enabled")
		}
		if c.Terminal.RuntimeProfileID != ProviderCodingShellRuntimeProfileID || c.Terminal.CapabilityProfileID != ProviderCodingShellTerminalProfileID {
			return errors.New("coding/shell profile requires the locked runtime and terminal capability profile IDs")
		}
	}
	files := make([]string, 0, 7)
	if c.ProtectedAdmission.Enabled {
		files = append(files, c.ProtectedAdmission.GuardStateFile)
	}
	if c.Lifecycle.Enabled && c.Lifecycle.Repository.Driver == ProviderLifecycleFileRepository {
		files = append(files, c.Lifecycle.Repository.File.Path)
	}
	if c.Exec.Enabled {
		files = append(files, c.Exec.RepositoryFile)
	}
	if c.Terminal.Enabled {
		files = append(files, c.Terminal.SessionRepositoryFile, c.Terminal.ReferenceRegistryFile)
	}
	if c.Artifact.Enabled {
		files = append(files, c.Artifact.RepositoryFile)
	}
	if c.Usage.Enabled {
		files = append(files, c.Usage.RepositoryFile)
	}
	if c.Browser.Enabled {
		files = append(files, c.Browser.SessionRepositoryFile, c.Browser.ReferenceRegistryFile)
	}
	seenFiles := make(map[string]struct{})
	for _, configured := range files {
		if strings.TrimSpace(configured) == "" {
			continue
		}
		clean := filepath.Clean(configured)
		if _, exists := seenFiles[clean]; exists {
			return errors.New("Provider component state files must be distinct")
		}
		seenFiles[clean] = struct{}{}
	}
	return nil
}

func (c *ProviderExecConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.RepositoryFile) == "" {
		return errors.New("repository_file must not be empty")
	}
	return nil
}

// Validate checks an explicitly enabled Provider exec configuration.
func (c ProviderExecConfig) Validate() error {
	return c.validateEnabled()
}

func (c *ProviderTerminalConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	for _, path := range []struct {
		name  string
		value string
	}{
		{"session_repository_file", c.SessionRepositoryFile},
		{"reference_registry_file", c.ReferenceRegistryFile},
	} {
		if strings.TrimSpace(path.value) == "" {
			return fmt.Errorf("%s must not be empty", path.name)
		}
	}
	if filepath.Clean(c.SessionRepositoryFile) == filepath.Clean(c.ReferenceRegistryFile) {
		return errors.New("session_repository_file and reference_registry_file must be distinct")
	}
	if !providerProfileIDPattern.MatchString(c.RuntimeProfileID) || !providerProfileIDPattern.MatchString(c.CapabilityProfileID) {
		return errors.New("runtime_profile_id and capability_profile_id must be bounded identifiers")
	}
	if !validProviderGuestExecutable(c.BrokerPath) || !validProviderGuestExecutable(c.ShellPath) {
		return errors.New("broker_path and shell_path must be absolute safe guest executable paths")
	}
	if c.MaxSessionsPerSandbox < 1 || c.MaxSessionsPerSandbox > 1_000 ||
		c.MaxSessionsPerController < c.MaxSessionsPerSandbox || c.MaxSessionsPerController > 1_000 {
		return errors.New("terminal session capacities must be bounded and controller capacity must cover each sandbox")
	}
	if c.ShutdownCleanupSeconds < 1 || c.ShutdownCleanupSeconds > 300 {
		return errors.New("shutdown_cleanup_seconds must be between 1 and 300")
	}
	return nil
}

// Validate checks an explicitly enabled Provider terminal configuration.
func (c ProviderTerminalConfig) Validate() error {
	return c.validateEnabled()
}

func (c *ProviderArtifactConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.RepositoryFile) == "" || strings.TrimSpace(c.StagingRoot) == "" {
		return errors.New("repository_file and staging_root must not be empty")
	}
	if filepath.Clean(c.RepositoryFile) == filepath.Clean(c.StagingRoot) {
		return errors.New("repository_file and staging_root must be distinct")
	}
	if !validProviderCommand(c.ActiveContentCommand) || !validProviderCommand(c.MalwareCommand) {
		return errors.New("active_content_command and malware_command must be bounded argv arrays")
	}
	return nil
}

func (c ProviderArtifactConfig) Validate() error { return c.validateEnabled() }

func (c *ProviderUsageConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.RepositoryFile) == "" {
		return errors.New("repository_file must not be empty")
	}
	return nil
}

func (c ProviderUsageConfig) Validate() error { return c.validateEnabled() }

func (c *ProviderBrowserConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	for name, value := range map[string]string{
		"session_repository_file": c.SessionRepositoryFile,
		"reference_registry_file": c.ReferenceRegistryFile,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must not be empty", name)
		}
	}
	if filepath.Clean(c.SessionRepositoryFile) == filepath.Clean(c.ReferenceRegistryFile) {
		return errors.New("session_repository_file and reference_registry_file must be distinct")
	}
	if c.ShutdownCleanupSeconds < 1 || c.ShutdownCleanupSeconds > 300 ||
		c.UsageRetentionSeconds < 60 || c.UsageRetentionSeconds > 2_592_000 {
		return errors.New("shutdown and usage-retention durations are outside their bounds")
	}
	if err := c.Docker.validate(); err != nil {
		return fmt.Errorf("docker %w", err)
	}
	if !filepath.IsAbs(c.Provenance.ExecutablePath) || !providerSHA256Pattern.MatchString(c.Provenance.ExecutableDigest) {
		return errors.New("provenance executable_path must be absolute and executable_digest must be sha256-pinned")
	}
	if err := c.RestrictedNetwork.validate(c.Docker.NetworkPolicyReference); err != nil {
		return fmt.Errorf("restricted network %w", err)
	}
	if c.Docker.Namespace != c.RestrictedNetwork.Namespace || c.Docker.ControllerID != c.RestrictedNetwork.ControllerID {
		return errors.New("docker and restricted-network ownership identities must match")
	}
	if strings.TrimSpace(c.Docker.Host) != strings.TrimSpace(c.RestrictedNetwork.Host) {
		return errors.New("docker and restricted-network hosts must match")
	}
	return nil
}

func (c ProviderBrowserConfig) Validate() error { return c.validateEnabled() }

func (c ProviderBrowserDockerConfig) validate() error {
	if !providerPinnedImagePattern.MatchString(c.Image) {
		return errors.New("image must be pinned by sha256 digest")
	}
	switch c.PullPolicy {
	case "never", "if_not_present", "always":
	default:
		return errors.New("pull_policy is unsupported")
	}
	const maxBytes = int64(64 << 30)
	for _, value := range []int64{c.MemoryBytes, c.InputsBytes, c.TmpfsBytes, c.WorkspaceBytes, c.OutputsBytes} {
		if value <= 0 || value > maxBytes {
			return errors.New("byte limits must be positive and bounded")
		}
	}
	if c.InputsBytes > c.MemoryBytes || c.TmpfsBytes > c.MemoryBytes || c.WorkspaceBytes > c.MemoryBytes || c.OutputsBytes > c.MemoryBytes ||
		c.NanoCPUs <= 0 || c.NanoCPUs > 64_000_000_000 || c.PidsLimit <= 0 || c.PidsLimit > 4_096 {
		return errors.New("resource limits are invalid")
	}
	for _, value := range []int{c.OperationTimeoutSeconds, c.ProvenanceTimeoutSeconds, c.PullTimeoutSeconds} {
		if value < 1 || value > 600 {
			return errors.New("operation, provenance, and pull timeouts must be between 1 and 600 seconds")
		}
	}
	if c.StopTimeoutSeconds < 0 || c.StopTimeoutSeconds > 600 || strings.TrimSpace(c.DataRoot) == "" ||
		strings.TrimSpace(c.ManifestPath) == "" || strings.TrimSpace(c.SeccompPath) == "" ||
		!providerProfileIDPattern.MatchString(c.NetworkPolicyReference) ||
		!providerOwnershipPattern.MatchString(c.Namespace) || !providerOwnershipPattern.MatchString(c.ControllerID) ||
		c.MaxSessionsPerSandbox != 1 || c.MaxSessionsPerController < 1 || c.MaxSessionsPerController > 1_000 {
		return errors.New("state paths, ownership, policy, capacity, or stop timeout is invalid")
	}
	return nil
}

func (c ProviderBrowserNetworkConfig) validate(expectedPolicy string) error {
	if !providerImmutableImagePattern.MatchString(c.GatewayImage) || !providerDockerNamePattern.MatchString(c.UplinkNetwork) ||
		!providerOwnershipPattern.MatchString(c.Namespace) || !providerOwnershipPattern.MatchString(c.ControllerID) ||
		c.MemoryBytes <= 0 || c.MemoryBytes > 1<<30 || c.NanoCPUs <= 0 || c.NanoCPUs > 4_000_000_000 ||
		c.PidsLimit <= 0 || c.PidsLimit > 256 || c.OperationTimeoutSeconds < 1 || c.OperationTimeoutSeconds > 600 ||
		c.StopTimeoutSeconds < 0 || c.StopTimeoutSeconds > 600 || len(c.Policies) < 1 || len(c.Policies) > 64 {
		return errors.New("gateway image, uplink, ownership, resources, timeouts, or policies are invalid")
	}
	switch c.UplinkNetwork {
	case "none", "host", "bridge", "default":
		return errors.New("uplink network must be explicitly operator-owned")
	}
	seen := make(map[string]struct{}, len(c.Policies))
	for _, policy := range c.Policies {
		if !providerProfileIDPattern.MatchString(policy.Reference) || len(policy.AllowedHosts) < 1 || len(policy.AllowedHosts) > 256 {
			return errors.New("network policy reference or hostname count is invalid")
		}
		if _, exists := seen[policy.Reference]; exists {
			return errors.New("network policy references must be unique")
		}
		seen[policy.Reference] = struct{}{}
		for _, host := range policy.AllowedHosts {
			if strings.TrimSpace(host) == "" || strings.TrimSpace(host) != host || len(host) > 253 {
				return errors.New("network policy host is invalid")
			}
		}
	}
	if _, exists := seen[expectedPolicy]; !exists {
		return errors.New("docker network policy reference is not configured")
	}
	return nil
}

func validProviderCommand(command []string) bool {
	if len(command) < 1 || len(command) > 64 {
		return false
	}
	for _, argument := range command {
		if !utf8.ValidString(argument) || utf8.RuneCountInString(argument) < 1 || utf8.RuneCountInString(argument) > 4096 || strings.ContainsAny(argument, "\x00\r\n") {
			return false
		}
	}
	return true
}

func validProviderGuestExecutable(value string) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(value, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
		for _, char := range component {
			if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func (c *ProviderLifecycleConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	switch c.Driver {
	case ProviderLifecycleFakeDriver:
	case ProviderLifecycleDockerDriver:
		if err := c.Docker.validate(); err != nil {
			return fmt.Errorf("docker %w", err)
		}
	case ProviderLifecycleBrowserDriver:
	default:
		return fmt.Errorf("driver %q is unsupported", c.Driver)
	}
	switch c.Repository.Driver {
	case ProviderLifecycleMemoryRepository:
	case ProviderLifecycleFileRepository:
		if strings.TrimSpace(c.Repository.File.Path) == "" {
			return errors.New("repository.file.path must not be empty")
		}
	default:
		return fmt.Errorf("repository driver %q is unsupported", c.Repository.Driver)
	}
	if c.Driver == ProviderLifecycleDockerDriver && c.Repository.Driver != ProviderLifecycleFileRepository {
		return errors.New("docker driver requires the single-controller file repository")
	}
	return nil
}

func (c ProviderLifecycleDockerConfig) validate() error {
	if !providerPinnedImagePattern.MatchString(c.Image) {
		return errors.New("image must be pinned by sha256 digest")
	}
	if c.PullPolicy != "never" && c.PullPolicy != "if_not_present" && c.PullPolicy != "always" {
		return fmt.Errorf("pull policy %q is unsupported", c.PullPolicy)
	}
	if c.MemoryBytes <= 0 || c.NanoCPUs <= 0 || c.PidsLimit <= 0 || c.TmpfsBytes <= 0 {
		return errors.New("resource limits must be positive")
	}
	if c.OperationTimeoutSeconds <= 0 || c.PullTimeoutSeconds <= 0 || c.StopTimeoutSeconds < 0 {
		return errors.New("operation timeouts are invalid")
	}
	if !validProviderNumericUser(c.User) {
		return errors.New("user must be numeric non-root uid:gid")
	}
	if len(c.Command) == 0 || strings.TrimSpace(c.DataRoot) == "" {
		return errors.New("command and data_root are required")
	}
	if !providerOwnershipPattern.MatchString(c.Namespace) || !providerOwnershipPattern.MatchString(c.ControllerID) {
		return errors.New("namespace and controller_id must be bounded ownership identifiers")
	}
	return nil
}

func validProviderNumericUser(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	uid, uidErr := strconv.ParseUint(parts[0], 10, 31)
	gid, gidErr := strconv.ParseUint(parts[1], 10, 31)
	return uidErr == nil && gidErr == nil && uid > 0 && gid > 0
}

// Validate checks an explicitly enabled Provider lifecycle configuration.
func (c ProviderLifecycleConfig) Validate() error {
	return c.validateEnabled()
}

func (c *ProviderTransportConfig) validateEnabled() error {
	if strings.TrimSpace(c.Address.Host) == "" {
		return errors.New("address host must not be empty")
	}
	if err := c.Address.Validate(); err != nil {
		return fmt.Errorf("address %w", err)
	}
	requiredPaths := []struct {
		name  string
		value string
	}{
		{"server certificate file", c.ServerCertificateFile},
		{"server private key file", c.ServerPrivateKeyFile},
		{"client CA bundle file", c.ClientCABundleFile},
	}
	for _, path := range requiredPaths {
		if strings.TrimSpace(path.value) == "" {
			return fmt.Errorf("%s must not be empty", path.name)
		}
	}
	return provideridentity.ValidateAllowlist(c.AllowedClientURIIdentities)
}

func (c *ProviderCapabilityConfig) validateEnabled() error {
	if !utf8.ValidString(c.ProviderRevisionID) || strings.TrimSpace(c.ProviderRevisionID) == "" {
		return errors.New("provider revision ID must be valid UTF-8 and not empty")
	}
	if err := c.Limits.validateEnabled(); err != nil {
		return fmt.Errorf("limits %w", err)
	}
	if count := len(c.SnapshotRestoreProfiles); count < 1 || count > 32 {
		return fmt.Errorf("snapshot/restore compatibility profiles count must be between 1 and 32, got %d", count)
	}
	profilesByID := make(map[string]ProviderCompatibilityProfile, len(c.SnapshotRestoreProfiles))
	for index, profile := range c.SnapshotRestoreProfiles {
		if err := profile.validate(); err != nil {
			return fmt.Errorf("snapshot/restore compatibility profile %d: %w", index, err)
		}
		if previous, exists := profilesByID[profile.ProfileID]; exists {
			if previous == profile {
				return fmt.Errorf("duplicate snapshot/restore compatibility profile %q", profile.ProfileID)
			}
			return fmt.Errorf("conflicting snapshot/restore compatibility profile %q", profile.ProfileID)
		}
		profilesByID[profile.ProfileID] = profile
	}
	return nil
}

func (c *ProviderProtectedAdmissionConfig) validateEnabled() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.GuardStateFile) == "" {
		return errors.New("guard state file must not be empty")
	}
	if count := len(c.TrustedVerificationKeys); count < 1 || count > 32 {
		return fmt.Errorf("trusted verification key count must be between 1 and 32, got %d", count)
	}

	ids := make(map[string]struct{}, len(c.TrustedVerificationKeys))
	for index, key := range c.TrustedVerificationKeys {
		if !utf8.ValidString(key.ID) || strings.TrimSpace(key.ID) == "" {
			return fmt.Errorf("trusted verification key %d ID must be valid UTF-8 and not blank", index)
		}
		if count := utf8.RuneCountInString(key.ID); count < 1 || count > 128 {
			return fmt.Errorf("trusted verification key %d ID must contain between 1 and 128 characters, got %d", index, count)
		}
		if _, exists := ids[key.ID]; exists {
			return fmt.Errorf("trusted verification key %d duplicates ID %q", index, key.ID)
		}
		ids[key.ID] = struct{}{}
		switch key.Algorithm {
		case "EdDSA", "ES256":
		default:
			return fmt.Errorf("trusted verification key %d has unsupported algorithm %q", index, key.Algorithm)
		}
		if strings.TrimSpace(key.PublicKeyFile) == "" {
			return fmt.Errorf("trusted verification key %d public-key file must not be empty", index)
		}
	}
	return nil
}

func (c *ProviderLimitsConfig) validateEnabled() error {
	required := []struct {
		name  string
		value int64
	}{
		{"max CPU millis", c.MaxCPUMillis},
		{"max memory bytes", c.MaxMemoryBytes},
		{"max ephemeral storage bytes", c.MaxEphemeralStorageBytes},
		{"max lease seconds", c.MaxLeaseSeconds},
		{"max exec seconds", c.MaxExecSeconds},
	}
	for _, limit := range required {
		if limit.value <= 0 {
			return fmt.Errorf("%s must be positive", limit.name)
		}
	}
	if c.MaxWorkspaceBytes != nil && *c.MaxWorkspaceBytes <= 0 {
		return errors.New("max workspace bytes must be positive when present")
	}
	if c.MaxGPUCount != nil && *c.MaxGPUCount < 0 {
		return errors.New("max GPU count must be nonnegative when present")
	}
	return nil
}

func (c ProviderCompatibilityProfile) validate() error {
	if !utf8.ValidString(c.ProfileID) || strings.TrimSpace(c.ProfileID) == "" {
		return errors.New("profile ID must be valid UTF-8 and not blank")
	}
	if count := utf8.RuneCountInString(c.ProfileID); count < 1 || count > 200 {
		return fmt.Errorf("profile ID must contain between 1 and 200 characters, got %d", count)
	}
	switch c.Level {
	case "workspace", "filesystem", "process":
	default:
		return fmt.Errorf("invalid snapshot level %q", c.Level)
	}
	if c.SuiteID != "sandbox-provider" {
		return fmt.Errorf("invalid suite ID %q", c.SuiteID)
	}
	if !providerSuiteVersionPattern.MatchString(c.SuiteVersion) {
		return fmt.Errorf("invalid suite version %q", c.SuiteVersion)
	}
	if !providerSuiteDigestPattern.MatchString(c.SuiteDigest) {
		return errors.New("invalid suite digest")
	}
	return nil
}

// defaultServerConfig returns the built-in server defaults.
func defaultServerConfig() *ServerConfig {
	return &ServerConfig{
		API: option.HTTP{
			Host: defaultServerAPIHost,
			Port: defaultServerAPIPort,
		},
		Provider: ProviderConfig{
			Exec: ProviderExecConfig{RepositoryFile: "data/provider-exec.json"},
			Artifact: ProviderArtifactConfig{
				RepositoryFile: "data/provider-artifacts.json", StagingRoot: "data/provider-artifact-staging",
			},
			Usage: ProviderUsageConfig{RepositoryFile: "data/provider-usage.json"},
			Browser: ProviderBrowserConfig{
				SessionRepositoryFile: "data/provider-browser-sessions.json", ReferenceRegistryFile: "data/provider-browser-references.json",
				ShutdownCleanupSeconds: 10, UsageRetentionSeconds: 3600,
				Docker: ProviderBrowserDockerConfig{
					Image:      "ghcr.io/shell-echo/sandbox-runtime-browser@sha256:87d3216c22ada0fea74b375a3ee5c2ddf021d3e1913569e2aeb4a316ed3b5c2f",
					PullPolicy: "if_not_present", MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
					InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
					OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
					DataRoot: "data/provider-browser-runtime", ManifestPath: "profiles/browser/image/manifest.json",
					SeccompPath: "profiles/browser/image/chromium-seccomp.json", Namespace: "default",
					NetworkPolicyReference: "browser-egress-policy-1", MaxSessionsPerSandbox: 1, MaxSessionsPerController: 16,
				},
				RestrictedNetwork: ProviderBrowserNetworkConfig{
					Namespace: "default", MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
					OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10,
				},
			},
			Terminal: ProviderTerminalConfig{
				SessionRepositoryFile: "data/provider-terminal-sessions.json", ReferenceRegistryFile: "data/provider-terminal-references.json",
				RuntimeProfileID: ProviderCodingShellRuntimeProfileID, CapabilityProfileID: ProviderCodingShellTerminalProfileID,
				BrokerPath: "/workspace/.sandbox-runtime/terminal-broker", ShellPath: "/bin/sh",
				MaxSessionsPerSandbox: 4, MaxSessionsPerController: 64, ShutdownCleanupSeconds: 10,
			},
			Lifecycle: ProviderLifecycleConfig{
				Driver: ProviderLifecycleFakeDriver,
				Repository: ProviderLifecycleRepositoryConfig{
					Driver: ProviderLifecycleMemoryRepository,
					File:   ProviderLifecycleRepositoryFileConfig{Path: "data/provider-lifecycle.json"},
				},
				Docker: ProviderLifecycleDockerConfig{
					PullPolicy: "if_not_present", MemoryBytes: 512 << 20,
					NanoCPUs: 1_000_000_000, PidsLimit: 256, TmpfsBytes: 64 << 20,
					OperationTimeoutSeconds: 30, PullTimeoutSeconds: 300, StopTimeoutSeconds: 10,
					User: "65532:65532", Command: []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
					DataRoot: "data/provider-runtime", Namespace: "default",
				},
			},
		},
	}
}

// Server is the committed server configuration, initialised to the defaults and
// replaced by Load.
var Server = defaultServerConfig()

// init registers the loader that parses the server section and commits it.
func init() {
	register(func(v *viper.Viper) (commit, error) {
		c := &ServerConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Server = c; return nil }, nil
	})
}
