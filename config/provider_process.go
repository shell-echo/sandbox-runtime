package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/option"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/spf13/viper"
)

const (
	defaultProviderProcessHost         = "127.0.0.1"
	defaultProviderProcessPort         = 8444
	ProviderLegacyLocalCandidateSchema = "sandbox-runtime.provider-process.legacy-local-candidate.v1"
	ProviderProductionSchemaV2         = "sandbox-runtime.provider-process.v2"
	ProviderProductionSchemaV3         = "sandbox-runtime.provider-process.v3"
)

type ProviderProcessProfile string

type ProviderDeploymentLevel string

const (
	ProviderProductionLevel           ProviderDeploymentLevel = "production"
	ProviderLocalCandidateLevel       ProviderDeploymentLevel = "local_candidate"
	ProviderProcessCodingShellProfile ProviderProcessProfile  = "coding_shell"
	ProviderProcessBrowserProfile     ProviderProcessProfile  = "browser"
	ProviderProcessDesktopProfile     ProviderProcessProfile  = "desktop"
)

// ProviderProcessConfig is the independent production Provider role. It has
// no local /instances listener, local repository, Product identity, or public
// Gateway configuration.
type ProviderProcessConfig struct {
	SchemaVersion      string                          `mapstructure:"schema_version"`
	Enabled            bool                            `mapstructure:"enabled"`
	DeploymentLevel    ProviderDeploymentLevel         `mapstructure:"deployment_level"`
	Profile            ProviderProcessProfile          `mapstructure:"profile"`
	Transport          ProviderTransportConfig         `mapstructure:"transport"`
	Probe              option.HTTP                     `mapstructure:"probe"`
	Capability         ProviderProcessCapabilityConfig `mapstructure:"capability"`
	ProtectedAdmission ProviderProcessAdmissionConfig  `mapstructure:"protected_admission"`
	Postgres           ProviderPostgresConfig          `mapstructure:"postgres"`
	Coding             ProviderProcessCodingConfig     `mapstructure:"coding"`
	Browser            ProviderProcessBrowserConfig    `mapstructure:"browser"`
	Desktop            ProviderProcessDesktopConfig    `mapstructure:"desktop"`
	Reconciliation     ProviderReconciliationConfig    `mapstructure:"reconciliation"`
	Materials          RoleMaterialsConfig             `mapstructure:"materials"`
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
	RuntimeDSNBindingID     string `mapstructure:"runtime_dsn_binding_id"`
	ClientAgentSocket       string `mapstructure:"client_agent_socket"`
	ClientAgentUID          uint32 `mapstructure:"client_agent_uid"`
	ClientAgentGID          uint32 `mapstructure:"client_agent_gid"`
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

// Browser is a separate Provider instance, never an executor process or a
// second owner of the Browser handoff. Static executor credentials and file
// session registries are intentionally absent from this v3 authority.
type ProviderProcessBrowserConfig struct {
	ExecutorURL            string                          `mapstructure:"executor_url"`
	MuxSocketPath          string                          `mapstructure:"mux_socket_path"`
	UsageRetentionSeconds  int                             `mapstructure:"usage_retention_seconds"`
	ShutdownCleanupSeconds int                             `mapstructure:"shutdown_cleanup_seconds"`
	Docker                 ProviderBrowserDockerConfig     `mapstructure:"docker"`
	Provenance             ProviderBrowserProvenanceConfig `mapstructure:"provenance"`
	RestrictedNetwork      ProviderBrowserNetworkConfig    `mapstructure:"restricted_network"`
}

var browserMuxSocketPattern = regexp.MustCompile(`^browser-mux-[0-9a-f]{32}\.sock$`)

type ProviderProcessDesktopConfig struct {
	Architecture                      string                          `mapstructure:"architecture"`
	ExecutorURL                       string                          `mapstructure:"executor_url"`
	BrokerMuxSocketPath               string                          `mapstructure:"broker_mux_socket_path"`
	ExecutorCABundleFile              string                          `mapstructure:"executor_ca_bundle_file"`
	ExecutorCertificateFile           string                          `mapstructure:"executor_certificate_file"`
	ExecutorPrivateKeyFile            string                          `mapstructure:"executor_private_key_file"`
	ExecutorIdentity                  string                          `mapstructure:"executor_identity"`
	ExecutorBridgeKeyID               string                          `mapstructure:"executor_bridge_key_id"`
	ExecutorBridgePrivateKeyFile      string                          `mapstructure:"executor_bridge_private_key_file"`
	ExecutorCABundleBindingID         string                          `mapstructure:"executor_ca_bundle_binding_id"`
	ExecutorCertificateBindingID      string                          `mapstructure:"executor_certificate_binding_id"`
	ExecutorPrivateKeyBindingID       string                          `mapstructure:"executor_private_key_binding_id"`
	ExecutorBridgePrivateKeyBindingID string                          `mapstructure:"executor_bridge_private_key_binding_id"`
	LocalCandidateManifestFile        string                          `mapstructure:"local_candidate_manifest_file"`
	LocalCandidateSourceRoot          string                          `mapstructure:"local_candidate_source_root"`
	UsageRetentionSeconds             int                             `mapstructure:"usage_retention_seconds"`
	ShutdownCleanupSeconds            int                             `mapstructure:"shutdown_cleanup_seconds"`
	Docker                            ProviderDesktopDockerConfig     `mapstructure:"docker"`
	Provenance                        ProviderBrowserProvenanceConfig `mapstructure:"provenance"`
	RestrictedNetwork                 ProviderBrowserNetworkConfig    `mapstructure:"restricted_network"`
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
		SchemaVersion:   ProviderLegacyLocalCandidateSchema,
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
	liveSchema := c.SchemaVersion == ProviderProductionSchemaV3
	materialSchema := c.SchemaVersion == ProviderProductionSchemaV2 || liveSchema
	if !materialSchema && c.SchemaVersion != ProviderLegacyLocalCandidateSchema {
		return errors.New("provider_process schema_version is invalid")
	}
	if liveSchema && !((c.DeploymentLevel == ProviderProductionLevel && (c.Profile == ProviderProcessCodingShellProfile || c.Profile == ProviderProcessBrowserProfile)) ||
		(c.DeploymentLevel == ProviderLocalCandidateLevel && c.Profile == ProviderProcessDesktopProfile)) {
		return errors.New("Provider v3 requires coding_shell/Browser production or Desktop local_candidate")
	}
	if c.DeploymentLevel != ProviderProductionLevel && c.DeploymentLevel != ProviderLocalCandidateLevel {
		return errors.New("provider_process requires deployment_level=production or local_candidate")
	}
	if !c.Transport.Enabled {
		return errors.New("provider_process transport must be enabled")
	}
	var transportErr error
	if liveSchema {
		route := ProviderPrivateRouteTerminal
		switch c.Profile {
		case ProviderProcessBrowserProfile:
			route = ProviderPrivateRouteBrowser
		case ProviderProcessDesktopProfile:
			route = ProviderPrivateRouteDesktop
		}
		transportErr = c.Transport.validateLiveEnabled(route)
	} else if materialSchema {
		transportErr = c.Transport.validateMaterialEnabled()
	} else {
		transportErr = c.Transport.validateEnabled()
	}
	if transportErr != nil {
		return fmt.Errorf("provider_process.transport: %w", transportErr)
	}
	if !liveSchema && (c.Transport.SecurityProfilePath != "" || c.Transport.SecurityProfileDigest != "" ||
		c.Transport.PeerCRLRoleFile != "" || c.Transport.PeerCRLRoleDigest != "" || c.Transport.PeerCRLSourceMappingDigest != "" ||
		c.Transport.AgentSocket != "" || c.Transport.AgentUID != 0 || c.Transport.AgentGID != 0 ||
		c.Transport.OperationTimeoutMillis != 0) {
		return errors.New("Provider legacy and v2 transports cannot select a live signer")
	}
	if net.ParseIP(c.Transport.Address.Host) == nil {
		return errors.New("provider_process.transport.address.host must be an explicit IP address")
	}
	if err := c.Probe.Validate(); err != nil || !exactLoopbackIP(c.Probe.Host) || c.Probe.Port == c.Transport.Address.Port ||
		(c.Transport.Private.Enabled && c.Probe.Port == c.Transport.Private.Address.Port) {
		return errors.New("provider_process.probe must use a distinct explicit loopback address")
	}
	capability := ProviderCapabilityConfig{ProviderRevisionID: c.Capability.ProviderRevisionID, Limits: c.Capability.Limits, SnapshotRestoreProfiles: c.Capability.SnapshotRestoreProfiles}
	if err := capability.validateEnabled(); err != nil {
		return fmt.Errorf("provider_process.capability: %w", err)
	}
	if err := c.validateAdmission(materialSchema); err != nil {
		return err
	}
	if err := c.validatePostgres(materialSchema); err != nil {
		return err
	}
	if c.Reconciliation.IntervalSeconds < 1 || c.Reconciliation.IntervalSeconds > 60 || c.Reconciliation.TimeoutSeconds < 1 || c.Reconciliation.TimeoutSeconds > 30 || c.Reconciliation.TimeoutSeconds > c.Reconciliation.IntervalSeconds*5 {
		return errors.New("provider_process reconciliation bounds are invalid")
	}
	switch c.Profile {
	case ProviderProcessCodingShellProfile:
		if !reflect.DeepEqual(c.Browser, ProviderProcessBrowserConfig{}) {
			return errors.New("Browser runtime authority is forbidden for the coding_shell Provider profile")
		}
		if c.DeploymentLevel != ProviderProductionLevel {
			return errors.New("coding_shell Provider profile requires deployment_level=production")
		}
		if err := c.validateCoding(); err != nil {
			return err
		}
		if c.Desktop.Architecture != "" || c.Desktop.Docker.Image != "" {
			return errors.New("Desktop runtime authority is forbidden for the coding_shell Provider profile")
		}
		if liveSchema && (c.Desktop.ExecutorURL != "" || c.Desktop.BrokerMuxSocketPath != "" ||
			c.Desktop.ExecutorCABundleFile != "" || c.Desktop.ExecutorCertificateFile != "" ||
			c.Desktop.ExecutorPrivateKeyFile != "" || c.Desktop.ExecutorBridgePrivateKeyFile != "" ||
			c.Desktop.ExecutorCABundleBindingID != "" || c.Desktop.ExecutorCertificateBindingID != "" ||
			c.Desktop.ExecutorPrivateKeyBindingID != "" || c.Desktop.ExecutorBridgePrivateKeyBindingID != "") {
			return errors.New("Provider coding-shell v3 forbids Desktop executor authority")
		}
	case ProviderProcessDesktopProfile:
		if !reflect.DeepEqual(c.Browser, ProviderProcessBrowserConfig{}) {
			return errors.New("Browser runtime authority is forbidden for the Desktop Provider profile")
		}
		if err := c.validateDesktop(materialSchema); err != nil {
			return err
		}
		if c.Coding.Lifecycle.Image != "" {
			return errors.New("coding runtime authority is forbidden for the desktop Provider profile")
		}
	case ProviderProcessBrowserProfile:
		if !liveSchema || c.DeploymentLevel != ProviderProductionLevel {
			return errors.New("Browser Provider profile requires v3 production authority")
		}
		if len(c.Transport.Private.AllowedClientURIIdentities) != 1 ||
			c.Transport.Private.AllowedClientURIIdentities[0] != "spiffe://sandbox-runtime.test/browser-action-ingress-runtime" {
			return errors.New("Browser Provider private listener requires only the action ingress identity")
		}
		if err := c.validateBrowser(); err != nil {
			return err
		}
		defaults := defaultProviderProcessConfig()
		if !reflect.DeepEqual(c.Coding, defaults.Coding) || !reflect.DeepEqual(c.Desktop, defaults.Desktop) {
			return errors.New("coding/Desktop runtime authority is forbidden for the Browser Provider profile")
		}
	default:
		return fmt.Errorf("provider_process.profile %q is invalid", c.Profile)
	}
	if materialSchema {
		return c.validateMaterialAuthority()
	}
	return c.validateAuthorityPaths()
}

func (c *ProviderTransportConfig) validateLiveEnabled(route string) error {
	if (route != ProviderPrivateRouteTerminal && route != ProviderPrivateRouteBrowser && route != ProviderPrivateRouteDesktop) ||
		!c.Private.Enabled || len(c.Private.RoutePolicy) != 1 || c.Private.RoutePolicy[0] != route ||
		net.ParseIP(c.Private.Address.Host) == nil ||
		validateAbsoluteSecretPath("Provider security profile", c.SecurityProfilePath) != nil ||
		validateAbsoluteSecretPath("Provider peer CRL role", c.PeerCRLRoleFile) != nil ||
		validateAbsoluteSecretPath("Provider TLS agent socket", c.AgentSocket) != nil ||
		c.SecurityProfilePath == c.AgentSocket || c.PeerCRLRoleFile == c.SecurityProfilePath ||
		c.PeerCRLRoleFile == c.AgentSocket || !providerSHA256Pattern.MatchString(c.SecurityProfileDigest) ||
		!providerSHA256Pattern.MatchString(c.PeerCRLRoleDigest) ||
		!providerSHA256Pattern.MatchString(c.PeerCRLSourceMappingDigest) ||
		c.AgentUID == 0 || c.AgentGID == 0 || c.OperationTimeoutMillis < 1000 || c.OperationTimeoutMillis > 30_000 {
		return errors.New("Provider v3 requires a pinned live signer and exact separate private listener")
	}
	if c.ServerCertificateFile != "" || c.ServerPrivateKeyFile != "" || c.ClientCABundleFile != "" ||
		c.ServerCertificateBindingID != "" || c.ServerPrivateKeyBindingID != "" ||
		c.ClientCABundleBindingID != "" || c.ExpectedServerName != "" ||
		c.Private.ServerCertificateFile != "" || c.Private.ServerPrivateKeyFile != "" ||
		c.Private.ClientCABundleFile != "" || c.Private.ServerCertificateBindingID != "" ||
		c.Private.ServerPrivateKeyBindingID != "" || c.Private.ClientCABundleBindingID != "" ||
		c.Private.ExpectedServerName != "" {
		return errors.New("Provider v3 cannot contain frozen TLS material")
	}
	probe := *c
	probe.SecurityProfilePath, probe.SecurityProfileDigest, probe.AgentSocket = "", "", ""
	probe.PeerCRLRoleFile, probe.PeerCRLRoleDigest, probe.PeerCRLSourceMappingDigest = "", "", ""
	probe.AgentUID, probe.AgentGID, probe.OperationTimeoutMillis = 0, 0, 0
	probe.ServerCertificateBindingID = "provider-contract-cert"
	probe.ServerPrivateKeyBindingID = "provider-contract-key"
	probe.ClientCABundleBindingID = "provider-contract-ca"
	probe.ExpectedServerName = "provider.sandbox-runtime.test"
	probe.Private.ServerCertificateBindingID = "provider-private-cert"
	probe.Private.ServerPrivateKeyBindingID = "provider-private-key"
	probe.Private.ClientCABundleBindingID = "provider-private-ca"
	probe.Private.ExpectedServerName = "provider.sandbox-runtime.test"
	return probe.validateMaterialEnabled()
}

func (c *ProviderProcessConfig) validateAdmission(materialSchema bool) error {
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
		if materialSchema {
			if key.PublicKeyFile != "" || key.PublicKeyBindingID == "" {
				return errors.New("provider_process trusted verification key requires a material binding")
			}
		} else if key.PublicKeyBindingID != "" {
			return errors.New("provider_process legacy verification key cannot contain a material binding")
		}
	}
	return nil
}

func (c *ProviderProcessConfig) validatePostgres(materialSchema bool) error {
	p := c.Postgres
	separateClientAgent := c.SchemaVersion == ProviderProductionSchemaV3 &&
		(c.Profile == ProviderProcessBrowserProfile || c.Profile == ProviderProcessDesktopProfile)
	if separateClientAgent {
		if validateAbsoluteSecretPath("Provider PostgreSQL client agent socket", p.ClientAgentSocket) != nil ||
			p.ClientAgentSocket == c.Transport.AgentSocket || p.ClientAgentSocket == c.Transport.SecurityProfilePath ||
			p.ClientAgentSocket == c.Transport.PeerCRLRoleFile || p.ClientAgentUID == 0 || p.ClientAgentGID == 0 ||
			p.ClientAgentUID == c.Transport.AgentUID || p.ClientAgentGID == c.Transport.AgentGID {
			return errors.New("Provider PostgreSQL requires a distinct purpose-bound client agent")
		}
	} else if p.ClientAgentSocket != "" || p.ClientAgentUID != 0 || p.ClientAgentGID != 0 {
		return errors.New("Provider PostgreSQL client agent is only available to v3 Browser/Desktop")
	}
	if p.StartupTimeoutSeconds < 1 || p.StartupTimeoutSeconds > 60 || p.OperationTimeoutSeconds < 1 || p.OperationTimeoutSeconds > 30 || p.MaxConnections < 1 || p.MaxConnections > 64 || p.MinConnections < 0 || p.MinConnections > p.MaxConnections {
		return errors.New("provider_process PostgreSQL connection bounds are invalid")
	}
	if !postgresRolePattern.MatchString(p.RuntimeRole) {
		return errors.New("provider_process runtime PostgreSQL role must be an explicit identifier")
	}
	if materialSchema {
		if p.MigrationDSNFile != "" || p.RuntimeDSNFile != "" || p.MigrationRole != "" || p.MigrationMaxConnections != 0 || p.RuntimeDSNBindingID == "" {
			return errors.New("provider_process runtime schema forbids migration and raw PostgreSQL authority")
		}
		return nil
	}
	if p.RuntimeDSNBindingID != "" || p.MigrationMaxConnections < 1 || p.MigrationMaxConnections > 4 || !postgresRolePattern.MatchString(p.MigrationRole) || p.MigrationRole == p.RuntimeRole {
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

func (c *ProviderProcessConfig) validateBrowser() error {
	b := c.Browser
	if b.ExecutorURL == "" || b.MuxSocketPath == "" || b.UsageRetentionSeconds < 60 ||
		b.UsageRetentionSeconds > 2_592_000 || b.ShutdownCleanupSeconds < 1 || b.ShutdownCleanupSeconds > 300 ||
		b.Docker.validate() != nil || b.Docker.Image != browserimage.LockedPublication().Image() ||
		!filepath.IsAbs(b.Docker.DataRoot) || filepath.Clean(b.Docker.DataRoot) != b.Docker.DataRoot ||
		!filepath.IsAbs(b.Docker.ManifestPath) || filepath.Clean(b.Docker.ManifestPath) != b.Docker.ManifestPath ||
		!filepath.IsAbs(b.Docker.SeccompPath) || filepath.Clean(b.Docker.SeccompPath) != b.Docker.SeccompPath ||
		!filepath.IsAbs(b.MuxSocketPath) || filepath.Clean(b.MuxSocketPath) != b.MuxSocketPath ||
		filepath.Dir(b.MuxSocketPath) != phase6security.BrowserMuxSocketDirectory ||
		!browserMuxSocketPattern.MatchString(filepath.Base(b.MuxSocketPath)) ||
		!filepath.IsAbs(b.Provenance.ExecutablePath) || filepath.Clean(b.Provenance.ExecutablePath) != b.Provenance.ExecutablePath ||
		!providerSHA256Pattern.MatchString(b.Provenance.ExecutableDigest) {
		return errors.New("Provider Browser runtime, paths, provenance, or bounds are invalid")
	}
	parsed, err := url.Parse(b.ExecutorURL)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Path != "/executor" ||
		parsed.EscapedPath() != "/executor" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		net.ParseIP(parsed.Hostname()) == nil || parsed.Port() == "" || parsed.String() != b.ExecutorURL {
		return errors.New("Provider Browser executor URL must be an exact private numeric endpoint")
	}
	if err := b.RestrictedNetwork.validate(b.Docker.NetworkPolicyReference); err != nil {
		return fmt.Errorf("provider_process.browser.restricted_network: %w", err)
	}
	if b.RestrictedNetwork.Namespace != b.Docker.Namespace || b.RestrictedNetwork.ControllerID != b.Docker.ControllerID ||
		strings.TrimSpace(b.RestrictedNetwork.Host) != strings.TrimSpace(b.Docker.Host) {
		return errors.New("Provider Browser runtime and network ownership must match")
	}
	return nil
}

func (c *ProviderProcessConfig) validateDesktop(materialSchema bool) error {
	d := c.Desktop
	if d.Architecture != "amd64" && d.Architecture != "arm64" || d.UsageRetentionSeconds < 60 || d.UsageRetentionSeconds > 2_592_000 || d.ShutdownCleanupSeconds < 1 || d.ShutdownCleanupSeconds > 300 {
		return errors.New("provider_process Desktop architecture or duration is invalid")
	}
	if c.SchemaVersion != ProviderProductionSchemaV3 && d.LocalCandidateSourceRoot != "" {
		return errors.New("provider_process Desktop source root is only valid for v3 local candidate")
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
		if !filepath.IsAbs(d.Provenance.ExecutablePath) || !providerSHA256Pattern.MatchString(d.Provenance.ExecutableDigest) ||
			d.LocalCandidateManifestFile != "" || d.LocalCandidateSourceRoot != "" {
			return errors.New("provider_process Desktop production provenance or candidate boundary is invalid")
		}
	} else if d.Provenance.ExecutablePath != "" || d.Provenance.ExecutableDigest != "" {
		return errors.New("provider_process local candidate cannot claim production provenance")
	} else if c.SchemaVersion == ProviderProductionSchemaV3 && (!filepath.IsAbs(d.LocalCandidateSourceRoot) || filepath.Clean(d.LocalCandidateSourceRoot) != d.LocalCandidateSourceRoot) {
		return errors.New("provider_process Desktop v3 local candidate requires an exact source root")
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
		if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Path != "/executor" ||
			parsed.EscapedPath() != "/executor" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			net.ParseIP(parsed.Hostname()) == nil || parsed.Port() == "" || parsed.String() != d.ExecutorURL {
			return errors.New("provider_process Desktop executor_url is invalid")
		}
		if !providerProfileIDPattern.MatchString(d.ExecutorIdentity) || !providerProfileIDPattern.MatchString(d.ExecutorBridgeKeyID) {
			return errors.New("provider_process Desktop executor identity or bridge key ID is invalid")
		}
		if c.SchemaVersion == ProviderProductionSchemaV3 {
			if d.ExecutorCABundleFile != "" || d.ExecutorCertificateFile != "" || d.ExecutorPrivateKeyFile != "" || d.ExecutorBridgePrivateKeyFile != "" ||
				d.ExecutorCABundleBindingID != "" || d.ExecutorCertificateBindingID != "" || d.ExecutorPrivateKeyBindingID != "" || d.ExecutorBridgePrivateKeyBindingID == "" {
				return errors.New("Provider Desktop v3 requires only a bridge key material binding and live executor TLS")
			}
		} else if materialSchema {
			if d.ExecutorCABundleFile != "" || d.ExecutorCertificateFile != "" || d.ExecutorPrivateKeyFile != "" || d.ExecutorBridgePrivateKeyFile != "" ||
				d.ExecutorCABundleBindingID == "" || d.ExecutorCertificateBindingID == "" || d.ExecutorPrivateKeyBindingID == "" || d.ExecutorBridgePrivateKeyBindingID == "" {
				return errors.New("provider_process Desktop executor requires material bindings and forbids raw credential paths")
			}
		} else {
			for name, path := range map[string]string{"executor CA": d.ExecutorCABundleFile, "executor certificate": d.ExecutorCertificateFile, "executor key": d.ExecutorPrivateKeyFile, "executor bridge key": d.ExecutorBridgePrivateKeyFile} {
				if err := validateAbsoluteSecretPath("provider_process Desktop "+name, path); err != nil {
					return err
				}
			}
		}
		if !filepath.IsAbs(d.BrokerMuxSocketPath) || filepath.Clean(d.BrokerMuxSocketPath) != d.BrokerMuxSocketPath || !providerDesktopBrokerMuxSocketPattern.MatchString(filepath.Base(d.BrokerMuxSocketPath)) {
			return errors.New("provider_process Desktop broker mux socket path is invalid")
		}
	} else if c.DeploymentLevel == ProviderLocalCandidateLevel {
		return errors.New("provider_process local candidate requires the Desktop executor")
	} else if d.ExecutorCABundleFile != "" || d.ExecutorCertificateFile != "" || d.ExecutorPrivateKeyFile != "" || d.ExecutorIdentity != "" || d.ExecutorBridgeKeyID != "" || d.ExecutorBridgePrivateKeyFile != "" || d.BrokerMuxSocketPath != "" || d.ExecutorCABundleBindingID != "" || d.ExecutorCertificateBindingID != "" || d.ExecutorPrivateKeyBindingID != "" || d.ExecutorBridgePrivateKeyBindingID != "" {
		return errors.New("provider_process Desktop executor credentials require executor_url")
	}
	return nil
}

func (c *ProviderProcessConfig) validateAuthorityPaths() error {
	if !c.Materials.IsZero() || c.Transport.ServerCertificateBindingID != "" || c.Transport.ServerPrivateKeyBindingID != "" || c.Transport.ClientCABundleBindingID != "" || c.Transport.ExpectedServerName != "" ||
		c.Transport.Private.ServerCertificateBindingID != "" || c.Transport.Private.ServerPrivateKeyBindingID != "" || c.Transport.Private.ClientCABundleBindingID != "" || c.Transport.Private.ExpectedServerName != "" ||
		c.Postgres.RuntimeDSNBindingID != "" || c.Desktop.ExecutorCABundleBindingID != "" || c.Desktop.ExecutorCertificateBindingID != "" || c.Desktop.ExecutorPrivateKeyBindingID != "" || c.Desktop.ExecutorBridgePrivateKeyBindingID != "" {
		return errors.New("provider_process legacy schema cannot contain production material bindings")
	}
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

func (c *ProviderProcessConfig) validateMaterialAuthority() error {
	bindings, err := c.Materials.DecodeBindings(secretref.RoleProvider)
	if err != nil || c.Materials.Provider.CacheSeconds < 1 {
		return errors.New("provider_process material registry is invalid")
	}
	selections := []struct {
		id      string
		purpose secretref.Purpose
	}{
		{c.Postgres.RuntimeDSNBindingID, secretref.PurposePostgresRuntimeDSN},
	}
	if c.SchemaVersion == ProviderProductionSchemaV2 {
		selections = append(selections,
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Transport.ServerCertificateBindingID, secretref.PurposeTLSCertificate},
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Transport.ServerPrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Transport.ClientCABundleBindingID, secretref.PurposeCABundle},
		)
	}
	if c.Transport.Private.Enabled && c.SchemaVersion == ProviderProductionSchemaV2 {
		selections = append(selections,
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Transport.Private.ServerCertificateBindingID, secretref.PurposeTLSCertificate},
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Transport.Private.ServerPrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Transport.Private.ClientCABundleBindingID, secretref.PurposeCABundle},
		)
	}
	for _, key := range c.ProtectedAdmission.TrustedVerificationKeys {
		selections = append(selections, struct {
			id      string
			purpose secretref.Purpose
		}{key.PublicKeyBindingID, secretref.PurposeAdmissionVerification})
	}
	if c.Desktop.ExecutorURL != "" {
		if c.SchemaVersion == ProviderProductionSchemaV2 {
			selections = append(selections,
				struct {
					id      string
					purpose secretref.Purpose
				}{c.Desktop.ExecutorCABundleBindingID, secretref.PurposeCABundle},
				struct {
					id      string
					purpose secretref.Purpose
				}{c.Desktop.ExecutorCertificateBindingID, secretref.PurposeTLSCertificate},
				struct {
					id      string
					purpose secretref.Purpose
				}{c.Desktop.ExecutorPrivateKeyBindingID, secretref.PurposeExecutorClientKey},
			)
		}
		selections = append(selections,
			struct {
				id      string
				purpose secretref.Purpose
			}{c.Desktop.ExecutorBridgePrivateKeyBindingID, secretref.PurposeExecutorBridgeKey},
		)
	}
	if len(bindings) != len(selections) {
		return errors.New("provider_process material bindings must contain exactly the selected authorities")
	}
	selected := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		binding, ok := bindings[selection.id]
		if selection.id == "" || !ok || binding.Purpose != selection.purpose || binding.TenantID != secretref.SystemTenant || binding.Role != secretref.RoleProvider {
			return errors.New("provider_process material selection is invalid")
		}
		if _, duplicate := selected[selection.id]; duplicate {
			return errors.New("provider_process material selections must be distinct")
		}
		selected[selection.id] = struct{}{}
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
