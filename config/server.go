package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

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
	Transport  ProviderTransportConfig  `mapstructure:"transport"`
	Capability ProviderCapabilityConfig `mapstructure:"capability"`
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
	ProviderRevisionID      string                         `mapstructure:"provider_revision_id"`
	Limits                  ProviderLimitsConfig           `mapstructure:"limits"`
	SnapshotRestoreProfiles []ProviderCompatibilityProfile `mapstructure:"snapshot_restore_profiles"`
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
	providerSuiteVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	providerSuiteDigestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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
	return nil
}

// Validate applies the conditional Provider configuration policy. Disabled
// configuration is inert and may retain template placeholders.
func (c *ProviderConfig) Validate() error {
	if !c.Transport.Enabled {
		return nil
	}
	if err := c.Transport.validateEnabled(); err != nil {
		return fmt.Errorf("transport %w", err)
	}
	if err := c.Capability.validateEnabled(); err != nil {
		return fmt.Errorf("capability %w", err)
	}
	return nil
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
	if len(c.AllowedClientURIIdentities) == 0 {
		return errors.New("at least one allowed client URI identity is required")
	}
	seen := make(map[string]struct{}, len(c.AllowedClientURIIdentities))
	for index, identity := range c.AllowedClientURIIdentities {
		if err := validateExactAbsoluteURI(identity); err != nil {
			return fmt.Errorf("allowed client URI identity %d: %w", index, err)
		}
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("duplicate allowed client URI identity %q", identity)
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func validateExactAbsoluteURI(identity string) error {
	if identity == "" || strings.TrimSpace(identity) != identity {
		return errors.New("must be a nonempty exact URI without surrounding whitespace")
	}
	parsed, err := url.Parse(identity)
	if err != nil {
		return fmt.Errorf("must be an absolute URI: %w", err)
	}
	if !parsed.IsAbs() || parsed.Scheme == "" || parsed.String() != identity {
		return errors.New("must be an exact absolute URI")
	}
	return nil
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
