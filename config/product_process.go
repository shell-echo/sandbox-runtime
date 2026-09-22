package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

const (
	defaultProductProcessAPIHost   = "127.0.0.1"
	defaultProductProcessAPIPort   = 8082
	ProductLegacyDevelopmentSchema = "sandbox-runtime.product-process.legacy-development.v1"
	ProductProductionSchemaV2      = "sandbox-runtime.product-process.v2"
	ProductUnixMaterialProviderV1  = "unix-workload-material.v1"
)

// ProductDeploymentLevel is the assurance level requested for the Product
// process. Phase 6 Slice 1 intentionally composes only the development level.
type ProductDeploymentLevel string

const (
	ProductDevelopmentLevel ProductDeploymentLevel = "development"
	ProductStandaloneLevel  ProductDeploymentLevel = "standalone"
	ProductProductionLevel  ProductDeploymentLevel = "production"
)

// ProductProcessConfig configures the independent Product process. It does not
// configure the Provider, Gateway, Guest, Browser, Desktop, or local /instances
// listeners.
type ProductProcessConfig struct {
	SchemaVersion   string                 `mapstructure:"schema_version"`
	Enabled         bool                   `mapstructure:"enabled"`
	DeploymentLevel ProductDeploymentLevel `mapstructure:"deployment_level"`
	API             option.HTTP            `mapstructure:"api"`
	TLS             ProductTLSConfig       `mapstructure:"tls"`
	Postgres        ProductPostgresConfig  `mapstructure:"postgres"`
	Identity        ProductIdentityConfig  `mapstructure:"identity"`
	Materials       ProductMaterialsConfig `mapstructure:"materials"`
}

// ProductTLSConfig identifies the production listener's atomically versioned
// certificate and private-key bindings. Development leaves this section empty.
type ProductTLSConfig struct {
	CertificateBindingID string `mapstructure:"certificate_binding_id"`
	PrivateKeyBindingID  string `mapstructure:"private_key_binding_id"`
	ExpectedServerName   string `mapstructure:"expected_server_name"`
}

// ProductPostgresConfig contains non-secret connection policy plus either the
// development DSN file or the production runtime-registry binding ID.
type ProductPostgresConfig struct {
	DSNFile                 string `mapstructure:"dsn_file"`
	RuntimeDSNBindingID     string `mapstructure:"runtime_dsn_binding_id"`
	RuntimeRole             string `mapstructure:"runtime_role"`
	StartupTimeoutSeconds   int    `mapstructure:"startup_timeout_seconds"`
	OperationTimeoutSeconds int    `mapstructure:"operation_timeout_seconds"`
	MaxConnections          int32  `mapstructure:"max_connections"`
	MinConnections          int32  `mapstructure:"min_connections"`
}

// ProductIdentityConfig selects either the development-only frozen bearer
// binding file or the production signed-token verification policy.
type ProductIdentityConfig struct {
	BindingsFile            string `mapstructure:"bindings_file"`
	Issuer                  string `mapstructure:"issuer"`
	Audience                string `mapstructure:"audience"`
	KeyRingBindingID        string `mapstructure:"key_ring_binding_id"`
	ClockSkewSeconds        int    `mapstructure:"clock_skew_seconds"`
	MaxTokenLifetimeSeconds int    `mapstructure:"max_token_lifetime_seconds"`
}

type ProductMaterialsConfig struct {
	Provider ProductMaterialProviderConfig  `mapstructure:"provider"`
	Bindings []ProductMaterialBindingConfig `mapstructure:"bindings"`
}

type ProductMaterialProviderConfig struct {
	Type                    string `mapstructure:"type"`
	Alias                   string `mapstructure:"alias"`
	SocketPath              string `mapstructure:"socket_path"`
	ExpectedUID             int64  `mapstructure:"expected_uid"`
	ExpectedGID             int64  `mapstructure:"expected_gid"`
	OperationTimeoutSeconds int    `mapstructure:"operation_timeout_seconds"`
	CacheSeconds            int    `mapstructure:"cache_seconds"`
}

type ProductMaterialBindingConfig struct {
	ID       string `mapstructure:"id"`
	Provider string `mapstructure:"provider"`
	Document string `mapstructure:"document"`
}

func defaultProductProcessConfig() *ProductProcessConfig {
	return &ProductProcessConfig{
		SchemaVersion:   ProductLegacyDevelopmentSchema,
		DeploymentLevel: ProductDevelopmentLevel,
		API:             option.HTTP{Host: defaultProductProcessAPIHost, Port: defaultProductProcessAPIPort},
		Postgres: ProductPostgresConfig{
			StartupTimeoutSeconds:   10,
			OperationTimeoutSeconds: 3,
			MaxConnections:          8,
			MinConnections:          1,
		},
		Identity: ProductIdentityConfig{
			ClockSkewSeconds:        30,
			MaxTokenLifetimeSeconds: 900,
		},
	}
}

// Validate rejects partial or broader-than-implemented Product composition.
// Disabled defaults remain inert so existing Provider/local commands are not
// forced to supply Product secrets.
func (c *ProductProcessConfig) Validate() error {
	if c == nil {
		return errors.New("product_process configuration is required")
	}
	if !c.Enabled {
		return nil
	}
	if err := c.API.Validate(); err != nil {
		return fmt.Errorf("product_process.api: %w", err)
	}
	if net.ParseIP(c.API.Host) == nil {
		return errors.New("product_process.api.host must be an explicit IP address")
	}
	if c.Postgres.StartupTimeoutSeconds < 1 || c.Postgres.StartupTimeoutSeconds > 60 {
		return errors.New("product_process.postgres.startup_timeout_seconds must be between 1 and 60")
	}
	if c.Postgres.OperationTimeoutSeconds < 1 || c.Postgres.OperationTimeoutSeconds > 30 {
		return errors.New("product_process.postgres.operation_timeout_seconds must be between 1 and 30")
	}
	if c.Postgres.MaxConnections < 1 || c.Postgres.MaxConnections > 64 {
		return errors.New("product_process.postgres.max_connections must be between 1 and 64")
	}
	if c.Postgres.MinConnections < 0 || c.Postgres.MinConnections > c.Postgres.MaxConnections {
		return errors.New("product_process.postgres.min_connections must be between 0 and max_connections")
	}
	switch c.DeploymentLevel {
	case ProductDevelopmentLevel:
		return c.validateDevelopment()
	case ProductProductionLevel:
		return c.validateProduction()
	case ProductStandaloneLevel:
		return errors.New("product_process.deployment_level standalone is not a Phase 6 production assurance level")
	default:
		return fmt.Errorf("product_process.deployment_level %q is invalid", c.DeploymentLevel)
	}
}

func (c *ProductProcessConfig) validateDevelopment() error {
	if c.SchemaVersion != ProductLegacyDevelopmentSchema {
		return errors.New("development Product configuration must use the explicit legacy-development schema")
	}
	if !exactLoopbackIP(c.API.Host) {
		return errors.New("product_process.api.host must be an explicit loopback IP in development")
	}
	if err := validateAbsoluteSecretPath("product_process.postgres.dsn_file", c.Postgres.DSNFile); err != nil {
		return err
	}
	if err := validateAbsoluteSecretPath("product_process.identity.bindings_file", c.Identity.BindingsFile); err != nil {
		return err
	}
	if filepath.Clean(c.Postgres.DSNFile) == filepath.Clean(c.Identity.BindingsFile) {
		return errors.New("Product PostgreSQL and identity secrets must use different files")
	}
	if c.TLS != (ProductTLSConfig{}) || c.Postgres.RuntimeRole != "" || c.Identity.Issuer != "" ||
		c.Identity.Audience != "" || c.Postgres.RuntimeDSNBindingID != "" || c.Identity.KeyRingBindingID != "" || !c.Materials.isZero() {
		return errors.New("production Product authority is not accepted in development mode")
	}
	return nil
}

var postgresRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func (c *ProductProcessConfig) validateProduction() error {
	if c.SchemaVersion != ProductProductionSchemaV2 {
		return errors.New("production Product configuration must use schema sandbox-runtime.product-process.v2")
	}
	if c.Postgres.DSNFile != "" || c.Identity.BindingsFile != "" {
		return errors.New("development Product identity or database authority is forbidden in production")
	}
	bindings, err := c.Materials.decode(secretref.RoleProduct)
	if err != nil {
		return err
	}
	selections := []struct {
		name, id string
		purpose  secretref.Purpose
	}{
		{"TLS certificate", c.TLS.CertificateBindingID, secretref.PurposeTLSCertificate},
		{"TLS private key", c.TLS.PrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
		{"runtime DSN", c.Postgres.RuntimeDSNBindingID, secretref.PurposePostgresRuntimeDSN},
		{"identity key ring", c.Identity.KeyRingBindingID, secretref.PurposeIdentityKeyRing},
	}
	if len(bindings) != len(selections) {
		return errors.New("production Product material bindings must contain exactly the selected authorities")
	}
	selected := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		binding, ok := bindings[selection.id]
		if !ok || binding.Purpose != selection.purpose || binding.TenantID != secretref.SystemTenant || binding.Role != secretref.RoleProduct {
			return fmt.Errorf("production Product %s binding is invalid", selection.name)
		}
		if _, duplicate := selected[selection.id]; duplicate {
			return errors.New("production Product material binding selections must be distinct")
		}
		selected[selection.id] = struct{}{}
	}
	if bindings[c.TLS.CertificateBindingID].Version != bindings[c.TLS.PrivateKeyBindingID].Version {
		return errors.New("production Product TLS bindings must select one version")
	}
	if !validProductServerName(c.TLS.ExpectedServerName) {
		return errors.New("production Product TLS expected_server_name is invalid")
	}
	if !postgresRolePattern.MatchString(c.Postgres.RuntimeRole) {
		return errors.New("production Product runtime database role must be an explicit identifier")
	}
	if c.Materials.Provider.CacheSeconds < 1 || c.Materials.Provider.CacheSeconds > 60 {
		return errors.New("production Product runtime material cache_seconds must be between 1 and 60")
	}
	if !validProductIdentityIssuer(c.Identity.Issuer) || !validProductIdentityURI(c.Identity.Audience) {
		return errors.New("production Product identity issuer and audience must be canonical absolute URIs")
	}
	if c.Identity.ClockSkewSeconds < 0 || c.Identity.ClockSkewSeconds > 120 {
		return errors.New("product_process.identity.clock_skew_seconds must be between 0 and 120")
	}
	if c.Identity.MaxTokenLifetimeSeconds < 60 || c.Identity.MaxTokenLifetimeSeconds > 3600 {
		return errors.New("product_process.identity.max_token_lifetime_seconds must be between 60 and 3600")
	}
	return nil
}

var productMaterialIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

func (c ProductMaterialsConfig) isZero() bool {
	return c.Provider == (ProductMaterialProviderConfig{}) && len(c.Bindings) == 0
}

func (c ProductMaterialsConfig) DecodeBindings(role secretref.Role) (map[string]secretref.Binding, error) {
	return c.decode(role)
}

func (c ProductMaterialsConfig) decode(role secretref.Role) (map[string]secretref.Binding, error) {
	provider := c.Provider
	if provider.Type != ProductUnixMaterialProviderV1 || !productMaterialIDPattern.MatchString(provider.Alias) ||
		!filepath.IsAbs(provider.SocketPath) || filepath.Clean(provider.SocketPath) != provider.SocketPath || len(provider.SocketPath) > 100 ||
		provider.ExpectedUID < 0 || provider.ExpectedUID > (1<<32)-1 || provider.ExpectedGID < 0 || provider.ExpectedGID > (1<<32)-1 ||
		provider.OperationTimeoutSeconds < 1 || provider.OperationTimeoutSeconds > 60 || provider.CacheSeconds < 0 || provider.CacheSeconds > 60 ||
		len(c.Bindings) < 1 || len(c.Bindings) > 32 {
		return nil, errors.New("production Product material provider configuration is invalid")
	}
	decoded := make(map[string]secretref.Binding, len(c.Bindings))
	references := make(map[string]struct{}, len(c.Bindings))
	for _, item := range c.Bindings {
		if !productMaterialIDPattern.MatchString(item.ID) || item.Provider != provider.Alias || len(item.Document) < 1 || len(item.Document) > 4<<10 {
			return nil, errors.New("production Product material binding configuration is invalid")
		}
		if _, duplicate := decoded[item.ID]; duplicate {
			return nil, errors.New("production Product material binding IDs must be unique")
		}
		binding, err := secretref.DecodeBinding([]byte(item.Document))
		if err != nil || binding.Role != role || binding.Kind != secretref.KindSecret {
			return nil, errors.New("production Product material binding is invalid")
		}
		if _, duplicate := references[binding.Reference.String()]; duplicate {
			return nil, errors.New("production Product material references must be distinct")
		}
		references[binding.Reference.String()] = struct{}{}
		decoded[item.ID] = binding
	}
	return decoded, nil
}

func validProductServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t /\\") {
		return false
	}
	parsed := net.ParseIP(value)
	if parsed != nil {
		return parsed.String() == value
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validProductIdentityIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == "" && parsed.String() == value &&
		strings.TrimSpace(value) == value && len(value) <= 2048
}

func validProductIdentityURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs() && (parsed.Host != "" || parsed.Opaque != "") && parsed.Fragment == "" && parsed.String() == value &&
		strings.TrimSpace(value) == value && len(value) <= 2048
}

func exactLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateAbsoluteSecretPath(name, value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") || !filepath.IsAbs(value) {
		return fmt.Errorf("%s must be a clean absolute path", name)
	}
	if filepath.Clean(value) != value {
		return fmt.Errorf("%s must be a clean absolute path", name)
	}
	return nil
}

// ProductProcess is the committed independent Product process configuration.
var ProductProcess = defaultProductProcessConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		if err := bindEnvDefaults(v, "product_process", defaultProductProcessConfig()); err != nil {
			return nil, fmt.Errorf("bind config %q: %w", "product_process", err)
		}
		section := v.Sub("product_process")
		if section == nil {
			return nil, errors.New("parse config \"product_process\": section unavailable")
		}
		candidate := &ProductProcessConfig{}
		if err := section.UnmarshalExact(candidate); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", "product_process", err)
		}
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		return func() error { ProductProcess = candidate; return nil }, nil
	})
}
