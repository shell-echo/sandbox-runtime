package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

const (
	defaultProductProcessAPIHost = "127.0.0.1"
	defaultProductProcessAPIPort = 8082
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
	Enabled         bool                   `mapstructure:"enabled"`
	DeploymentLevel ProductDeploymentLevel `mapstructure:"deployment_level"`
	API             option.HTTP            `mapstructure:"api"`
	TLS             ProductTLSConfig       `mapstructure:"tls"`
	Postgres        ProductPostgresConfig  `mapstructure:"postgres"`
	Identity        ProductIdentityConfig  `mapstructure:"identity"`
}

// ProductTLSConfig identifies the production listener key pair. Both files are
// loaded once before bind; certificate rotation therefore uses an overlapping
// deployment and process replacement rather than an in-place partial reload.
type ProductTLSConfig struct {
	CertificateFile string `mapstructure:"certificate_file"`
	PrivateKeyFile  string `mapstructure:"private_key_file"`
}

// ProductPostgresConfig contains only non-secret connection policy. DSNs are
// loaded from private bounded files at process startup.
type ProductPostgresConfig struct {
	DSNFile                 string `mapstructure:"dsn_file"`
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

// ProductIdentityConfig selects either the development-only frozen bearer
// binding file or the production signed-token verification policy.
type ProductIdentityConfig struct {
	BindingsFile            string `mapstructure:"bindings_file"`
	Issuer                  string `mapstructure:"issuer"`
	Audience                string `mapstructure:"audience"`
	KeyRingFile             string `mapstructure:"key_ring_file"`
	ClockSkewSeconds        int    `mapstructure:"clock_skew_seconds"`
	MaxTokenLifetimeSeconds int    `mapstructure:"max_token_lifetime_seconds"`
}

func defaultProductProcessConfig() *ProductProcessConfig {
	return &ProductProcessConfig{
		DeploymentLevel: ProductDevelopmentLevel,
		API:             option.HTTP{Host: defaultProductProcessAPIHost, Port: defaultProductProcessAPIPort},
		Postgres: ProductPostgresConfig{
			StartupTimeoutSeconds:   10,
			OperationTimeoutSeconds: 3,
			MigrationMaxConnections: 1,
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
	if c.TLS != (ProductTLSConfig{}) || c.Postgres.MigrationDSNFile != "" || c.Postgres.RuntimeDSNFile != "" ||
		c.Postgres.MigrationRole != "" || c.Postgres.RuntimeRole != "" || c.Identity.Issuer != "" ||
		c.Identity.Audience != "" || c.Identity.KeyRingFile != "" {
		return errors.New("production Product authority is not accepted in development mode")
	}
	return nil
}

var postgresRolePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

func (c *ProductProcessConfig) validateProduction() error {
	if c.Postgres.DSNFile != "" || c.Identity.BindingsFile != "" {
		return errors.New("development Product identity or database authority is forbidden in production")
	}
	paths := []struct{ name, value string }{
		{"product_process.tls.certificate_file", c.TLS.CertificateFile},
		{"product_process.tls.private_key_file", c.TLS.PrivateKeyFile},
		{"product_process.postgres.migration_dsn_file", c.Postgres.MigrationDSNFile},
		{"product_process.postgres.runtime_dsn_file", c.Postgres.RuntimeDSNFile},
		{"product_process.identity.key_ring_file", c.Identity.KeyRingFile},
	}
	seen := make(map[string]struct{}, len(paths))
	for _, item := range paths {
		if err := validateAbsoluteSecretPath(item.name, item.value); err != nil {
			return err
		}
		clean := filepath.Clean(item.value)
		if _, exists := seen[clean]; exists {
			return errors.New("production Product authority files must use distinct paths")
		}
		seen[clean] = struct{}{}
	}
	if !postgresRolePattern.MatchString(c.Postgres.MigrationRole) || !postgresRolePattern.MatchString(c.Postgres.RuntimeRole) ||
		c.Postgres.MigrationRole == c.Postgres.RuntimeRole {
		return errors.New("production Product migration and runtime database roles must be distinct explicit identifiers")
	}
	if c.Postgres.MigrationMaxConnections < 1 || c.Postgres.MigrationMaxConnections > 4 {
		return errors.New("product_process.postgres.migration_max_connections must be between 1 and 4")
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
