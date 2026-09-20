package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
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
	Enabled         bool                        `mapstructure:"enabled"`
	DeploymentLevel ProductDeploymentLevel      `mapstructure:"deployment_level"`
	API             option.HTTP                 `mapstructure:"api"`
	Postgres        ProductPostgresConfig       `mapstructure:"postgres"`
	Identity        ProductStaticIdentityConfig `mapstructure:"identity"`
}

// ProductPostgresConfig contains only non-secret connection policy. The DSN is
// loaded from a private bounded file at process startup.
type ProductPostgresConfig struct {
	DSNFile                 string `mapstructure:"dsn_file"`
	StartupTimeoutSeconds   int    `mapstructure:"startup_timeout_seconds"`
	OperationTimeoutSeconds int    `mapstructure:"operation_timeout_seconds"`
	MaxConnections          int32  `mapstructure:"max_connections"`
	MinConnections          int32  `mapstructure:"min_connections"`
}

// ProductStaticIdentityConfig selects the development-only frozen bearer
// binding file. Later Phase 6 slices replace it for standalone/production.
type ProductStaticIdentityConfig struct {
	BindingsFile string `mapstructure:"bindings_file"`
}

func defaultProductProcessConfig() *ProductProcessConfig {
	return &ProductProcessConfig{
		DeploymentLevel: ProductDevelopmentLevel,
		API:             option.HTTP{Host: defaultProductProcessAPIHost, Port: defaultProductProcessAPIPort},
		Postgres: ProductPostgresConfig{
			StartupTimeoutSeconds:   10,
			OperationTimeoutSeconds: 3,
			MaxConnections:          8,
			MinConnections:          1,
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
	if c.DeploymentLevel != ProductDevelopmentLevel {
		return fmt.Errorf("product_process.deployment_level %q is not composed in Phase 6 Slice 1", c.DeploymentLevel)
	}
	if err := c.API.Validate(); err != nil {
		return fmt.Errorf("product_process.api: %w", err)
	}
	if !exactLoopbackIP(c.API.Host) {
		return errors.New("product_process.api.host must be an explicit loopback IP in the development slice")
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
	return nil
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
