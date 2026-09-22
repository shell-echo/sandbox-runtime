package config

import (
	"errors"
	"fmt"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

const ProviderMigrationSchemaV1 = "sandbox-runtime.provider-migration.v1"

type ProviderMigrationConfig struct {
	SchemaVersion string                          `mapstructure:"schema_version"`
	Enabled       bool                            `mapstructure:"enabled"`
	Postgres      ProviderMigrationPostgresConfig `mapstructure:"postgres"`
	Materials     RoleMaterialsConfig             `mapstructure:"materials"`
}

type ProviderMigrationPostgresConfig struct {
	DSNBindingID          string `mapstructure:"dsn_binding_id"`
	Role                  string `mapstructure:"role"`
	StartupTimeoutSeconds int    `mapstructure:"startup_timeout_seconds"`
	MaxConnections        int32  `mapstructure:"max_connections"`
}

func defaultProviderMigrationConfig() *ProviderMigrationConfig {
	return &ProviderMigrationConfig{SchemaVersion: ProviderMigrationSchemaV1, Postgres: ProviderMigrationPostgresConfig{StartupTimeoutSeconds: 10, MaxConnections: 1}}
}

func (c *ProviderMigrationConfig) Validate() error {
	if c == nil {
		return errors.New("provider_migration configuration is required")
	}
	if !c.Enabled {
		return nil
	}
	if c.SchemaVersion != ProviderMigrationSchemaV1 || !postgresRolePattern.MatchString(c.Postgres.Role) ||
		c.Postgres.StartupTimeoutSeconds < 1 || c.Postgres.StartupTimeoutSeconds > 60 || c.Postgres.MaxConnections < 1 || c.Postgres.MaxConnections > 4 {
		return errors.New("Provider migration configuration is invalid")
	}
	if c.Materials.Provider.CacheSeconds != 0 {
		return errors.New("Provider migration material caching is forbidden")
	}
	bindings, err := c.Materials.DecodeBindings(secretref.RoleProvider)
	if err != nil || len(bindings) != 1 {
		return errors.New("Provider migration must contain exactly one material binding")
	}
	binding, ok := bindings[c.Postgres.DSNBindingID]
	if !ok || binding.Purpose != secretref.PurposePostgresMigrationDSN || binding.TenantID != secretref.SystemTenant || binding.Role != secretref.RoleProvider {
		return errors.New("Provider migration DSN binding is invalid")
	}
	return nil
}

var ProviderMigration = defaultProviderMigrationConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		if err := bindEnvDefaults(v, "provider_migration", defaultProviderMigrationConfig()); err != nil {
			return nil, fmt.Errorf("bind config %q: %w", "provider_migration", err)
		}
		section := v.Sub("provider_migration")
		if section == nil {
			return nil, errors.New("parse config \"provider_migration\": section unavailable")
		}
		candidate := &ProviderMigrationConfig{}
		if err := section.UnmarshalExact(candidate); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", "provider_migration", err)
		}
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		return func() error { ProviderMigration = candidate; return nil }, nil
	})
}
