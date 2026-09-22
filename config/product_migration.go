package config

import (
	"errors"
	"fmt"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

const ProductMigrationSchemaV1 = "sandbox-runtime.product-migration.v1"

// ProductMigrationConfig is the one-shot Product schema authority. It is
// intentionally disjoint from the long-running Product process configuration.
type ProductMigrationConfig struct {
	SchemaVersion string                         `mapstructure:"schema_version"`
	Enabled       bool                           `mapstructure:"enabled"`
	Postgres      ProductMigrationPostgresConfig `mapstructure:"postgres"`
	Materials     ProductMaterialsConfig         `mapstructure:"materials"`
}

type ProductMigrationPostgresConfig struct {
	DSNBindingID          string `mapstructure:"dsn_binding_id"`
	Role                  string `mapstructure:"role"`
	StartupTimeoutSeconds int    `mapstructure:"startup_timeout_seconds"`
	MaxConnections        int32  `mapstructure:"max_connections"`
}

func defaultProductMigrationConfig() *ProductMigrationConfig {
	return &ProductMigrationConfig{
		SchemaVersion: ProductMigrationSchemaV1,
		Postgres: ProductMigrationPostgresConfig{
			StartupTimeoutSeconds: 10, MaxConnections: 1,
		},
	}
}

func (c *ProductMigrationConfig) Validate() error {
	if c == nil {
		return errors.New("product_migration configuration is required")
	}
	if !c.Enabled {
		return nil
	}
	if c.SchemaVersion != ProductMigrationSchemaV1 {
		return errors.New("Product migration must use schema sandbox-runtime.product-migration.v1")
	}
	if !postgresRolePattern.MatchString(c.Postgres.Role) {
		return errors.New("Product migration database role must be an explicit identifier")
	}
	if c.Postgres.StartupTimeoutSeconds < 1 || c.Postgres.StartupTimeoutSeconds > 60 ||
		c.Postgres.MaxConnections < 1 || c.Postgres.MaxConnections > 4 {
		return errors.New("Product migration PostgreSQL bounds are invalid")
	}
	if c.Materials.Provider.CacheSeconds != 0 {
		return errors.New("Product migration material caching is forbidden")
	}
	bindings, err := c.Materials.DecodeBindings(secretref.RoleProduct)
	if err != nil {
		return err
	}
	if len(bindings) != 1 {
		return errors.New("Product migration must contain exactly one material binding")
	}
	binding, ok := bindings[c.Postgres.DSNBindingID]
	if !ok || binding.Purpose != secretref.PurposePostgresMigrationDSN || binding.TenantID != secretref.SystemTenant || binding.Role != secretref.RoleProduct {
		return errors.New("Product migration DSN binding is invalid")
	}
	return nil
}

var ProductMigration = defaultProductMigrationConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		if err := bindEnvDefaults(v, "product_migration", defaultProductMigrationConfig()); err != nil {
			return nil, fmt.Errorf("bind config %q: %w", "product_migration", err)
		}
		section := v.Sub("product_migration")
		if section == nil {
			return nil, errors.New("parse config \"product_migration\": section unavailable")
		}
		candidate := &ProductMigrationConfig{}
		if err := section.UnmarshalExact(candidate); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", "product_migration", err)
		}
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		return func() error { ProductMigration = candidate; return nil }, nil
	})
}
