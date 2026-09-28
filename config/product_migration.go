package config

import (
	"errors"
	"fmt"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

const (
	ProductMigrationSchemaV1 = "sandbox-runtime.product-migration.v1"
	ProductMigrationSchemaV2 = "sandbox-runtime.product-migration.v2"
)

// ProductMigrationConfig is the one-shot Product schema authority. It is
// intentionally disjoint from the long-running Product process configuration.
type ProductMigrationConfig struct {
	SchemaVersion string                         `mapstructure:"schema_version"`
	Enabled       bool                           `mapstructure:"enabled"`
	Postgres      ProductMigrationPostgresConfig `mapstructure:"postgres"`
	Materials     ProductMaterialsConfig         `mapstructure:"materials"`
}

type ProductMigrationPostgresConfig struct {
	DSNBindingID               string `mapstructure:"dsn_binding_id"`
	Role                       string `mapstructure:"role"`
	SecurityProfilePath        string `mapstructure:"security_profile_path"`
	SecurityProfileDigest      string `mapstructure:"security_profile_digest"`
	ClientAgentSocket          string `mapstructure:"client_agent_socket"`
	ClientAgentUID             uint32 `mapstructure:"client_agent_uid"`
	ClientAgentGID             uint32 `mapstructure:"client_agent_gid"`
	PeerCRLRoleFile            string `mapstructure:"peer_crl_role_file"`
	PeerCRLRoleDigest          string `mapstructure:"peer_crl_role_digest"`
	PeerCRLSourceMappingDigest string `mapstructure:"peer_crl_source_mapping_digest"`
	StartupTimeoutSeconds      int    `mapstructure:"startup_timeout_seconds"`
	MaxConnections             int32  `mapstructure:"max_connections"`
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
	if c.SchemaVersion != ProductMigrationSchemaV1 && c.SchemaVersion != ProductMigrationSchemaV2 {
		return errors.New("Product migration requires an explicit supported schema")
	}
	if !postgresRolePattern.MatchString(c.Postgres.Role) {
		return errors.New("Product migration database role must be an explicit identifier")
	}
	if c.Postgres.StartupTimeoutSeconds < 1 || c.Postgres.StartupTimeoutSeconds > 60 ||
		c.Postgres.MaxConnections < 1 || c.Postgres.MaxConnections > 4 {
		return errors.New("Product migration PostgreSQL bounds are invalid")
	}
	if c.SchemaVersion == ProductMigrationSchemaV1 {
		if c.Postgres.SecurityProfilePath != "" || c.Postgres.SecurityProfileDigest != "" ||
			c.Postgres.ClientAgentSocket != "" || c.Postgres.ClientAgentUID != 0 || c.Postgres.ClientAgentGID != 0 ||
			c.Postgres.PeerCRLRoleFile != "" || c.Postgres.PeerCRLRoleDigest != "" ||
			c.Postgres.PeerCRLSourceMappingDigest != "" {
			return errors.New("Product migration v1 cannot select final-profile authority")
		}
	} else if c.Postgres.Role != "product_migrator" ||
		validateAbsoluteSecretPath("Product migration security profile", c.Postgres.SecurityProfilePath) != nil ||
		validateAbsoluteSecretPath("Product migration PostgreSQL signer", c.Postgres.ClientAgentSocket) != nil ||
		validateAbsoluteSecretPath("Product migration peer CRL role", c.Postgres.PeerCRLRoleFile) != nil ||
		!providerSHA256Pattern.MatchString(c.Postgres.SecurityProfileDigest) ||
		!providerSHA256Pattern.MatchString(c.Postgres.PeerCRLRoleDigest) ||
		!providerSHA256Pattern.MatchString(c.Postgres.PeerCRLSourceMappingDigest) ||
		c.Postgres.ClientAgentUID == 0 || c.Postgres.ClientAgentGID == 0 ||
		c.Postgres.SecurityProfilePath == c.Postgres.PeerCRLRoleFile ||
		c.Postgres.ClientAgentSocket == c.Postgres.PeerCRLRoleFile ||
		c.Postgres.ClientAgentSocket == c.Materials.Provider.SocketPath {
		return errors.New("Product migration v2 requires a distinct profile-bound PostgreSQL signer")
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
