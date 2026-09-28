package config

import (
	"errors"
	"fmt"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

const (
	ProviderMigrationSchemaV1 = "sandbox-runtime.provider-migration.v1"
	ProviderMigrationSchemaV2 = "sandbox-runtime.provider-migration.v2"
)

type ProviderMigrationConfig struct {
	SchemaVersion string                          `mapstructure:"schema_version"`
	Enabled       bool                            `mapstructure:"enabled"`
	Postgres      ProviderMigrationPostgresConfig `mapstructure:"postgres"`
	Materials     RoleMaterialsConfig             `mapstructure:"materials"`
}

type ProviderMigrationPostgresConfig struct {
	Job                        string `mapstructure:"job"`
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
	if (c.SchemaVersion != ProviderMigrationSchemaV1 && c.SchemaVersion != ProviderMigrationSchemaV2) ||
		!postgresRolePattern.MatchString(c.Postgres.Role) ||
		c.Postgres.StartupTimeoutSeconds < 1 || c.Postgres.StartupTimeoutSeconds > 60 || c.Postgres.MaxConnections < 1 || c.Postgres.MaxConnections > 4 {
		return errors.New("Provider migration configuration is invalid")
	}
	if c.SchemaVersion == ProviderMigrationSchemaV1 {
		if c.Postgres.Job != "" || c.Postgres.SecurityProfilePath != "" || c.Postgres.SecurityProfileDigest != "" ||
			c.Postgres.ClientAgentSocket != "" || c.Postgres.ClientAgentUID != 0 || c.Postgres.ClientAgentGID != 0 ||
			c.Postgres.PeerCRLRoleFile != "" || c.Postgres.PeerCRLRoleDigest != "" ||
			c.Postgres.PeerCRLSourceMappingDigest != "" {
			return errors.New("Provider migration v1 cannot select final-profile authority")
		}
	} else {
		roles := map[string]string{"provider-migration-job": "provider_migrator",
			"provider-browser-migration-job": "browser_provider_migrator",
			"provider-desktop-migration-job": "desktop_provider_migrator"}
		if roles[c.Postgres.Job] != c.Postgres.Role ||
			validateAbsoluteSecretPath("Provider migration security profile", c.Postgres.SecurityProfilePath) != nil ||
			validateAbsoluteSecretPath("Provider migration PostgreSQL signer", c.Postgres.ClientAgentSocket) != nil ||
			validateAbsoluteSecretPath("Provider migration peer CRL role", c.Postgres.PeerCRLRoleFile) != nil ||
			!providerSHA256Pattern.MatchString(c.Postgres.SecurityProfileDigest) ||
			!providerSHA256Pattern.MatchString(c.Postgres.PeerCRLRoleDigest) ||
			!providerSHA256Pattern.MatchString(c.Postgres.PeerCRLSourceMappingDigest) ||
			c.Postgres.ClientAgentUID == 0 || c.Postgres.ClientAgentGID == 0 ||
			c.Postgres.SecurityProfilePath == c.Postgres.PeerCRLRoleFile ||
			c.Postgres.ClientAgentSocket == c.Postgres.PeerCRLRoleFile ||
			c.Postgres.ClientAgentSocket == c.Materials.Provider.SocketPath {
			return errors.New("Provider migration v2 requires one closed profile-bound job and signer")
		}
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
