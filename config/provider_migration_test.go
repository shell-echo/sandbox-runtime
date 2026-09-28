package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestProviderMigrationRequiresOneUncachedMigrationBinding(t *testing.T) {
	binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/kv/provider-migration-dsn", Version: "v1", Purpose: secretref.PurposePostgresMigrationDSN,
		TenantID: secretref.SystemTenant, Role: secretref.RoleProvider}
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &ProviderMigrationConfig{
		SchemaVersion: ProviderMigrationSchemaV1, Enabled: true,
		Postgres: ProviderMigrationPostgresConfig{DSNBindingID: "provider-migration-dsn", Role: "provider_migrator", StartupTimeoutSeconds: 10, MaxConnections: 1},
		Materials: RoleMaterialsConfig{
			Provider: RoleMaterialProviderConfig{Type: UnixWorkloadMaterialProviderV1, Alias: "provider-migration-agent", SocketPath: "/tmp/sandbox-runtime-provider-migration-agent.sock", ExpectedUID: 501, ExpectedGID: 20, OperationTimeoutSeconds: 3},
			Bindings: []RoleMaterialBindingConfig{{ID: "provider-migration-dsn", Provider: "provider-migration-agent", Document: string(document)}},
		},
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Provider migration: %v", err)
	}
	unsafe := *candidate
	unsafe.Materials = candidate.Materials
	unsafe.Materials.Provider.CacheSeconds = 1
	if err := unsafe.Validate(); err == nil {
		t.Fatal("Provider migration accepted material caching")
	}
}

func TestProviderMigrationV2SpecializesThreeClosedJobs(t *testing.T) {
	for job, role := range map[string]string{
		"provider-migration-job":         "provider_migrator",
		"provider-browser-migration-job": "browser_provider_migrator",
		"provider-desktop-migration-job": "desktop_provider_migrator",
	} {
		t.Run(job, func(t *testing.T) {
			binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
				Reference: "secret://vault/kv/provider-migration-dsn", Version: "v1",
				Purpose: secretref.PurposePostgresMigrationDSN, TenantID: secretref.SystemTenant, Role: secretref.RoleProvider}
			document, err := json.Marshal(binding)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			valid := &ProviderMigrationConfig{SchemaVersion: ProviderMigrationSchemaV2, Enabled: true,
				Postgres: ProviderMigrationPostgresConfig{Job: job, DSNBindingID: "provider-migration-dsn", Role: role,
					StartupTimeoutSeconds: 10, MaxConnections: 1,
					SecurityProfilePath: filepath.Join(root, "profile.json"), SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
					ClientAgentSocket: filepath.Join(root, "postgres-agent.sock"), ClientAgentUID: 503, ClientAgentGID: 21,
					PeerCRLRoleFile: filepath.Join(root, "postgres-peer-role.json"), PeerCRLRoleDigest: "sha256:" + strings.Repeat("b", 64),
					PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64)},
				Materials: RoleMaterialsConfig{Provider: RoleMaterialProviderConfig{Type: UnixWorkloadMaterialProviderV1,
					Alias: "migration-agent", SocketPath: "/tmp/p6-provider-migration-material.sock",
					ExpectedUID: 501, ExpectedGID: 20, OperationTimeoutSeconds: 2},
					Bindings: []RoleMaterialBindingConfig{{ID: "provider-migration-dsn", Provider: "migration-agent", Document: string(document)}}}}
			if err := valid.Validate(); err != nil {
				t.Fatalf("valid Provider migration v2: %v", err)
			}
			for _, mutate := range []func(*ProviderMigrationConfig){
				func(c *ProviderMigrationConfig) { c.Postgres.Job = "gateway-migration-job" },
				func(c *ProviderMigrationConfig) { c.Postgres.Role = "provider_runtime" },
				func(c *ProviderMigrationConfig) { c.Postgres.PeerCRLRoleFile = "" },
				func(c *ProviderMigrationConfig) { c.SchemaVersion = ProviderMigrationSchemaV1 },
			} {
				candidate := *valid
				mutate(&candidate)
				if candidate.Validate() == nil {
					t.Fatal("unreviewed Provider migration admitted")
				}
			}
		})
	}
}
