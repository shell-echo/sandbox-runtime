package config

import (
	"encoding/json"
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
