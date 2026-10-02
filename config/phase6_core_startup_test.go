package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func productMigrationPhase6StartupFixture(t *testing.T) []byte {
	t.Helper()
	binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://phase6/kv/product-migration-agent/postgres_migration_dsn",
		Version:   "v1", Purpose: secretref.PurposePostgresMigrationDSN,
		TenantID: secretref.SystemTenant, Role: secretref.RoleProduct}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`[application]
mode = "production"

[product_migration]
schema_version = "sandbox-runtime.product-migration.v2"
enabled = true

[product_migration.postgres]
dsn_binding_id = "product-migration-dsn"
role = "product_migrator"
security_profile_path = "/run/phase6/config/profile.json"
security_profile_digest = "sha256:%s"
client_agent_socket = "/run/tls/product-migration-postgres-tls-agent/signer.sock"
client_agent_uid = 56001
client_agent_gid = 58001
peer_crl_role_file = "/run/phase6/config/postgres-peer-crl-role.json"
peer_crl_role_digest = "sha256:%s"
peer_crl_source_mapping_digest = "sha256:%s"
startup_timeout_seconds = 30
max_connections = 1

[product_migration.materials.provider]
type = "unix-workload-material.v2"
alias = "product-migration-agent"
socket_path = "/run/material/product-migration-agent/material.sock"
expected_uid = 20038
expected_gid = 30038
directory_gid = 30039
operation_timeout_seconds = 15
cache_seconds = 0

[[product_migration.materials.bindings]]
id = "product-migration-dsn"
provider = "product-migration-agent"
document = %q
`, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), string(document)))
}

func TestLoadPhase6CoreBytesClosedRoleAndEnvironment(t *testing.T) {
	snapshotGlobals(t)
	valid := productMigrationPhase6StartupFixture(t)
	if err := LoadPhase6CoreBytes(valid, "product-migration-job"); err != nil {
		t.Fatalf("exact migration startup rejected: %v", err)
	}
	if ProductMigration == nil || !ProductMigration.Enabled || ProductMigration.SchemaVersion != ProductMigrationSchemaV2 {
		t.Fatal("validated migration startup did not commit")
	}
	for name, document := range map[string][]byte{
		"missing role":     []byte("[application]\nmode='production'\n"),
		"other role":       append(append([]byte(nil), valid...), []byte("\n[provider_migration]\nenabled=true\n")...),
		"unknown key":      []byte(strings.Replace(string(valid), "max_connections = 1", "max_connections = 1\nunreviewed = true", 1)),
		"legacy schema":    []byte(strings.Replace(string(valid), ProductMigrationSchemaV2, ProductMigrationSchemaV1, 1)),
		"wrong app mode":   []byte(strings.Replace(string(valid), "mode = \"production\"", "mode = \"development\"", 1)),
		"oversized":        []byte(strings.Repeat("x", (64<<10)+1)),
		"wrong deployment": valid,
	} {
		t.Run(name, func(t *testing.T) {
			deployment := "product-migration-job"
			if name == "wrong deployment" {
				deployment = "provider-migration-job"
			}
			if err := LoadPhase6CoreBytes(document, deployment); err == nil {
				t.Fatal("unsafe Phase 6 startup config admitted")
			}
		})
	}
	t.Setenv("SANDBOX_RUNTIME_PRODUCT_MIGRATION_ENABLED", "false")
	if err := LoadPhase6CoreBytes(valid, "product-migration-job"); err == nil {
		t.Fatal("environment override admitted in Phase 6 core startup")
	}
}
