package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestLoadStrictProductMigrationConfiguration(t *testing.T) {
	snapshotGlobals(t)
	binding := productMaterialBindings()["product-migration-dsn"]
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`[application]
mode = "production"

[product_migration]
schema_version = "sandbox-runtime.product-migration.v1"
enabled = true

[product_migration.postgres]
dsn_binding_id = "product-migration-dsn"
role = "product_migrator"
startup_timeout_seconds = 10
max_connections = 1

[product_migration.materials.provider]
type = "unix-workload-material.v1"
alias = "migration-agent"
socket_path = "/tmp/sandbox-runtime-product-migration-agent.sock"
expected_uid = 501
expected_gid = 20
operation_timeout_seconds = 2
cache_seconds = 0

[[product_migration.materials.bindings]]
id = "product-migration-dsn"
provider = "migration-agent"
document = '%s'

`, document)
	if err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("Load Product migration: %v", err)
	}
	if !ProductMigration.Enabled || ProductMigration.Postgres.Role != "product_migrator" || ProductMigration.Postgres.DSNBindingID != "product-migration-dsn" {
		t.Fatalf("Product migration = %#v", ProductMigration)
	}
}

func TestProductMigrationRejectsRuntimeAuthorityAndCaching(t *testing.T) {
	binding := productMaterialBindings()["product-migration-dsn"]
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	valid := &ProductMigrationConfig{
		SchemaVersion: ProductMigrationSchemaV1,
		Enabled:       true,
		Postgres: ProductMigrationPostgresConfig{
			DSNBindingID: "product-migration-dsn", Role: "product_migrator", StartupTimeoutSeconds: 10,
			MaxConnections: 1,
		},
		Materials: ProductMaterialsConfig{
			Provider: ProductMaterialProviderConfig{Type: ProductUnixMaterialProviderV1, Alias: "migration-agent", SocketPath: "/tmp/sandbox-runtime-product-migration-agent.sock", ExpectedUID: 501, ExpectedGID: 20, OperationTimeoutSeconds: 2},
			Bindings: []ProductMaterialBindingConfig{{ID: "product-migration-dsn", Provider: "migration-agent", Document: string(document)}},
		},
	}
	for name, mutate := range map[string]func(*ProductMigrationConfig){
		"cache": func(c *ProductMigrationConfig) { c.Materials.Provider.CacheSeconds = 1 },
		"runtime binding": func(c *ProductMigrationConfig) {
			runtime := binding
			runtime.Purpose = secretref.PurposePostgresRuntimeDSN
			raw, _ := json.Marshal(runtime)
			c.Materials.Bindings[0].Document = string(raw)
		},
		"extra authority": func(c *ProductMigrationConfig) {
			runtime := productMaterialBindings()["product-runtime-dsn"]
			raw, _ := json.Marshal(runtime)
			c.Materials.Bindings = append(c.Materials.Bindings, ProductMaterialBindingConfig{ID: "runtime", Provider: "migration-agent", Document: string(raw)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			candidate.Materials.Bindings = append([]ProductMaterialBindingConfig(nil), valid.Materials.Bindings...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe Product migration configuration was accepted")
			}
		})
	}
}

func TestProductServeConfigRejectsMigrationAuthorityField(t *testing.T) {
	snapshotGlobals(t)
	err := Load(writeConfig(t, `[product_process]
schema_version = "sandbox-runtime.product-process.legacy-development.v1"
enabled = true
deployment_level = "development"
[product_process.api]
host = "127.0.0.1"
port = 8082
[product_process.postgres]
dsn_file = "/tmp/product.dsn"
migration_dsn_binding_id = "forbidden"
[product_process.identity]
bindings_file = "/tmp/product-identities.json"
`))
	if err == nil || !strings.Contains(err.Error(), "invalid keys") {
		t.Fatalf("migration authority field error = %v", err)
	}
}
