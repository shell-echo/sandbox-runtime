package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestProductProcessDisabledDefaultsAreInert(t *testing.T) {
	config := defaultProductProcessConfig()
	if config.Enabled {
		t.Fatal("Product process is enabled by default")
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("disabled Product defaults: %v", err)
	}
}

func TestLoadProductProcessStrictDevelopmentConfiguration(t *testing.T) {
	snapshotGlobals(t)
	directory := t.TempDir()
	dsn := filepath.Join(directory, "postgres.dsn")
	identities := filepath.Join(directory, "identities.json")
	body := "[product_process]\n" +
		"schema_version = '" + ProductLegacyDevelopmentSchema + "'\n" +
		"enabled = true\n" +
		"deployment_level = 'development'\n" +
		"[product_process.api]\nhost = '127.0.0.1'\nport = 18082\n" +
		"[product_process.postgres]\ndsn_file = '" + dsn + "'\nstartup_timeout_seconds = 9\noperation_timeout_seconds = 2\nmax_connections = 6\nmin_connections = 1\n" +
		"[product_process.identity]\nbindings_file = '" + identities + "'\n"
	if err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("Load Product process: %v", err)
	}
	if !ProductProcess.Enabled || ProductProcess.API.Port != 18082 || ProductProcess.Postgres.MaxConnections != 6 || ProductProcess.Identity.BindingsFile != identities {
		t.Fatalf("Product process = %#v", ProductProcess)
	}
}

func TestLoadProductProcessRejectsUnknownField(t *testing.T) {
	snapshotGlobals(t)
	err := Load(writeConfig(t, "[product_process]\nunknown = true\n"))
	if err == nil || !strings.Contains(err.Error(), "invalid keys") {
		t.Fatalf("unknown Product field error = %v", err)
	}
}

func TestLoadProductProcessStrictProductionConfiguration(t *testing.T) {
	snapshotGlobals(t)
	path := func(name string) string { return filepath.Join("/tmp", "sandbox-runtime-test-"+name) }
	body := "[application]\nmode = 'production'\n" +
		"[product_process]\nschema_version = '" + ProductProductionSchemaV2 + "'\nenabled = true\ndeployment_level = 'production'\n" +
		"[product_process.api]\nhost = '0.0.0.0'\nport = 8443\n" +
		"[product_process.tls]\ncertificate_binding_id = 'product-tls-certificate'\nprivate_key_binding_id = 'product-tls-private-key'\nexpected_server_name = 'product.example.test'\n" +
		"[product_process.postgres]\nruntime_dsn_binding_id = 'product-runtime-dsn'\n" +
		"runtime_role = 'product_runtime'\nstartup_timeout_seconds = 12\noperation_timeout_seconds = 2\nmax_connections = 12\nmin_connections = 2\n" +
		"[product_process.identity]\nissuer = 'https://identity.product.example.test'\naudience = 'urn:shell-echo:sandbox-runtime:product-api:production'\nkey_ring_binding_id = 'product-identity-key-ring'\nclock_skew_seconds = 20\nmax_token_lifetime_seconds = 600\n" +
		"[product_process.materials.provider]\ntype = '" + ProductUnixMaterialProviderV1 + "'\nalias = 'role-material-agent'\nsocket_path = '" + path("agent.sock") + "'\nexpected_uid = 501\nexpected_gid = 20\noperation_timeout_seconds = 3\ncache_seconds = 30\n" +
		productMaterialBindingsTOML(t)
	if err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("Load Product production process: %v", err)
	}
	if ProductProcess.DeploymentLevel != ProductProductionLevel || ProductProcess.Postgres.RuntimeRole != "product_runtime" || ProductProcess.TLS.PrivateKeyBindingID != "product-tls-private-key" {
		t.Fatalf("Product process = %#v", ProductProcess)
	}
}

func TestProductProcessRejectsUnsafeProductionAuthority(t *testing.T) {
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	valid := validProductionProductConfig(t, directory)
	for name, mutate := range map[string]func(*ProductProcessConfig){
		"static identity": func(c *ProductProcessConfig) { c.Identity.BindingsFile = path("static.json") },
		"missing runtime": func(c *ProductProcessConfig) { c.Postgres.RuntimeDSNBindingID = "product-tls-certificate" },
		"relative socket": func(c *ProductProcessConfig) { c.Materials.Provider.SocketPath = "agent.sock" },
		"bad issuer":      func(c *ProductProcessConfig) { c.Identity.Issuer = "identity" },
		"excess cache":    func(c *ProductProcessConfig) { c.Materials.Provider.CacheSeconds = 61 },
		"migration binding": func(c *ProductProcessConfig) {
			binding := productMaterialBindings()["product-migration-dsn"]
			document, _ := json.Marshal(binding)
			c.Materials.Bindings = append(c.Materials.Bindings, ProductMaterialBindingConfig{ID: "product-migration-dsn", Provider: "role-material-agent", Document: string(document)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe production Product configuration was accepted")
			}
		})
	}
}

func validProductionProductConfig(t *testing.T, _ string) *ProductProcessConfig {
	t.Helper()
	valid := defaultProductProcessConfig()
	valid.SchemaVersion = ProductProductionSchemaV2
	valid.Enabled = true
	valid.DeploymentLevel = ProductProductionLevel
	valid.API.Host = "0.0.0.0"
	valid.TLS = ProductTLSConfig{CertificateBindingID: "product-tls-certificate", PrivateKeyBindingID: "product-tls-private-key", ExpectedServerName: "product.example.test"}
	valid.Postgres.RuntimeDSNBindingID = "product-runtime-dsn"
	valid.Postgres.RuntimeRole = "product_runtime"
	valid.Identity.Issuer = "https://identity.product.example.test"
	valid.Identity.Audience = "urn:shell-echo:sandbox-runtime:product-api:production"
	valid.Identity.KeyRingBindingID = "product-identity-key-ring"
	valid.Materials.Provider = ProductMaterialProviderConfig{Type: ProductUnixMaterialProviderV1, Alias: "role-material-agent", SocketPath: "/tmp/sandbox-runtime-product-agent.sock", ExpectedUID: 501, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30}
	for _, id := range []string{"product-tls-certificate", "product-tls-private-key", "product-runtime-dsn", "product-identity-key-ring"} {
		binding := productMaterialBindings()[id]
		document, err := json.Marshal(binding)
		if err != nil {
			t.Fatal(err)
		}
		valid.Materials.Bindings = append(valid.Materials.Bindings, ProductMaterialBindingConfig{ID: id, Provider: "role-material-agent", Document: string(document)})
	}
	return valid
}

func productMaterialBindings() map[string]secretref.Binding {
	return map[string]secretref.Binding{
		"product-tls-certificate":   {Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-certificate", Version: "v1", Purpose: secretref.PurposeTLSCertificate, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		"product-tls-private-key":   {Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-private-key", Version: "v1", Purpose: secretref.PurposeTLSPrivateKey, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		"product-migration-dsn":     {Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-migration-dsn", Version: "v1", Purpose: secretref.PurposePostgresMigrationDSN, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		"product-runtime-dsn":       {Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-runtime-dsn", Version: "v1", Purpose: secretref.PurposePostgresRuntimeDSN, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		"product-identity-key-ring": {Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-identity-key-ring", Version: "v1", Purpose: secretref.PurposeIdentityKeyRing, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
	}
}

func productMaterialBindingsTOML(t *testing.T) string {
	t.Helper()
	var builder strings.Builder
	for _, id := range []string{"product-tls-certificate", "product-tls-private-key", "product-runtime-dsn", "product-identity-key-ring"} {
		document, err := json.Marshal(productMaterialBindings()[id])
		if err != nil {
			t.Fatal(err)
		}
		builder.WriteString("[[product_process.materials.bindings]]\nid = '")
		builder.WriteString(id)
		builder.WriteString("'\nprovider = 'role-material-agent'\ndocument = '")
		builder.Write(document)
		builder.WriteString("'\n")
	}
	return builder.String()
}

func TestProductProcessRejectsBroaderOrUnsafeComposition(t *testing.T) {
	directory := t.TempDir()
	valid := defaultProductProcessConfig()
	valid.Enabled = true
	valid.Postgres.DSNFile = filepath.Join(directory, "postgres.dsn")
	valid.Identity.BindingsFile = filepath.Join(directory, "identities.json")
	for name, mutate := range map[string]func(*ProductProcessConfig){
		"standalone":     func(c *ProductProcessConfig) { c.DeploymentLevel = ProductStandaloneLevel },
		"production":     func(c *ProductProcessConfig) { c.DeploymentLevel = ProductProductionLevel },
		"non-loopback":   func(c *ProductProcessConfig) { c.API.Host = "0.0.0.0" },
		"relative dsn":   func(c *ProductProcessConfig) { c.Postgres.DSNFile = "postgres.dsn" },
		"shared secrets": func(c *ProductProcessConfig) { c.Identity.BindingsFile = c.Postgres.DSNFile },
		"too many conns": func(c *ProductProcessConfig) { c.Postgres.MaxConnections = 65 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe Product configuration was accepted")
			}
		})
	}
}
