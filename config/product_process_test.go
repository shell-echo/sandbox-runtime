package config

import (
	"path/filepath"
	"strings"
	"testing"
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
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	body := "[application]\nmode = 'production'\n" +
		"[product_process]\nenabled = true\ndeployment_level = 'production'\n" +
		"[product_process.api]\nhost = '0.0.0.0'\nport = 8443\n" +
		"[product_process.tls]\ncertificate_file = '" + path("tls.crt") + "'\nprivate_key_file = '" + path("tls.key") + "'\n" +
		"[product_process.postgres]\nmigration_dsn_file = '" + path("migration.dsn") + "'\nruntime_dsn_file = '" + path("runtime.dsn") + "'\n" +
		"migration_role = 'product_migrator'\nruntime_role = 'product_runtime'\nstartup_timeout_seconds = 12\noperation_timeout_seconds = 2\nmigration_max_connections = 1\nmax_connections = 12\nmin_connections = 2\n" +
		"[product_process.identity]\nissuer = 'https://identity.product.example.test'\naudience = 'urn:shell-echo:sandbox-runtime:product-api:production'\nkey_ring_file = '" + path("keys.json") + "'\nclock_skew_seconds = 20\nmax_token_lifetime_seconds = 600\n"
	if err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("Load Product production process: %v", err)
	}
	if ProductProcess.DeploymentLevel != ProductProductionLevel || ProductProcess.Postgres.MigrationRole != "product_migrator" || ProductProcess.TLS.PrivateKeyFile != path("tls.key") {
		t.Fatalf("Product process = %#v", ProductProcess)
	}
}

func TestProductProcessRejectsUnsafeProductionAuthority(t *testing.T) {
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	valid := defaultProductProcessConfig()
	valid.Enabled = true
	valid.DeploymentLevel = ProductProductionLevel
	valid.API.Host = "0.0.0.0"
	valid.TLS = ProductTLSConfig{CertificateFile: path("tls.crt"), PrivateKeyFile: path("tls.key")}
	valid.Postgres.MigrationDSNFile = path("migration.dsn")
	valid.Postgres.RuntimeDSNFile = path("runtime.dsn")
	valid.Postgres.MigrationRole = "product_migrator"
	valid.Postgres.RuntimeRole = "product_runtime"
	valid.Identity.Issuer = "https://identity.product.example.test"
	valid.Identity.Audience = "urn:shell-echo:sandbox-runtime:product-api:production"
	valid.Identity.KeyRingFile = path("keys.json")
	for name, mutate := range map[string]func(*ProductProcessConfig){
		"static identity":  func(c *ProductProcessConfig) { c.Identity.BindingsFile = path("static.json") },
		"single db role":   func(c *ProductProcessConfig) { c.Postgres.RuntimeRole = c.Postgres.MigrationRole },
		"shared authority": func(c *ProductProcessConfig) { c.Identity.KeyRingFile = c.TLS.PrivateKeyFile },
		"relative key":     func(c *ProductProcessConfig) { c.TLS.PrivateKeyFile = "tls.key" },
		"bad issuer":       func(c *ProductProcessConfig) { c.Identity.Issuer = "identity" },
		"excess pool":      func(c *ProductProcessConfig) { c.Postgres.MigrationMaxConnections = 5 },
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
