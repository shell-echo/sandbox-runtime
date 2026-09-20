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
