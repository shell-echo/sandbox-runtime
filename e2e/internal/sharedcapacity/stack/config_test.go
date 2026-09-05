package stack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

func TestValidateConfigAcceptsStrictFixture(t *testing.T) {
	if err := ValidateConfig(validConfig(t)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfigRejectsUnsafeOrAmbiguousInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*wire.GatewayConfig)
	}{
		{name: "wildcard listener", mutate: func(config *wire.GatewayConfig) { config.Address = "0.0.0.0:8443" }},
		{name: "zero listener port", mutate: func(config *wire.GatewayConfig) { config.Address = "127.0.0.1:0" }},
		{name: "relative audit", mutate: func(config *wire.GatewayConfig) { config.AuditFile = "audit.jsonl" }},
		{name: "colliding evidence", mutate: func(config *wire.GatewayConfig) { config.ObservationFile = config.AuditFile }},
		{name: "Redis options", mutate: func(config *wire.GatewayConfig) { config.RedisURL += "?skip_verify=true" }},
		{name: "local headroom absent", mutate: func(config *wire.GatewayConfig) { config.Policy.MaxTotal = 1000 }},
		{name: "duration overflow", mutate: func(config *wire.GatewayConfig) { config.Policy.LeaseTTLMillis = 1<<63 - 1 }},
		{name: "duplicate token", mutate: func(config *wire.GatewayConfig) {
			config.Principals = append(config.Principals, config.Principals[0])
			config.Principals[1].ID = "principal-2"
		}},
		{name: "unowned endpoint tenant", mutate: func(config *wire.GatewayConfig) { config.Endpoints[0].TenantID = "tenant-other" }},
		{name: "loose reference", mutate: func(config *wire.GatewayConfig) {
			config.Endpoints[0].HandoffReference = "ref:browser-session:not-exact"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(t)
			test.mutate(&config)
			if err := ValidateConfig(config); err == nil {
				t.Fatal("ValidateConfig() accepted invalid configuration")
			}
		})
	}
}

func TestLoadConfigRejectsUnknownAndTrailingInput(t *testing.T) {
	config := validConfig(t)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		content []byte
	}{
		{name: "trailing", content: append(append([]byte(nil), encoded...), []byte(" {}")...)},
		{name: "unknown", content: []byte(strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`)},
		{name: "duplicate nested field", content: []byte(strings.Replace(string(encoded), `"max_total":4`, `"max_total":4,"max_total":3`, 1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.json")
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("LoadConfig() accepted invalid input")
			}
		})
	}
}

func validConfig(t *testing.T) wire.GatewayConfig {
	t.Helper()
	root := t.TempDir()
	return wire.GatewayConfig{
		Address: "127.0.0.1:18443", ServerCertificateFile: filepath.Join(root, "server.pem"),
		ServerPrivateKeyFile: filepath.Join(root, "server-key.pem"), RedisURL: "redis://127.0.0.1:16379/0",
		CapacityNamespace: "shared-capacity-e2e", AuditFile: filepath.Join(root, "audit.jsonl"),
		ObservationFile: filepath.Join(root, "observations.jsonl"),
		Policy: wire.CapacityPolicy{
			MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1,
			LeaseTTLMillis: 2000, RenewIntervalMillis: 400,
			RenewalSafetyMarginMillis: 500, OperationTimeoutMillis: 200,
		},
		Principals: []wire.Principal{{
			ID: "principal-1", Token: strings.Repeat("a", 32), CallerID: "caller-1", TenantID: "tenant-1",
		}},
		Endpoints: []wire.Endpoint{{
			ID: "endpoint-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
			BrowserSessionID: "browser-session-1", CapabilityProfileID: providerbrowser.CapabilityProfileID,
			HandoffReference: "ref:browser-session:" + strings.Repeat("1", 32), ConnectionGeneration: 1,
		}},
	}
}
