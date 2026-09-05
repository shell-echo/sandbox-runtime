package stack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

func TestValidateConfigAcceptsStrictDurableRevocationFixture(t *testing.T) {
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
		{name: "relative audit", mutate: func(config *wire.GatewayConfig) { config.AuditFile = "audit.jsonl" }},
		{name: "colliding evidence", mutate: func(config *wire.GatewayConfig) { config.ObservationFile = config.AuditFile }},
		{name: "Redis options", mutate: func(config *wire.GatewayConfig) { config.RedisURL += "?skip_verify=true" }},
		{name: "raw namespace syntax", mutate: func(config *wire.GatewayConfig) { config.RevocationNamespace = "revocation/{tenant}" }},
		{name: "operation beyond poll", mutate: func(config *wire.GatewayConfig) {
			config.RevocationPolicy.OperationTimeoutMillis = config.RevocationPolicy.PollIntervalMillis + 1
		}},
		{name: "duration overflow", mutate: func(config *wire.GatewayConfig) {
			config.RevocationPolicy.MaxGrantLifetimeMillis = 1<<63 - 1
		}},
		{name: "invalid local capacity", mutate: func(config *wire.GatewayConfig) {
			config.LocalCapacity.MaxPerTenant = config.LocalCapacity.MaxTotal + 1
		}},
		{name: "implicit reconnect default", mutate: func(config *wire.GatewayConfig) {
			config.ReconnectPolicy.MaxReconnects = 0
		}},
		{name: "reconnect overflow", mutate: func(config *wire.GatewayConfig) {
			config.ReconnectPolicy.BackoffMillis = 1<<63 - 1
		}},
		{name: "duplicate grant", mutate: func(config *wire.GatewayConfig) {
			duplicate := config.GrantBindings[0]
			duplicate.ID = "binding-2"
			config.GrantBindings = append(config.GrantBindings, duplicate)
		}},
		{name: "unknown binding principal", mutate: func(config *wire.GatewayConfig) {
			config.GrantBindings[0].PrincipalID = "principal-missing"
		}},
		{name: "cross tenant binding", mutate: func(config *wire.GatewayConfig) {
			config.Principals = append(config.Principals, wire.Principal{
				ID: "principal-2", Token: strings.Repeat("b", 32), CallerID: "caller-2", TenantID: "tenant-2",
			})
			config.GrantBindings[0].PrincipalID = "principal-2"
		}},
		{name: "noncanonical binding expiry", mutate: func(config *wire.GatewayConfig) {
			config.GrantBindings[0].ExpiresAt = strings.Replace(config.GrantBindings[0].ExpiresAt, "Z", "+00:00", 1)
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

func TestLoadConfigRejectsUnknownDuplicateAndPublicInput(t *testing.T) {
	config := validConfig(t)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		content []byte
		mode    os.FileMode
	}{
		{name: "unknown", content: []byte(strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`), mode: 0o600},
		{name: "duplicate nested", content: []byte(strings.Replace(string(encoded), `"max_total":4`, `"max_total":4,"max_total":3`, 1)), mode: 0o600},
		{name: "public permissions", content: encoded, mode: 0o644},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.json")
			if err := os.WriteFile(path, test.content, test.mode); err != nil {
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
		RevocationNamespace: "durable-revocation-e2e", AuditFile: filepath.Join(root, "audit.jsonl"),
		ObservationFile: filepath.Join(root, "observations.jsonl"),
		RevocationPolicy: wire.RevocationPolicy{
			MaxGrantLifetimeMillis: 900_000, PollIntervalMillis: 100, OperationTimeoutMillis: 100,
		},
		LocalCapacity:   wire.LocalCapacityPolicy{MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1},
		ReconnectPolicy: wire.ReconnectPolicy{MaxReconnects: 1, BackoffMillis: 10},
		Principals: []wire.Principal{{
			ID: "principal-1", Token: strings.Repeat("a", 32), CallerID: "caller-1", TenantID: "tenant-1",
		}},
		Endpoints: []wire.Endpoint{{
			ID: "endpoint-1", TenantID: "tenant-1", SandboxID: "sandbox-1",
			BrowserSessionID: "browser-session-1", CapabilityProfileID: providerbrowser.CapabilityProfileID,
			HandoffReference: "ref:browser-session:" + strings.Repeat("1", 32), ConnectionGeneration: 1,
		}},
		GrantBindings: []wire.GrantBinding{{
			ID: "binding-1", GrantID: "grant-1", PrincipalID: "principal-1", EndpointID: "endpoint-1",
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
		}},
	}
}
