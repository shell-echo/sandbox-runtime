package gatewaystack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
)

func TestValidateConfigAcceptsLockedGatewayTopology(t *testing.T) {
	config := validConfig(t)
	if err := ValidateConfig(config); err != nil {
		t.Fatal(err)
	}
	config.GatewayID = "gateway-b"
	config.PrivateIngress.GatewayRoleURI = wire.GatewayBRoleURI
	if err := ValidateConfig(config); err != nil {
		t.Fatalf("Gateway B: %v", err)
	}
}

func TestValidateConfigRejectsRoleTopologyAndLockDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "unknown Gateway", mutate: func(config *Config) { config.GatewayID = "gateway-c" }},
		{name: "wrong role", mutate: func(config *Config) { config.PrivateIngress.GatewayRoleURI = wire.GatewayBRoleURI }},
		{name: "public edge", mutate: func(config *Config) { config.Address = "0.0.0.0:18443" }},
		{name: "public ingress", mutate: func(config *Config) { config.PrivateIngress.Address = "0.0.0.0:19443" }},
		{name: "aliased listener collision", mutate: func(config *Config) { config.PrivateIngress.Address = "localhost:18443" }},
		{name: "relative private key", mutate: func(config *Config) { config.PrivateIngress.ClientPrivateKeyFile = "gateway-key.pem" }},
		{name: "colliding key", mutate: func(config *Config) { config.PrivateIngress.ClientPrivateKeyFile = config.ServerPrivateKeyFile }},
		{name: "uncredentialed Redis", mutate: func(config *Config) { config.Authority.RedisURL = "redis://127.0.0.1:16379/0" }},
		{name: "remote Redis", mutate: func(config *Config) { config.Authority.RedisURL = "redis://e2e:secret@redis.invalid:6379/0" }},
		{name: "same namespace", mutate: func(config *Config) { config.Authority.RevocationNamespace = config.Authority.CapacityNamespace }},
		{name: "capacity drift", mutate: func(config *Config) { config.Authority.CapacityPolicy.LeaseTTLMillis++ }},
		{name: "session limit drift", mutate: func(config *Config) { config.Authority.CapacityPolicy.MaxPerSession = 2 }},
		{name: "revocation drift", mutate: func(config *Config) { config.Authority.RevocationPolicy.PollIntervalMillis++ }},
		{name: "resolve drift", mutate: func(config *Config) { config.PrivateIngress.ResolveTimeoutMillis++ }},
		{name: "I/O drift", mutate: func(config *Config) { config.PrivateIngress.ConnectAndIOTimeoutMillis++ }},
		{name: "message drift", mutate: func(config *Config) { config.PrivateIngress.MaxMessageBytes++ }},
		{name: "endpoint generation", mutate: func(config *Config) { config.Endpoints[0].ConnectionGeneration = 0 }},
		{name: "duplicate grant", mutate: func(config *Config) {
			duplicate := config.GrantBindings[0]
			duplicate.ID = "binding-2"
			config.GrantBindings = append(config.GrantBindings, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(t)
			test.mutate(&config)
			if err := ValidateConfig(config); err == nil {
				t.Fatal("ValidateConfig() accepted unsafe configuration")
			}
		})
	}
}

func TestLoadConfigRequiresPrivateStrictRegularFile(t *testing.T) {
	config := validConfig(t)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		mode    os.FileMode
		content []byte
	}{
		{name: "public", mode: 0o640, content: encoded},
		{name: "unknown", mode: 0o600, content: []byte(strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`)},
		{name: "duplicate", mode: 0o600, content: []byte(strings.Replace(string(encoded), `"max_total":4`, `"max_total":4,"max_total":4`, 1))},
		{name: "trailing", mode: 0o600, content: append(append([]byte(nil), encoded...), []byte(" {}")...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "gateway.json")
			if err := os.WriteFile(path, test.content, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("LoadConfig() accepted unsafe input")
			}
		})
	}

	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(filepath.Join(root, "link.json")); err == nil {
		t.Fatal("LoadConfig() accepted a symlink")
	}
	fifo := filepath.Join(root, "config.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := LoadConfig(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("LoadConfig() accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("LoadConfig() blocked on a FIFO")
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		GatewayID: "gateway-a", Address: "127.0.0.1:18443",
		ServerCertificateFile: filepath.Join(root, "public-cert.pem"),
		ServerPrivateKeyFile:  filepath.Join(root, "public-key.pem"),
		AuditFile:             filepath.Join(root, "audit.jsonl"),
		Authority: AuthorityConfig{
			RedisURL:          "redis://e2e:" + strings.Repeat("s", 32) + "@127.0.0.1:16379/0",
			CapacityNamespace: "downstream-fencing-capacity", RevocationNamespace: "downstream-fencing-revocation",
			CapacityPolicy: CapacityPolicy{
				MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1, LeaseTTLMillis: 3000,
				RenewIntervalMillis: 400, RenewalSafetyMarginMillis: 500, OperationTimeoutMillis: 200,
			},
			RevocationPolicy: RevocationPolicy{
				MaxGrantLifetimeMillis: 900_000, PollIntervalMillis: 100, OperationTimeoutMillis: 100,
			},
		},
		PrivateIngress: PrivateIngressConfig{
			Address: "127.0.0.1:19443", ServerName: "localhost",
			ClientCertificateFile: filepath.Join(root, "client-cert.pem"),
			ClientPrivateKeyFile:  filepath.Join(root, "client-key.pem"), ServerCAFile: filepath.Join(root, "ca.pem"),
			GatewayRoleURI: wire.GatewayARoleURI, ResolveTimeoutMillis: 1000,
			ConnectAndIOTimeoutMillis: 2000, MaxMessageBytes: 64 << 10,
		},
		Principals: []Principal{{
			ID: "principal-1", Token: strings.Repeat("a", 32), CallerID: "caller-1", TenantID: "tenant-1",
		}},
		Endpoints: []Endpoint{{
			ID: "endpoint-1", TenantID: "tenant-1", SandboxID: "sandbox-1", BrowserSessionID: "browser-session-1",
			CapabilityProfileID: "browser-v1", HandoffReference: "ref:browser-session:" + strings.Repeat("1", 32),
			ConnectionGeneration: 1,
		}},
		GrantBindings: []GrantBinding{{
			ID: "binding-1", GrantID: "grant-1", PrincipalID: "principal-1", EndpointID: "endpoint-1",
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
		}},
	}
}
