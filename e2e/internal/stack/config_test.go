package stack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigRejectsTrailingAndUnknownInput(t *testing.T) {
	t.Parallel()
	valid := validConfig(t)
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "trailing object", content: string(encoded) + `{}`},
		{name: "trailing scalar", content: string(encoded) + ` true`},
		{name: "unknown field", content: strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stack.json")
			if err := os.WriteFile(path, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("LoadConfig() succeeded for invalid input")
			}
		})
	}
}

func TestConfigValidateRejectsAmbiguousIdentityInputs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "duplicate URI", mutate: func(config *Config) { config.AllowedClientURIs[1] = config.AllowedClientURIs[0] }},
		{name: "duplicate key ID", mutate: func(config *Config) { config.TrustedJWSKeys[1].ID = config.TrustedJWSKeys[0].ID }},
		{name: "unsupported key algorithm", mutate: func(config *Config) { config.TrustedJWSKeys[0].Algorithm = "ES256" }},
		{name: "non loopback Provider", mutate: func(config *Config) { config.ProviderAddress = "0.0.0.0:10443" }},
		{name: "same listener", mutate: func(config *Config) { config.GatewayAddress = config.ProviderAddress }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(t)
			test.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() succeeded for invalid input")
			}
		})
	}
}

func TestSplitAddress(t *testing.T) {
	t.Parallel()
	host, port, err := splitAddress("127.0.0.1:10443")
	if err != nil || host != "127.0.0.1" || port != 10443 {
		t.Fatalf("splitAddress() = (%q, %d, %v)", host, port, err)
	}
	for _, value := range []string{"localhost:10443", "127.0.0.1", "[::1]:10443", "127.0.0.1:0", "127.0.0.1:65536"} {
		if _, _, err := splitAddress(value); err == nil {
			t.Fatalf("splitAddress(%q) succeeded", value)
		}
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		ProviderAddress: "127.0.0.1:10443", GatewayAddress: "127.0.0.1:10444",
		ProviderCertificateFile: filepath.Join(root, "provider.pem"), ProviderPrivateKeyFile: filepath.Join(root, "provider-key.pem"),
		GatewayCertificateFile: filepath.Join(root, "gateway.pem"), GatewayPrivateKeyFile: filepath.Join(root, "gateway-key.pem"),
		ClientCAFile:      filepath.Join(root, "ca.pem"),
		AllowedClientURIs: []string{"spiffe://reference-caller/controller-a", "spiffe://reference-caller/controller-b"},
		TrustedJWSKeys: []TrustedJWSKey{
			{ID: "controller-a", Algorithm: "EdDSA", Path: filepath.Join(root, "a.pem")},
			{ID: "controller-b", Algorithm: "EdDSA", Path: filepath.Join(root, "b.pem")},
		},
		ProviderRevisionID: "provider-revision-e2e-v1", ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:e2e",
		StateRoot: filepath.Join(root, "state"), RuntimeDataRoot: filepath.Join(root, "runtime"),
		RuntimeImage: "example.invalid/alpine@sha256:" + strings.Repeat("a", 64), RuntimeControllerID: "reference-e2e-controller",
		TerminalBrokerPath: filepath.Join(root, "terminal-broker"),
		GatewayPrincipals: []GatewayPrincipal{
			{Token: "token-a", CallerID: "caller-a", TenantID: "tenant-a"},
			{Token: "token-b", CallerID: "caller-b", TenantID: "tenant-b"},
		},
		GatewayAdminToken: "admin-token", GatewayAuditFile: filepath.Join(root, "gateway.jsonl"),
	}
}
