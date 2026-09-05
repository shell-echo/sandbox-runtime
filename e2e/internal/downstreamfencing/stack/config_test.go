package stack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	basestack "github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
)

func TestValidateConfigAcceptsBoundedProviderIngressTopology(t *testing.T) {
	if err := ValidateConfig(validConfig(t)); err != nil {
		t.Fatal(err)
	}
}

func TestValidateConfigRejectsUnsafeTopologyAndPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "public Provider listener", mutate: func(config *Config) { config.Provider.ProviderAddress = "0.0.0.0:18443" }},
		{name: "public ingress listener", mutate: func(config *Config) { config.Ingress.Address = "0.0.0.0:19443" }},
		{name: "colliding listeners", mutate: func(config *Config) { config.Ingress.Address = "127.0.0.1:18443" }},
		{name: "relative Provider material", mutate: func(config *Config) { config.Provider.TrustedJWSKeys[0].Path = "key.pem" }},
		{name: "colliding role keys", mutate: func(config *Config) { config.Ingress.ServerPrivateKeyFile = config.Provider.ProviderPrivateKeyFile }},
		{name: "colliding JWS keys", mutate: func(config *Config) { config.Provider.TrustedJWSKeys[1].Path = config.Provider.TrustedJWSKeys[0].Path }},
		{name: "wrong Gateway role", mutate: func(config *Config) { config.Ingress.AllowedGatewayURIs[1] = "spiffe://downstream-fencing/controller" }},
		{name: "duplicate Gateway role", mutate: func(config *Config) { config.Ingress.AllowedGatewayURIs[1] = config.Ingress.AllowedGatewayURIs[0] }},
		{name: "uncredentialed Redis", mutate: func(config *Config) { config.Authority.RedisURL = "redis://127.0.0.1:16379/0" }},
		{name: "remote Redis", mutate: func(config *Config) { config.Authority.RedisURL = "redis://e2e:secret@redis.invalid:6379/0" }},
		{name: "different Redis database", mutate: func(config *Config) { config.Authority.RedisURL = "redis://e2e:secret@127.0.0.1:16379/1" }},
		{name: "multi-owner Browser session", mutate: func(config *Config) { config.Authority.CapacityPolicy.MaxPerSession = 2 }},
		{name: "capacity TTL profile drift", mutate: func(config *Config) { config.Authority.CapacityPolicy.LeaseTTLMillis++ }},
		{name: "resolve profile drift", mutate: func(config *Config) { config.Ingress.ResolveTimeoutMillis++ }},
		{name: "listener profile drift", mutate: func(config *Config) { config.Ingress.MaxConnections++ }},
		{name: "HTTP timeout profile drift", mutate: func(config *Config) { config.Ingress.ReadTimeoutMillis++ }},
		{name: "HTTP header profile drift", mutate: func(config *Config) { config.Ingress.MaxHeaderBytes++ }},
		{name: "action outside lease window", mutate: func(config *Config) { config.Ingress.ActionTimeoutMillis = 2000 }},
		{name: "transport does not cover action", mutate: func(config *Config) { config.Ingress.ActivationTimeoutMillis = config.Ingress.ActionTimeoutMillis }},
		{name: "unbounded actions", mutate: func(config *Config) { config.Ingress.MaxActionBytes = 64<<10 + 1 }},
		{name: "unbounded accepted connections", mutate: func(config *Config) { config.Ingress.MaxConnections = 10001 }},
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

func TestLoadConfigRequiresPrivateStrictJSONAndReturnsCopy(t *testing.T) {
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
		{name: "group readable", mode: 0o640, content: encoded},
		{name: "trailing", mode: 0o600, content: append(append([]byte(nil), encoded...), []byte(" {}")...)},
		{name: "unknown", mode: 0o600, content: []byte(strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`)},
		{name: "duplicate nested field", mode: 0o600, content: []byte(strings.Replace(string(encoded), `"max_total":4`, `"max_total":4,"max_total":3`, 1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "provider-ingress.json")
			if err := os.WriteFile(path, test.content, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("LoadConfig() accepted unsafe input")
			}
		})
	}

	path := filepath.Join(t.TempDir(), "provider-ingress.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Ingress.AllowedGatewayURIs[0] = "changed"
	loaded.Provider.AllowedClientURIs[0] = "changed"
	loaded.Provider.TrustedJWSKeys[0].ID = "changed"
	loaded.Provider.Browser.AllowedHosts[0] = "changed"
	if config.Ingress.AllowedGatewayURIs[0] == "changed" || config.Provider.AllowedClientURIs[0] == "changed" ||
		config.Provider.TrustedJWSKeys[0].ID == "changed" || config.Provider.Browser.AllowedHosts[0] == "changed" {
		t.Fatal("LoadConfig() result aliases source configuration")
	}
}

func TestLoadConfigRejectsOversizeSymlinkAndFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	oversize := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(oversize, make([]byte, maxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(oversize); err == nil {
		t.Fatal("LoadConfig() accepted an oversized file")
	}

	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "config-link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(symlink); err == nil {
		t.Fatal("LoadConfig() accepted a symbolic link")
	}

	fifo := filepath.Join(root, "config.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := LoadConfig(fifo)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("LoadConfig() accepted a FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("LoadConfig() blocked opening a FIFO")
	}
}

func validConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		Provider: basestack.BrowserProviderConfig{
			ProviderAddress: "127.0.0.1:18443", ProviderCertificateFile: filepath.Join(root, "provider-cert.pem"),
			ProviderPrivateKeyFile: filepath.Join(root, "provider-key.pem"), ClientCAFile: filepath.Join(root, "provider-ca.pem"),
			AllowedClientURIs: []string{"spiffe://reference-caller/controller-a", "spiffe://reference-caller/controller-b"},
			TrustedJWSKeys: []basestack.TrustedJWSKey{
				{ID: "controller-a-2026-08", Algorithm: "EdDSA", Path: filepath.Join(root, "controller-a.pem")},
				{ID: "controller-b-2026-08", Algorithm: "EdDSA", Path: filepath.Join(root, "controller-b.pem")},
			},
			ProviderRevisionID: "provider-revision", StateRoot: filepath.Join(root, "state"),
			RuntimeDataRoot: filepath.Join(root, "runtime"), RuntimeImage: "sha256:" + strings.Repeat("a", 64),
			RuntimeControllerID: "downstream-fencing-provider",
			Browser: &basestack.BrowserConfig{
				GatewayImage: "sha256:" + strings.Repeat("b", 64), UplinkNetwork: "bridge",
				Namespace: "downstream-fencing-browser", RuntimeArchitecture: "arm64",
				ManifestPath: filepath.Join(root, "manifest.json"), SeccompPath: filepath.Join(root, "seccomp.json"),
				ProvenanceExecutablePath: filepath.Join(root, "gh"), ProvenanceExecutableDigest: "sha256:" + strings.Repeat("c", 64),
				NetworkPolicyReference: "browser-egress-v1", AllowedHosts: []string{"example.com"},
			},
		},
		Ingress: IngressConfig{
			Address: "127.0.0.1:19443", ServerCertificateFile: filepath.Join(root, "ingress-cert.pem"),
			ServerPrivateKeyFile: filepath.Join(root, "ingress-key.pem"), ClientCAFile: filepath.Join(root, "ingress-ca.pem"),
			AllowedGatewayURIs:   []string{wire.GatewayARoleURI, wire.GatewayBRoleURI},
			ResolveTimeoutMillis: 1000, ActivationTimeoutMillis: 2000, ActionTimeoutMillis: 1000,
			CloseTimeoutMillis: 5000, MaxSessions: 4, MaxActionBytes: wire.MaxMessageBytes,
			MaxConnections: 32, ReadHeaderTimeoutMillis: 1000, ReadTimeoutMillis: 30000,
			WriteTimeoutMillis: 30000, IdleTimeoutMillis: 60000, MaxHeaderBytes: 16 << 10,
		},
		Authority: AuthorityConfig{
			RedisURL:          "redis://e2e:" + strings.Repeat("s", 32) + "@127.0.0.1:16379/0",
			CapacityNamespace: "downstream-fencing-e2e",
			CapacityPolicy: CapacityPolicy{
				MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1, LeaseTTLMillis: 3000,
				RenewIntervalMillis: 400, RenewalSafetyMarginMillis: 500, OperationTimeoutMillis: 200,
			},
		},
	}
}
