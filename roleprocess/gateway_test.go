package roleprocess

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestLoadGatewayAuthorityRejectsUnknownAndBroadConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*GatewayCredentialAuthority, *GatewayDependencyAuthority, *GatewayPolicyAuthority)
		unknown bool
	}{
		{name: "credential role", mutate: func(c *GatewayCredentialAuthority, _ *GatewayDependencyAuthority, _ *GatewayPolicyAuthority) {
			c.Role = string(config.DataPlaneGuest)
		}},
		{name: "provider origin", mutate: func(c *GatewayCredentialAuthority, _ *GatewayDependencyAuthority, _ *GatewayPolicyAuthority) {
			c.ProviderOrigin = "http://provider.invalid/private"
		}},
		{name: "zero timeout", mutate: func(_ *GatewayCredentialAuthority, d *GatewayDependencyAuthority, _ *GatewayPolicyAuthority) {
			d.OperationTimeoutMillis = 0
		}},
		{name: "session capacity", mutate: func(_ *GatewayCredentialAuthority, d *GatewayDependencyAuthority, _ *GatewayPolicyAuthority) {
			d.MaxConnectionsPerSession = d.MaxConnections + 1
		}},
		{name: "premature Desktop enable", mutate: func(_ *GatewayCredentialAuthority, _ *GatewayDependencyAuthority, p *GatewayPolicyAuthority) {
			p.DesktopLive = gatewayCapabilityEnabled
		}},
		{name: "unknown field", unknown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := gatewayAuthorityFixture(t)
			if test.unknown {
				if err := os.WriteFile(fixture.cfg.Authority.CredentialFile, []byte(`{"version":1,"role":"gateway","unexpected":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				test.mutate(&fixture.credential, &fixture.dependency, &fixture.policy)
				writeJSON0600(t, fixture.cfg.Authority.CredentialFile, fixture.credential)
			}
			writeJSON0600(t, fixture.cfg.Authority.DependencyFile, fixture.dependency)
			writeJSON0600(t, fixture.cfg.Authority.PolicyFile, fixture.policy)
			if _, err := LoadGatewayAuthority(fixture.cfg); err == nil {
				t.Fatal("invalid Gateway authority was accepted")
			}
		})
	}
}

type gatewayAuthorityFixtureState struct {
	cfg        *config.DataPlaneProcessConfig
	credential GatewayCredentialAuthority
	dependency GatewayDependencyAuthority
	policy     GatewayPolicyAuthority
}

func gatewayAuthorityFixture(t *testing.T) gatewayAuthorityFixtureState {
	t.Helper()
	directory := t.TempDir()
	cfg := *config.GatewayProcess
	cfg.Enabled = true
	cfg.Role = config.DataPlaneGateway
	cfg.Public.Port = 18445
	cfg.Private.Port = 18445
	cfg.Probe.Port = 18485
	cfg.TLS.CertificateFile = filepath.Join(directory, "gateway.crt")
	cfg.TLS.PrivateKeyFile = filepath.Join(directory, "gateway.key")
	cfg.Authority.CredentialFile = filepath.Join(directory, "credential.json")
	cfg.Authority.DependencyFile = filepath.Join(directory, "dependency.json")
	cfg.Authority.PolicyFile = filepath.Join(directory, "policy.json")
	cfg.Authority.RecordingKeyRef = "kms://recording/gateway"
	return gatewayAuthorityFixtureState{
		cfg: &cfg,
		credential: GatewayCredentialAuthority{
			Version: gatewayAuthorityVersion, Role: string(config.DataPlaneGateway), ProductRuntimeDSNFile: filepath.Join(directory, "product.dsn"),
			GrantKeyID: "grant-key-v1", GrantKeyFile: filepath.Join(directory, "grant.key"), ProviderOrigin: "wss://provider.example.test/private/terminal",
			ProviderCABundleFile: filepath.Join(directory, "provider-ca.pem"), ProviderClientCertificateFile: filepath.Join(directory, "provider.crt"), ProviderClientPrivateKeyFile: filepath.Join(directory, "provider.key"),
		},
		dependency: GatewayDependencyAuthority{Version: gatewayAuthorityVersion, Role: string(config.DataPlaneGateway), OperationTimeoutMillis: 500, MaxConnections: 100, MaxConnectionsPerSession: 4},
		policy: GatewayPolicyAuthority{
			Version: gatewayAuthorityVersion, Role: string(config.DataPlaneGateway), Terminal: gatewayCapabilityEnabled,
			BrowserAutomation: gatewayCapabilityAuthorityUnavailable, BrowserLive: gatewayCapabilityAuthorityUnavailable,
			DesktopLive: gatewayCapabilityAuthorityUnavailable, DeferredAuthorityReason: gatewayDeferredAuthorityReason,
		},
	}
}

func TestGatewayAuthorityJSONUsesClosedSchema(t *testing.T) {
	document, err := json.Marshal(GatewayCredentialAuthority{Version: gatewayAuthorityVersion, Role: string(config.DataPlaneGateway)})
	if err != nil {
		t.Fatal(err)
	}
	if len(document) == 0 {
		t.Fatal("empty Gateway authority document")
	}
}

func TestLoadGatewayV3AuthorityHasNoStaticTLSMaterials(t *testing.T) {
	fixture := gatewayAuthorityFixture(t)
	fixture.cfg.SchemaVersion = config.DataPlaneProductionSchemaV3
	fixture.cfg.DeploymentLevel = config.ProviderProductionLevel
	fixture.cfg.Private.Host, fixture.cfg.Private.Port = "127.0.0.1", 8445
	fixture.cfg.TLS = config.DataPlaneTLSConfig{
		SecurityProfilePath:        filepath.Join(filepath.Dir(fixture.cfg.Authority.CredentialFile), "profile.json"),
		SecurityProfileDigest:      "sha256:" + strings.Repeat("a", 64),
		PeerCRLRoleFile:            filepath.Join(filepath.Dir(fixture.cfg.Authority.CredentialFile), "peer-crl-role.json"),
		PeerCRLRoleDigest:          "sha256:" + strings.Repeat("b", 64),
		PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64),
		AgentSocket:                filepath.Join(filepath.Dir(fixture.cfg.Authority.CredentialFile), "tls-agent.sock"),
		AgentUID:                   501, AgentGID: 20, OperationTimeoutMillis: 3000,
	}
	fixture.cfg.Materials.Provider = config.RoleMaterialProviderConfig{
		Type: config.UnixWorkloadMaterialProviderV1, Alias: "gateway-material-agent",
		SocketPath:  "/tmp/gateway-material-agent-test.sock",
		ExpectedUID: 502, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30,
	}
	for _, item := range []struct {
		id      string
		purpose secretref.Purpose
	}{
		{"gateway-dsn", secretref.PurposePostgresRuntimeDSN},
		{"gateway-grant", secretref.PurposeGatewayGrantKey},
	} {
		document, err := json.Marshal(secretref.Binding{
			Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://vault/kv/" + item.id), Version: "v1", Purpose: item.purpose,
			TenantID: secretref.SystemTenant, Role: secretref.RoleGateway,
		})
		if err != nil {
			t.Fatal(err)
		}
		fixture.cfg.Materials.Bindings = append(fixture.cfg.Materials.Bindings, config.RoleMaterialBindingConfig{
			ID: item.id, Provider: "gateway-material-agent", Document: string(document),
		})
	}
	fixture.credential.Version = gatewayAuthorityVersionV4
	fixture.credential.ProductRuntimeDSNFile = ""
	fixture.credential.GrantKeyFile = ""
	fixture.credential.ProviderCABundleFile = ""
	fixture.credential.ProviderClientCertificateFile = ""
	fixture.credential.ProviderClientPrivateKeyFile = ""
	fixture.credential.ProductRuntimeDSNBindingID = "gateway-dsn"
	fixture.credential.PostgresRuntimeRole = "product_gateway"
	fixture.credential.PostgresMaxConnections = 16
	fixture.credential.PostgresClientAgentSocket = filepath.Join(filepath.Dir(fixture.cfg.Authority.CredentialFile), "gateway-postgres-tls-agent.sock")
	fixture.credential.PostgresClientAgentUID, fixture.credential.PostgresClientAgentGID = 503, 21
	fixture.credential.PostgresPeerCRLRoleFile = filepath.Join(filepath.Dir(fixture.cfg.Authority.CredentialFile), "gateway-postgres-peer-crl-role.json")
	fixture.credential.PostgresPeerCRLRoleDigest = "sha256:" + strings.Repeat("d", 64)
	fixture.credential.PostgresPeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("e", 64)
	fixture.credential.GrantKeyBindingID = "gateway-grant"
	write := func() {
		writeJSON0600(t, fixture.cfg.Authority.CredentialFile, fixture.credential)
		writeJSON0600(t, fixture.cfg.Authority.DependencyFile, fixture.dependency)
		writeJSON0600(t, fixture.cfg.Authority.PolicyFile, fixture.policy)
	}
	write()
	if _, err := LoadGatewayAuthority(fixture.cfg); err != nil {
		t.Fatalf("valid live Gateway authority: %v", err)
	}
	for name, mutate := range map[string]func(*GatewayCredentialAuthority){
		"old authority version":     func(value *GatewayCredentialAuthority) { value.Version = gatewayAuthorityVersionV3 },
		"static CA path":            func(value *GatewayCredentialAuthority) { value.ProviderCABundleFile = "/tmp/old-ca.pem" },
		"static client key":         func(value *GatewayCredentialAuthority) { value.ProviderClientPrivateKeyBindingID = "old-key" },
		"missing grant":             func(value *GatewayCredentialAuthority) { value.GrantKeyBindingID = "" },
		"missing PostgreSQL signer": func(value *GatewayCredentialAuthority) { value.PostgresClientAgentSocket = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixture.credential
			mutate(&candidate)
			writeJSON0600(t, fixture.cfg.Authority.CredentialFile, candidate)
			if _, err := LoadGatewayAuthority(fixture.cfg); err == nil {
				t.Fatal("unsafe Gateway credential authority was accepted")
			}
			write()
		})
	}
}

func TestGatewayPublicHandlerProjectsDeferredCapabilitiesWithoutPrivateCoordinates(t *testing.T) {
	terminal := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusBadRequest) })
	policy := GatewayPolicyAuthority{
		Version: gatewayAuthorityVersion, Role: string(config.DataPlaneGateway), Terminal: gatewayCapabilityEnabled,
		BrowserAutomation: gatewayCapabilityAuthorityUnavailable, BrowserLive: gatewayCapabilityAuthorityUnavailable,
		DesktopLive: gatewayCapabilityAuthorityUnavailable, DeferredAuthorityReason: gatewayDeferredAuthorityReason,
	}
	handler := newGatewayPublicHandler(terminal, policy)

	terminalResponse := httptest.NewRecorder()
	handler.ServeHTTP(terminalResponse, httptest.NewRequest(http.MethodGet, "/terminal/connect", nil))
	if terminalResponse.Code != http.StatusBadRequest {
		t.Fatalf("terminal status=%d", terminalResponse.Code)
	}
	for _, path := range []string{"/browser/automation", "/browser/live", "/desktop/connect"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{}`))))
		body := response.Body.String()
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(body, "PRODUCT_CAPABILITY_UNAVAILABLE") ||
			strings.Contains(body, "wss://") || strings.Contains(body, "ref:") || strings.Contains(body, "/tmp/") {
			t.Fatalf("%s status=%d body=%q", path, response.Code, body)
		}
	}
	capabilities := httptest.NewRecorder()
	handler.ServeHTTP(capabilities, httptest.NewRequest(http.MethodGet, "/capabilities", nil))
	document, err := io.ReadAll(capabilities.Result().Body)
	if err != nil || capabilities.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d err=%v", capabilities.Code, err)
	}
	var projection gatewayCapabilityProjection
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil || projection.Terminal != gatewayCapabilityEnabled ||
		projection.BrowserAutomation != gatewayCapabilityAuthorityUnavailable || projection.BrowserLive != gatewayCapabilityAuthorityUnavailable ||
		projection.DesktopLive != gatewayCapabilityAuthorityUnavailable || projection.Reason != gatewayDeferredAuthorityReason {
		t.Fatalf("capabilities=%#v err=%v", projection, err)
	}
	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/private", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown status=%d", unknown.Code)
	}
}
