package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestDataPlaneProcessValidatesRoleSpecificAuthority(t *testing.T) {
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	base := func(role DataPlaneRole) *DataPlaneProcessConfig {
		value := defaultDataPlaneProcess(role, 8445)
		value.Enabled = true
		value.Probe.Port = 8085
		value.Authority = DataPlaneAuthorityConfig{CredentialFile: path("credential-" + string(role)), DependencyFile: path("dependency-" + string(role)), PolicyFile: path("policy-" + string(role)), RecordingKeyRef: "kms://recording/phase6/" + string(role)}
		return value
	}

	gateway := base(DataPlaneGateway)
	gateway.TLS.CertificateFile, gateway.TLS.PrivateKeyFile = path("gateway.crt"), path("gateway.key")
	if err := gateway.Validate(); err != nil {
		t.Fatalf("valid gateway role: %v", err)
	}
	for name, mutate := range map[string]func(*DataPlaneProcessConfig){
		"role file":   func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleFile = path("peer-role.json") },
		"role digest": func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleDigest = "sha256:" + strings.Repeat("a", 64) },
		"mapping digest": func(value *DataPlaneProcessConfig) {
			value.TLS.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run("legacy rejects "+name, func(t *testing.T) {
			value := *gateway
			value.TLS = gateway.TLS
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("legacy accepted peer CRL role binding")
			}
		})
	}

	guest := base(DataPlaneGuest)
	guest.Public.Port, guest.Private.Port = 0, 0
	guest.OutboundURL = "wss://guest.example.test/agent"
	guest.TLS.ClientCABundleFile, guest.TLS.ClientCertificateFile, guest.TLS.ClientPrivateKeyFile = path("guest-ca.pem"), path("guest.crt"), path("guest.key")
	if err := guest.Validate(); err != nil {
		t.Fatalf("valid guest role: %v", err)
	}

	for name, mutate := range map[string]func(*DataPlaneProcessConfig){
		"development": func(value *DataPlaneProcessConfig) {
			value.DeploymentLevel = ProviderDeploymentLevel(ProductDevelopmentLevel)
		},
		"public private overlap": func(value *DataPlaneProcessConfig) {
			value.Role = DataPlaneBrowser
			value.Public.Port = 8444
			value.TLS.ClientCABundleFile = path("ca.pem")
			value.TLS.AllowedClientIdentity = []string{"spiffe://product/browser"}
		},
		"guest credentials in URL": func(value *DataPlaneProcessConfig) {
			value.OutboundURL = "wss://user:password@guest.example.test/agent"
		},
		"shared authority":     func(value *DataPlaneProcessConfig) { value.Authority.PolicyFile = value.Authority.CredentialFile },
		"inline recording key": func(value *DataPlaneProcessConfig) { value.Authority.RecordingKeyRef = strings.Repeat("x", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			value := *gateway
			value.Authority = gateway.Authority
			value.TLS = gateway.TLS
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe data-plane configuration was accepted")
			}
		})
	}
}

func TestDataPlaneProductionV2RequiresRoleScopedMaterialBindings(t *testing.T) {
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	candidate := defaultDataPlaneProcess(DataPlaneBrowser, defaultBrowserPort)
	candidate.SchemaVersion = DataPlaneProductionSchemaV2
	candidate.DeploymentLevel = ProviderProductionLevel
	candidate.Enabled = true
	candidate.Authority = DataPlaneAuthorityConfig{
		CredentialFile: path("credential.json"), DependencyFile: path("dependency.json"), PolicyFile: path("policy.json"),
		RecordingKeyRef: "kms://recording/phase6/browser",
	}
	candidate.TLS = DataPlaneTLSConfig{
		CertificateBindingID: "browser-server-certificate", PrivateKeyBindingID: "browser-server-key",
		ClientCABundleBindingID: "browser-ca", ClientCertificateBindingID: "browser-client-certificate",
		ClientPrivateKeyBindingID: "browser-client-key", ExpectedServerName: "browser.example.test",
		AllowedClientIdentity: []string{"spiffe://sandbox-runtime/provider"},
	}
	candidate.Materials.Provider = RoleMaterialProviderConfig{
		Type: UnixWorkloadMaterialProviderV1, Alias: "browser-material-agent", SocketPath: "/tmp/sandbox-runtime-browser-material-agent.sock",
		ExpectedUID: 501, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30,
	}
	bindings := []struct {
		id      string
		purpose secretref.Purpose
	}{
		{"browser-server-certificate", secretref.PurposeTLSCertificate},
		{"browser-server-key", secretref.PurposeTLSPrivateKey},
		{"browser-ca", secretref.PurposeCABundle},
		{"browser-client-certificate", secretref.PurposeTLSCertificate},
		{"browser-client-key", secretref.PurposeTLSPrivateKey},
	}
	for _, item := range bindings {
		document, err := json.Marshal(secretref.Binding{
			Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://vault/kv/" + item.id), Version: "v1", Purpose: item.purpose,
			TenantID: secretref.SystemTenant, Role: secretref.RoleBrowser,
		})
		if err != nil {
			t.Fatal(err)
		}
		candidate.Materials.Bindings = append(candidate.Materials.Bindings, RoleMaterialBindingConfig{ID: item.id, Provider: "browser-material-agent", Document: string(document)})
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Browser production material configuration: %v", err)
	}
	for name, mutate := range map[string]func(*DataPlaneProcessConfig){
		"role file":   func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleFile = path("peer-role.json") },
		"role digest": func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleDigest = "sha256:" + strings.Repeat("a", 64) },
		"mapping digest": func(value *DataPlaneProcessConfig) {
			value.TLS.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run("v2 rejects "+name, func(t *testing.T) {
			value := *candidate
			value.TLS = candidate.TLS
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("v2 accepted peer CRL role binding")
			}
		})
	}

	unsafe := *candidate
	unsafe.TLS = candidate.TLS
	unsafe.TLS.PrivateKeyFile = path("raw.key")
	if err := unsafe.Validate(); err == nil {
		t.Fatal("production Browser accepted a raw TLS private-key path")
	}

	wrongRole := *candidate
	wrongRole.Materials = candidate.Materials
	wrongRole.Materials.Bindings = append([]RoleMaterialBindingConfig(nil), candidate.Materials.Bindings...)
	var binding secretref.Binding
	if err := json.Unmarshal([]byte(wrongRole.Materials.Bindings[0].Document), &binding); err != nil {
		t.Fatal(err)
	}
	binding.Role = secretref.RoleDesktop
	document, _ := json.Marshal(binding)
	wrongRole.Materials.Bindings[0].Document = string(document)
	if err := wrongRole.Validate(); err == nil {
		t.Fatal("Browser accepted a Desktop-scoped material binding")
	}
}

func TestGatewayProductionV3RequiresLiveTLSAndOnlyTwoMaterials(t *testing.T) {
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	candidate := defaultDataPlaneProcess(DataPlaneGateway, defaultGatewayPort)
	candidate.SchemaVersion = DataPlaneProductionSchemaV3
	candidate.DeploymentLevel = ProviderProductionLevel
	candidate.Enabled = true
	candidate.Authority = DataPlaneAuthorityConfig{
		CredentialFile: path("credential.json"), DependencyFile: path("dependency.json"), PolicyFile: path("policy.json"),
		RecordingKeyRef: "kms://recording/phase6/gateway",
	}
	candidate.TLS = DataPlaneTLSConfig{
		SecurityProfilePath: path("security-profile.json"), SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
		PeerCRLRoleFile: path("peer-crl-role.json"), PeerCRLRoleDigest: "sha256:" + strings.Repeat("b", 64),
		PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64),
		AgentSocket:                path("tls-agent.sock"), AgentUID: 501, AgentGID: 20, OperationTimeoutMillis: 3000,
	}
	candidate.Materials.Provider = RoleMaterialProviderConfig{
		Type: UnixWorkloadMaterialProviderV1, Alias: "gateway-material-agent", SocketPath: "/tmp/gateway-material-agent-test.sock",
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
		candidate.Materials.Bindings = append(candidate.Materials.Bindings, RoleMaterialBindingConfig{ID: item.id, Provider: "gateway-material-agent", Document: string(document)})
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Gateway v3: %v", err)
	}
	for name, mutate := range map[string]func(*DataPlaneProcessConfig){
		"missing peer role":      func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleFile = "" },
		"missing role digest":    func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleDigest = "" },
		"missing mapping digest": func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLSourceMappingDigest = "" },
		"malformed role digest":  func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleDigest = "sha256:ABC" },
		"malformed map digest":   func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLSourceMappingDigest = "sha256:ABC" },
		"old v3 all absent": func(value *DataPlaneProcessConfig) {
			value.TLS.PeerCRLRoleFile = ""
			value.TLS.PeerCRLRoleDigest = ""
			value.TLS.PeerCRLSourceMappingDigest = ""
		},
		"raw private key":      func(value *DataPlaneProcessConfig) { value.TLS.PrivateKeyFile = path("raw.key") },
		"static key binding":   func(value *DataPlaneProcessConfig) { value.TLS.PrivateKeyBindingID = "old-key" },
		"client CA binding":    func(value *DataPlaneProcessConfig) { value.TLS.ClientCABundleBindingID = "old-ca" },
		"wrong profile digest": func(value *DataPlaneProcessConfig) { value.TLS.SecurityProfileDigest = "sha256:abc" },
		"missing signer socket": func(value *DataPlaneProcessConfig) {
			value.TLS.AgentSocket = ""
		},
		"missing signer identity": func(value *DataPlaneProcessConfig) { value.TLS.AgentUID = 0 },
		"wrong role": func(value *DataPlaneProcessConfig) {
			value.Role = DataPlaneBrowser
			value.Public, value.Private = value.Private, value.Public
		},
		"extra material": func(value *DataPlaneProcessConfig) {
			value.Materials.Bindings = append(value.Materials.Bindings, value.Materials.Bindings[0])
		},
		"wrong material purpose": func(value *DataPlaneProcessConfig) {
			var binding secretref.Binding
			if err := json.Unmarshal([]byte(value.Materials.Bindings[0].Document), &binding); err != nil {
				t.Fatal(err)
			}
			binding.Purpose = secretref.PurposeTLSPrivateKey
			document, _ := json.Marshal(binding)
			value.Materials.Bindings[0].Document = string(document)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := *candidate
			value.TLS = candidate.TLS
			value.Materials = candidate.Materials
			value.Materials.Bindings = append([]RoleMaterialBindingConfig(nil), candidate.Materials.Bindings...)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe Gateway v3 configuration was accepted")
			}
		})
	}
}

func TestPrivateExecutorProductionV3RequiresLiveTLSWithoutStaticMaterial(t *testing.T) {
	for _, role := range []DataPlaneRole{DataPlaneBrowser, DataPlaneDesktop} {
		t.Run(string(role), func(t *testing.T) {
			directory := t.TempDir()
			path := func(name string) string { return filepath.Join(directory, name) }
			port := defaultBrowserPort
			if role == DataPlaneDesktop {
				port = defaultDesktopPort
			}
			candidate := defaultDataPlaneProcess(role, port)
			candidate.Enabled = true
			candidate.SchemaVersion = DataPlaneProductionSchemaV3
			candidate.DeploymentLevel = ProviderProductionLevel
			candidate.Authority = DataPlaneAuthorityConfig{
				CredentialFile: path("credential.json"), DependencyFile: path("dependency.json"),
				PolicyFile: path("policy.json"), RecordingKeyRef: "kms://recording/phase6/" + string(role),
			}
			candidate.TLS = DataPlaneTLSConfig{
				SecurityProfilePath: path("profile.json"), SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
				PeerCRLRoleFile: path("peer-role.json"), PeerCRLRoleDigest: "sha256:" + strings.Repeat("b", 64),
				PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64),
				AgentSocket:                path("agent.sock"), AgentUID: 501, AgentGID: 20, OperationTimeoutMillis: 3000,
			}
			if err := candidate.Validate(); err != nil {
				t.Fatalf("valid private v3 process: %v", err)
			}
			for name, mutate := range map[string]func(*DataPlaneProcessConfig){
				"static server key": func(value *DataPlaneProcessConfig) { value.TLS.PrivateKeyBindingID = "key" },
				"static client key": func(value *DataPlaneProcessConfig) { value.TLS.ClientPrivateKeyBindingID = "key" },
				"raw key":           func(value *DataPlaneProcessConfig) { value.TLS.PrivateKeyFile = path("key.pem") },
				"missing peer role": func(value *DataPlaneProcessConfig) { value.TLS.PeerCRLRoleFile = "" },
				"material provider": func(value *DataPlaneProcessConfig) { value.Materials.Provider.Alias = "old-agent" },
				"material binding": func(value *DataPlaneProcessConfig) {
					value.Materials.Bindings = []RoleMaterialBindingConfig{{ID: "old-key"}}
				},
			} {
				t.Run(name, func(t *testing.T) {
					value := *candidate
					mutate(&value)
					if err := value.Validate(); err == nil {
						t.Fatal("private v3 accepted static or missing authority")
					}
				})
			}
		})
	}
}

func TestGuestProductionV3RetainsOnlySigningKeyMaterial(t *testing.T) {
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	value := defaultDataPlaneProcess(DataPlaneGuest, 0)
	value.Enabled = true
	value.SchemaVersion = DataPlaneProductionSchemaV3
	value.DeploymentLevel = ProviderProductionLevel
	value.OutboundURL = "wss://10.16.0.3:8449/agent"
	value.Authority = DataPlaneAuthorityConfig{CredentialFile: path("credential"), DependencyFile: path("dependency"),
		PolicyFile: path("policy"), RecordingKeyRef: "kms://recording/phase6/guest"}
	value.TLS = DataPlaneTLSConfig{SecurityProfilePath: path("profile"), SecurityProfileDigest: "sha256:" + strings.Repeat("a", 64),
		PeerCRLRoleFile: path("peer-role"), PeerCRLRoleDigest: "sha256:" + strings.Repeat("b", 64),
		PeerCRLSourceMappingDigest: "sha256:" + strings.Repeat("c", 64),
		AgentSocket:                path("agent.sock"), AgentUID: 501, AgentGID: 20, OperationTimeoutMillis: 3000}
	value.Materials.Provider = RoleMaterialProviderConfig{Type: UnixWorkloadMaterialProviderV1,
		Alias: "guest-material-agent", SocketPath: "/tmp/phase6-guest-material-test.sock", ExpectedUID: 502, ExpectedGID: 20,
		OperationTimeoutSeconds: 3, CacheSeconds: 30}
	document, err := json.Marshal(secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/kv/guest-signing-key", Version: "v1", Purpose: secretref.PurposeGuestSigningKey,
		TenantID: secretref.SystemTenant, Role: secretref.RoleGuest})
	if err != nil {
		t.Fatal(err)
	}
	value.Materials.Bindings = []RoleMaterialBindingConfig{{ID: "guest-signing-key", Provider: "guest-material-agent", Document: string(document)}}
	if err := value.Validate(); err != nil {
		t.Fatalf("valid Guest v3: %v", err)
	}
	for name, mutate := range map[string]func(*DataPlaneProcessConfig){
		"static TLS key": func(candidate *DataPlaneProcessConfig) { candidate.TLS.ClientPrivateKeyBindingID = "old-key" },
		"raw TLS key":    func(candidate *DataPlaneProcessConfig) { candidate.TLS.ClientPrivateKeyFile = path("old.pem") },
		"missing signing key": func(candidate *DataPlaneProcessConfig) {
			candidate.Materials.Bindings = nil
		},
		"extra material": func(candidate *DataPlaneProcessConfig) {
			candidate.Materials.Bindings = append(candidate.Materials.Bindings, RoleMaterialBindingConfig{ID: "extra"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *value
			candidate.Materials.Bindings = append([]RoleMaterialBindingConfig(nil), value.Materials.Bindings...)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("Guest v3 accepted invalid material or TLS authority")
			}
		})
	}
}

func TestDataPlaneRolesHaveDistinctDefaultProbePorts(t *testing.T) {
	ports := map[DataPlaneRole]int{
		DataPlaneGateway: defaultDataPlaneProcess(DataPlaneGateway, defaultGatewayPort).Probe.Port,
		DataPlaneGuest:   defaultDataPlaneProcess(DataPlaneGuest, defaultGuestPort).Probe.Port,
		DataPlaneBrowser: defaultDataPlaneProcess(DataPlaneBrowser, defaultBrowserPort).Probe.Port,
		DataPlaneDesktop: defaultDataPlaneProcess(DataPlaneDesktop, defaultDesktopPort).Probe.Port,
	}
	seen := make(map[int]DataPlaneRole, len(ports))
	for role, port := range ports {
		if previous, ok := seen[port]; ok {
			t.Fatalf("roles %s and %s share default probe port %d", previous, role, port)
		}
		seen[port] = role
	}
}
