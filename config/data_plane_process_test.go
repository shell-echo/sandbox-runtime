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
