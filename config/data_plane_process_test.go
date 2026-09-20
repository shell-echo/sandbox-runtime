package config

import (
	"path/filepath"
	"strings"
	"testing"
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
