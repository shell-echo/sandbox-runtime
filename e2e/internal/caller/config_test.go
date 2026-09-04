package caller

import (
	"strings"
	"testing"
)

func TestConfigValidateRequiresExplicitProfileAndArchitecture(t *testing.T) {
	valid := validCallerConfig()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"profile":      func(config *Config) { config.Profile = "" },
		"architecture": func(config *Config) { config.RuntimeArchitecture = "riscv64" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validCallerConfig()
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid caller config was accepted")
			}
		})
	}
}

func validCallerConfig() Config {
	return Config{
		Profile: ProfileBrowser, Phase: PhaseInitial,
		ProviderBaseURL: "https://127.0.0.1:10443", GatewayBaseURL: "https://127.0.0.1:10444",
		CAFile: "/tmp/ca.pem", ProviderRevisionID: "provider-revision-e2e-v1",
		ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:e2e",
		RuntimeImageReference:    "example.invalid/browser", RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeArchitecture: "arm64", GatewayAdminToken: "admin-token",
		ControllerA: IdentityConfig{
			ControllerSubject: "spiffe://reference-caller/controller-a", CertificateFile: "/tmp/a.pem", PrivateKeyFile: "/tmp/a-key.pem",
			JWSPrivateKeyFile: "/tmp/a-jws.pem", JWSKeyID: "a", GatewayToken: "token-a", GatewayCallerID: "caller-a",
			TenantID: "tenant-a", WorkOrderID: "work-a",
		},
		ControllerB: IdentityConfig{
			ControllerSubject: "spiffe://reference-caller/controller-b", CertificateFile: "/tmp/b.pem", PrivateKeyFile: "/tmp/b-key.pem",
			JWSPrivateKeyFile: "/tmp/b-jws.pem", JWSKeyID: "b", GatewayToken: "token-b", GatewayCallerID: "caller-b",
			TenantID: "tenant-b", WorkOrderID: "work-b",
		},
	}
}
