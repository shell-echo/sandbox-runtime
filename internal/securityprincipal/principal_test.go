package securityprincipal

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func principalRegistry(t *testing.T) *Registry {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	registry, err := NewRegistry(digest, "sha256:"+strings.Repeat("b", 64), map[string]Role{
		"product_egress_broker": RoleProduct, "vault_egress_broker": RoleProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestRegistryAcceptsEveryClosedKindNameCombination(t *testing.T) {
	registry := principalRegistry(t)
	instance := "sha256:" + strings.Repeat("c", 64)
	for kind, names := range registry.allowed {
		for name, role := range names {
			t.Run(string(kind)+"/"+name, func(t *testing.T) {
				principal, err := registry.New(kind, name, role, instance)
				if err != nil || registry.Validate(principal) != nil || principal.Digest() == "" {
					t.Fatalf("New() = %#v, %v", principal, err)
				}
				document, err := registry.Encode(principal)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := registry.Decode(document)
				if err != nil || decoded != principal {
					t.Fatalf("Decode() = %#v, %v", decoded, err)
				}
			})
		}
	}
}

func TestRegistryRejectsCrossKindRoleAndProfileSubstitution(t *testing.T) {
	registry := principalRegistry(t)
	instance := "sha256:" + strings.Repeat("c", 64)
	valid, err := registry.New(KindController, "certificate_controller", "", instance)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Principal){
		"runtime as controller": func(p *Principal) { p.Kind, p.Name, p.Role = KindController, "product", RoleProduct },
		"controller as Product": func(p *Principal) { p.Kind, p.Name, p.Role = KindRuntimeRole, "certificate_controller", RoleProduct },
		"agent job confusion":   func(p *Principal) { p.Kind, p.Name, p.Role = KindMigrationJob, "product_migration_agent", RoleProduct },
		"wrong role":            func(p *Principal) { p.Role = RoleProduct },
		"wrong profile":         func(p *Principal) { p.ProfileDigest = "sha256:" + strings.Repeat("d", 64) },
		"wrong environment":     func(p *Principal) { p.EnvironmentDigest = "sha256:" + strings.Repeat("d", 64) },
		"wrong instance":        func(p *Principal) { p.InstanceDigest = "" },
		"digest substitution":   func(p *Principal) { p.PrincipalDigest = "sha256:" + strings.Repeat("d", 64) },
		"unknown kind":          func(p *Principal) { p.Kind = "unknown" },
		"unregistered broker":   func(p *Principal) { p.Kind, p.Name, p.Role = KindEgressBroker, "other_egress_broker", RoleProduct },
		"unregistered ingress":  func(p *Principal) { p.Kind, p.Name, p.Role = KindIngressRelay, "other_ingress_relay", "" },
		"ingress role":          func(p *Principal) { p.Kind, p.Name, p.Role = KindIngressRelay, "public_ingress_relay", RoleProduct },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if registry.Validate(candidate) == nil {
				t.Fatal("principal substitution was accepted")
			}
		})
	}
}

func TestDecodeRejectsUnknownDuplicateTrailingAndNonCanonical(t *testing.T) {
	registry := principalRegistry(t)
	principal, err := registry.New(KindMaterialAgent, "product_runtime_agent", RoleProduct, "sha256:"+strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(principal)
	unknown := append([]byte(`{"unknown":true,`), document[1:]...)
	duplicate := append([]byte(`{"schema":"sandbox-runtime.security-principal.v1",`), document[1:]...)
	for name, candidate := range map[string][]byte{"unknown": unknown, "duplicate": duplicate, "trailing": append(document, '\n'), "whitespace": append([]byte(" "), document...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := registry.Decode(candidate); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
}

func TestRegistryRejectsUnregisteredDynamicPrincipalNames(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	if _, err := NewRegistry(digest, digest, map[string]Role{"not-a-broker": RoleProduct}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewRegistry() error = %v", err)
	}
}

func TestPolicyAuthorityControllerRequiresExactRegistration(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	registry, err := NewRegistryWithPolicyAuthorities(digest, digest, nil, map[string]Role{"product_policy_authority": ""})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.New(KindController, "product_policy_authority", "", digest); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.New(KindController, "other_policy_authority", "", digest); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unregistered authority accepted: %v", err)
	}
	for _, candidate := range []map[string]Role{
		{"product_policy_authority": RoleProduct}, {"product_controller": ""}, {"certificate_controller": ""},
	} {
		if _, err := NewRegistryWithPolicyAuthorities(digest, digest, nil, candidate); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid authority registry accepted: %v", candidate)
		}
	}
}

func TestTLSAgentKindIsDistinctAndBrokerRegistrationIsExact(t *testing.T) {
	registry := principalRegistry(t)
	instance := "sha256:" + strings.Repeat("c", 64)
	for _, item := range []struct {
		name string
		role Role
	}{
		{"product_tls_agent", RoleProduct},
		{"browser_executor_tls_agent", RoleBrowser},
		{"product_egress_broker_tls_agent", RoleProduct},
	} {
		principal, err := registry.New(KindTLSAgent, item.name, item.role, instance)
		if err != nil || principal.Kind != KindTLSAgent {
			t.Fatalf("TLS agent %q = %#v, %v", item.name, principal, err)
		}
		if _, err := registry.New(KindMaterialAgent, item.name, item.role, instance); !errors.Is(err, ErrInvalid) {
			t.Fatalf("TLS agent %q gained material-agent identity: %v", item.name, err)
		}
	}
	if _, err := registry.New(KindTLSAgent, "other_egress_broker_tls_agent", RoleProduct, instance); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unregistered broker TLS agent accepted: %v", err)
	}
}
