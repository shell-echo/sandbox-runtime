package workloadpki

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type phase6DelegationCase struct {
	owner, agent, subject string
	kind                  securityprincipal.Kind
	role                  securityprincipal.Role
}

func phase6DelegationPrincipal(t *testing.T, registry *securityprincipal.Registry,
	kind securityprincipal.Kind, name string, role securityprincipal.Role, instance int) securityprincipal.Principal {
	t.Helper()
	value, err := registry.New(kind, name, role, "sha256:"+fmt.Sprintf("%064x", instance))
	if err != nil {
		t.Fatalf("registered principal %s: %v", name, err)
	}
	return value
}

func phase6PostgresPolicy(t *testing.T, row phase6DelegationCase) Policy {
	t.Helper()
	registry, err := securityprincipal.NewRegistry("sha256:"+fmt.Sprintf("%064x", 1),
		"sha256:"+fmt.Sprintf("%064x", 2), nil)
	if err != nil {
		t.Fatal(err)
	}
	requester := phase6DelegationPrincipal(t, registry, securityprincipal.KindTLSAgent, row.agent, row.role, 3)
	subject := phase6DelegationPrincipal(t, registry, row.kind, row.subject, row.role, 4)
	uri := "spiffe://sandbox-runtime.test/" + row.owner
	return Policy{ID: "phase6-postgres-purpose", Registry: registry,
		Requester: requester, Subject: subject, TrustDomain: "sandbox-runtime.test", URI: uri,
		Usages: []string{"client_auth"}, VaultRole: "phase6-postgres-role", IssuerSourceID: "general",
		MaxTTLSeconds: 600, PublicKey: bytes.Repeat([]byte{7}, 32), Purpose: PostgresClientPurpose,
		Postgres: PostgresClientIdentity{OwnerDeployment: row.owner, DatabaseName: "phase6_db",
			RuntimeRole: "phase6_role", ServiceName: "postgres", URI: uri,
			CommonName: "phase6_role", MaxTTL: 10 * time.Minute}}
}

func TestPhase6PostgresPurposeDelegationIsNineExactOwnerVocabularies(t *testing.T) {
	rows := []phase6DelegationCase{
		{"product-runtime", "product_postgres_tls_agent", "product", securityprincipal.KindRuntimeRole, securityprincipal.RoleProduct},
		{"gateway-runtime", "gateway_postgres_tls_agent", "gateway", securityprincipal.KindRuntimeRole, securityprincipal.RoleGateway},
		{"provider-runtime", "provider_postgres_tls_agent", "provider", securityprincipal.KindRuntimeRole, securityprincipal.RoleProvider},
		{"provider-browser-runtime", "provider_tls_agent", "provider", securityprincipal.KindRuntimeRole, securityprincipal.RoleProvider},
		{"provider-desktop-runtime", "provider_tls_agent", "provider", securityprincipal.KindRuntimeRole, securityprincipal.RoleProvider},
		{"product-migration-job", "product_migration_postgres_tls_agent", "product_migration", securityprincipal.KindMigrationJob, securityprincipal.RoleProduct},
		{"provider-migration-job", "provider_migration_postgres_tls_agent", "provider_migration", securityprincipal.KindMigrationJob, securityprincipal.RoleProvider},
		{"provider-browser-migration-job", "provider_browser_migration_postgres_tls_agent", "provider_browser_migration", securityprincipal.KindMigrationJob, securityprincipal.RoleProvider},
		{"provider-desktop-migration-job", "provider_desktop_migration_postgres_tls_agent", "provider_desktop_migration", securityprincipal.KindMigrationJob, securityprincipal.RoleProvider},
	}
	if len(rows) != 9 {
		t.Fatal("PostgreSQL purpose signer inventory changed")
	}
	for _, row := range rows {
		t.Run(row.owner, func(t *testing.T) {
			policy := phase6PostgresPolicy(t, row)
			if err := policy.Validate(); err != nil {
				t.Fatalf("approved purpose delegation rejected: %v", err)
			}
			mutations := map[string]func(*Policy){
				"wrong purpose": func(p *Policy) { p.Purpose = "other" },
				"wrong owner": func(p *Policy) {
					p.Postgres.OwnerDeployment = "provider-browser-runtime"
					if row.owner == "provider-browser-runtime" {
						p.Postgres.OwnerDeployment = "provider-desktop-runtime"
					}
				},
				"wrong URI":              func(p *Policy) { p.URI = "spiffe://sandbox-runtime.test/other" },
				"wrong CN":               func(p *Policy) { p.Postgres.CommonName = "other_role" },
				"wrong SQL role":         func(p *Policy) { p.Postgres.RuntimeRole = "other_role" },
				"wrong issuer syntax":    func(p *Policy) { p.IssuerSourceID = "../other" },
				"server usage":           func(p *Policy) { p.Usages = []string{"client_auth", "server_auth"} },
				"different subject role": func(p *Policy) { p.Subject.Role = securityprincipal.RoleGuest },
			}
			// The two split Provider PG signers share the historical
			// provider_tls_agent vocabulary with an ordinary signer. Their
			// distinct signed InstanceDigest is checked against the final
			// Profile by the production controller, not by this low layer.
			if row.agent != "provider_tls_agent" {
				mutations["ordinary downgrade"] = func(p *Policy) {
					p.Purpose = ""
					p.Postgres = PostgresClientIdentity{}
				}
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					candidate := policy
					mutate(&candidate)
					if candidate.Validate() == nil {
						t.Fatal("cross-purpose or cross-owner delegation accepted")
					}
				})
			}
		})
	}
	providerRuntime := phase6PostgresPolicy(t, rows[2])
	providerRuntime.Requester = phase6DelegationPrincipal(t, providerRuntime.Registry,
		securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider, 5)
	if providerRuntime.Validate() == nil {
		t.Fatal("ordinary Provider signer gained provider-runtime PostgreSQL purpose")
	}
	product := phase6PostgresPolicy(t, rows[0])
	product.Requester = phase6DelegationPrincipal(t, product.Registry,
		securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct, 5)
	if product.Validate() == nil {
		t.Fatal("ordinary Product signer gained PostgreSQL purpose")
	}
}

func TestPhase6OrdinaryTLSDelegationHasOnlyApprovedMaterialAgentKinds(t *testing.T) {
	rows := []phase6DelegationCase{
		{"", "browser_action_ingress_tls_agent", "browser_action_ingress", securityprincipal.KindRuntimeRole, securityprincipal.RoleGateway},
		{"", "browser_action_ingress_agent_tls_agent", "browser_action_ingress_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleGateway},
		{"", "gateway_agent_tls_agent", "gateway_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleGateway},
		{"", "guest_agent_tls_agent", "guest_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleGuest},
		{"", "product_migration_agent_tls_agent", "product_migration_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProduct},
		{"", "product_runtime_agent_tls_agent", "product_runtime_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProduct},
		{"", "provider_browser_migration_agent_tls_agent", "provider_browser_migration_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProvider},
		{"", "provider_browser_runtime_agent_tls_agent", "provider_runtime_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProvider},
		{"", "provider_desktop_migration_agent_tls_agent", "provider_desktop_migration_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProvider},
		{"", "provider_desktop_runtime_agent_tls_agent", "provider_runtime_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProvider},
		{"", "provider_migration_agent_tls_agent", "provider_migration_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProvider},
		{"", "provider_runtime_agent_tls_agent", "provider_runtime_agent", securityprincipal.KindMaterialAgent, securityprincipal.RoleProvider},
	}
	if len(rows) != 12 {
		t.Fatal("ordinary TLS delegation expansion drifted")
	}
	for _, row := range rows {
		t.Run(row.agent, func(t *testing.T) {
			registry, err := securityprincipal.NewRegistry("sha256:"+fmt.Sprintf("%064x", 1),
				"sha256:"+fmt.Sprintf("%064x", 2), nil)
			if err != nil {
				t.Fatal(err)
			}
			requester := phase6DelegationPrincipal(t, registry, securityprincipal.KindTLSAgent, row.agent, row.role, 3)
			subject := phase6DelegationPrincipal(t, registry, row.kind, row.subject, row.role, 4)
			policy := Policy{ID: "ordinary-policy", Registry: registry, Requester: requester, Subject: subject,
				TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/ordinary",
				Usages: []string{"client_auth"}, VaultRole: "ordinary-vault",
				MaxTTLSeconds: 600, PublicKey: bytes.Repeat([]byte{9}, 32)}
			if err := policy.Validate(); err != nil {
				t.Fatalf("approved ordinary delegation rejected: %v", err)
			}
			if row.kind == securityprincipal.KindMaterialAgent {
				candidate := policy
				candidate.Subject = phase6DelegationPrincipal(t, registry, securityprincipal.KindRuntimeRole,
					"provider", securityprincipal.RoleProvider, 5)
				if candidate.Validate() == nil {
					t.Fatal("material-agent signer gained runtime certificate authority")
				}
			}
		})
	}
}
