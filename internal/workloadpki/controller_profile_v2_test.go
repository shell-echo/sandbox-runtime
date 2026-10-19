package workloadpki

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

// Deliberately a policy-field fixture, not a complete or admitted Profile.
func controllerV2PolicyFields(t *testing.T) (phase6security.ProfileV2, phase6security.PeerCRLSources, []Policy) {
	t.Helper()
	digest := func(value string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))) }
	brokers := map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct,
		"gateway_egress_broker": securityprincipal.RoleGateway, "browser_action_ingress_egress_broker": securityprincipal.RoleGateway,
		"provider_browser_egress_broker": securityprincipal.RoleProvider, "provider_desktop_egress_broker": securityprincipal.RoleProvider}
	registry, err := securityprincipal.NewSlice6V2Registry(digest("environment"), digest("principals"), brokers, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := phase6security.ProfileV2{}
	sources := phase6security.PeerCRLSources{Sources: []phase6security.PeerCRLSource{
		{ID: "broker", Mount: "pki", IssuerID: "11111111-1111-4111-8111-111111111111", IssuerDigest: digest("broker")},
		{ID: "general", Mount: "pki", IssuerID: "22222222-2222-4222-8222-222222222222", IssuerDigest: digest("general")}}}
	profile.External = []phase6security.ExternalService{{Name: "dns", DNSClientCA: &phase6security.DNSClientCA{
		IssuerID: sources.Sources[0].IssuerID, IssuerDigest: sources.Sources[0].IssuerDigest}}}
	var policies []Policy
	newPrincipal := func(deployment, name string, kind securityprincipal.Kind, role securityprincipal.Role) phase6security.Principal {
		p, err := registry.New(kind, name, role, digest(deployment))
		if err != nil {
			t.Fatal(err)
		}
		return phase6security.Principal{Name: deployment, UID: 20001, GID: 30001, AuthorizationPrincipal: &p,
			PrincipalDigest: p.Digest(), TLS: &phase6security.TLSIdentity{TrustDomain: "sandbox-runtime.test",
				URI: "spiffe://sandbox-runtime.test/" + deployment, DNSNames: []string{deployment + ".test"},
				Usages: []string{"client_auth", "server_auth"}, TTLSeconds: 900}}
	}
	addPolicy := func(id string, requester, subject phase6security.Principal, source string) (Policy, string) {
		key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		p := Policy{ID: id, Registry: registry, Requester: *requester.AuthorizationPrincipal, Subject: *subject.AuthorizationPrincipal,
			TrustDomain: subject.TLS.TrustDomain, URI: subject.TLS.URI, DNSNames: subject.TLS.DNSNames, Usages: subject.TLS.Usages,
			VaultRole: id, IssuerSourceID: source, MaxTTLSeconds: subject.TLS.TTLSeconds, ExpectedUID: requester.UID,
			ExpectedGID: requester.GID, PublicKey: key}
		return p, phase6security.TLSAgentRequestPublicKeyDigest(key)
	}
	for _, spec := range []struct {
		deployment, subject, agent string
		kind                       securityprincipal.Kind
		role                       securityprincipal.Role
		source                     string
	}{
		{"product-runtime", "product", "product_tls_agent", securityprincipal.KindRuntimeRole, securityprincipal.RoleProduct, "general"},
		{"provider-docker-control", "provider_docker_control", "provider_docker_control_tls_agent", securityprincipal.KindDockerControl, securityprincipal.RoleControl, "general"},
		{"provider-artifact-scanner", "provider_artifact_scanner", "provider_artifact_scanner_tls_agent", securityprincipal.KindArtifactScanner, securityprincipal.RoleScanner, "general"},
		{"egress-broker-product", "product_egress_broker", "product_egress_broker_tls_agent", securityprincipal.KindEgressBroker, securityprincipal.RoleProduct, "broker"},
		{"egress-broker-gateway", "gateway_egress_broker", "gateway_egress_broker_tls_agent", securityprincipal.KindEgressBroker, securityprincipal.RoleGateway, "broker"},
		{"egress-broker-browser-action-ingress", "browser_action_ingress_egress_broker", "browser_action_ingress_egress_broker_tls_agent", securityprincipal.KindEgressBroker, securityprincipal.RoleGateway, "broker"},
		{"egress-broker-provider-browser", "provider_browser_egress_broker", "provider_browser_egress_broker_tls_agent", securityprincipal.KindEgressBroker, securityprincipal.RoleProvider, "broker"},
		{"egress-broker-provider-desktop", "provider_desktop_egress_broker", "provider_desktop_egress_broker_tls_agent", securityprincipal.KindEgressBroker, securityprincipal.RoleProvider, "broker"},
	} {
		subject := newPrincipal(spec.deployment, spec.subject, spec.kind, spec.role)
		agent := newPrincipal(spec.deployment+"-tls-agent", spec.agent, securityprincipal.KindTLSAgent, spec.role)
		profile.Principals = append(profile.Principals, subject, agent)
		policy, keyDigest := addPolicy(spec.deployment+"-tls", agent, subject, spec.source)
		policies = append(policies, policy)
		profile.TLSAgentBindings = append(profile.TLSAgentBindings, phase6security.TLSAgentBinding{
			AgentDeployment: agent.Name, SubjectDeployment: subject.Name, IssuerPolicyID: policy.ID,
			IssuerVaultRole: policy.VaultRole, AgentRequestKeyDigest: keyDigest, AgentUID: agent.UID, AgentGID: agent.GID})
	}
	for _, spec := range []struct{ deployment, name string }{{"certificate-controller", "certificate_controller"}, {"workload-credential-controller", "credential_controller"}} {
		principal := newPrincipal(spec.deployment, spec.name, securityprincipal.KindController, "")
		profile.Principals = append(profile.Principals, principal)
		policy, keyDigest := addPolicy(spec.deployment+"-tls", principal, principal, "general")
		policies = append(policies, policy)
		if spec.name == "certificate_controller" {
			profile.CertificateController = phase6security.CertificateControllerAuthority{DeploymentName: principal.Name,
				UID: principal.UID, GID: principal.GID, ManagedPolicyID: policy.ID, ManagedVaultRole: policy.VaultRole, ManagedRequestKeyDigest: keyDigest}
		} else {
			profile.CertificateController.CredentialController = phase6security.CredentialControllerManagedAuthority{
				PolicyID: policy.ID, VaultRole: policy.VaultRole, RequestKeyDigest: keyDigest}
		}
	}
	subject := profile.Principals[0]
	agent := newPrincipal("product-postgres-tls-agent", "product_postgres_tls_agent", securityprincipal.KindTLSAgent, securityprincipal.RoleProduct)
	profile.Principals = append(profile.Principals, agent)
	policy, keyDigest := addPolicy("product-postgres-client", agent, subject, "general")
	var target phase6security.Slice6PostgresSignerTarget
	for _, candidate := range phase6security.Slice6DesiredFinalPostgresSignerTargets() {
		if candidate.SubjectDeployment == subject.Name {
			target = candidate
		}
	}
	policy.Purpose = PostgresClientPurpose
	policy.DNSNames, policy.Usages = nil, []string{"client_auth"}
	policy.Postgres = PostgresClientIdentity{OwnerDeployment: subject.Name, DatabaseName: target.DatabaseName,
		RuntimeRole: target.SQLRole, ServiceName: "postgres", URI: subject.TLS.URI, CommonName: target.SQLRole, MaxTTL: 900 * time.Second}
	policies = append(policies, policy)
	profile.PostgresClientAgents = []phase6security.PostgresClientAgentBinding{{TLSAgentBinding: phase6security.TLSAgentBinding{
		AgentDeployment: agent.Name, SubjectDeployment: subject.Name, IssuerPolicyID: policy.ID, IssuerVaultRole: policy.VaultRole,
		AgentUID: agent.UID, AgentGID: agent.GID, AgentRequestKeyDigest: keyDigest}, CommonName: target.SQLRole}}
	return profile, sources, policies
}

func TestControllerV2ExactPolicySetAndTwoIssuerPartition(t *testing.T) {
	profile, sources, policies := controllerV2PolicyFields(t)
	if err := validateControllerPoliciesV2Fields(profile, sources, policies); err != nil {
		t.Fatal(err)
	}
	for _, original := range policies {
		for name, mutate := range map[string]func(*Policy){
			"id":         func(p *Policy) { p.ID += "-unbound" },
			"key":        func(p *Policy) { p.PublicKey[0] ^= 1 },
			"uri":        func(p *Policy) { p.URI += "-other" },
			"dns":        func(p *Policy) { p.DNSNames = []string{"other.test"} },
			"usages":     func(p *Policy) { p.Usages = []string{"server_auth"} },
			"vault-role": func(p *Policy) { p.VaultRole += "-other" },
			"ttl":        func(p *Policy) { p.MaxTTLSeconds-- },
			"uid":        func(p *Policy) { p.ExpectedUID++ },
			"gid":        func(p *Policy) { p.ExpectedGID++ },
			"issuer": func(p *Policy) {
				if p.IssuerSourceID == "broker" {
					p.IssuerSourceID = "general"
				} else {
					p.IssuerSourceID = "broker"
				}
			},
			"instance": func(p *Policy) {
				p.Subject, _ = p.Registry.New(p.Subject.Kind, p.Subject.Name, p.Subject.Role, "sha256:"+strings.Repeat("f", 64))
			},
		} {
			t.Run(original.ID+"/"+name, func(t *testing.T) {
				changed := freezeControllerPolicies(policies)
				for i := range changed {
					if changed[i].ID == original.ID {
						mutate(&changed[i])
					}
				}
				if validateControllerPoliciesV2Fields(profile, sources, changed) == nil {
					t.Fatal("unbound policy admitted")
				}
			})
		}
	}
	for name, change := range map[string]func([]Policy) []Policy{
		"missing":   func(p []Policy) []Policy { return p[:len(p)-1] },
		"extra":     func(p []Policy) []Policy { extra := p[0]; extra.ID += "-extra"; return append(p, extra) },
		"duplicate": func(p []Policy) []Policy { p[1] = p[0]; return p },
		"wrong-purpose": func(p []Policy) []Policy {
			p[len(p)-1].Purpose = ""
			p[len(p)-1].Postgres = PostgresClientIdentity{}
			return p
		},
		"wrong-database": func(p []Policy) []Policy { p[len(p)-1].Postgres.DatabaseName = "other_database"; return p },
		"wrong-sql-role": func(p []Policy) []Policy {
			p[len(p)-1].Postgres.RuntimeRole = "other_role"
			p[len(p)-1].Postgres.CommonName = "other_role"
			return p
		},
	} {
		t.Run(name, func(t *testing.T) {
			if validateControllerPoliciesV2Fields(profile, sources, change(freezeControllerPolicies(policies))) == nil {
				t.Fatal("policy set drift admitted")
			}
		})
	}
	if ValidateControllerPoliciesV2(profile, sources, sources.Digest(), policies) == nil {
		t.Fatal("field fixture bypassed public hold")
	}
}

type preflightOnlyAuthority struct{ calls int }

func (a *preflightOnlyAuthority) Issue(context.Context, Policy, []byte, time.Duration) (IssuedCertificate, error) {
	a.calls++
	return IssuedCertificate{}, ErrUnavailable
}
func (a *preflightOnlyAuthority) Revocations(context.Context) (RevocationSnapshot, error) {
	a.calls++
	return RevocationSnapshot{}, ErrUnavailable
}
func (a *preflightOnlyAuthority) Revoke(context.Context, string) error {
	a.calls++
	return ErrUnavailable
}
func (a *preflightOnlyAuthority) ValidatePolicyIssuers([]Policy) error { a.calls++; return nil }
func (a *preflightOnlyAuthority) PolicyRevocations(context.Context, Policy) (RevocationSnapshot, error) {
	a.calls++
	return RevocationSnapshot{}, ErrUnavailable
}
func (a *preflightOnlyAuthority) ValidatePeerSources([]phase6security.PeerCRLSource) error {
	a.calls++
	return nil
}
func (a *preflightOnlyAuthority) PeerIssuerCertificate(context.Context, string) ([]byte, error) {
	a.calls++
	return nil, ErrUnavailable
}
func (a *preflightOnlyAuthority) PeerRevocations(context.Context, string, []byte) (RevocationSnapshot, error) {
	a.calls++
	return RevocationSnapshot{}, ErrUnavailable
}

func TestControllerV2HeldBeforeAuthorityAndLedger(t *testing.T) {
	profile, sources, policies := controllerV2PolicyFields(t)
	authority := &preflightOnlyAuthority{}
	path := filepath.Join(securePKIDirectory(t), "ledger.json")
	config := ControllerConfig{LedgerPath: path, Policies: policies, Authority: authority,
		ControllerKeyID: "controller", ControllerKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour}
	for _, legacy := range []bool{false, true} {
		if legacy {
			config.PeerCRLProfile, config.PeerCRLSources = &phase6security.Profile{}, &sources
		}
		controller, err := NewControllerV2(config, profile, sources, sources.Digest())
		if controller != nil || err == nil || authority.calls != 0 {
			t.Fatal("held profile reached controller/authority")
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("held profile touched ledger: %v", err)
	}
}

func TestLegacyControllerRejectsV2RolePolicyBeforeSideEffects(t *testing.T) {
	_, _, policies := controllerV2PolicyFields(t)
	for _, policy := range policies {
		if policy.Subject.Kind != securityprincipal.KindDockerControl && policy.Subject.Kind != securityprincipal.KindArtifactScanner {
			continue
		}
		t.Run(policy.ID, func(t *testing.T) {
			if policy.Validate() != nil {
				t.Fatal("regression requires a valid v2 policy")
			}
			authority := &preflightOnlyAuthority{}
			path := filepath.Join(securePKIDirectory(t), "ledger.json")
			controller, err := NewController(ControllerConfig{LedgerPath: path, Policies: []Policy{policy}, Authority: authority,
				ControllerKeyID: "controller", ControllerKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
				Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
			if controller != nil {
				controller.Close()
			}
			if err == nil || controller != nil || authority.calls != 0 {
				t.Fatal("legacy entry admitted v2 policy without Profile-v2")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("legacy rejection touched ledger: %v", err)
			}
		})
	}
}
