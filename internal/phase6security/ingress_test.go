package phase6security

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

func TestIngressBoundaryAcceptsClosedProfile(t *testing.T) {
	profile := validProfile()
	registry, err := profile.principalRegistry()
	if err != nil {
		t.Fatalf("principal registry: %v", err)
	}
	principals := make(map[string]Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		principals[principal.Name] = principal
	}
	authorityBindings := map[string]principalBinding{}
	dynamicTLSBindings := map[string]principalBinding{}
	for _, policy := range profile.EgressPolicies {
		authorityBindings[policy.Authority.DeploymentName] = principalBinding{securityprincipal.KindController, policy.Authority.AuthorizationName, ""}
		for _, binding := range profile.TLSAgentBindings {
			if binding.SubjectDeployment == policy.Broker {
				identity := principals[policy.Broker].AuthorizationPrincipal
				dynamicTLSBindings[binding.AgentDeployment] = principalBinding{securityprincipal.KindTLSAgent, identity.Name + "_tls_agent", identity.Role}
			}
		}
	}
	for _, principal := range profile.Principals {
		if err := validatePrincipal(principal, registry, authorityBindings, dynamicTLSBindings); err != nil {
			t.Fatalf("principal %s: %v", principal.Name, err)
		}
	}
	if err := validatePrincipal(principals["public-ingress-relay"], registry, nil, nil); err != nil {
		t.Fatalf("ingress principal: %v", err)
	}
	external, err := validateExternal(profile.External)
	if err != nil {
		t.Fatalf("external: %v", err)
	}
	if err := validateNetworks(profile.Networks, principals, external, profile.EgressPolicies); err != nil {
		t.Fatalf("ingress networks: %v", err)
	}
	if err := validatePublicListeners(profile.PublicListeners, principals); err != nil {
		t.Fatalf("public listeners: %v", err)
	}
	if err := validateIngressBindings(profile.IngressBindings, profile.PublicListeners, principals, profile.Networks); err != nil {
		t.Fatalf("ingress bindings: %v", err)
	}
	edges, err := validateEdges(profile.TrustEdges, principals, external)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	if err := validateTrustAnchorsWithPostgres(profile.TrustAnchors, profile.TrustEdges, profile.PublicListeners,
		profile.CertificateController, profile.PostgresClientAgents, principals, external); err != nil {
		t.Fatalf("anchors: %v", err)
	}
	if err := validateEgress(profile.EgressPolicies, principals, edges); err != nil {
		t.Fatalf("egress: %v", err)
	}
	if err := validateCertificateControllerAuthority(profile.CertificateController, principals, edges); err != nil {
		t.Fatalf("controller: %v", err)
	}
	if err := validatePostgresClientAgents(profile.PostgresClientAgents, profile.ProviderDatabases, profile.TLSAgentBindings, profile.EgressPolicies,
		profile.CertificateController, profile.TrustAnchors, principals, edges); err != nil {
		t.Fatalf("PostgreSQL agents: %v", err)
	}
	if err := validateTLSAgentBindingsWithPostgres(profile.TLSAgentBindings, profile.PostgresClientAgents,
		profile.EgressPolicies, profile.CertificateController, principals, edges); err != nil {
		t.Fatalf("agents: %v", err)
	}
	if profile.ProfileDigest != profile.Digest() {
		t.Fatal("profile digest")
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("complete profile: %v", err)
	}
	config, relay, err := profile.IngressRelayConfig()
	if err != nil || relay.Name != "public-ingress-relay" || len(config.Mappings) != 2 {
		t.Fatalf("ingress relay config: %+v %+v %v", config, relay, err)
	}
}

func TestIngressBoundaryRejectsEndpointIdentityAndTopologyDrift(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"relay principal":   func(p *Profile) { p.IngressBindings[0].RelayPrincipalDigest = testDigest("other") },
		"target principal":  func(p *Profile) { p.IngressBindings[0].TargetPrincipalDigest = testDigest("other") },
		"private target":    func(p *Profile) { p.IngressBindings[0].Target = "provider-runtime" },
		"wrong trust edge":  func(p *Profile) { p.IngressBindings[0].TrustNetwork = "ingress-product" },
		"wrong frontend":    func(p *Profile) { p.IngressBindings[0].FrontendNetwork = "external-uplink" },
		"wrong target port": func(p *Profile) { p.IngressBindings[0].UpstreamAddress = "10.12.0.3:9445" },
		"frontend on trust subnet": func(p *Profile) {
			p.IngressBindings[0].FrontendAddress = "10.12.0.2:8445"
			p.IngressBindings[1].FrontendAddress = "10.12.0.2:8444"
		},
		"target outside trust subnet": func(p *Profile) { p.IngressBindings[0].UpstreamAddress = "10.13.0.3:8445" },
		"overlapping profile subnets": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "ingress-gateway" {
					p.Networks[index].IPv4Subnet = "10.11.0.0/24"
				}
			}
		},
		"noncanonical profile subnet": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "ingress-gateway" {
					p.Networks[index].IPv4Subnet = "10.12.0.1/24"
				}
			}
		},
		"dynamic DNS":          func(p *Profile) { p.IngressBindings[0].UpstreamAddress = "gateway.test:8445" },
		"wildcard publication": func(p *Profile) { p.IngressBindings[0].HostBindAddress = "0.0.0.0:18445" },
		"unbounded capacity":   func(p *Profile) { p.IngressBindings[0].MaxConnections = 0 },
		"relay TLS identity": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "public-ingress-relay" {
					p.Principals[index].TLS = p.Principals[0].TLS
				}
			}
		},
		"relay joins other network": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "public-ingress-relay" {
					p.Principals[index].Networks = append(p.Principals[index].Networks, "external-uplink")
				}
			}
		},
		"role joins frontend": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "public-ingress" {
					p.Networks[index].Principals = append([]string{"gateway-runtime"}, p.Networks[index].Principals...)
				}
			}
		},
		"extra relay listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "public-ingress-relay" {
					p.Principals[index].Listeners = append(p.Principals[index].Listeners,
						Listener{Name: "proxy", Protocol: "tcp", Port: 1080, Exposure: "ingress_frontend"})
				}
			}
		},
		"role claims ingress frontend": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "provider-runtime" {
					p.Principals[index].Listeners = append(p.Principals[index].Listeners,
						Listener{Name: "rogue-frontend", Protocol: "tcp", Port: 18888, Exposure: "ingress_frontend"})
				}
			}
		},
		"relay non-frontend listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "public-ingress-relay" {
					p.Principals[index].Listeners[0].Exposure = "trust_edge"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			for index := range profile.IngressBindings {
				profile.IngressBindings[index].ConfigurationDigest = profile.IngressBindings[index].Digest()
			}
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("ingress authority drift accepted")
			}
		})
	}
	profile := validProfile()
	profile.IngressBindings[0].ConfigurationDigest = testDigest("tampered")
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err == nil {
		t.Fatal("ingress configuration digest drift accepted")
	}
}
