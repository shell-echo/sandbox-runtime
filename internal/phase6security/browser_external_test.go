package phase6security

import "testing"

func TestBrowserExternalAuthorityRejectsDrift(t *testing.T) {
	mutateEdge := func(profile *Profile, id string, change func(*TrustEdge)) {
		for index := range profile.TrustEdges {
			if profile.TrustEdges[index].ID == id {
				change(&profile.TrustEdges[index])
				return
			}
		}
		t.Fatalf("missing fixture edge %s", id)
	}
	mutatePolicy := func(profile *Profile, id string, change func(*EgressPolicy)) {
		for index := range profile.EgressPolicies {
			if profile.EgressPolicies[index].ID == id {
				change(&profile.EgressPolicies[index])
				return
			}
		}
		t.Fatalf("missing fixture policy %s", id)
	}
	tests := map[string]func(*Profile){
		"missing witness identity": func(p *Profile) { p.External = p.External[1:] },
		"extra external identity": func(p *Profile) {
			p.External = append(p.External, ExternalService{Name: "other"})
		},
		"witness aliases product database": func(p *Profile) {
			p.External[0].DNSNames[0] = "postgres.sandbox-runtime.test"
			p.External[0].IdentityDigest = p.External[0].Digest()
		},
		"extra witness DNS alias": func(p *Profile) {
			p.External[0].DNSNames = append(p.External[0].DNSNames, "other.sandbox-runtime.test")
			p.External[0].IdentityDigest = p.External[0].Digest()
		},
		"missing gateway capacity edge": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == "gateway-capacity-valkey" {
					p.TrustEdges = append(p.TrustEdges[:index], p.TrustEdges[index+1:]...)
					return
				}
			}
		},
		"missing ingress broker DNS edge": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == "egress-dns-browser-action-ingress" {
					p.TrustEdges = append(p.TrustEdges[:index], p.TrustEdges[index+1:]...)
					return
				}
			}
		},
		"gateway broker DNS port drift": func(p *Profile) {
			mutateEdge(p, "egress-dns-gateway", func(e *TrustEdge) { e.Port = 5353 })
		},
		"gateway reaches witness": func(p *Profile) {
			mutateEdge(p, "gateway-capacity-valkey", func(e *TrustEdge) { e.To = "action-history-postgres" })
		},
		"gateway reaches product database": func(p *Profile) {
			p.TrustEdges = append(p.TrustEdges, TrustEdge{ID: "gateway-postgres", From: "gateway-runtime", To: "postgres"})
		},
		"swapped capacity purpose": func(p *Profile) {
			mutateEdge(p, "browser-capacity-valkey", func(e *TrustEdge) { e.Protocol = "postgres" })
		},
		"alternate capacity port": func(p *Profile) {
			mutateEdge(p, "browser-capacity-valkey", func(e *TrustEdge) { e.Port = 6380 })
		},
		"wrong witness trust anchor": func(p *Profile) {
			mutateEdge(p, "browser-action-history-postgres", func(e *TrustEdge) { e.ServerAnchorID = "internal-server-ca" })
		},
		"plaintext broker edge": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.Authentication = "unix_peer_credentials" })
		},
		"missing ingress broker": func(p *Profile) {
			mutatePolicy(p, "browser-action-ingress-egress", func(policy *EgressPolicy) { policy.Broker = "egress-broker-gateway" })
		},
		"alternate capacity target": func(p *Profile) {
			mutatePolicy(p, "gateway-egress", func(policy *EgressPolicy) { policy.Targets[0].Host = "alternate.sandbox-runtime.test" })
		},
		"alternate witness target": func(p *Profile) {
			mutatePolicy(p, "browser-action-ingress-egress", func(policy *EgressPolicy) { policy.Targets[0].Host = "postgres.sandbox-runtime.test" })
		},
		"extra gateway target": func(p *Profile) {
			mutatePolicy(p, "gateway-egress", func(policy *EgressPolicy) {
				policy.Targets = append(policy.Targets, EgressTarget{Alias: "witness", Host: "action-history.sandbox-runtime.test", Port: 5432, Protocol: "postgres"})
			})
		},
		"direct ingress egress": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "browser-action-ingress-runtime" {
					p.Principals[index].DirectEgressBlocked = false
					return
				}
			}
		},
		"direct gateway egress": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "gateway-runtime" {
					p.Principals[index].DirectEgressBlocked = false
					return
				}
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}
