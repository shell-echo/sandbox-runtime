package phase6security

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderV2PostgresFrozenGraphAndPublicHold(t *testing.T) {
	p := testCompleteV2Fields(t)
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		a, err := p.resolvePostgresV2Fields(rule.Owner)
		if err != nil || a.Owner != rule.Owner || a.Database != rule.Database || a.SQLRole != rule.SQLRole || a.SourceAddress+"/32" != rule.SourceCIDR || a.Migration != rule.Migration ||
			a.BrokerOnly != (rule.Dialer != rule.Owner) || a.Dialer != rule.Dialer || !strings.HasSuffix(a.SourceAddress, ".2") || !strings.HasSuffix(a.ServerAddress, ".3") {
			t.Fatalf("owner %s: %+v %v", rule.Owner, a, err)
		}
		if _, err := p.ResolveSlice6FinalPostgresAuthority(rule.Owner); err == nil {
			t.Fatal("public v2 PG hold bypassed")
		}
	}
	if _, err := p.resolvePostgresV2Fields("provider-docker-control"); err == nil {
		t.Fatal("tenth PG owner accepted")
	}
	if _, err := p.resolvePostgresV2Fields("provider-artifact-scanner"); err == nil {
		t.Fatal("scanner gained PG")
	}
	a, _ := p.resolvePostgresV2Fields("provider-runtime")
	document, _ := json.Marshal(p)
	for name, mutate := range map[string]func(*ProfileV2){
		"changed CIDR": func(p *ProfileV2) {
			for i := range p.Networks {
				if p.Networks[i].Name == a.Network {
					p.Networks[i].IPv4Subnet = "172.29.240.0/24"
				}
			}
		},
		"host routing": func(p *ProfileV2) {
			for i := range p.Networks {
				if p.Networks[i].Name == a.Network {
					p.Networks[i].GatewayModeIPv4 = "nat"
				}
			}
		},
		"extra network": func(p *ProfileV2) {
			p.Networks = append(p.Networks, Network{Name: "unexpected-pg", ExternalServices: []string{"postgres"}})
		},
		"extra edge": func(p *ProfileV2) {
			p.TrustEdges = append(p.TrustEdges, TrustEdge{ID: "unexpected-pg", To: "postgres", Protocol: "postgres"})
		},
		"broker downgrade": func(p *ProfileV2) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].ID == a.PeerEdgeID {
					p.TrustEdges[i].From = "provider-browser-runtime"
				}
			}
		},
		"retimed edge": func(p *ProfileV2) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].ID == a.PeerEdgeID {
					p.TrustEdges[i].MaxConnectionSeconds++
				}
			}
		},
		"service URI": func(p *ProfileV2) {
			for i := range p.External {
				if p.External[i].Name == "postgres" {
					p.External[i].URI = "spiffe://sandbox-runtime.test/other"
				}
			}
		},
		"different HBA": func(p *ProfileV2) { p.PostgresServerAuth.HBAArtifactID = "other-hba" },
		"wrong SQL role": func(p *ProfileV2) {
			for i := range p.PostgresClientAgents {
				if p.PostgresClientAgents[i].SubjectDeployment == "provider-runtime" {
					p.PostgresClientAgents[i].CommonName = "other_role"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var q ProfileV2
			if json.Unmarshal(document, &q) != nil {
				t.Fatal("fixture decode")
			}
			mutate(&q)
			q.ProfileDigest = q.Digest()
			if _, err := q.resolvePostgresV2Fields("provider-runtime"); err == nil {
				t.Fatal("rewritten PG authority accepted")
			}
		})
	}
	access, err := buildSlice6MaterialAccessFields(p.ProfileDigest, p.Principals, p.CredentialIssuerSockets)
	if err != nil || len(access) != 11 {
		t.Fatalf("typed material fields: %d %v", len(access), err)
	}
	if _, err := BuildSlice6DesiredMaterialAccessV2(p); err == nil {
		t.Fatal("material public hold bypassed")
	}
	if _, err := p.Slice6MaterialSocketForOwner("provider-runtime"); err == nil {
		t.Fatal("material socket public hold bypassed")
	}
	edge, _, owner, _, _, err := productProviderInstanceBoundaryFields(p.TrustEdges, p.Principals, p.Networks, p.TrustAnchors, "provider-runtime")
	if err != nil || edge.ID != ProductProviderContractEdgeID || owner.Name != "provider-runtime" {
		t.Fatalf("typed contract fields: %v", err)
	}
	if _, _, _, _, _, err := p.ProductProviderInstanceBoundary(owner.Name); err == nil {
		t.Fatal("contract public hold bypassed")
	}
}
