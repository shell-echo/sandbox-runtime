package phase6security

import (
	"sort"
	"testing"
)

func TestBrokerBoundaryReturnsOnlyExactPolicyTarget(t *testing.T) {
	profile := validProfile()
	for _, expected := range []struct{ policy, caller, broker, network, address string }{
		{"browser-action-ingress-egress", "browser-action-ingress-runtime", "egress-broker-browser-action-ingress", "browser-action-ingress-internal", "10.26.0.3:8443"},
		{"gateway-egress", "gateway-runtime", "egress-broker-gateway", "gateway-internal", "10.27.0.3:8443"},
		{"product-egress", "product-runtime", "egress-broker-product", "product-internal", "10.28.0.3:8443"},
	} {
		edge, caller, broker, network, err := profile.BrokerBoundaryForPolicy(expected.policy)
		if err != nil || edge.TargetAddress != expected.address || caller.Name != expected.caller ||
			broker.Name != expected.broker || network.Name != expected.network {
			t.Fatalf("broker boundary %s = %#v, %s, %s, %s, %v", expected.policy, edge, caller.Name, broker.Name, network.Name, err)
		}
	}
	if _, _, _, _, err := profile.BrokerBoundaryForPolicy("other-policy"); err == nil {
		t.Fatal("unknown policy selected a broker")
	}
}

func TestBrokerBoundaryRejectsAddressAndEdgeDrift(t *testing.T) {
	mutateEdge := func(profile *Profile, id string, change func(*TrustEdge)) {
		for index := range profile.TrustEdges {
			if profile.TrustEdges[index].ID == id {
				change(&profile.TrustEdges[index])
				return
			}
		}
		t.Fatalf("missing fixture edge %s", id)
	}
	tests := map[string]func(*Profile){
		"missing target": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "" })
		},
		"wrong subnet": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "10.26.0.3:8443" })
		},
		"network address": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "10.27.0.0:8443" })
		},
		"broadcast": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "10.27.0.255:8443" })
		},
		"wrong port": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "10.27.0.3:9443" })
		},
		"wildcard": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "0.0.0.0:8443" })
		},
		"uplink address": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "172.20.8.3:8443" })
		},
		"public address": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "203.0.113.3:8443" })
		},
		"ipv6 address": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.TargetAddress = "[fd00::3]:8443" })
		},
		"unexpected route": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.RoutePath = "/egress" })
		},
		"wrong protocol": func(p *Profile) {
			mutateEdge(p, "egress-role-gateway", func(e *TrustEdge) { e.Protocol = "https" })
		},
		"nonbroker tls target": func(p *Profile) {
			mutateEdge(p, "gateway-browser-action-ingress", func(e *TrustEdge) { e.Protocol, e.RoutePath = "tls", "" })
		},
		"duplicate broker ingress": func(p *Profile) {
			for _, edge := range p.TrustEdges {
				if edge.ID == "egress-role-gateway" {
					edge.ID = "egress-role-gateway-extra"
					p.TrustEdges = append(p.TrustEdges, edge)
					sort.Slice(p.TrustEdges, func(i, j int) bool { return p.TrustEdges[i].ID < p.TrustEdges[j].ID })
					return
				}
			}
		},
		"shared network member": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "gateway-internal" {
					p.Networks[index].Principals = append(p.Networks[index].Principals, "guest-runtime")
					sort.Strings(p.Networks[index].Principals)
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
				t.Fatal("broker boundary drift accepted")
			}
		})
	}
}
