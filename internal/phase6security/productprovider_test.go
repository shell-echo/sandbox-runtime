package phase6security

import "testing"

func TestProductProviderBoundaryPinsContractListenerAndPrivateNetwork(t *testing.T) {
	profile := validProfile()
	edge, product, provider, server, client, err := profile.ProductProviderBoundary()
	if err != nil || edge.TargetAddress != "10.15.0.3:8444" || product.Name != "product-runtime" ||
		provider.Name != "provider-runtime" || server.ID != "internal-server-ca" || client.ID != "internal-client-ca" {
		t.Fatalf("valid Contract boundary: edge=%+v product=%s provider=%s roots=%s/%s err=%v",
			edge, product.Name, provider.Name, server.ID, client.ID, err)
	}
	for name, mutate := range map[string]func(*Profile){
		"wrong route": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == ProductProviderContractEdgeID {
					p.TrustEdges[index].RoutePath = "/private/terminal"
				}
			}
		},
		"wrong target network": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == ProductProviderContractEdgeID {
					p.TrustEdges[index].TargetAddress = "10.14.0.3:8444"
				}
			}
		},
		"wrong listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "provider-runtime" {
					p.Principals[index].Listeners[0].Port = 8449
				}
			}
		},
		"crossed caller": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == ProductProviderContractEdgeID {
					p.TrustEdges[index].From = "gateway-runtime"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validProfile()
			mutate(&candidate)
			candidate.ProfileDigest = candidate.Digest()
			if _, _, _, _, _, err := candidate.ProductProviderBoundary(); err == nil {
				t.Fatal("Contract trust-edge drift accepted")
			}
		})
	}
}
