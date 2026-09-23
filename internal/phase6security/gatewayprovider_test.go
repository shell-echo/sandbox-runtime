package phase6security

import "testing"

func TestGatewayProviderBoundaryPinsPrivateOriginAndBothIdentities(t *testing.T) {
	profile := validProfile()
	origin := "wss://10.14.0.3:8448/private/terminal"
	edge, gateway, provider, server, client, err := profile.GatewayProviderBoundary(origin)
	if err != nil || edge.ID != GatewayProviderPrivateEdgeID || gateway.Name != "gateway-runtime" ||
		provider.Name != "provider-runtime" || server.ID != "internal-server-ca" || client.ID != "internal-client-ca" {
		t.Fatalf("valid private boundary: edge=%+v gateway=%s provider=%s roots=%s/%s err=%v",
			edge, gateway.Name, provider.Name, server.ID, client.ID, err)
	}
	for _, candidate := range []string{
		"wss://10.14.0.4:8448/private/terminal", "wss://10.14.0.3:8444/private/terminal",
		"wss://10.14.0.3:8448/", "wss://10.14.0.3:8448/private/browser",
		"wss://provider.sandbox-runtime.test:8448/private/terminal", "ws://10.14.0.3:8448/private/terminal",
		"wss://10.14.0.3:8448/private/terminal?role=admin",
	} {
		if _, _, _, _, _, err := profile.GatewayProviderBoundary(candidate); err == nil {
			t.Fatalf("unbound Provider origin accepted: %s", candidate)
		}
	}
	for name, mutate := range map[string]func(*Profile){
		"wrong target network": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == GatewayProviderPrivateEdgeID {
					p.TrustEdges[index].TargetAddress = "10.13.0.3:8448"
				}
			}
		},
		"missing private listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "provider-runtime" {
					p.Principals[index].Listeners = nil
				}
			}
		},
		"cross-principal edge": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == GatewayProviderPrivateEdgeID {
					p.TrustEdges[index].From = "product-runtime"
				}
			}
		},
		"unbound route": func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == GatewayProviderPrivateEdgeID {
					p.TrustEdges[index].RoutePath = "/private/browser"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validProfile()
			mutate(&candidate)
			candidate.ProfileDigest = candidate.Digest()
			if _, _, _, _, _, err := candidate.GatewayProviderBoundary(origin); err == nil {
				t.Fatal("private Gateway→Provider drift accepted")
			}
		})
	}
}
