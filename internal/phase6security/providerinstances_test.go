package phase6security

import "testing"

func TestProviderInstanceBoundariesSeparateBrowserActionIngress(t *testing.T) {
	profile := validProfile()
	for _, item := range []struct {
		provider, contractID, privateID, route string
	}{
		{"provider-runtime", ProductProviderContractEdgeID, GatewayProviderPrivateEdgeID, "/private/terminal"},
		{"provider-desktop-runtime", ProductProviderDesktopContractEdgeID, GatewayProviderDesktopPrivateEdgeID, "/desktop"},
	} {
		t.Run(item.provider, func(t *testing.T) {
			contract, product, provider, serverRoot, clientRoot, err := profile.ProductProviderInstanceBoundary(item.provider)
			if err != nil || contract.ID != item.contractID || product.Name != "product-runtime" || provider.Name != item.provider ||
				serverRoot.ID != contract.ServerAnchorID || clientRoot.ID != contract.ClientAnchorID ||
				serverRoot.ID == clientRoot.ID {
				t.Fatalf("Contract instance boundary: edge=%+v product=%s provider=%s err=%v", contract, product.Name, provider.Name, err)
			}
			var privateOrigin string
			for _, edge := range profile.TrustEdges {
				if edge.ID == item.privateID {
					privateOrigin = "wss://" + edge.TargetAddress + item.route
				}
			}
			private, gateway, privateProvider, privateServerRoot, privateClientRoot, err := profile.GatewayProviderInstanceBoundary(item.provider, privateOrigin)
			if err != nil || private.ID != item.privateID || gateway.Name != "gateway-runtime" || privateProvider.Name != item.provider ||
				privateServerRoot.ID != private.ServerAnchorID || privateClientRoot.ID != private.ClientAnchorID ||
				privateServerRoot.ID == privateClientRoot.ID {
				t.Fatalf("private instance boundary: edge=%+v gateway=%s provider=%s err=%v", private, gateway.Name, privateProvider.Name, err)
			}
			for _, wrong := range []string{
				"wss://" + contract.TargetAddress + item.route,
				"wss://" + private.TargetAddress + "/private/terminal/alias",
				"wss://" + private.TargetAddress + "/executor",
			} {
				if _, _, _, _, _, err := profile.GatewayProviderInstanceBoundary(item.provider, wrong); err == nil {
					t.Fatalf("private boundary accepted substituted origin %q", wrong)
				}
			}
		})
	}
	if _, _, _, _, _, err := profile.GatewayProviderInstanceBoundary("provider-browser-runtime", "wss://10.25.0.3:8448/private/browser"); err == nil {
		t.Fatal("Gateway directly inherited Browser Provider private authority")
	}
	browserContract, _, browserProvider, _, _, err := profile.ProductProviderInstanceBoundary("provider-browser-runtime")
	if err != nil || browserContract.ID != ProductProviderBrowserContractEdgeID || browserProvider.Name != "provider-browser-runtime" {
		t.Fatalf("Browser Contract boundary: edge=%+v provider=%s err=%v", browserContract, browserProvider.Name, err)
	}
	gatewayIngress, gateway, ingress, _, _, err := profile.GatewayBrowserActionIngressBoundary("wss://10.21.0.3:8452/browser/action")
	if err != nil || gatewayIngress.ID != GatewayBrowserActionIngressEdgeID || gateway.Name != "gateway-runtime" || ingress.Name != "browser-action-ingress-runtime" {
		t.Fatalf("Gateway action ingress boundary: edge=%+v gateway=%s ingress=%s err=%v", gatewayIngress, gateway.Name, ingress.Name, err)
	}
	ingressPrivate, ingressCaller, provider, _, _, err := profile.BrowserActionIngressProviderBoundary("wss://10.25.0.3:8448/private/browser")
	if err != nil || ingressPrivate.ID != BrowserActionIngressProviderPrivateEdgeID || ingressCaller.Name != ingress.Name || provider.Name != browserProvider.Name {
		t.Fatalf("ingress Provider private boundary: edge=%+v ingress=%s provider=%s err=%v", ingressPrivate, ingressCaller.Name, provider.Name, err)
	}
	if _, _, _, _, _, err := profile.ProductProviderInstanceBoundary("provider-any-runtime"); err == nil {
		t.Fatal("unknown Provider instance inherited Contract authority")
	}
	if _, _, _, _, _, err := profile.GatewayProviderInstanceBoundary("provider-any-runtime", "wss://127.0.0.1:8448/desktop"); err == nil {
		t.Fatal("unknown Provider instance inherited private authority")
	}
}
