package phase6tls

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestBrowserActionIngressServerRejectsProviderEdgeSelection(t *testing.T) {
	for _, edge := range []string{"", phase6security.GatewayProviderPrivateEdgeID,
		phase6security.BrowserActionIngressProviderPrivateEdgeID, phase6security.ProductProviderBrowserContractEdgeID} {
		if config, probe, peer, guard, err := BrowserActionIngressServer(phase6security.Profile{}, ProviderServerAuthority{EdgeID: edge}); err == nil || config != nil || probe != nil || peer != "" || guard != nil {
			t.Fatalf("action ingress accepted a Provider listener edge %q", edge)
		}
	}
}
