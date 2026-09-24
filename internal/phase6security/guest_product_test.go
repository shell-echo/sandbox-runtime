package phase6security

import "testing"

func TestGuestProductBoundaryUsesOnlyPrivateControlEdge(t *testing.T) {
	profile := validProfile()
	var origin string
	for _, edge := range profile.TrustEdges {
		if edge.ID == "guest-product" {
			origin = "wss://" + edge.TargetAddress + edge.RoutePath
		}
	}
	edge, guest, product, serverAnchor, clientAnchor, err := profile.GuestProductBoundary(origin)
	if err != nil || edge.ID != "guest-product" || guest.Name != "guest-runtime" ||
		product.Name != "product-runtime" || serverAnchor.ID != edge.ServerAnchorID ||
		clientAnchor.ID != edge.ClientAnchorID {
		t.Fatalf("Guest Product boundary mismatch: %v", err)
	}
	for _, wrong := range []string{"wss://" + edge.TargetAddress + "/v1", origin + "/agent", ""} {
		if _, _, _, _, _, err := profile.GuestProductBoundary(wrong); err == nil {
			t.Fatalf("Guest accepted non-control endpoint %q", wrong)
		}
	}
}
