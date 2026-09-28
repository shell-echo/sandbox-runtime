package phase6security

import "testing"

func TestBuildSlice6DesiredTrustEdgesUsesOnlyReviewedIPAMAndIdentity(t *testing.T) {
	fixture := validProfile() // Structural unit input only; not a deployable profile.
	edges, err := BuildSlice6DesiredTrustEdges(fixture.Principals, fixture.External)
	if err != nil || len(edges) != 117 {
		t.Fatalf("reviewed edge construction = %d, %v", len(edges), err)
	}
	foundLocal, foundExternal, foundUnix := false, false, false
	for _, edge := range edges {
		switch edge.ID {
		case "product-provider-contract":
			wanted, err := slice6PlannedLocalTarget(edge)
			foundLocal = err == nil && edge.TargetAddress == wanted && edge.Authentication == "mtls" &&
				edge.FromPrincipalDigest != "" && edge.ToPrincipalDigest != ""
		case "certificate-vault":
			foundExternal = edge.TargetAddress == "" && edge.CrossDomain && edge.ExternalIdentityDigest != "" &&
				edge.ToURI == "spiffe://sandbox-runtime.test/external/vault"
		case "certificate-controller-self":
			foundUnix = edge.Protocol == "unix" && edge.Authentication == "unix_peer_credentials" &&
				edge.FromPrincipalDigest == edge.ToPrincipalDigest
		}
	}
	if !foundLocal || !foundExternal || !foundUnix {
		t.Fatal("reviewed local, external or Unix trust edge drifted")
	}
	if _, err := BuildSlice6DesiredTrustEdges(fixture.Principals[1:], fixture.External); err == nil {
		t.Fatal("missing principal admitted")
	}
	wrong := append([]ExternalService(nil), fixture.External...)
	wrong[0].URI = "spiffe://sandbox-runtime.test/external/other"
	wrong[0].IdentityDigest = wrong[0].Digest()
	if _, err := BuildSlice6DesiredTrustEdges(fixture.Principals, wrong); err == nil {
		t.Fatal("external identity substitution admitted")
	}
}
