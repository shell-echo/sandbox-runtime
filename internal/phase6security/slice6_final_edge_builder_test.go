package phase6security

import (
	"slices"
	"testing"
)

func TestBuildSlice6DesiredFinalTrustEdgesMatchesReviewedFinalProfile(t *testing.T) {
	final, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	edges, err := BuildSlice6DesiredFinalTrustEdges(final.Principals, final.External)
	if err != nil || len(edges) != len(final.TrustEdges) {
		t.Fatalf("final edge builder returned %d edges: %v", len(edges), err)
	}
	if !slices.Equal(edges, final.TrustEdges) {
		t.Fatal("final edge builder diverged from reviewed final external target")
	}
	changed := append([]ExternalService(nil), final.External...)
	changed[0].IdentityDigest = "sha256:deadbeef"
	if _, err := BuildSlice6DesiredFinalTrustEdges(final.Principals, changed); err == nil {
		t.Fatal("external identity drift accepted")
	}
	changed = append([]ExternalService(nil), final.External...)
	changed[0].Name = "unreviewed"
	if _, err := BuildSlice6DesiredFinalTrustEdges(final.Principals, changed); err == nil {
		t.Fatal("external substitution accepted")
	}
}
