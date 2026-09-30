package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6FinalTrustAnchorTemplatesMatchReviewedProfile(t *testing.T) {
	final, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	templates := Slice6DesiredFinalTrustAnchorTemplates()
	if len(templates) != 5 || len(final.TrustAnchors) != len(templates) {
		t.Fatal("reviewed final CA inventory drifted")
	}
	for index, template := range templates {
		actual := final.TrustAnchors[index]
		if template.BundleDigest != "" || template.ID != actual.ID || template.Purpose != actual.Purpose ||
			template.TrustDomain != actual.TrustDomain || template.ArtifactID != actual.ArtifactID ||
			template.StorageID != actual.StorageID || template.TargetPath != actual.TargetPath ||
			template.WriterAuthority != actual.WriterAuthority || template.OwnerUID != actual.OwnerUID ||
			template.OwnerGID != actual.OwnerGID || !slices.Equal(template.Consumers, actual.Consumers) {
			t.Fatalf("CA template %s drifted from final reviewed profile", template.ID)
		}
	}
	templates[0].Consumers[0] = "wrong-role"
	fresh := Slice6DesiredFinalTrustAnchorTemplates()
	if fresh[0].Consumers[0] == "wrong-role" {
		t.Fatal("caller mutated reviewed CA consumer inventory")
	}
}
