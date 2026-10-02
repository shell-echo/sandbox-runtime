package phase6profilebuilder

import (
	"context"
	"testing"
	"time"
)

func TestSlice6CandidateProfileRefusesSyntheticSourceChain(t *testing.T) {
	static, err := bindSlice6StaticDraft(testSlice6CertificateDraft(t))
	if err != nil {
		t.Fatal(err)
	}
	if candidate, err := FreezeSlice6CandidateProfile(context.Background(), KeyedStaticDraft{StaticDraft: static}, time.Now().UTC()); err == nil ||
		candidate.Profile.ProfileDigest != "" {
		t.Fatal("synthetic image, resource, CA, external or authority input admitted to final profile")
	}
	if (CandidateProfile{}).VerifySources(context.Background(), time.Now().UTC()) == nil {
		t.Fatal("empty candidate profile passed source recheck")
	}
}
