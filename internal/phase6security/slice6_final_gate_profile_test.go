package phase6security

import "testing"

func TestSlice6FinalGateProfileRejectsEarlierCandidates(t *testing.T) {
	draft := reviewedSlice6ImageFixture(t)
	if VerifySlice6FinalGateProfile(draft) == nil {
		t.Fatal("historical 17/12 draft admitted to the live gate")
	}
	intermediate, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatalf("intermediate candidate: %v", err)
	}
	if VerifySlice6FinalGateProfile(intermediate) == nil {
		t.Fatal("historical 28/33 candidate admitted to the live gate")
	}
	final, err := BuildSlice6FinalExternalProfileTarget(draft)
	if err != nil {
		t.Fatalf("final static candidate: %v", err)
	}
	if err := VerifySlice6FinalGateProfile(final); err != nil {
		t.Fatalf("final static candidate rejected: %v", err)
	}
	final.PostgresServerAuth.HBADigest = testDigest("wrong-hba")
	final.ProfileDigest = final.Digest()
	if VerifySlice6FinalGateProfile(final) == nil {
		t.Fatal("self-consistent profile with wrong HBA bytes admitted")
	}
}
