package phase6security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"slices"
	"testing"
)

func TestSlice6BreakGlassKeyAuthorityClosesActorIdentity(t *testing.T) {
	if ids := Slice6DesiredCredentialKeyIDs(); len(ids) != 12 || !slices.Contains(ids, "credential-guest-agent") ||
		slices.Contains(ids, "credential-browser-agent") {
		t.Fatal("credential identity inventory drift")
	}
	if len(Slice6DesiredBreakGlassIndependentKeyIDs()) != 5 {
		t.Fatal("independent key inventory drift")
	}
	key := func(id string) ed25519.PublicKey {
		seed := sha256.Sum256([]byte("unit-only/" + id))
		return ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	}
	credential, independent := map[string]ed25519.PublicKey{}, map[string]ed25519.PublicKey{}
	for _, id := range Slice6DesiredCredentialKeyIDs() {
		credential[id] = key(id)
	}
	for _, id := range Slice6DesiredBreakGlassIndependentKeyIDs() {
		independent[id] = key(id)
	}
	authority, err := BuildSlice6BreakGlassKeyAuthority(independent, credential)
	if err != nil || VerifySlice6BreakGlassKeyAuthority(authority) != nil {
		t.Fatalf("closed actor inventory: %v", err)
	}
	for _, mutate := range []func(*Slice6BreakGlassKeyAuthority){
		func(a *Slice6BreakGlassKeyAuthority) { a.Actors[0].Kind = "requester" },
		func(a *Slice6BreakGlassKeyAuthority) { a.Actors[0].Owner = "other" },
		func(a *Slice6BreakGlassKeyAuthority) { a.Actors[0].KeyID = "credential-guest-agent" },
		func(a *Slice6BreakGlassKeyAuthority) { a.Actors[0].PublicKeyDigest = a.ControllerPublicKeyDigest },
		func(a *Slice6BreakGlassKeyAuthority) { a.Actors = a.Actors[1:] },
	} {
		changed := authority
		changed.Actors = slices.Clone(authority.Actors)
		mutate(&changed)
		if VerifySlice6BreakGlassKeyAuthority(changed) == nil {
			t.Fatal("actor authority drift admitted")
		}
	}
	credential["credential-guest-agent"] = independent["break-glass-operator-a"]
	if _, err := BuildSlice6BreakGlassKeyAuthority(independent, credential); err == nil {
		t.Fatal("target/operator key alias admitted")
	}
}
