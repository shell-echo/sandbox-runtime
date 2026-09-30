package phase6security

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"
)

func TestSlice6CertificateBindingsUseDistinctRealPublicKeys(t *testing.T) {
	keys := make(map[string]ed25519.PublicKey)
	for _, id := range Slice6DesiredCertificateKeyIDs() {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = public
	}
	profile := validProfile()
	bound, err := BuildSlice6DesiredCertificateBindings(profile.Principals, keys)
	if err != nil || len(bound.Ordinary)+len(bound.Postgres) != len(slice6ApprovedTLSAgentSubjects) ||
		len(bound.Postgres) != 9 || bound.Controller.ResponsePublicKeyDigest !=
		CertificateControllerPublicKeyDigest(keys[slice6ControllerResponseKey]) {
		t.Fatalf("certificate binding inventory failed: %v", err)
	}
	if !slices.IsSortedFunc(bound.Ordinary, func(a, b TLSAgentBinding) int {
		if a.AgentDeployment < b.AgentDeployment {
			return -1
		}
		if a.AgentDeployment > b.AgentDeployment {
			return 1
		}
		return 0
	}) {
		t.Fatal("ordinary agents not sorted")
	}
	for _, binding := range bound.Ordinary {
		if binding.AgentRequestKeyDigest != TLSAgentRequestPublicKeyDigest(keys[binding.AgentRequestKeyID]) {
			t.Fatal("agent request key not bound")
		}
	}
	for _, binding := range bound.Postgres {
		if binding.AgentRequestKeyDigest != TLSAgentRequestPublicKeyDigest(keys[binding.AgentRequestKeyID]) ||
			binding.IssuerAnchorID != "postgres-client-ca" {
			t.Fatal("postgres-purpose agent not bound")
		}
	}
	missing := make(map[string]ed25519.PublicKey, len(keys)-1)
	for id, key := range keys {
		if id != slice6CredentialManagedKey {
			missing[id] = key
		}
	}
	if _, err := BuildSlice6DesiredCertificateBindings(profile.Principals, missing); err == nil {
		t.Fatal("missing credential-controller key admitted")
	}
	shared := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		shared[id] = key
	}
	shared[slice6ControllerManagedKey] = shared[slice6ControllerResponseKey]
	if _, err := BuildSlice6DesiredCertificateBindings(profile.Principals, shared); err == nil {
		t.Fatal("shared response/request key admitted")
	}
}
