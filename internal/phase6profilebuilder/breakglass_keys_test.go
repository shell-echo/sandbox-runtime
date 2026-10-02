package phase6profilebuilder

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testSlice6BreakGlassKeyPaths(t *testing.T) (map[string]string, map[string]string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	credential, independent := make(map[string]string), make(map[string]string)
	write := func(id string, publicOnly bool) string {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, id)
		payload, mode := []byte(private), os.FileMode(0o600)
		if publicOnly {
			payload, mode = []byte(public), 0o400
		}
		if err := os.WriteFile(path, payload, mode); err != nil {
			t.Fatal(err)
		}
		clear(private)
		return path
	}
	for _, id := range phase6security.Slice6DesiredCredentialKeyIDs() {
		credential[id] = write(id, false)
	}
	for _, id := range phase6security.Slice6DesiredBreakGlassIndependentKeyIDs() {
		independent[id] = write(id, id != "break-glass-controller-signer")
	}
	return credential, independent
}

func TestSlice6BreakGlassKeySupplyProjectsExistingCredentialIdentity(t *testing.T) {
	credential, independent := testSlice6BreakGlassKeyPaths(t)
	supply, err := LoadSlice6BreakGlassKeySupply(credential, independent)
	if err != nil || supply.VerifySources() != nil {
		t.Fatalf("closed source rejected: %v", err)
	}
	authority, err := phase6security.BuildSlice6BreakGlassKeyAuthority(supply.independentKeys, supply.credentialKeys)
	if err != nil || len(authority.Actors) != 11 {
		t.Fatalf("actor projection: %v", err)
	}
	for _, actor := range authority.Actors {
		if actor.Kind != "target" {
			continue
		}
		if actor.PublicKeyDigest != phase6security.Slice6BreakGlassPublicKeyDigest(supply.credentialKeys[actor.KeyID]) {
			t.Fatal("target actor does not use existing credential identity")
		}
	}
	actorPath := independent["break-glass-approver-a"]
	if err := os.Chmod(actorPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if supply.VerifySources() == nil {
		t.Fatal("relaxed external public source admitted")
	}
	if err := os.Chmod(actorPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(actorPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actorPath, bytes.Repeat([]byte{9}, ed25519.PublicKeySize), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(actorPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if supply.VerifySources() == nil {
		t.Fatal("post-freeze public source mutation admitted")
	}
}

func TestSlice6BreakGlassKeySupplyRejectsMissingAliasAndPrivateActorSource(t *testing.T) {
	credential, independent := testSlice6BreakGlassKeyPaths(t)
	missing := make(map[string]string, len(credential))
	for id, path := range credential {
		missing[id] = path
	}
	delete(missing, "credential-guest-agent")
	if _, err := LoadSlice6BreakGlassKeySupply(missing, independent); err == nil {
		t.Fatal("missing target key admitted")
	}
	aliased := make(map[string]string, len(independent))
	for id, path := range independent {
		aliased[id] = path
	}
	aliased["break-glass-approver-b"] = aliased["break-glass-approver-a"]
	if _, err := LoadSlice6BreakGlassKeySupply(credential, aliased); err == nil {
		t.Fatal("alias admitted")
	}
	privateActor := make(map[string]string, len(independent))
	for id, path := range independent {
		privateActor[id] = path
	}
	privateActor["break-glass-requester-a"] = credential["credential-guest-agent"]
	if _, err := LoadSlice6BreakGlassKeySupply(credential, privateActor); err == nil {
		t.Fatal("private requester source admitted")
	}
}
