//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// verifySlice6ControllerKeyHandoff reopens the private keys that will be
// delivered through sealed startup FDs. A Profile source check alone does not
// prove that the later FD payload still matches the frozen public digests.
func verifySlice6ControllerKeyHandoff(profile phase6security.Profile, paths map[string]string) error {
	expected := map[string]string{
		profile.CertificateController.ResponseKeyID:                     profile.CertificateController.ResponsePublicKeyDigest,
		profile.CertificateController.ManagedRequestKeyID:               profile.CertificateController.ManagedRequestKeyDigest,
		profile.CertificateController.CredentialController.RequestKeyID: profile.CertificateController.CredentialController.RequestKeyDigest,
	}
	for _, binding := range profile.TLSAgentBindings {
		if _, duplicate := expected[binding.AgentRequestKeyID]; duplicate {
			return errors.New("duplicate controller key binding")
		}
		expected[binding.AgentRequestKeyID] = binding.AgentRequestKeyDigest
	}
	for _, binding := range profile.PostgresClientAgents {
		if _, duplicate := expected[binding.AgentRequestKeyID]; duplicate {
			return errors.New("duplicate postgres key binding")
		}
		expected[binding.AgentRequestKeyID] = binding.AgentRequestKeyDigest
	}
	if len(expected) != len(phase6security.Slice6DesiredCertificateKeyIDs()) || len(paths) != len(expected) {
		return errors.New("incomplete controller key inventory")
	}
	seenPaths := make(map[string]bool, len(paths))
	for _, id := range phase6security.Slice6DesiredCertificateKeyIDs() {
		path, ok := paths[id]
		if !ok || !filepath.IsAbs(path) || seenPaths[path] {
			return fmt.Errorf("missing or aliased controller key %q", id)
		}
		seenPaths[path] = true
		metadata, err := os.Lstat(path)
		if err != nil || !metadata.Mode().IsRegular() || metadata.Mode().Perm() != 0o600 || metadata.Size() != ed25519.PrivateKeySize {
			return fmt.Errorf("unsafe controller key file %q", id)
		}
		private, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unreadable controller key %q: %w", id, err)
		}
		if len(private) != ed25519.PrivateKeySize {
			clear(private)
			return fmt.Errorf("wrong controller key size %q", id)
		}
		derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
		if !bytes.Equal(derived, private) {
			clear(derived)
			clear(private)
			return fmt.Errorf("inconsistent controller key encoding %q", id)
		}
		clear(derived)
		public := ed25519.PrivateKey(private).Public().(ed25519.PublicKey)
		got := phase6security.TLSAgentRequestPublicKeyDigest(public)
		if id == profile.CertificateController.ResponseKeyID {
			got = phase6security.CertificateControllerPublicKeyDigest(public)
		}
		clear(private)
		if got != expected[id] {
			return fmt.Errorf("controller key digest drift %q", id)
		}
	}
	return nil
}

func TestSlice6ControllerKeyHandoffRejectsDrift(t *testing.T) {
	const responseID = "certificate-controller-response"
	const managedID = "request-certificate-controller-self"
	const credentialID = "request-credential-controller-managed"
	directory := t.TempDir()
	profile := phase6security.Profile{CertificateController: phase6security.CertificateControllerAuthority{
		ResponseKeyID: responseID, ManagedRequestKeyID: managedID,
		CredentialController: phase6security.CredentialControllerManagedAuthority{RequestKeyID: credentialID},
	}}
	paths := make(map[string]string)
	for _, id := range phase6security.Slice6DesiredCertificateKeyIDs() {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, id+".key")
		if err := os.WriteFile(path, private, 0o600); err != nil {
			t.Fatal(err)
		}
		clear(private)
		paths[id] = path
		switch id {
		case responseID:
			profile.CertificateController.ResponsePublicKeyDigest = phase6security.CertificateControllerPublicKeyDigest(public)
		case managedID:
			profile.CertificateController.ManagedRequestKeyDigest = phase6security.TLSAgentRequestPublicKeyDigest(public)
		case credentialID:
			profile.CertificateController.CredentialController.RequestKeyDigest = phase6security.TLSAgentRequestPublicKeyDigest(public)
		default:
			profile.TLSAgentBindings = append(profile.TLSAgentBindings, phase6security.TLSAgentBinding{
				AgentRequestKeyID: id, AgentRequestKeyDigest: phase6security.TLSAgentRequestPublicKeyDigest(public),
			})
		}
	}
	if err := verifySlice6ControllerKeyHandoff(profile, paths); err != nil {
		t.Fatalf("unchanged private-key handoff rejected: %v", err)
	}
	copyPaths := func() map[string]string {
		copy := make(map[string]string, len(paths))
		for id, path := range paths {
			copy[id] = path
		}
		return copy
	}
	missing := copyPaths()
	delete(missing, managedID)
	if verifySlice6ControllerKeyHandoff(profile, missing) == nil {
		t.Fatal("missing managed key accepted")
	}
	aliased := copyPaths()
	aliased[managedID] = paths[credentialID]
	if verifySlice6ControllerKeyHandoff(profile, aliased) == nil {
		t.Fatal("aliased private key path accepted")
	}
	extra := copyPaths()
	extra["unreviewed"] = paths[managedID]
	if verifySlice6ControllerKeyHandoff(profile, extra) == nil {
		t.Fatal("extra key accepted")
	}
	if err := os.Chmod(paths[responseID], 0o644); err != nil {
		t.Fatal(err)
	}
	if verifySlice6ControllerKeyHandoff(profile, paths) == nil {
		t.Fatal("world-readable response key accepted")
	}
	if err := os.Chmod(paths[responseID], 0o600); err != nil {
		t.Fatal(err)
	}
	mutated, err := os.ReadFile(paths[responseID])
	if err != nil {
		t.Fatal(err)
	}
	mutated[0] ^= 1
	if err := os.WriteFile(paths[responseID], mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(mutated)
	if verifySlice6ControllerKeyHandoff(profile, paths) == nil {
		t.Fatal("response key digest drift accepted")
	}
	symlink := filepath.Join(directory, "symlink.key")
	if err := os.Symlink(paths[credentialID], symlink); err != nil {
		t.Fatal(err)
	}
	linked := copyPaths()
	linked[credentialID] = symlink
	if verifySlice6ControllerKeyHandoff(profile, linked) == nil {
		t.Fatal("symlink private key accepted")
	}
}
