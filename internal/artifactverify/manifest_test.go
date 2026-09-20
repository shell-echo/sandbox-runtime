package artifactverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyDigestAndSignatureRequireImmutablePrivateFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "artifact")
	if err := os.WriteFile(path, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("artifact"))
	manifest := Manifest{Version: 1, Revision: "revision-1", Artifacts: []File{{Name: "runtime", Path: path, Digest: "sha256:" + hex.EncodeToString(digest[:]), Mode: 0o600}}}
	if err := Verify(manifest); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(manifest)
	signature := ed25519.Sign(private, document)
	if err := VerifySignature(manifest, public, signature); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(manifest); err == nil {
		t.Fatal("world-readable artifact was accepted")
	}
}

func TestVerifyFilesBindsManifestSignatureAndInputs(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "artifact")
	manifestPath := filepath.Join(directory, "manifest.json")
	signaturePath := filepath.Join(directory, "manifest.sig")
	publicPath := filepath.Join(directory, "manifest.pub")
	for _, path := range []string{artifactPath, manifestPath, signaturePath, publicPath} {
		if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("artifact"))
	manifest := Manifest{Version: 1, Revision: "revision-1", Artifacts: []File{{Name: "runtime", Path: artifactPath, Digest: "sha256:" + hex.EncodeToString(digest[:]), Mode: 0o600}}}
	document, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, ed25519.Sign(private, document), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, public, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFiles(manifestPath, signaturePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(document, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFiles(manifestPath, signaturePath, publicPath); err == nil {
		t.Fatal("accepted multiple JSON values")
	}
}
