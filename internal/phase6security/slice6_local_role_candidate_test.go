package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSlice6LocalRoleArchiveDigestRejectsMissingPublicAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "candidate.oci.tar")
	if _, _, err := digestSlice6LocalRoleArchive(path); err == nil {
		t.Fatal("missing candidate archive admitted")
	}
	document := []byte("private candidate archive bytes")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(document)
	digest, size, err := digestSlice6LocalRoleArchive(path)
	if err != nil || digest != "sha256:"+hex.EncodeToString(want[:]) || size != int64(len(document)) {
		t.Fatalf("private archive digest = %s, %d, %v", digest, size, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := digestSlice6LocalRoleArchive(path); err == nil {
		t.Fatal("public candidate archive admitted")
	}
	link := filepath.Join(filepath.Dir(path), "candidate-link.oci.tar")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := digestSlice6LocalRoleArchive(link); err == nil {
		t.Fatal("symlinked candidate archive admitted")
	}
}
