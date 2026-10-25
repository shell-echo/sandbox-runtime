package phase6security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Explicitly exported synthetic declaration for cross-package source tests.
// No image, source capability, issuer or operator approval is established.
func TestExportControlSourceCandidateProfile(t *testing.T) {
	directory := os.Getenv("SANDBOX_RUNTIME_CONTROL_SOURCE_PROFILE_OUTPUT")
	if directory == "" {
		t.Skip("explicit synthetic declaration export")
	}
	info, err := os.Lstat(directory)
	if err != nil || !filepath.IsAbs(directory) || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatal("private output directory required")
	}
	p := testControlTrust(t)
	document, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReviewControlBootstrap(document); err != nil || p.Validate() == nil {
		t.Fatal("synthetic complete declaration must retain public hold", err)
	}
	f, err := os.OpenFile(filepath.Join(directory, "profile.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.Write(document)
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != len(document) {
		t.Fatal("fixture export failed", err, closeErr)
	}
}
