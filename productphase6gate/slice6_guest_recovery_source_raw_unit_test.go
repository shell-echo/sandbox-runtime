//go:build phase6slice6gate

package productphase6gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSlice6GuestOperatorRawSourceIsPrivateImmutableAndRunBound(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	runID := strings.Repeat("a", 32)
	run, err := root.newRun(runID)
	if err != nil {
		t.Fatal(err)
	}
	defer run.close()
	source := slice6GuestOperatorFormalSource{runID: runID, evidence: run,
		rawFiles: make(map[string]string)}
	for _, name := range slice6GuestOperatorSourceRawNames() {
		raw := []byte("same-run-observed-" + name + "\n")
		if name == "guest-source-settings.stdout" {
			raw = []byte("true|1791080000000000\n")
		}
		digest, err := run.writeV2GuestSourceRaw(name, raw)
		if err != nil || digest != slice6ReceiptSHA256(raw) {
			t.Fatalf("source raw %s unavailable: %v", name, err)
		}
		source.rawFiles[name] = digest
		info, err := os.Lstat(filepath.Join(rootPath, runID, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("source raw %s not private", name)
		}
		if _, err := run.writeV2GuestSourceRaw(name, raw); err == nil {
			t.Fatalf("source raw %s overwritten", name)
		}
	}
	source.rawProofDigest = slice6GuestOperatorRawProofDigest(source.rawFiles)
	if err := source.verifyRawFiles(); err != nil {
		t.Fatalf("same-run source raw not independently readable: %v", err)
	}
	if _, err := run.writeV2GuestSourceRaw("unlisted.raw", []byte("x")); err == nil {
		t.Fatal("unlisted raw name accepted")
	}
	wrongRun := source
	wrongRun.runID = strings.Repeat("b", 32)
	if wrongRun.verifyRawFiles() == nil {
		t.Fatal("another run accepted the source")
	}
	wrongDigest := source
	wrongDigest.rawProofDigest = slice6ReceiptSHA256([]byte("other"))
	if wrongDigest.verifyRawFiles() == nil {
		t.Fatal("raw inventory digest replacement accepted")
	}
	file, err := os.OpenFile(filepath.Join(rootPath, runID, "guest-source-hba.raw"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{'x'}, 0); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if source.verifyRawFiles() == nil {
		t.Fatal("same-inode raw tampering accepted")
	}
}
