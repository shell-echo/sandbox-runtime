//go:build phase6slice6gate

package productphase6gate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSlice6GuestRecoveryEFileInventoryIndependentReplayNoIssuer(t *testing.T) {
	rootPath := slice6ReceiptTestRoot(t)
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	id := strings.Repeat("a", 32)
	run, err := root.newRun(id)
	if err != nil {
		t.Fatal(err)
	}
	limits := slice6GuestRecoveryEFileLimits()
	if len(limits) != 119 {
		t.Fatalf("E exact file inventory changed: %d", len(limits))
	}
	for _, name := range slice6GuestRecoveryExpectedNames(limits, false) {
		if err := run.writeV2BoundedPrivateFile(name, []byte("component fixture\n"), limits[name], false); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	digest, err := run.captureGuestRecoveryEFileInventory()
	if err != nil || slice6VerifyGuestRecoveryEFileInventory(rootPath, id, digest) != nil {
		t.Fatal("independent exact retained-file replay failed")
	}
	if err := run.closeV2Incomplete(); err != nil ||
		slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) != nil {
		t.Fatal("retained incomplete evidence inventory failed independent replay")
	}
	if slice6VerifyGuestRecoveryEFileInventory(rootPath, id, digest) == nil {
		t.Fatal("incomplete evidence accepted by pre-binding verifier")
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id,
		"sha256:"+strings.Repeat("0", 64)) == nil {
		t.Fatal("wrong externally supplied inventory digest accepted")
	}
	extra := filepath.Join(rootPath, id, "unlisted.raw")
	if err := os.WriteFile(extra, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) == nil {
		t.Fatal("unexpected retained file accepted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) != nil {
		t.Fatal("exact inventory did not recover after scratch extra removal")
	}
	changed := filepath.Join(rootPath, id, slice6GuestRecoveryBeforeBFile)
	if err := os.WriteFile(changed, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) == nil {
		t.Fatal("same-inode content mutation accepted")
	}
	if err := os.WriteFile(changed, []byte("component fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) != nil {
		t.Fatal("restored content did not replay")
	}
	backup := filepath.Join(t.TempDir(), "original-e-file")
	if err := os.Rename(changed, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(changed, []byte("component fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) == nil {
		t.Fatal("same-content replacement inode accepted")
	}
	if err := os.Remove(changed); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, changed); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) == nil {
		t.Fatal("public retained file accepted")
	}
	if err := os.Chmod(changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) != nil {
		t.Fatal("restored owner-only mode did not replay")
	}
	if err := os.WriteFile(filepath.Join(rootPath, id, "incomplete.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6VerifyGuestRecoveryEIncompleteFileInventory(rootPath, id, digest) == nil {
		t.Fatal("noncanonical incomplete marker accepted")
	}
}
