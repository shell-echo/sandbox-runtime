package orchestrator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupRunRootRestoresDirectoryPermissions(t *testing.T) {
	temporaryRoot := t.TempDir()
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix)
	if err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(runRoot, "runtime", "sandbox", "inputs")
	if err := os.MkdirAll(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inputs, "terminal-broker"), []byte("binary"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inputs, 0o555); err != nil {
		t.Fatal(err)
	}

	if err := cleanupRunRoot(temporaryRoot, runRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runRoot); !os.IsNotExist(err) {
		t.Fatalf("run root still exists: %v", err)
	}
}

func TestCleanupRunRootRejectsUnrecognizedTarget(t *testing.T) {
	temporaryRoot := t.TempDir()
	target := filepath.Join(temporaryRoot, "unrelated")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := cleanupRunRoot(temporaryRoot, target); err == nil {
		t.Fatal("cleanup accepted an unrecognized target")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("rejected target was changed: %v", err)
	}
}
