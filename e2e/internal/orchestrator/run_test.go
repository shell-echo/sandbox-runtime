package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalImageIDReference(t *testing.T) {
	imageID := "sha256:" + strings.Repeat("a", 64)
	gotReference, gotDigest, err := localImageIDReference("example.invalid/reference:local", imageID)
	if err != nil {
		t.Fatal(err)
	}
	if gotReference != "example.invalid/reference:local@"+imageID {
		t.Fatalf("reference = %q", gotReference)
	}
	if gotDigest != imageID {
		t.Fatalf("digest = %q, want %q", gotDigest, imageID)
	}
}

func TestLocalImageIDReferenceRejectsInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		name, tag, imageID string
	}{
		{name: "missing digest", tag: "example.invalid/reference:local", imageID: ""},
		{name: "wrong digest length", tag: "example.invalid/reference:local", imageID: "sha256:" + strings.Repeat("a", 63)},
		{name: "non-hex digest", tag: "example.invalid/reference:local", imageID: "sha256:" + strings.Repeat("g", 64)},
		{name: "empty tag", tag: "", imageID: "sha256:" + strings.Repeat("a", 64)},
		{name: "tag with digest", tag: "example.invalid/reference:local@sha256:" + strings.Repeat("a", 64), imageID: "sha256:" + strings.Repeat("a", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := localImageIDReference(test.tag, test.imageID); err == nil {
				t.Fatal("accepted invalid local image identity")
			}
		})
	}
}

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
