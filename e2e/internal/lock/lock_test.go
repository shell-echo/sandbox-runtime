package lock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParentProviderCheckoutMatchesLock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
}

func TestProviderDocumentationPathIsNarrow(t *testing.T) {
	for path, want := range map[string]bool{
		"README.md":             true,
		"docs/STATUS.md":        true,
		"docs/plan/p2.5.md":     true,
		"README.md/embedded.go": false,
		"cmd/README.md":         false,
		"provider/code.go":      false,
	} {
		if got := providerDocumentationPath(path); got != want {
			t.Errorf("providerDocumentationPath(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestProviderChangePathAllowsOnlyHarnessAndDocumentation(t *testing.T) {
	for path, want := range map[string]bool{
		"README.md":                           true,
		"docs/STATUS.md":                      true,
		"e2e/cmd/caller/main.go":              true,
		"e2e/internal/lock/lock.go":           true,
		".github/workflows/reference-e2e.yml": true,
		"cmd/serve.go":                        false,
		"provider/code.go":                    false,
		"e2e/../provider/code.go":             false,
	} {
		if got := providerChangePath(path); got != want {
			t.Errorf("providerChangePath(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestHarnessRevisionRequiresCleanCommit(t *testing.T) {
	root := t.TempDir()
	runTestGit(t, root, "init", "-q")
	tracked := filepath.Join(root, "tracked.txt")
	if err := os.WriteFile(tracked, []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, root, "add", "tracked.txt")
	runTestGit(t, root, "-c", "user.name=E2E Test", "-c", "user.email=e2e-test@example.invalid", "commit", "-qm", "initial")

	revision, err := HarnessRevision(root)
	if err != nil || !commitPattern.MatchString(revision) {
		t.Fatalf("HarnessRevision() = %q, %v", revision, err)
	}
	if err := os.WriteFile(tracked, []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HarnessRevision(root); !errors.Is(err, errDirtyHarness) {
		t.Fatalf("dirty HarnessRevision() error = %v", err)
	}
}

func runTestGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}
