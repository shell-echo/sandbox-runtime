package phase6slice6admission

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

func TestVerifierBinaryMatchesCleanEvidenceSource(t *testing.T) {
	if runtime.Version() != "go1.26.8" {
		t.Skip("requires pinned Go 1.26.8 toolchain")
	}
	root := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runGit := func(args ...string) string {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", root}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %.512s", args, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	write := func(path, contents string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(message string) (string, string) {
		t.Helper()
		runGit("add", "-A")
		runGit("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", message)
		revision := runGit("rev-parse", "HEAD")
		tree, err := desktopcandidate.SourceTreeDigest(root)
		if err != nil {
			t.Fatal(err)
		}
		return revision, tree
	}
	runGit("init", "-q")
	write("go.mod", "module example.test/verifier\n\ngo 1.26\n")
	write("go.sum", "")
	write("cmd/verify-product-phase6-slice6-evidence/main.go", "package main\nvar version = \"one\"\nfunc main() { println(version) }\n")
	revision, tree := commit("verifier")
	environment, err := fixedBuildEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(t.TempDir(), "actual-verifier")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-trimpath",
		"-buildvcs=false", "-ldflags=-buildid=", "-o", actual,
		"./cmd/verify-product-phase6-slice6-evidence")
	build.Dir, build.Env = root, environment
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build exact executable fixture: %v: %.512s", err, output)
	}
	if err := verifyBinary(context.Background(), root, revision, tree, actual); err != nil {
		t.Fatalf("real same-recipe executable rejected: %v", err)
	}
	write("README.md", "documentation advanced without command source change\n")
	docRevision, docTree := commit("documentation")
	if err := verifyBinary(context.Background(), root, docRevision, docTree, actual); err != nil {
		t.Fatalf("documentation-only E advancement changed binary: %v", err)
	}
	changedBytes, err := os.ReadFile(actual)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "tampered-verifier")
	if err := os.WriteFile(tampered, append(changedBytes, byte(0)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinary(context.Background(), root, docRevision, docTree, tampered); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("changed executable bytes admitted: %v", err)
	}
	wrongFlags := filepath.Join(t.TempDir(), "wrong-flags")
	flagsBuild := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-trimpath",
		"-buildvcs=false", "-ldflags=-buildid= -X main.version=wrong", "-o", wrongFlags,
		"./cmd/verify-product-phase6-slice6-evidence")
	flagsBuild.Dir, flagsBuild.Env = root, environment
	if output, err := flagsBuild.CombinedOutput(); err != nil {
		t.Fatalf("build wrong-flags fixture: %v: %.512s", err, output)
	}
	if err := verifyBinary(context.Background(), root, docRevision, docTree, wrongFlags); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("changed linker parameters admitted: %v", err)
	}
	if err := verifyBinary(context.Background(), root, revision, tree, actual); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("old E revision mislabeled after doc commit: %v", err)
	}
	write("cmd/verify-product-phase6-slice6-evidence/main.go", "package main\nvar version = \"two\"\nfunc main() { println(version) }\n")
	changedRevision, changedTree := commit("changed command")
	if err := verifyBinary(context.Background(), root, changedRevision, changedTree, actual); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("changed verifier command accepted old executable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "dirty.txt"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinary(context.Background(), root, changedRevision, changedTree, actual); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("dirty E source accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "dirty.txt")); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyBinary(canceled, root, changedRevision, changedTree, actual); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("canceled verifier rebuild admitted: %v", err)
	}
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	if err := verifyBinary(expired, root, changedRevision, changedTree, actual); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("expired verifier rebuild admitted: %v", err)
	}
	write("go.mod", "module example.test/verifier\n\ngo 1.26\n\nreplace example.test/dependency => ../local\n")
	replacedRevision, replacedTree := commit("unapproved local replace")
	if err := verifyBinary(context.Background(), root, replacedRevision, replacedTree, actual); !errors.Is(err, ErrInvalidAdmission) {
		t.Fatalf("local module replacement admitted: %v", err)
	}
}
