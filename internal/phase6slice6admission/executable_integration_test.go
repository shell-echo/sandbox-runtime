//go:build integration

package phase6slice6admission

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

// This is a real current-source verifier reproducibility component, not a
// complete Slice 6 artifact/bundle or live-topology release gate.
func TestRealVerifierExecutableRebuild(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_VERIFIER_REBUILD") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_VERIFIER_REBUILD=1 for real clean-source verifier rebuild")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	revisionCommand := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD")
	revisionBytes, err := revisionCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.TrimSpace(string(revisionBytes))
	tree, err := desktopcandidate.SourceTreeDigest(root)
	if err != nil || verifySource(ctx, root, revision, tree) != nil {
		t.Fatal("real evidence source must be clean and committed")
	}
	environment, err := fixedBuildEnvironment()
	if err != nil || runtime.Version() != "go1.26.8" {
		t.Fatal("pinned verifier toolchain is unavailable")
	}
	actual := filepath.Join(t.TempDir(), "actual-verifier")
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly",
		"-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", actual,
		"./cmd/verify-product-phase6-slice6-evidence")
	build.Dir, build.Env = root, environment
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual verifier: %v: %.512s", err, output)
	}
	if err := verifyBinary(ctx, root, revision, tree, actual); err != nil {
		t.Fatalf("actual verifier does not match independently rebuilt E: %v", err)
	}
}
