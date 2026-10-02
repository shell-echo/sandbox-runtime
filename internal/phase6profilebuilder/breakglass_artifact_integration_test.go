//go:build integration

package phase6profilebuilder

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestSlice6BreakGlassArtifactCleanSourceRebuild(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BREAK_GLASS_ARTIFACT_INTEGRATION") != "1" {
		t.Skip("explicit clean-source build only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	root := os.Getenv("SANDBOX_RUNTIME_BREAK_GLASS_ARTIFACT_SOURCE_ROOT")
	if !cleanAbsolute(root) {
		t.Fatal("clean source root required")
	}
	revisionOutput, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal("source revision unavailable")
	}
	tree, err := desktopcandidate.SourceTreeDigest(root)
	if err != nil {
		t.Fatal("source tree unavailable")
	}
	private := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(private, "phase6-break-glass-operator")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binary, "./cmd/phase6-break-glass-operator")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("source build: %v: %.256s", err, output)
	}
	if err := os.Chmod(binary, 0o555); err != nil {
		t.Fatal(err)
	}
	images := ImageSupply{RuntimeRevision: strings.TrimSpace(string(revisionOutput)), RuntimeTreeDigest: tree,
		Platform: "linux/arm64/v8", sourceRoot: root}
	artifact, err := LoadSlice6BreakGlassExecutableArtifact(ctx, images, binary)
	if err != nil || artifact.BinaryDigest == "" || artifact.BinaryBytes < 1 ||
		artifact.CarrierIndexDigest != phase6security.Slice6BreakGlassCarrierIndexDigest ||
		verifySlice6OperatorBinarySource(binary, artifact) != nil {
		t.Fatalf("source-bound operator artifact rejected: %v", err)
	}
	if err := os.Chmod(binary, 0o600); err != nil {
		t.Fatal(err)
	}
	modified, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	modified[len(modified)-1] ^= 1
	if err := os.WriteFile(binary, modified, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(modified)
	if err := os.Chmod(binary, 0o555); err != nil {
		t.Fatal(err)
	}
	if verifySlice6OperatorBinarySource(binary, artifact) == nil {
		t.Fatal("mutated operator executable source admitted")
	}
	if err := os.Chmod(binary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, bytes.Repeat([]byte{0}, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(binary, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSlice6OperatorBinary(binary); err == nil {
		t.Fatal("non-ELF operator admitted")
	}
}
