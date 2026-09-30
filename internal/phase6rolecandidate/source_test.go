package phase6rolecandidate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectSourceInputsRequiresReviewedCleanBuild(t *testing.T) {
	root := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("profiles/phase6/local-role/Dockerfile", "FROM alpine@"+baseImageDigest+" AS role-base\nUSER 65532:65532\n")
	write("profiles/phase6/local-role/build.sh", "#!/bin/sh\nexit 0\n")
	write("go.mod", "module example.test/phase6\n\ngo 1.26\n")
	write("go.sum", "example.test/dependency v1.0.0 h1:fixture\n")
	write("main.go", "package main\nfunc main() {}\n")
	for _, args := range [][]string{
		{"init", "-q"}, {"add", "."},
		{"-c", "user.name=Phase6Test", "-c", "user.email=phase6@example.test", "commit", "-qm", "fixture"},
	} {
		command := exec.CommandContext(t.Context(), "git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v: %s", err, output)
		}
	}
	inputs, err := CollectSourceInputs(t.Context(), root, "product-runtime", "linux/arm64/v8")
	if err != nil || inputs.BuildTarget != "core" || inputs.Deployment != "product-runtime" ||
		inputs.Platform != "linux/arm64/v8" || len(inputs.SourceRevision) != 40 ||
		!strings.HasPrefix(inputs.SourceTreeDigest, "sha256:") ||
		!strings.HasPrefix(inputs.ToolchainDigest, "sha256:") ||
		inputs.BaseImageDigest != baseImageDigest {
		t.Fatalf("reviewed source inputs = %#v, %v", inputs, err)
	}
	if err := inputs.VerifySource(t.Context(), root); err != nil {
		t.Fatalf("clean source receipt failed independent recheck: %v", err)
	}
	changed := inputs
	changed.BuildParametersDigest = inputs.DockerfileDigest
	if err := changed.VerifySource(t.Context(), root); err == nil {
		t.Fatal("self-reported build parameter digest admitted")
	}
	for _, tc := range []struct{ deployment, platform string }{
		{"browser-sandbox-runtime", "linux/arm64/v8"},
		{"desktop-sandbox-runtime", "linux/arm64/v8"},
		{"unreviewed-runtime", "linux/arm64/v8"},
		{"product-runtime", "linux/386"},
	} {
		if _, err := CollectSourceInputs(t.Context(), root, tc.deployment, tc.platform); err == nil {
			t.Fatalf("unreviewed source target/platform admitted: %#v", tc)
		}
	}
	write("untracked.txt", "dirty\n")
	if _, err := CollectSourceInputs(t.Context(), root, "product-runtime", "linux/arm64/v8"); err == nil {
		t.Fatal("dirty source tree admitted")
	}
	if _, err := CollectSourceInputs(context.Background(), "relative", "product-runtime", "linux/arm64/v8"); err == nil {
		t.Fatal("relative source root admitted")
	}
}

func TestToolchainSourceDigestBindsFilesAndRejectsLinks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "runtime", "runtime.go")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package runtime\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := digestToolchainSource(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package runtime // changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := digestToolchainSource(t.Context(), root)
	if err != nil || first == second {
		t.Fatalf("stdlib source mutation not bound: %s, %s, %v", first, second, err)
	}
	if err := os.Symlink(path, filepath.Join(root, "runtime", "alias.go")); err != nil {
		t.Fatal(err)
	}
	if _, err := digestToolchainSource(t.Context(), root); err == nil {
		t.Fatal("symlinked toolchain source admitted")
	}
}
