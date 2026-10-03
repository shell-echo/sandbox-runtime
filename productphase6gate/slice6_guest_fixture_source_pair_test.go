//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func slice6PairGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Phase6 Test", "GIT_AUTHOR_EMAIL=phase6@example.test",
		"GIT_COMMITTER_NAME=Phase6 Test", "GIT_COMMITTER_EMAIL=phase6@example.test")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture Git command %v failed: %v: %s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}

func slice6PairWrite(t *testing.T, root, path, contents string) {
	t.Helper()
	target := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func slice6PairCommit(t *testing.T, root string) string {
	t.Helper()
	slice6PairGit(t, root, "add", "-A")
	slice6PairGit(t, root, "commit", "-q", "-m", "fixture source proof")
	return slice6PairGit(t, root, "rev-parse", "HEAD")
}

func slice6PairRepos(t *testing.T) (runtimeRoot, fixtureRoot, revision string) {
	t.Helper()
	base := t.TempDir()
	runtimeRoot, fixtureRoot = filepath.Join(base, "runtime"), filepath.Join(base, "fixture")
	if err := os.Mkdir(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	slice6PairGit(t, runtimeRoot, "init", "-q")
	slice6PairWrite(t, runtimeRoot, "go.mod", "module example.com/phase6-fixture-pair\n\ngo 1.26.8\n")
	slice6PairWrite(t, runtimeRoot, "cmd/base.go", "package cmd\n")
	for _, name := range []string{"phase6_guest_binding_fixture.go", "phase6_guest_revoke_fixture.go"} {
		slice6PairWrite(t, runtimeRoot, filepath.Join("cmd", name),
			"//go:build phase6slice6fixture\n\npackage cmd\n")
	}
	revision = slice6PairCommit(t, runtimeRoot)
	slice6PairGit(t, base, "clone", "-q", runtimeRoot, fixtureRoot)
	return runtimeRoot, fixtureRoot, revision
}

func TestSlice6GuestFixtureSourcePairClosedGitModes(t *testing.T) {
	ctx := context.Background()
	t.Run("same commit independent clean checkout", func(t *testing.T) {
		runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
		t.Setenv("GOFLAGS", "-tags=phase6slice6fixture")
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, revision); err != nil {
			t.Fatalf("exact clean R/F pair rejected: %v", err)
		}
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, runtimeRoot, revision); err == nil {
			t.Fatal("same root accepted as independent fixture")
		}
		alias := filepath.Join(filepath.Dir(runtimeRoot), "alias")
		if err := os.Symlink(runtimeRoot, alias); err != nil {
			t.Fatal(err)
		}
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, alias, revision); err == nil {
			t.Fatal("symlink alias accepted as independent fixture")
		}
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, "fixture", revision); err == nil {
			t.Fatal("relative fixture source accepted")
		}
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision,
			filepath.Join(fixtureRoot, "cmd"), revision); err == nil {
			t.Fatal("nested checkout directory accepted as independent root")
		}
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, strings.Repeat("0", 40),
			fixtureRoot, revision); err == nil {
			t.Fatal("wrong runtime HEAD accepted")
		}
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision,
			fixtureRoot, strings.Repeat("0", 40)); err == nil {
			t.Fatal("wrong fixture HEAD accepted")
		}
	})
	for name, mutate := range map[string]func(*testing.T, string){
		"dirty tracked": func(t *testing.T, root string) {
			slice6PairWrite(t, root, "cmd/base.go", "package cmd\n// changed\n")
		},
		"dirty untracked": func(t *testing.T, root string) {
			slice6PairWrite(t, root, "untracked.txt", "untracked\n")
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
			mutate(t, fixtureRoot)
			if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, revision); err == nil {
				t.Fatal("dirty fixture source accepted")
			}
		})
	}
	t.Run("dirty runtime", func(t *testing.T) {
		runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
		slice6PairWrite(t, runtimeRoot, "untracked.txt", "untracked\n")
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, revision); err == nil {
			t.Fatal("dirty runtime source accepted")
		}
	})
	t.Run("allowed strict descendant", func(t *testing.T) {
		runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
		slice6PairWrite(t, fixtureRoot, "cmd/phase6_guest_binding_fixture_test.go",
			"//go:build phase6slice6fixture\n\npackage cmd\n")
		fixtureRevision := slice6PairCommit(t, fixtureRoot)
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, fixtureRevision); err != nil {
			t.Fatalf("allowlisted descendant rejected: %v", err)
		}
	})
	for name, path := range map[string]string{
		"ordinary runtime drift": "cmd/base.go",
		"dependency drift":       "go.mod",
	} {
		t.Run(name, func(t *testing.T) {
			runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
			slice6PairWrite(t, fixtureRoot, path, "changed\n")
			fixtureRevision := slice6PairCommit(t, fixtureRoot)
			if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, fixtureRevision); err == nil {
				t.Fatal("ordinary runtime/dependency drift accepted")
			}
		})
	}
	t.Run("old fixture ancestor", func(t *testing.T) {
		runtimeRoot, fixtureRoot, fixtureRevision := slice6PairRepos(t)
		slice6PairWrite(t, runtimeRoot, "docs/new-runtime.md", "new runtime revision\n")
		runtimeRevision := slice6PairCommit(t, runtimeRoot)
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, runtimeRevision, fixtureRoot, fixtureRevision); err == nil {
			t.Fatal("ancestor fixture accepted as new R")
		}
	})
	t.Run("unrelated history", func(t *testing.T) {
		runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
		slice6PairGit(t, fixtureRoot, "checkout", "-q", "--orphan", "unrelated")
		slice6PairWrite(t, fixtureRoot, "README.md", "unrelated history\n")
		fixtureRevision := slice6PairCommit(t, fixtureRoot)
		if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, fixtureRevision); err == nil {
			t.Fatal("unrelated fixture history accepted")
		}
	})
	for name, change := range map[string]func(*testing.T, string){
		"missing tag": func(t *testing.T, root string) {
			slice6PairWrite(t, root, "cmd/phase6_guest_binding_fixture.go", "package cmd\n")
		},
		"missing source": func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "cmd", "phase6_guest_revoke_fixture.go")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtimeRoot, fixtureRoot, revision := slice6PairRepos(t)
			change(t, fixtureRoot)
			fixtureRevision := slice6PairCommit(t, fixtureRoot)
			if err := slice6VerifyGuestFixtureSourcePair(ctx, runtimeRoot, revision, fixtureRoot, fixtureRevision); err == nil {
				t.Fatal("fixture without exact build-tagged sources accepted")
			}
		})
	}
}

// This opt-in check binds an actual pair of clean checkouts without starting
// Docker, a fixture process, or any issuer. It does not approve a binary.
func TestSlice6GuestFixtureSourcePairActualNoIssuer(t *testing.T) {
	runtimeRoot := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT")
	runtimeRevision := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION")
	fixtureRoot := os.Getenv(slice6GuestFixtureSourceRootEnv)
	fixtureRevision := os.Getenv(slice6GuestFixtureSourceRevisionEnv)
	if runtimeRoot == "" && runtimeRevision == "" && fixtureRoot == "" && fixtureRevision == "" {
		t.Skip("actual independent source pair not selected")
	}
	if err := slice6VerifyGuestFixtureSourcePair(t.Context(), runtimeRoot, runtimeRevision,
		fixtureRoot, fixtureRevision); err != nil {
		t.Fatalf("actual independent source pair rejected: %v", err)
	}
}
