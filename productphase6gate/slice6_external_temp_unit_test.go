//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func slice6ExternalTempGit(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked"), []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q", root}, {"-C", root, "add", "tracked"},
		{"-C", root, "-c", "user.name=Slice6Test", "-c", "user.email=slice6@example.invalid", "commit", "-qm", "fixture"}} {
		if output, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("test-owned Git fixture: %v: %.200s", err, output)
		}
	}
	output, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return canonical, strings.TrimSpace(string(output))
}

func TestSlice6ExternalPrivateTempPreservesStrictCleanAndBoundedCleanup(t *testing.T) {
	source, revision := slice6ExternalTempGit(t)
	var sibling string
	t.Run("live", func(t *testing.T) {
		sibling = slice6PrivateSourceSibling(t, source, ".sr-p6-temp-test-")
		if !slice6OutsideAllSources(sibling, source) ||
			verifyCleanSlice6Source(t.Context(), source, revision) != nil {
			t.Fatal("external temporary allocation dirtied the source")
		}
		child := filepath.Join(sibling, "nested")
		if err := os.Mkdir(child, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(child, "artifact"), []byte("private"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(source, filepath.Join(sibling, "link-to-source")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "untracked"), []byte("drift"), 0o600); err != nil {
			t.Fatal(err)
		}
		if verifyCleanSlice6Source(t.Context(), source, revision) == nil {
			t.Fatal("extra untracked source file was accepted")
		}
		if err := os.Remove(filepath.Join(source, "untracked")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "tracked"), []byte("mutated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if verifyCleanSlice6Source(t.Context(), source, revision) == nil {
			t.Fatal("tracked source mutation was accepted")
		}
		if err := os.WriteFile(filepath.Join(source, "tracked"), []byte("original\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if verifyCleanSlice6Source(t.Context(), source, revision) != nil {
			t.Fatal("source did not return to exact clean revision")
		}
	})
	if _, err := os.Lstat(sibling); !os.IsNotExist(err) {
		t.Fatal("external temporary directory was not exactly removed", err)
	}
	if verifyCleanSlice6Source(context.Background(), source, revision) != nil {
		t.Fatal("source changed during external cleanup")
	}
}

func TestSlice6ExternalPrivateTempRejectsReplacementWithoutRemovingIt(t *testing.T) {
	source, _ := slice6ExternalTempGit(t)
	parent := filepath.Dir(source)
	path, err := os.MkdirTemp(parent, ".sr-p6-replace-test-")
	if err != nil {
		t.Fatal(err)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	rootFD, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(parentFD)
		t.Fatal(err)
	}
	var parentStat, rootStat unix.Stat_t
	if unix.Fstat(parentFD, &parentStat) != nil || unix.Fstat(rootFD, &rootStat) != nil {
		t.Fatal("test-owned directory identity unavailable")
	}
	moved := path + ".moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(path, "not-ours")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if slice6RemovePrivateSibling(path, parentFD, rootFD, parentStat, rootStat) == nil {
		t.Fatal("replacement directory accepted as exact cleanup target")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatal("replacement contents were removed", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(moved); err != nil {
		t.Fatal(err)
	}
}
