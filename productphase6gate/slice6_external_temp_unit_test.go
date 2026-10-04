//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
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

func TestSlice6ExternalPrivateOwnerFinishesBeforeTestCleanup(t *testing.T) {
	source, revision := slice6ExternalTempGit(t)
	owner := newSlice6PrivateSiblingOwner(t)
	first := slice6PrivateSourceSiblingOwned(t, owner, source, ".sr-p6-owner-first-")
	second := slice6PrivateSourceSiblingOwned(t, owner, source, ".sr-p6-owner-second-")
	if err := os.WriteFile(filepath.Join(first, "private"), []byte("ephemeral"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := owner.finish(); err != nil || owner.finish() != nil {
		t.Fatalf("explicit run owner finish unavailable: %v", err)
	}
	for _, path := range []string{first, second} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("owned sibling remained before test cleanup: %s: %v", path, err)
		}
	}
	if err := verifyCleanSlice6Source(t.Context(), source, revision); err != nil {
		t.Fatal("explicit finish dirtied frozen source")
	}
}

func TestSlice6ExternalPrivateOwnerRetainsReplacedName(t *testing.T) {
	source, _ := slice6ExternalTempGit(t)
	owner := &slice6PrivateSiblingOwner{}
	path := slice6PrivateSourceSiblingOwned(t, owner, source, ".sr-p6-owner-replace-")
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
	if owner.finish() == nil || owner.finish() == nil {
		t.Fatal("owner accepted a replaced temporary name")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatal("owner removed a replacement directory")
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

func TestSlice6GuestRecoveryPrivateSiblingZeroReplaysOriginalNames(t *testing.T) {
	source, _ := slice6ExternalTempGit(t)
	evidencePath := filepath.Join(t.TempDir(), "evidence")
	if err := os.Mkdir(evidencePath, 0o700); err != nil {
		t.Fatal(err)
	}
	evidencePath, err := filepath.EvalSymlinks(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRoot, err := slice6OpenReceiptEvidenceRoot(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	defer evidenceRoot.close()
	run, err := evidenceRoot.newRun(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	defer run.closeV2Incomplete()
	owner := newSlice6PrivateSiblingOwner(t)
	var original string
	for index, prefix := range slice6GuestRecoveryPrivateSiblingPrefixes {
		path := slice6PrivateSourceSiblingOwned(t, owner, source, prefix)
		if index == 0 {
			original = path
		}
	}
	if err := owner.finish(); err != nil {
		t.Fatal(err)
	}
	digest, err := run.captureGuestRecoveryPrivateSiblingZero(owner)
	if err != nil || !guestRevokeFixtureDigestGate(digest) ||
		run.verifyGuestRecoveryPrivateSiblingZero() != nil {
		t.Fatalf("original seven private sibling absences unavailable: %v", err)
	}
	raw, err := run.readFile(slice6GuestRecoveryPrivateSiblingZeroFile, 8<<10)
	if err != nil {
		t.Fatal(err)
	}
	var tampered slice6GuestRecoveryPrivateSiblingZero
	if json.Unmarshal(raw, &tampered) != nil {
		t.Fatal("private sibling receipt decode unavailable")
	}
	clear(raw)
	tampered.Absent[0].ParentIno++
	if slice6VerifyGuestRecoveryPrivateSiblingZero(tampered) == nil {
		t.Fatal("private sibling replay accepted a changed parent inode")
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	if run.verifyGuestRecoveryPrivateSiblingZero() == nil {
		t.Fatal("private sibling replay accepted a recreated original name")
	}
	if err := os.Remove(original); err != nil {
		t.Fatal(err)
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

func TestSlice6ExternalPrivateTempBudgetIsGlobalAcrossDepth(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(root, "a-child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(child, "within-budget")
	if err := os.WriteFile(file, []byte("remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(root, "z-sibling-not-within-budget")
	if err := os.WriteFile(sibling, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	budget := 2
	if slice6RemovePrivateContents(fd, &budget, 0) == nil || budget != 0 {
		t.Fatal("sibling after nested entries exceeded global cleanup budget")
	}
	if _, err := os.Lstat(file); !os.IsNotExist(err) {
		t.Fatal("within-budget nested file was not removed", err)
	}
	if data, err := os.ReadFile(sibling); err != nil || string(data) != "preserve" {
		t.Fatal("out-of-budget sibling file was removed", err)
	}
}

func TestSlice6VaultTemporarySourceSelectionNoIssuer(t *testing.T) {
	eRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	rRoot, _ := slice6ExternalTempGit(t)
	for _, value := range []struct{ name, configured, want string }{
		{"diagnostic", "", eRoot}, {"composed", rRoot, rRoot},
	} {
		t.Run(value.name, func(t *testing.T) {
			selected, err := slice6VaultTemporarySourceRoot(value.configured)
			if err != nil || selected != value.want {
				t.Fatal("Vault source selection drift", err)
			}
			sibling := slice6PrivateSourceSibling(t, selected, ".sr-vault-trust-switch-")
			if !slice6OutsideAllSources(sibling, selected) {
				t.Fatal("Vault diagnostic files entered a source root")
			}
		})
	}
}
