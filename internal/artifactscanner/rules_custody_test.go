//go:build darwin || linux

package artifactscanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// The real chunk loop calls Err after opening the file. This deterministic
// barrier changes only the test's filesystem; production has no test hook.
type ruleMutationContext struct {
	context.Context
	calls, at int
	mutate    func()
	observed  bool
}

func (c *ruleMutationContext) Err() error {
	c.calls++
	if c.calls == c.at {
		c.observed = true
		c.mutate()
	}
	return c.Context.Err()
}

func TestRuleDirectoryRetainsOriginalCustody(t *testing.T) {
	for _, name := range []string{"stable", "replacement", "symlink", "extra", "directory-mode", "directory-restored", "file-restored", "file-mode-restored", "earlier-file", "canceled"} {
		t.Run(name, func(t *testing.T) {
			_, manifest, directory := testRuleSnapshot(t)
			first := filepath.Join(directory, manifest.Files[0].Name)
			original, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			barrier := &ruleMutationContext{Context: ctx, at: 1}
			if name == "earlier-file" {
				// Each tiny file requires one data read and one EOF read. The
				// third check opens the second file after the first was hashed.
				barrier.at = 3
			}
			barrier.mutate = func() {
				switch name {
				case "replacement", "symlink":
					old := directory + "-original"
					must(os.Rename(directory, old))
					if name == "symlink" {
						must(os.Symlink(old, directory))
						break
					}
					must(os.Mkdir(directory, 0700))
					for _, file := range manifest.Files {
						raw, err := os.ReadFile(filepath.Join(old, file.Name))
						must(err)
						must(os.WriteFile(filepath.Join(directory, file.Name), raw, 0600))
					}
				case "extra":
					must(os.WriteFile(filepath.Join(directory, "extra.ndb"), []byte("unreviewed"), 0600))
				case "directory-mode":
					must(os.Chmod(directory, 0755))
				case "directory-restored", "file-restored", "file-mode-restored":
					path := first
					if name == "directory-restored" {
						path = directory
					}
					info, err := os.Lstat(path)
					must(err)
					var before, after unix.Stat_t
					must(unix.Lstat(path, &before))
					if name == "directory-restored" {
						extra := filepath.Join(directory, "temporary.ndb")
						must(os.WriteFile(extra, []byte("temporary"), 0600))
						must(os.Remove(extra))
					} else if name == "file-restored" {
						changed := append([]byte(nil), original...)
						changed[0] ^= 1
						must(os.WriteFile(first, changed, 0600))
						must(os.WriteFile(first, original, 0600))
					} else {
						must(os.Chmod(first, 0400))
						must(os.Chmod(first, info.Mode().Perm()))
					}
					must(os.Chtimes(path, info.ModTime(), info.ModTime()))
					must(unix.Lstat(path, &after))
					if before.Mtim != after.Mtim || before.Ctim == after.Ctim {
						t.Fatal("fixture did not restore mtime while changing ctime")
					}
				case "earlier-file":
					changed := append([]byte(nil), original...)
					changed[0] ^= 1
					must(os.WriteFile(first, changed, 0600))
				case "canceled":
					cancel()
				}
			}
			err = verifyRuleDirectory(barrier, directory, manifest.Files)
			if !barrier.observed {
				t.Fatal("filesystem observation barrier was not reached")
			}
			if name == "stable" {
				if err != nil {
					t.Fatal("unchanged original rules refused", err)
				}
			} else if name == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation lost", err)
				}
			} else if !errors.Is(err, ErrRulesUnavailable) {
				t.Fatal("changed original rules admitted", err)
			}
		})
	}
}

func TestRuleCustodyOpensOnlyApprovedRegularFiles(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "fifo", "directory", "writable", "empty", "unknown-name", "traversal"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			name := "bytecode.cvd"
			if kind == "unknown-name" {
				name = "extra.ndb"
			}
			path := filepath.Join(directory, name)
			var err error
			switch kind {
			case "symlink":
				target := filepath.Join(t.TempDir(), "original")
				err = os.WriteFile(target, []byte("x"), 0600)
				if err == nil {
					err = os.Symlink(target, path)
				}
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "empty":
				err = os.WriteFile(path, nil, 0600)
			default:
				err = os.WriteFile(path, []byte("x"), 0600)
				if err == nil && kind == "writable" {
					err = os.Chmod(path, 0620)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			root, err := openRuleDirectory(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := root.file.Close(); err != nil {
					t.Error(err)
				}
			}()
			if kind == "traversal" {
				name = "../bytecode.cvd"
			}
			file, err := root.open(name)
			if kind == "regular" {
				if err != nil || file == nil || file.size() != 1 || file.check() != nil {
					t.Fatal("original regular file refused", err)
				}
				if err := file.file.Close(); err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrRulesUnavailable) || file != nil {
				t.Fatal("unapproved file opened", err)
			}
		})
	}
}

func TestRuleDirectoryAcceptsPinnedDatabaseVariants(t *testing.T) {
	_, manifest, directory := testRuleSnapshot(t)
	for i := range manifest.Files {
		name := manifest.Files[i].Name
		cld := name[:len(name)-3] + "cld"
		if err := os.Rename(filepath.Join(directory, name), filepath.Join(directory, cld)); err != nil {
			t.Fatal(err)
		}
		manifest.Files[i].Name = cld
	}
	if err := verifyRuleDirectory(t.Context(), directory, manifest.Files); err != nil {
		t.Fatal("unchanged pinned cld files refused", err)
	}
}
