//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func executableFixture(t *testing.T) (*PreparedConfiguration, string, string) {
	t.Helper()
	// macOS temporary roots commonly have a /var symlink; the production
	// API deliberately does not resolve it. The test supplies the real path.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "adapter")
	body := []byte("synthetic artifact; never executed")
	if err := os.WriteFile(path, body, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	prepared, err := PrepareConfiguration(context.Background(), locationFixture())
	if err != nil {
		t.Fatal(err)
	}
	return prepared, path, "sha256:" + hex.EncodeToString(digest[:])
}

func TestExecutablePinnedIdentityRecheckAndClose(t *testing.T) {
	prepared, path, digest := executableFixture(t)
	e, err := OpenExecutable(context.Background(), prepared, path, digest, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Identity().Digest != digest || e.Identity().Bytes != 34 {
		t.Fatal(e.Identity())
	}
	if err := e.Recheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(e.Recheck(ctx), context.Canceled) {
		t.Fatal("canceled recheck accepted")
	}
	if err := e.Recheck(context.Background()); err != nil {
		t.Fatal("cancellation damaged held descriptor", err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e.Recheck(context.Background()), ErrExecutable) {
		t.Fatal("closed descriptor accepted")
	}
}

func TestExecutableRejectsInvalidTargets(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "symlink", "parent-symlink", "fifo", "hardlink", "no-exec", "writable", "set-id", "empty", "oversize", "digest", "malformed-digest", "relative", "unclean", "nil-context", "canceled", "invalid-limit", "zero-limit"} {
		t.Run(kind, func(t *testing.T) {
			prepared, path, digest := executableFixture(t)
			ctx := context.Background()
			limit := int64(1024)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing":
				path += "-missing"
			case "directory":
				path = filepath.Dir(path)
			case "symlink":
				link := path + "-link"
				must(os.Symlink(path, link))
				path = link
			case "parent-symlink":
				link := filepath.Join(filepath.Dir(path), "link")
				must(os.Symlink(filepath.Dir(path), link))
				path = filepath.Join(link, "adapter")
			case "fifo":
				path += "-fifo"
				must(unix.Mkfifo(path, 0700))
			case "hardlink":
				must(os.Link(path, path+"-alias"))
			case "no-exec":
				must(os.Chmod(path, 0600))
			case "writable":
				must(os.Chmod(path, 0770))
			case "set-id":
				must(os.Chmod(path, os.ModeSetuid|0700))
			case "empty":
				must(os.Truncate(path, 0))
			case "oversize":
				limit = 1
			case "digest":
				digest = "sha256:" + strings.Repeat("0", 64)
			case "malformed-digest":
				digest = "sha256:" + strings.Repeat("A", 64)
			case "relative":
				path = "private-relative-artifact"
			case "unclean":
				path = filepath.Dir(path) + "/./adapter"
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "invalid-limit":
				limit = MaxExecutableBytes + 1
			case "zero-limit":
				limit = 0
			}
			e, err := OpenExecutable(ctx, prepared, path, digest, limit)
			if err == nil {
				e.Close()
				t.Fatal("invalid artifact accepted")
			}
			if strings.Contains(err.Error(), path) || e != nil {
				t.Fatal("private path or descriptor leaked")
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		})
	}
}

func TestExecutableRecheckDetectsReplacementAndMutation(t *testing.T) {
	for _, kind := range []string{"content", "replacement", "symlink", "mode", "hardlink", "parent"} {
		t.Run(kind, func(t *testing.T) {
			prepared, path, digest := executableFixture(t)
			e, err := OpenExecutable(context.Background(), prepared, path, digest, 1024)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "content":
				must(os.WriteFile(path, []byte("different artifact"), 0700))
			case "replacement":
				body, err := os.ReadFile(path)
				must(err)
				must(os.Rename(path, path+"-old"))
				must(os.WriteFile(path, body, 0700))
			case "symlink":
				must(os.Rename(path, path+"-old"))
				must(os.Symlink(path+"-old", path))
			case "mode":
				must(os.Chmod(path, 0600))
			case "hardlink":
				must(os.Link(path, path+"-alias"))
			case "parent":
				root := filepath.Dir(path)
				must(os.Rename(root, root+"-old"))
				t.Cleanup(func() { _ = os.Rename(root+"-old", root) })
			}
			if !errors.Is(e.Recheck(context.Background()), ErrExecutable) {
				t.Fatal("changed artifact accepted")
			}
		})
	}
}
