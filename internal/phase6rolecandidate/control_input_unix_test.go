//go:build darwin || linux

package phase6rolecandidate

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestControlCandidateOriginalCustodyRejectsMutation(t *testing.T) {
	for _, scenario := range []string{"replace", "rewrite-and-restore", "hardlink", "file-mode", "parent-mode", "parent-replace"} {
		t.Run(scenario, func(t *testing.T) {
			root := candidateTestDirectory(t)
			parent := filepath.Join(root, "inputs")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(parent, "original")
			original := []byte("same original bytes")
			candidateTestWrite(t, path, original)
			opened, err := openCandidateFile(path, 64)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if digest, err := opened.copy(t.Context(), nil); err != nil || digest != hashBytes(original) {
				t.Fatal("initial original", err)
			}
			switch scenario {
			case "replace":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				candidateTestWrite(t, path, original)
			case "rewrite-and-restore":
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				candidateTestWrite(t, path, bytes.Repeat([]byte{'x'}, len(original)))
				candidateTestWrite(t, path, original)
				if err := os.Chtimes(path, time.Now(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "parent-mode":
				if err := os.Chmod(parent, 0o755); err != nil {
					t.Fatal(err)
				}
			case "parent-replace":
				if err := os.Rename(parent, parent+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				candidateTestWrite(t, path, original)
			}
			if _, err := opened.copy(t.Context(), nil); err == nil {
				t.Fatal("changed original accepted")
			}
		})
	}
}

type candidateFailWriter struct{}

func (candidateFailWriter) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

type candidateCancelWriter struct{ cancel context.CancelFunc }

func (w candidateCancelWriter) Write(p []byte) (int, error) { w.cancel(); return len(p), nil }

func TestControlCandidateOriginalRejectsUnsafeFilesAndIncompleteCopy(t *testing.T) {
	root := candidateTestDirectory(t)
	path := filepath.Join(root, "original")
	candidateTestWrite(t, path, bytes.Repeat([]byte{'x'}, (64<<10)+3))
	for _, maximum := range []int64{0, 1, 64 << 10} {
		if f, err := openCandidateFile(path, maximum); err == nil {
			f.Close()
			t.Fatal("file size bound bypassed")
		}
	}
	opened, err := openCandidateFile(path, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.copy(t.Context(), candidateFailWriter{}); err == nil {
		t.Fatal("short write accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, err := opened.copy(ctx, candidateCancelWriter{cancel}); err == nil {
		t.Fatal("canceled stream accepted")
	}
	if _, err := opened.copy(nil, nil); err == nil {
		t.Fatal("nil context accepted")
	}
	for _, scenario := range []string{"symlink", "parent-symlink", "fifo", "directory", "empty", "public"} {
		t.Run(scenario, func(t *testing.T) {
			bad := filepath.Join(root, scenario)
			switch scenario {
			case "symlink":
				if err := os.Symlink(path, bad); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink":
				if err := os.Symlink(root, bad); err != nil {
					t.Fatal(err)
				}
				bad = filepath.Join(bad, "original")
			case "fifo":
				if err := unix.Mkfifo(bad, 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(bad, 0o700); err != nil {
					t.Fatal(err)
				}
			case "empty":
				candidateTestWrite(t, bad, nil)
			case "public":
				candidateTestWrite(t, bad, []byte("public"))
				if err := os.Chmod(bad, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if f, err := openCandidateFile(bad, 128<<10); err == nil {
				f.Close()
				t.Fatal("unsafe file accepted")
			}
		})
	}
}
