package files

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServiceConfinesPathsAndRejectsSymlinkAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "main.go"), []byte("package main\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	entry, err := service.Stat(context.Background(), "src/main.go")
	if err != nil || entry.Path != "src/main.go" || entry.Type != "file" || !strings.HasPrefix(entry.Revision, "sha256:") || strings.Contains(entry.Path, root) {
		t.Fatalf("Stat() = %#v, %v", entry, err)
	}
	for _, unsafe := range []string{"../secret", "/etc/passwd", "src/../escape", "src\\main.go", "escape", "pipe"} {
		if _, err := service.Stat(context.Background(), unsafe); err == nil {
			t.Fatalf("Stat(%q) unexpectedly succeeded", unsafe)
		}
	}
	listing, err := service.List(context.Background(), ListRequest{Limit: 10})
	if err != nil || len(listing.Items) != 2 {
		t.Fatalf("List() = %#v, %v", listing, err)
	}
	for _, item := range listing.Items {
		if strings.Contains(item.Path, root) || strings.Contains(item.Path, outside) {
			t.Fatalf("host path disclosed: %#v", item)
		}
	}
	snapshot, err := service.Snapshot(context.Background(), "")
	if err != nil || len(snapshot) != 2 {
		t.Fatalf("Snapshot() = %#v, %v", snapshot, err)
	}
	for _, item := range snapshot {
		if item.Path == "escape" || item.Path == "pipe" {
			t.Fatalf("unsafe entry included in snapshot: %#v", item)
		}
	}
}

func TestServicePaginationRenameAndContentRevision(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	service, _ := New(root)
	defer service.Close()
	first, err := service.List(context.Background(), ListRequest{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextAfter != "b.txt" {
		t.Fatalf("first page = %#v, %v", first, err)
	}
	second, err := service.List(context.Background(), ListRequest{AfterName: first.NextAfter, Limit: 2})
	if err != nil || len(second.Items) != 1 || second.Items[0].Name != "c.txt" || second.NextAfter != "" {
		t.Fatalf("second page = %#v, %v", second, err)
	}
	before, _ := service.Stat(context.Background(), "a.txt")
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("changed content"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := service.Stat(context.Background(), "a.txt")
	if before.Revision == after.Revision {
		t.Fatal("content change did not alter revision")
	}
	if err := os.Rename(filepath.Join(root, "c.txt"), filepath.Join(root, "renamed.txt")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Snapshot(context.Background(), "")
	if err != nil || len(snapshot) != 3 || snapshot[2].Path != "renamed.txt" {
		t.Fatalf("renamed snapshot = %#v, %v", snapshot, err)
	}
}

func TestServiceRejectsSymlinkRootAndBounds(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(link); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New(symlink) err=%v", err)
	}
	service, _ := New(root)
	defer service.Close()
	if _, err := service.List(context.Background(), ListRequest{Limit: MaxListEntries + 1}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("oversized List() err=%v", err)
	}
}
