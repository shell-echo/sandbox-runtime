package controlstorage

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestSourceFDRejectsWritableAndReplacement(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "record")
	if err := os.WriteFile(name, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a, err := sourceFDAnchor(int(f.Fd()), unix.AT_FDCWD, name)
	if err != nil || a.Mount == 0 {
		t.Fatal("real read-only file/statx anchor unavailable")
	}
	w, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := sourceFDAnchor(int(w.Fd()), unix.AT_FDCWD, name); err == nil {
		t.Fatal("writable descriptor accepted")
	}
	if err := os.Rename(name, name+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sourceFDAnchor(int(f.Fd()), unix.AT_FDCWD, name); err == nil {
		t.Fatal("same-content replacement accepted")
	}
}
