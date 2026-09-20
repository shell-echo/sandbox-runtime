package secretfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrivateBoundedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := Read(path, 64)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(value) != "secret-value" {
		t.Fatalf("value = %q", value)
	}
}

func TestReadRejectsUnsafePrivateFiles(t *testing.T) {
	directory := t.TempDir()
	public := filepath.Join(directory, "public")
	if err := os.WriteFile(public, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(public, 64); err == nil {
		t.Fatal("accepted group/world-readable file")
	}
	large := filepath.Join(directory, "large")
	if err := os.WriteFile(large, make([]byte, 65), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(large, 64); err == nil {
		t.Fatal("accepted oversized file")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(large, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, 128); err == nil {
		t.Fatal("accepted symlink")
	}
}
