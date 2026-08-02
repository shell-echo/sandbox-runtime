//go:build darwin || linux

package providerapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadBoundedTLSMaterialRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls-material.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	if _, err := readBoundedTLSMaterial(path, maxServerCertificateBytes); err == nil || !strings.Contains(err.Error(), "file must be a regular file") {
		t.Fatalf("readBoundedTLSMaterial FIFO error = %v", err)
	}
}

func TestReadBoundedTLSMaterialAcceptsSymlinkToRegularFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pem")
	want := []byte("test TLS material")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	path := filepath.Join(directory, "material.pem")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	got, err := readBoundedTLSMaterial(path, len(want))
	if err != nil {
		t.Fatalf("readBoundedTLSMaterial: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("readBoundedTLSMaterial = %q, want %q", got, want)
	}
}
