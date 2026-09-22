package main

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func TestReadBoundedAcceptsOnlyPrivateRegularDescriptorAtStart(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "certificate-controller-secret-")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	value, err := readBounded(uintptr(descriptor), "test-secret", 32)
	if err != nil || string(value) != "secret" {
		t.Fatalf("readBounded() = %q, %v", value, err)
	}
	clear(value)
	if _, err := file.Seek(1, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err = syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(uintptr(descriptor), "offset-secret", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("offset descriptor error = %v", err)
	}
	if err := file.Chmod(0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err = syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(uintptr(descriptor), "public-secret", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("public descriptor error = %v", err)
	}
	_ = file.Close()
}

func TestReadBoundedRejectsPipeDirectoryMissingAndOversizedDescriptors(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if _, err := readBounded(reader.Fd(), "pipe", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("pipe descriptor error = %v", err)
	}
	directory, err := os.Open("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(directory.Fd(), "directory", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("directory descriptor error = %v", err)
	}
	file, err := os.CreateTemp("/tmp", "certificate-controller-oversized-")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(make([]byte, 33)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(file.Fd(), "oversized", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("oversized descriptor error = %v", err)
	}
	if _, err := readBounded(^uintptr(0), "missing", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("missing descriptor error = %v", err)
	}
}
