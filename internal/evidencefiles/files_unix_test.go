//go:build darwin || linux

package evidencefiles

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadRejectsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("special file unavailable: %v", err)
	}
	if _, err := Read(root, nil, DefaultOptions()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Read() error = %v, want special-file rejection", err)
	}
}
