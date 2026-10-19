//go:build integration && linux

package controlstorage

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

// Executed by the explicit Docker fixture as the high-UID process owning a NEW
// named local volume. It cannot be enabled by an ordinary all-package host run.
func TestKernelStorageRealLocalVolumeRefusal(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_KERNEL_LOCAL_VOLUME") != "1" {
		t.Skip("explicit restricted Linux volume fixture required")
	}
	if os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("wrong fixture owner")
	}
	const path = "/receipt"
	var fs unix.Statfs_t
	if unix.Statfs(path, &fs) != nil {
		t.Fatal("statfs unavailable")
	}
	if fs.Frsize <= 0 || fs.Blocks <= uint64((1<<30)/fs.Frsize) {
		t.Fatal("fixture is not the expected unbounded shared local filesystem")
	}
	b := testBinding()
	if s, err := InitializeKernelChecked(t.Context(), path, b); err == nil {
		s.Close()
		t.Fatal("unbounded local volume admitted")
	}
	names, err := os.ReadDir(path)
	if err != nil || len(names) != 0 {
		t.Fatal("rejected volume gained a namespace marker")
	}
	fmt.Printf("KERNEL_LOCAL_VOLUME_REFUSED total_data_bytes=%d owner=%d:%d objects=0; no physical admission\n", fs.Blocks*uint64(fs.Frsize), os.Geteuid(), os.Getegid())
}
