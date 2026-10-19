//go:build integration && linux

package main

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The external operator fixture must keep its exact owned filesystem mounted
// throughout this test. No alternate node, unmount or forced detach is allowed.
func TestMountedBackendExclusiveDetachRefusal(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CONTROL_BACKEND_MOUNTED") != "1" {
		t.Skip("explicit operator-authorized mounted-loop fixture required")
	}
	ns := os.Getenv("SANDBOX_RUNTIME_BACKEND_NAMESPACE")
	if os.Geteuid() != 0 || !namespacePattern.MatchString(ns) {
		t.Fatal("invalid diagnostic principal or namespace")
	}
	const device = "/dev/loop7"
	// Production inspect independently verifies the retained file and every
	// visible loop, comparing the recorded backing dev/inode to kernel status.
	if err := run("inspect", ns, device); err != nil {
		t.Fatal("source inode observation before refusal failed")
	}
	fd, err := unix.Open(device, unix.O_RDWR|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
		t.Fatal("mounted device allowed exclusive ownership")
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("exclusive open returned %v, want EBUSY", err)
	}
	if err := run("detach", ns, device); !errors.Is(err, invalid) {
		t.Fatal("helper failed to refuse mounted device")
	}
	if err := run("inspect", ns, device); err != nil {
		t.Fatal("source inode observation after refusal failed")
	}
	t.Log("MOUNTED_DETACH_REFUSED: O_EXCL returned EBUSY; helper refused; exact backing inode remains configured")
}
