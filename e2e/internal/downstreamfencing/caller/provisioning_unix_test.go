//go:build darwin || linux

package caller

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidateProvisioningFileRequiresPipeDirectionAndSetsCloseOnExec(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if _, err := unix.FcntlInt(read.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateProvisioningFile(read, unix.O_RDONLY); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(read.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("read FD flags = %d, error = %v", flags, err)
	}
	if err := validateProvisioningFile(read, unix.O_WRONLY); err == nil {
		t.Fatal("read end accepted as write-only provisioning file")
	}
	if err := validateProvisioningFile(write, unix.O_WRONLY); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProvisioningFileRejectsRegularFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "provisioning-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateProvisioningFile(file, unix.O_RDWR); err == nil {
		t.Fatal("regular file accepted as inherited provisioning pipe")
	}
}
