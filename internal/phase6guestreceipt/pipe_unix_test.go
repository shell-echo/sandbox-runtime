//go:build linux

package phase6guestreceipt

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestIndependentPipeDescriptorFlags(t *testing.T) {
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	raw, err := writer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd, before int
	if err := raw.Control(func(value uintptr) {
		fd = int(value)
		before, _ = unix.FcntlInt(value, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	root := "/proc/self/fd/"
	if runtime.GOOS == "darwin" {
		root = "/dev/fd/"
	}
	opened, err := unix.Open(root+strconv.Itoa(fd), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("platform fd reopening unavailable: %v; original_nonblock=%v", err, before&unix.O_NONBLOCK != 0)
	}
	defer unix.Close(opened)
	after, _ := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	flags, _ := unix.FcntlInt(uintptr(opened), unix.F_GETFL, 0)
	if before&unix.O_NONBLOCK != 0 || after&unix.O_NONBLOCK != 0 || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("independent flags unavailable: before=%v after=%v opened=%v", before, after, flags)
	}
}

func TestReceiptWriterFDIsCLOEXECAndClosedAfterSeal(t *testing.T) {
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	recorder, err := New(writer, "guest", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	fd := recorder.outputFD
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("writer fd is not close-on-exec")
	}
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestChildReceiptWriterFDNotInherited$")
	child.Env = append(os.Environ(), "PHASE6_RECEIPT_CHILD_FD="+strconv.Itoa(fd), "PHASE6_RECEIPT_CHILD_PIPE="+link)
	if err := child.Run(); err != nil {
		t.Fatal("receipt writer fd was inherited by exec child")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := recorder.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("sealed writer fd remained open")
	}
	raw, err := writer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var originalFlags int
	if err := raw.Control(func(value uintptr) {
		originalFlags, _ = unix.FcntlInt(value, unix.F_GETFL, 0)
	}); err != nil || originalFlags&unix.O_NONBLOCK != 0 {
		t.Fatal("receipt writer changed original stdout status flags")
	}
}

func TestChildReceiptWriterFDNotInherited(t *testing.T) {
	value := os.Getenv("PHASE6_RECEIPT_CHILD_FD")
	if value == "" {
		t.Skip("child-only fd inheritance check")
	}
	if link, err := os.Readlink("/proc/self/fd/" + value); err == nil && link == os.Getenv("PHASE6_RECEIPT_CHILD_PIPE") {
		t.Fatal("private receipt fd survived exec")
	}
}
