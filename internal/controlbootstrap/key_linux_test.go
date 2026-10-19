//go:build linux

package controlbootstrap

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func sealedTestKey(t *testing.T, seals int) *os.File {
	t.Helper()
	fd, e := unix.MemfdCreate("bootstrap-test", unix.MFD_ALLOW_SEALING)
	if e != nil {
		t.Fatal(e)
	}
	f := os.NewFile(uintptr(fd), "test")
	t.Cleanup(func() { f.Close() })
	if f.Chmod(0600) != nil {
		t.Fatal("mode")
	}
	if _, e = f.Write(bytes.Repeat([]byte{7}, 32)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	if _, e = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestSealedBootstrapKeyRejectsMutableAliasedInputs(t *testing.T) {
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	good := sealedTestKey(t, seals)
	b, e := readSealedKey(context.Background(), good)
	if e != nil || !bytes.Equal(b, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("sealed key", e)
	}
	if _, e := readSealedKey(context.Background(), sealedTestKey(t, unix.F_SEAL_WRITE)); e == nil {
		t.Fatal("incomplete seals")
	}
	if _, e := good.WriteAt([]byte{1}, 0); e == nil {
		t.Fatal("kernel permitted overwrite")
	}
	for _, mutate := range []func(*os.File){func(f *os.File) { _ = f.Chmod(0400) }, func(f *os.File) { _, _ = f.Seek(1, 0) }, func(f *os.File) { _, _ = unix.FcntlInt(f.Fd(), unix.F_SETFD, unix.FD_CLOEXEC) }} {
		f := sealedTestKey(t, seals)
		mutate(f)
		if _, e := readSealedKey(context.Background(), f); e == nil {
			t.Fatal("metadata drift")
		}
	}
	f, e := os.CreateTemp(t.TempDir(), "regular")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	_, _ = f.Write(bytes.Repeat([]byte{7}, 32))
	_, _ = f.Seek(0, 0)
	if _, e := readSealedKey(context.Background(), f); e == nil {
		t.Fatal("regular file")
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	if _, e := readSealedKey(context.Background(), r); e == nil {
		t.Fatal("legacy FIFO accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := readSealedKey(ctx, good); e == nil {
		t.Fatal("cancelled")
	}
}
