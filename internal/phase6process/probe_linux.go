//go:build linux

package phase6process

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"syscall"
)

// ObserveProbe checks the fixed image-owned path and its entire parent chain.
// Docker mount/config/image verification remains an independent host duty.
func ObserveProbe(ctx context.Context, digest string, self bool) (ProbeObservation, error) {
	var out ProbeObservation
	if ctx == nil || ctx.Err() != nil {
		return out, ErrIdentity
	}
	for _, path := range []string{"/", "/usr", "/usr/local", "/usr/local/bin"} {
		st, e := os.Lstat(path)
		if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
			return out, ErrIdentity
		}
		v, ok := st.Sys().(*syscall.Stat_t)
		if !ok || v.Uid != 0 || v.Gid != 0 {
			return out, ErrIdentity
		}
	}
	fd, e := unix.Open(ProbePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return out, ErrIdentity
	}
	f := os.NewFile(uintptr(fd), "control-probe")
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0555 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || st.Size() < 1 || st.Size() > 128<<20 {
		return out, ErrIdentity
	}
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || v.Uid != 0 || v.Gid != 0 || v.Nlink != 1 {
		return out, ErrIdentity
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if ctx.Err() != nil {
			return out, ErrIdentity
		}
		n, e := f.Read(buf)
		total += int64(n)
		if total > 128<<20 {
			return out, ErrIdentity
		}
		h.Write(buf[:n])
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, ErrIdentity
		}
	}
	end, e := f.Stat()
	path, pe := os.Lstat(ProbePath)
	if e != nil || pe != nil || !os.SameFile(st, end) || !os.SameFile(st, path) || end.Size() != st.Size() || path.Mode() != st.Mode() || total != st.Size() || ctx.Err() != nil {
		return out, ErrIdentity
	}
	if self {
		exe, e := os.Stat("/proc/self/exe")
		link, le := os.Readlink("/proc/self/exe")
		if e != nil || le != nil || link != ProbePath || !os.SameFile(st, exe) {
			return out, ErrIdentity
		}
	}
	got := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if got != digest {
		return out, ErrIdentity
	}
	return ProbeObservation{got, uint64(v.Dev), v.Ino, st.Size()}, nil
}
