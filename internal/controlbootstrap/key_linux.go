//go:build linux

package controlbootstrap

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
)

func readSealedKey(ctx context.Context, f *os.File) ([]byte, error) {
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	fd := int(f.Fd())
	var before, after unix.Stat_t
	flags, e := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	inherit, ie := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	valid := func(st unix.Stat_t) bool {
		s, e := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
		return e == nil && s == seals && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0o7777 == 0o600 && st.Size == 32 && st.Nlink == 0 && st.Uid == uint32(os.Geteuid()) && st.Gid == uint32(os.Getegid())
	}
	if ctx.Err() != nil || e != nil || ie != nil || flags&unix.O_ACCMODE != unix.O_RDWR || inherit&unix.FD_CLOEXEC != 0 || unix.Fstat(fd, &before) != nil || !valid(before) {
		return nil, ErrUnavailable
	}
	offset, e := unix.Seek(fd, 0, unix.SEEK_CUR)
	if e != nil || offset != 0 {
		return nil, ErrUnavailable
	}
	data := make([]byte, 32)
	n, e := unix.Pread(fd, data, 0)
	if e != nil || n != 32 || unix.Fstat(fd, &after) != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || ctx.Err() != nil {
		clear(data)
		return nil, ErrUnavailable
	}
	return data, nil
}
