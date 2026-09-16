//go:build darwin || linux

package qualificationsupervisor

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Resolve each component from an open directory. O_NONBLOCK ensures a FIFO
// supplied as the final component is rejected without waiting for a writer.
func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrExecutable
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		var before unix.Stat_t
		if i == len(parts)-1 {
			if unix.Fstatat(fd, part, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
				_ = unix.Close(fd)
				return nil, ErrExecutable
			}
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		closeErr := unix.Close(fd)
		if err != nil {
			return nil, ErrExecutable
		}
		if closeErr != nil {
			_ = unix.Close(next)
			return nil, ErrExecutable
		}
		fd = next
		if i == len(parts)-1 {
			var after unix.Stat_t
			if unix.Fstat(fd, &after) != nil || after.Mode&unix.S_IFMT != unix.S_IFREG || before.Dev != after.Dev || before.Ino != after.Ino {
				_ = unix.Close(fd)
				return nil, ErrExecutable
			}
		}
	}
	return os.NewFile(uintptr(fd), "adapter-executable"), nil
}

func admissibleFile(info os.FileInfo, limit int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || info.Mode().Perm()&0111 == 0 ||
		info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
