//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func openDirectoryPin(ctx context.Context, path string) (*directoryPin, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrLocationFiles
	}
	file := os.NewFile(uintptr(fd), "location-directory")
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ErrLocationFiles
	}
	pin := &directoryPin{path: path, ancestors: []os.FileInfo{info}}
	if path != "/" {
		for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			if err := contextFailure(ctx); err != nil {
				_ = file.Close()
				return nil, err
			}
			next, err := unix.Openat(int(file.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
			closeErr := file.Close()
			if err != nil {
				return nil, ErrLocationFiles
			}
			file = os.NewFile(uintptr(next), "location-directory")
			if closeErr != nil {
				_ = file.Close()
				return nil, ErrLocationFiles
			}
			info, err = file.Stat()
			if err != nil {
				_ = file.Close()
				return nil, ErrLocationFiles
			}
			pin.ancestors = append(pin.ancestors, info)
		}
	}
	pin.file, pin.info = file, info
	return pin, nil
}

func admissibleProfile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxLocationProfileBytes ||
		info.Mode().Perm()&0222 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1 && (stat.Uid == uint32(os.Geteuid()) || stat.Uid == 0)
}

func admissibleDirectory(info os.FileInfo, private bool) bool {
	if info == nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if private {
		return info.Mode().Perm() == 0700 && stat.Uid == uint32(os.Geteuid())
	}
	return stat.Uid == uint32(os.Geteuid()) || stat.Uid == 0
}

func sameDirectory(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.IsDir() || !b.IsDir() || !os.SameFile(a, b) || a.Mode() != b.Mode() {
		return false
	}
	return sameOwnership(a, b)
}

func sameProfileSnapshot(a, b os.FileInfo) bool {
	return sameSnapshot(a, b) && sameOwnership(a, b)
}

func sameOwnership(a, b os.FileInfo) bool {
	sa, aok := a.Sys().(*syscall.Stat_t)
	sb, bok := b.Sys().(*syscall.Stat_t)
	return aok && bok && sa.Uid == sb.Uid && sa.Gid == sb.Gid
}

func createStateDirectory(parent *os.File, leaf string) (bool, error) {
	if unix.Mkdirat(int(parent.Fd()), leaf, 0700) != nil {
		return false, ErrLocationFiles
	}
	return true, nil
}

func stateMatchesParent(parent *os.File, leaf string, info os.FileInfo) bool {
	var current unix.Stat_t
	if unix.Fstatat(int(parent.Fd()), leaf, &current, unix.AT_SYMLINK_NOFOLLOW) != nil || current.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == uint64(current.Dev) && stat.Ino == current.Ino
}
