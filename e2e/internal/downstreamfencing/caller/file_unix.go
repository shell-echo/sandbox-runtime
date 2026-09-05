//go:build darwin || linux

package caller

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readBoundedRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open bounded regular file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum || (private && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("file is not a bounded private regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		return nil, errors.New("file exceeds its byte limit")
	}
	return contents, nil
}
