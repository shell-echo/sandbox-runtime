//go:build linux

package phase6guestreceipt

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// openIndependentNonblockingPipe reopens only the exact already-open stdout
// FIFO through the platform fd filesystem. Unlike dup, this creates a new
// open-file description, so O_NONBLOCK cannot mutate the original stdout
// flags. CLOEXEC prevents Guest subprocesses from inheriting the receipt fd.
func openIndependentNonblockingPipe(output *os.File) (int, error) {
	raw, err := output.SyscallConn()
	if err != nil {
		return -1, ErrUnavailable
	}
	var originalFD int
	var originalStat unix.Stat_t
	var originalFlags int
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		originalFD = int(fd)
		if originalFD < 0 {
			controlErr = ErrUnavailable
			return
		}
		if controlErr = unix.Fstat(originalFD, &originalStat); controlErr != nil {
			return
		}
		originalFlags, controlErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil || controlErr != nil || originalStat.Mode&unix.S_IFMT != unix.S_IFIFO ||
		originalFlags&unix.O_NONBLOCK != 0 {
		return -1, ErrUnavailable
	}
	opened, err := unix.Open("/proc/self/fd/"+strconv.Itoa(originalFD), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	closeOnError := func() (int, error) {
		_ = unix.Close(opened)
		return -1, ErrUnavailable
	}
	var openedStat unix.Stat_t
	if unix.Fstat(opened, &openedStat) != nil || openedStat.Mode&unix.S_IFMT != unix.S_IFIFO ||
		openedStat.Dev != originalStat.Dev || openedStat.Ino != originalStat.Ino {
		return closeOnError()
	}
	flags, err := unix.FcntlInt(uintptr(opened), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		return closeOnError()
	}
	fdFlags, err := unix.FcntlInt(uintptr(opened), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		return closeOnError()
	}
	currentFlags, err := unix.FcntlInt(uintptr(originalFD), unix.F_GETFL, 0)
	if err != nil || currentFlags&unix.O_NONBLOCK != 0 {
		return closeOnError()
	}
	return opened, nil
}
