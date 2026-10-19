//go:build linux

package phase6fdloader

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"os"
)

func CheckReplyPipe(fd int) error {
	var st unix.Stat_t
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	inherited, ie := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if e != nil || ie != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_NONBLOCK == 0 || inherited&unix.FD_CLOEXEC != 0 || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return ErrInvalid
	}
	return nil
}

type DeliveryChannel struct{ active bool }

// OpenDeliveryChannel takes ownership of FD4 and FD5, including error paths.
func OpenDeliveryChannel(ctx context.Context) (*DeliveryChannel, StartupBinding, error) {
	binding, e := ReadStartupBinding(ctx)
	if e != nil || CheckReplyPipe(4) != nil {
		unix.Close(4)
		return nil, StartupBinding{}, ErrInvalid
	}
	return &DeliveryChannel{active: true}, binding, nil
}
func (c *DeliveryChannel) Close() {
	if c != nil && c.active {
		c.active = false
		unix.Close(4)
	}
}
func (c *DeliveryChannel) ReadReply(ctx context.Context, max int) ([]byte, error) {
	if c == nil || !c.active {
		return nil, ErrInvalid
	}
	c.active = false
	return readReply(ctx, 4, max)
}
func readReply(ctx context.Context, fd, max int) ([]byte, error) {
	defer unix.Close(fd)
	if ctx == nil || ctx.Err() != nil || CheckReplyPipe(fd) != nil {
		return nil, ErrInvalid
	}
	r := deadlineInput{ctx, fd}
	b, e := ReadFrame(r, max)
	if e != nil {
		return nil, e
	}
	var tail [1]byte
	n, e := r.Read(tail[:])
	if n != 0 || e != io.EOF || ctx.Err() != nil {
		clear(b)
		return nil, ErrInvalid
	}
	return b, nil
}

// ReadStartupBinding takes ownership of FD5. The memory must be privately
// owned, sealed, inherited and at offset zero, just like the bootstrap key.
func ReadStartupBinding(ctx context.Context) (StartupBinding, error) {
	defer unix.Close(5)
	var out StartupBinding
	b, e := ReadSealedPrivate(ctx, 5, 1, 2048)
	if e != nil {
		return out, e
	}
	if DecodeCanonical(b, &out) != nil {
		return StartupBinding{}, ErrInvalid
	}
	hostname, e := os.Hostname()
	if e != nil || out.Validate(hostname) != nil {
		return StartupBinding{}, ErrInvalid
	}
	return out, nil
}
func ReadSealedPrivate(ctx context.Context, fd, min, max int) ([]byte, error) {
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	var before, after unix.Stat_t
	flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	inherit, ie := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	valid := func(st unix.Stat_t) bool {
		s, e := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
		return e == nil && s == seals && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Size >= int64(min) && st.Size <= int64(max) && st.Nlink == 0 && st.Uid == uint32(os.Geteuid()) && st.Gid == uint32(os.Getegid())
	}
	if ctx == nil || ctx.Err() != nil || min < 1 || max < min || e != nil || ie != nil || flags&unix.O_ACCMODE != unix.O_RDWR || inherit&unix.FD_CLOEXEC != 0 || unix.Fstat(fd, &before) != nil || !valid(before) {
		return nil, ErrInvalid
	}
	offset, e := unix.Seek(fd, 0, unix.SEEK_CUR)
	if e != nil || offset != 0 {
		return nil, ErrInvalid
	}
	b := make([]byte, int(before.Size))
	n, e := unix.Pread(fd, b, 0)
	if e != nil || n != len(b) || unix.Fstat(fd, &after) != nil || !valid(after) || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || ctx.Err() != nil {
		clear(b)
		return nil, ErrInvalid
	}
	return b, nil
}

// A raw nonblocking writer prevents an unattached or stalled Docker reader
// from holding Control beyond the same operation deadline.
type deadlineOutput struct{ ctx context.Context }

func (w deadlineOutput) Write(b []byte) (int, error) {
	for {
		if w.ctx.Err() != nil {
			return 0, w.ctx.Err()
		}
		fds := []unix.PollFd{{Fd: 1, Events: unix.POLLOUT}}
		n, e := unix.Poll(fds, 100)
		if e == unix.EINTR || n == 0 {
			continue
		}
		if e != nil || fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return 0, ErrInvalid
		}
		n, e = unix.Write(1, b)
		if e == unix.EINTR || e == unix.EAGAIN {
			continue
		}
		return n, e
	}
}
func WriteOutput(ctx context.Context, b []byte, max int) error {
	if ctx == nil || ctx.Err() != nil || unix.SetNonblock(1, true) != nil {
		return ErrInvalid
	}
	return WriteFrame(deadlineOutput{ctx}, b, max)
}
