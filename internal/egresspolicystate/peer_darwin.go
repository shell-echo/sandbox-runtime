//go:build darwin

package egresspolicystate

import (
	"net"

	"golang.org/x/sys/unix"
)

func unixPeer(connection *net.UnixConn) (uint32, uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var UID, GID uint32
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		if credentials.Ngroups < 1 {
			socketErr = unix.EINVAL
			return
		}
		UID, GID = credentials.Uid, credentials.Groups[0]
	}); err != nil {
		return 0, 0, err
	}
	return UID, GID, socketErr
}
