//go:build linux

package egresspolicystate

import (
	"net"
	"syscall"
)

func unixPeer(connection *net.UnixConn) (uint32, uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var UID, GID uint32
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		UID, GID = credentials.Uid, credentials.Gid
	}); err != nil {
		return 0, 0, err
	}
	return UID, GID, socketErr
}
