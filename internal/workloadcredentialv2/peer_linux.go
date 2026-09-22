//go:build linux

package workloadcredentialv2

import (
	"net"
	"syscall"
)

func peerCredentials(connection *net.UnixConn) (peerIdentity, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return peerIdentity{}, err
	}
	var identity peerIdentity
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		identity.uid, identity.gid = credentials.Uid, credentials.Gid
	}); err != nil {
		return peerIdentity{}, err
	}
	return identity, socketErr
}
