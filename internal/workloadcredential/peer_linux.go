//go:build linux

package workloadcredential

import (
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(connection *net.UnixConn) (peerIdentity, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return peerIdentity{}, err
	}
	var identity peerIdentity
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		identity = peerIdentity{uid: credentials.Uid, gid: credentials.Gid}
	}); err != nil {
		return peerIdentity{}, err
	}
	return identity, controlErr
}
