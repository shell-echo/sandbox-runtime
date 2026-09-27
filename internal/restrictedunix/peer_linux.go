//go:build linux

package restrictedunix

import (
	"net"

	"golang.org/x/sys/unix"
)

func PeerUID(connection *net.UnixConn, expected uint32) bool {
	if connection == nil {
		return false
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	matched := false
	err = raw.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		matched = credentialErr == nil && credential.Uid == expected
	})
	return err == nil && matched
}
