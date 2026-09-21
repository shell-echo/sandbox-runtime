//go:build linux

package docker

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func peerIsCurrentUser(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	matched := false
	controlErr := raw.Control(func(fd uintptr) {
		credential, credentialErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		matched = credentialErr == nil && credential.Uid == uint32(os.Getuid())
	})
	return controlErr == nil && matched
}
