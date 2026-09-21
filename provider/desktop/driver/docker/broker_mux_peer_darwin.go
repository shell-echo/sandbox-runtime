//go:build darwin

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
		credential, credentialErr := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		matched = credentialErr == nil && credential.Uid == uint32(os.Getuid())
	})
	return controlErr == nil && matched
}
