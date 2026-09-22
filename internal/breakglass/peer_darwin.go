//go:build darwin

package breakglass

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
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		if credentials.Ngroups < 1 {
			controlErr = unix.EINVAL
			return
		}
		identity = peerIdentity{uid: credentials.Uid, gid: credentials.Groups[0]}
	}); err != nil {
		return peerIdentity{}, err
	}
	return identity, controlErr
}
