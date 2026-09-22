//go:build linux

package workloadtlsagent

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
	var operationErr error
	err = raw.Control(func(fd uintptr) {
		credentials, credentialErr := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if credentialErr != nil {
			operationErr = credentialErr
			return
		}
		identity.uid, identity.gid = credentials.Uid, credentials.Gid
	})
	if err != nil {
		return peerIdentity{}, err
	}
	return identity, operationErr
}
