//go:build !linux && !darwin

package workloadpki

import (
	"errors"
	"net"
)

func peerCredentials(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("unix peer credentials unsupported")
}
