//go:build !linux && !darwin

package workloadcredentialv2

import (
	"errors"
	"net"
)

func peerCredentials(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("unix peer credentials unsupported")
}
