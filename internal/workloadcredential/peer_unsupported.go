//go:build !darwin && !linux

package workloadcredential

import (
	"errors"
	"net"
)

func peerCredentials(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("Unix peer credentials unsupported")
}
