//go:build !linux && !darwin

package workloadagent

import (
	"errors"
	"net"
)

func peerCredentials(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("Unix peer credentials are unsupported")
}
