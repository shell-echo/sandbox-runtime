//go:build !darwin && !linux

package breakglass

import (
	"errors"
	"net"
)

func peerCredentials(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("Unix peer credentials unsupported")
}
