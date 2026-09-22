//go:build !darwin && !linux

package workloadtlsagent

import (
	"errors"
	"net"
)

func peerCredentials(*net.UnixConn) (peerIdentity, error) {
	return peerIdentity{}, errors.New("unsupported peer credentials")
}
