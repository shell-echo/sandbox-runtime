//go:build !linux && !darwin

package restrictedunix

import "net"

func PeerUID(*net.UnixConn, uint32) bool { return false }
