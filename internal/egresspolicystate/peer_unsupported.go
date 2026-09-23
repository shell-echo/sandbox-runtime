//go:build !linux && !darwin

package egresspolicystate

import "net"

func unixPeer(*net.UnixConn) (uint32, uint32, error) { return 0, 0, ErrInvalid }
