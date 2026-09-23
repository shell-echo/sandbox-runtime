package providerapi

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// PeerRevocationMonitor is a process-local, read-only revocation boundary.
// The HTTP transport owns sockets; the monitor owns only their verified TLS
// states and closes them when a fresh authenticated CRL revokes a peer or the
// source becomes unavailable.
type PeerRevocationMonitor interface {
	Track(net.Conn, tls.ConnectionState) error
	Forget(net.Conn)
	Poll(context.Context) error
	PollInterval() time.Duration
	Ready() bool
	Close()
}

func peerRevocationConnState(monitor PeerRevocationMonitor) func(net.Conn, http.ConnState) {
	if monitor == nil {
		return nil
	}
	return func(connection net.Conn, state http.ConnState) {
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok {
			_ = connection.Close()
			return
		}
		underlying := tlsConnection.NetConn()
		switch state {
		case http.StateActive:
			if !monitor.Ready() || monitor.Track(underlying, tlsConnection.ConnectionState()) != nil {
				_ = connection.Close()
			}
		case http.StateClosed:
			monitor.Forget(underlying)
			// A hijacked private terminal is still live and must remain registered
			// until its bounded underlying connection actually closes.
		}
	}
}

func startPeerRevocationPoll(parent context.Context, monitor PeerRevocationMonitor) func() {
	if monitor == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(monitor.PollInterval())
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = monitor.Poll(ctx)
			}
		}
	}()
	return func() { cancel(); <-done }
}
