package connectiondrain

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// PeerMonitor is a transport-independent revocation boundary. The HTTP
// server owns its sockets; the monitor owns their verified TLS states and
// closes them on revocation or authenticated-source loss.
type PeerMonitor interface {
	Track(net.Conn, tls.ConnectionState) error
	Forget(net.Conn)
	Poll(context.Context) error
	PollInterval() time.Duration
	Ready() bool
	Close()
}

// PeerConnState retains hijacked connections until the underlying tracked
// socket closes. Registry.OnClose must call monitor.Forget for exact cleanup.
func PeerConnState(monitor PeerMonitor) func(net.Conn, http.ConnState) {
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
			// StateHijacked is intentionally retained. The registry's close hook
			// handles upgrade teardown and bounded connection expiry.
		}
	}
}

// StartPeerPoll runs bounded refreshes until the server context is canceled
// or the returned stop function is called. Stop waits for an in-flight pull.
func StartPeerPoll(parent context.Context, monitor PeerMonitor) func() {
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
