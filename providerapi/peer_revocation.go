package providerapi

import (
	"context"
	"net"
	"net/http"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
)

// PeerRevocationMonitor is the Provider transport's view of the shared
// connection-drain boundary; the Provider API does not own CRL policy.
type PeerRevocationMonitor = connectiondrain.PeerMonitor

func peerRevocationConnState(monitor PeerRevocationMonitor) func(net.Conn, http.ConnState) {
	return connectiondrain.PeerConnState(monitor)
}

func startPeerRevocationPoll(parent context.Context, monitor PeerRevocationMonitor) func() {
	return connectiondrain.StartPeerPoll(parent, monitor)
}
