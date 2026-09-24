package roleprocess

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
)

// newPrivateTLSServerLive is the exclusive remote-signer transport for a
// Browser or Desktop v3 private attach listener. The caller still owns
// signer/source readiness and the exact profile/edge authorization.
func newPrivateTLSServerLive(address string, handler http.Handler, transport *tls.Config,
	peer connectiondrain.PeerMonitor, maxAge time.Duration) (*privateTLSServer, error) {
	if address == "" || handler == nil || transport == nil ||
		transport.MinVersion != tls.VersionTLS13 || transport.MaxVersion != tls.VersionTLS13 ||
		transport.ClientAuth != tls.RequireAndVerifyClientCert || transport.ClientCAs == nil ||
		transport.GetCertificate == nil || transport.VerifyConnection == nil || len(transport.Certificates) != 0 ||
		transport.InsecureSkipVerify || !transport.SessionTicketsDisabled ||
		peer == nil || peer.PollInterval() < 100*time.Millisecond || peer.PollInterval() > time.Minute {
		return nil, errors.New("private role live TLS configuration is invalid")
	}
	connections, err := connectiondrain.New(maxAge)
	if err != nil || connections.OnClose(peer.Forget) != nil {
		return nil, errors.New("private role connection drain is unavailable")
	}
	transport = transport.Clone()
	return &privateTLSServer{config: transport, connections: connections, peer: peer,
		http: &http.Server{Addr: address, Handler: handler, TLSConfig: transport,
			ConnState:         connectiondrain.PeerConnState(peer),
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10},
		listen: (&net.ListenConfig{}).Listen}, nil
}

func privatePeerReady(ctx context.Context, peer connectiondrain.PeerMonitor,
	signerProbe func(context.Context) error) error {
	if ctx == nil || peer == nil || signerProbe == nil || signerProbe(ctx) != nil ||
		peer.Poll(ctx) != nil || !peer.Ready() {
		return errors.New("private role live TLS peer source is unavailable")
	}
	return nil
}
