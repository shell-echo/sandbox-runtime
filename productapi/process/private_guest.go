package process

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/option"
)

// PrivateGuestServer serves only Product's outbound-Guest WebSocket receiver.
// It is physically separate from the public Product API listener.
type PrivateGuestServer struct {
	http        *http.Server
	connections *connectiondrain.Registry
	peer        connectiondrain.PeerMonitor
	listen      func(context.Context, string, string) (net.Listener, error)
}

func NewPrivateGuestServer(address option.HTTP, hub http.Handler, transport *tls.Config,
	peer connectiondrain.PeerMonitor, maxAge time.Duration) (*PrivateGuestServer, error) {
	if address.Validate() != nil || net.ParseIP(address.Host) == nil || isNil(hub) ||
		transport == nil || transport.MinVersion != tls.VersionTLS13 || transport.MaxVersion != tls.VersionTLS13 ||
		transport.ClientAuth != tls.RequireAndVerifyClientCert || transport.ClientCAs == nil ||
		transport.GetCertificate == nil || transport.VerifyConnection == nil || len(transport.Certificates) != 0 ||
		transport.InsecureSkipVerify || !transport.SessionTicketsDisabled ||
		peer == nil || peer.PollInterval() < 100*time.Millisecond || peer.PollInterval() > time.Minute {
		return nil, errors.New("Product private Guest transport is invalid")
	}
	connections, err := connectiondrain.New(maxAge)
	if err != nil || connections.OnClose(peer.Forget) != nil {
		return nil, errors.New("Product private Guest connection drain is invalid")
	}
	privateHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if request.URL.Path != "/agent" || request.URL.RawQuery != "" {
			http.NotFound(writer, request)
			return
		}
		if !peer.Ready() {
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		hub.ServeHTTP(writer, request)
	})
	return &PrivateGuestServer{http: &http.Server{
		Addr: address.Addr(), Handler: privateHandler, TLSConfig: transport.Clone(),
		ConnState:         connectiondrain.PeerConnState(peer),
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout,
		WriteTimeout: writeTimeout, IdleTimeout: idleTimeout, MaxHeaderBytes: maxHeaderBytes,
	}, connections: connections, peer: peer, listen: (&net.ListenConfig{}).Listen}, nil
}

func (s *PrivateGuestServer) Startup(ctx context.Context) error {
	if s == nil || s.http == nil || ctx == nil {
		return errors.New("Product private Guest server is not initialized")
	}
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return errors.New("bind Product private Guest listener")
	}
	defer listener.Close()
	tracked, err := s.connections.Wrap(listener)
	if err != nil {
		return errors.New("track Product private Guest connections")
	}
	defer s.connections.Drain()
	defer s.peer.Close()
	stopPeerPoll := connectiondrain.StartPeerPoll(ctx, s.peer)
	defer stopPeerPoll()
	stop := context.AfterFunc(ctx, func() { _ = tracked.Close() })
	defer stop()
	if err := s.http.ServeTLS(tracked, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) &&
		!(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return errors.New("serve Product private Guest listener")
	}
	return nil
}

func (s *PrivateGuestServer) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return nil
	}
	s.connections.Drain()
	s.peer.Close()
	if err := s.http.Shutdown(ctx); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
