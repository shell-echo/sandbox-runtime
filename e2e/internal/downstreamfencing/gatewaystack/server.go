package gatewaystack

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"
)

const maxPublicConnections = 10_000

type publicServer struct {
	http   *http.Server
	listen func(context.Context, string, string) (net.Listener, error)
}

func newPublicServer(address string, handler http.Handler, tlsConfig *tls.Config) (*publicServer, error) {
	if handler == nil || tlsConfig == nil {
		return nil, errors.New("public server configuration is invalid")
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	listenConfig := &net.ListenConfig{}
	return &publicServer{
		http: &http.Server{
			Addr: address, Handler: handler, TLSConfig: tlsConfig.Clone(), Protocols: protocols,
			ReadHeaderTimeout: time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10,
		},
		listen: listenConfig.Listen,
	}, nil
}

func (s *publicServer) Startup(ctx context.Context) error {
	if s == nil || s.http == nil || s.listen == nil || ctx == nil {
		return errors.New("Browser public-edge server is unavailable")
	}
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return errors.New("bind Browser public edge")
	}
	limited := netutil.LimitListener(listener, maxPublicConnections)
	stop := context.AfterFunc(ctx, func() { _ = limited.Close() })
	defer stop()
	if err := s.http.ServeTLS(limited, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) &&
		!(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return errors.New("serve Browser public edge")
	}
	return nil
}

func (s *publicServer) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil || ctx == nil {
		return errors.New("Browser public-edge server is unavailable")
	}
	err := s.http.Shutdown(ctx)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
