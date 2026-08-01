// Package api implements the HTTP API server: a gin engine wrapped in a
// net/http.Server with sensible timeouts, satisfying the server.Server
// lifecycle interface.
package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/instance"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
	"github.com/shell-echo/sandbox-runtime/server/api/middleware"
	"github.com/shell-echo/sandbox-runtime/server/api/router"
)

// Server timeouts. WriteTimeout is left at 0 (no write deadline) so long-lived
// or streamed responses are not cut off; set a bound here if every response is
// expected to be small.
const (
	readHeaderTimeout   = 10 * time.Second
	readTimeout         = 30 * time.Second
	idleTimeout         = 120 * time.Second
	writeTimeout        = 0 * time.Second
	maxRequestBodyBytes = 64 << 10
)

// Server is the HTTP API server. It wraps a net/http.Server and satisfies
// server.Server (Startup/Shutdown).
type Server struct {
	http *http.Server
}

// NewServer builds the API server with its process-scoped dependencies. The
// composition root owns dependency construction; the API layer never chooses a
// runtime backend.
func NewServer(debug bool, opts option.HTTP, instances instance.Service) (*Server, error) {
	if instances == nil {
		return nil, errors.New("instance service is required")
	}

	if debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gonic.New()
	engine.HandleMethodNotAllowed = true // enable 405 (NoMethod) handling
	engine.Use(middleware.Recovery(debug))
	engine.Use(middleware.RequestID())
	engine.Use(middleware.BodyLimit(maxRequestBodyBytes))
	engine.Use(middleware.AccessLog())
	engine.Use(middleware.Response(debug))

	// Trust no proxies by default; client IPs are taken from the direct peer.
	// (Wire this to configuration once reverse-proxy support is needed.)
	if err := engine.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("set trusted proxies: %w", err)
	}

	router.Init(engine, instances)

	return &Server{
		http: &http.Server{
			Addr:              opts.Addr(),
			Handler:           engine.Handler(),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
	}, nil
}

// Startup runs the HTTP server until it is shut down. http.ErrServerClosed is
// the expected error after Shutdown and is not reported.
func (s *Server) Startup(ctx context.Context) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind api server: %w", err)
	}
	stopClosingListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClosingListener()

	if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("start api server: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the HTTP server, honouring the context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
