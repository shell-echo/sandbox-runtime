// Package api implements the HTTP API server: a gin engine wrapped in a
// net/http.Server with sensible timeouts, satisfying the server.Server
// lifecycle interface.
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
	"github.com/shell-echo/sandbox-runtime/server/api/middleware"
	"github.com/shell-echo/sandbox-runtime/server/api/router"
)

// Server timeouts. WriteTimeout is left at 0 (no write deadline) so long-lived
// or streamed responses are not cut off; set a bound here if every response is
// expected to be small.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	idleTimeout       = 120 * time.Second
	writeTimeout      = 0 * time.Second
)

// Server is the HTTP API server. It wraps a net/http.Server and satisfies
// server.Server (Startup/Shutdown).
type Server struct {
	http *http.Server
}

// NewServer builds the API server for the given listener options. When debug is
// true the gin engine runs in debug mode with verbose output. It returns an
// error if the trusted-proxy configuration is rejected by gin.
func NewServer(debug bool, opts option.HTTP) (*Server, error) {
	if debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gonic.New()
	engine.HandleMethodNotAllowed = true // enable 405 (NoMethod) handling
	engine.Use(middleware.Recovery(debug))
	engine.Use(middleware.RequestID())
	engine.Use(middleware.AccessLog())
	engine.Use(middleware.Response(debug))

	// Trust no proxies by default; client IPs are taken from the direct peer.
	// (Wire this to configuration once reverse-proxy support is needed.)
	if err := engine.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("set trusted proxies: %w", err)
	}

	router.Init(engine)

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
func (s *Server) Startup() error {
	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("start api server: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the HTTP server, honouring the context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
