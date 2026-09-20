// Package process supplies process-only Provider liveness and dependency
// readiness. It intentionally serves no Provider Contract or local /instances
// route and is restricted to an operator-selected loopback listener.
package process

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
)

type Checker interface{ Ready(context.Context) error }

type Server struct {
	http    *http.Server
	checker Checker
	listen  func(context.Context, string, string) (net.Listener, error)
	mu      sync.RWMutex
	serving bool
}

func NewServer(address option.HTTP, checker Checker) (*Server, error) {
	if err := address.Validate(); err != nil || checker == nil {
		return nil, errors.New("invalid Provider process probe configuration")
	}
	ip := net.ParseIP(address.Host)
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("Provider process probe must bind an explicit loopback IP")
	}
	server := &Server{checker: checker}
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", server.livez)
	mux.HandleFunc("/readyz", server.readyz)
	// Keep every non-probe route bodyless. In particular, this listener must
	// never grow a local /instances or Provider Contract surface.
	mux.HandleFunc("/", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusNotFound) })
	server.http = &http.Server{Addr: address.Addr(), Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4 << 10}
	server.listen = (&net.ListenConfig{}).Listen
	return server, nil
}

func (s *Server) Startup(ctx context.Context) error {
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return errors.New("bind Provider process probe")
	}
	s.mu.Lock()
	s.serving = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.serving = false
		s.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return errors.New("serve Provider process probe")
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil {
		return nil
	}
	if err := s.http.Shutdown(ctx); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) livez(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	serving := s.serving
	s.mu.RUnlock()
	if !serving {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) readyz(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.checker.Ready(ctx); err != nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}
