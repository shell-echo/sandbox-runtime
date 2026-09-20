// Package process implements the independent Product HTTP process transport.
// It keeps process probes separate from Product capability readiness.
package process

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 32 << 10
)

// Readiness checks only process-level dependencies. A successful result does
// not imply that any Product capability is ready.
type Readiness interface {
	Ready(context.Context) error
}

type ReadinessFunc func(context.Context) error

func (f ReadinessFunc) Ready(ctx context.Context) error { return f(ctx) }

type Server struct {
	http *http.Server
}

func NewServer(address option.HTTP, api http.Handler, readiness Readiness) (*Server, error) {
	if err := address.Validate(); err != nil {
		return nil, fmt.Errorf("Product API address: %w", err)
	}
	if isNil(api) || isNil(readiness) {
		return nil, errors.New("Product API and readiness dependencies are required")
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.HandleFunc("/livez", func(writer http.ResponseWriter, request *http.Request) {
		if !getOnly(writer, request) {
			return
		}
		writeStatus(writer, http.StatusOK, "live")
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, request *http.Request) {
		if !getOnly(writer, request) {
			return
		}
		if err := readiness.Ready(request.Context()); err != nil {
			writeStatus(writer, http.StatusServiceUnavailable, "not_ready")
			return
		}
		writeStatus(writer, http.StatusOK, "ready")
	})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(writer, request)
	})
	return &Server{http: &http.Server{
		Addr: address.Addr(), Handler: handler, ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout,
		MaxHeaderBytes: maxHeaderBytes,
	}}, nil
}

func (s *Server) Startup(ctx context.Context) error {
	if s == nil || s.http == nil {
		return errors.New("Product server is not initialized")
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind Product API: %w", err)
	}
	stopClosing := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClosing()
	if err := s.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("serve Product API: %w", err)
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

func getOnly(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method == http.MethodGet {
		return true
	}
	writer.Header().Set("Allow", http.MethodGet)
	writeStatus(writer, http.StatusMethodNotAllowed, "method_not_allowed")
	return false
}

func writeStatus(writer http.ResponseWriter, status int, value string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Status string `json:"status"`
	}{Status: value})
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
