package process

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shell-echo/sandbox-runtime/option"
)

type checkerFunc func(context.Context) error

func (f checkerFunc) Ready(ctx context.Context) error { return f(ctx) }

func TestProbeRoutesAreClosedAndDependencyDerived(t *testing.T) {
	readyErr := error(nil)
	server, err := NewServer(option.HTTP{Host: "127.0.0.1", Port: 8084}, checkerFunc(func(context.Context) error { return readyErr }))
	if err != nil {
		t.Fatal(err)
	}
	server.serving = true

	for _, test := range []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/livez", http.StatusNoContent},
		{http.MethodGet, "/readyz", http.StatusNoContent},
		{http.MethodGet, "/instances", http.StatusNotFound},
		{http.MethodGet, "/v1/capabilities", http.StatusNotFound},
		{http.MethodPost, "/livez", http.StatusBadRequest},
		{http.MethodGet, "/livez?unexpected=true", http.StatusBadRequest},
	} {
		request := httptest.NewRequest(test.method, test.path, nil)
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, request)
		if response.Code != test.want || response.Body.Len() != 0 {
			t.Fatalf("%s %s = %d %q, want %d and empty body", test.method, test.path, response.Code, response.Body.String(), test.want)
		}
	}

	readyErr = errors.New("database unavailable")
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
		t.Fatalf("failed readiness = %d %q", response.Code, response.Body.String())
	}
}

func TestProbeConfigurationRequiresExplicitLoopback(t *testing.T) {
	checker := checkerFunc(func(context.Context) error { return nil })
	for _, address := range []option.HTTP{{Host: "0.0.0.0", Port: 8084}, {Host: "localhost", Port: 8084}, {Host: "127.0.0.1", Port: 0}} {
		if _, err := NewServer(address, checker); err == nil {
			t.Fatalf("unsafe probe address %#v was accepted", address)
		}
	}
}
