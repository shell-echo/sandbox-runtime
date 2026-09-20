package process

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/option"
)

func TestProcessProbesAndAPIBoundary(t *testing.T) {
	ready := false
	api := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
	})
	server, err := NewServer(option.HTTP{Host: "127.0.0.1", Port: 8082}, api, ReadinessFunc(func(context.Context) error {
		if !ready {
			return errors.New("dependency unavailable")
		}
		return nil
	}))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	assertResponse(t, server.http.Handler, http.MethodGet, "/livez", http.StatusOK, `"status":"live"`)
	assertResponse(t, server.http.Handler, http.MethodGet, "/readyz", http.StatusServiceUnavailable, `"status":"not_ready"`)
	ready = true
	assertResponse(t, server.http.Handler, http.MethodGet, "/readyz", http.StatusOK, `"status":"ready"`)
	assertResponse(t, server.http.Handler, http.MethodGet, "/api/v1/capabilities", http.StatusTeapot, "")
	assertResponse(t, server.http.Handler, http.MethodPost, "/readyz", http.StatusMethodNotAllowed, `"status":"method_not_allowed"`)
}

func TestNewServerRequiresDependencies(t *testing.T) {
	address := option.HTTP{Host: "127.0.0.1", Port: 8082}
	if _, err := NewServer(address, nil, ReadinessFunc(func(context.Context) error { return nil })); err == nil {
		t.Fatal("accepted nil API")
	}
	if _, err := NewServer(address, http.NotFoundHandler(), nil); err == nil {
		t.Fatal("accepted nil readiness")
	}
}

func TestNewTLSServerRequiresTLS13Certificate(t *testing.T) {
	address := option.HTTP{Host: "127.0.0.1", Port: 8082}
	ready := ReadinessFunc(func(context.Context) error { return nil })
	if _, err := NewTLSServer(address, http.NotFoundHandler(), ready, nil); err == nil {
		t.Fatal("accepted nil TLS")
	}
	if _, err := NewTLSServer(address, http.NotFoundHandler(), ready, &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{}}}); err == nil {
		t.Fatal("accepted TLS 1.2")
	}
	server, err := NewTLSServer(address, http.NotFoundHandler(), ready, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{}}})
	if err != nil {
		t.Fatalf("NewTLSServer: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/livez", nil)
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, request)
	if response.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("TLS response missing HSTS")
	}
}

func assertResponse(t *testing.T, handler http.Handler, method, path string, status int, contains string) {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("%s %s status = %d, want %d", method, path, response.Code, status)
	}
	if contains != "" && !strings.Contains(response.Body.String(), contains) {
		t.Fatalf("%s %s body = %q", method, path, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%s %s missing no-store", method, path)
	}
}
