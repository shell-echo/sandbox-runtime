package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
)

// TestHealth drives the /health route through the server's full handler chain
// (including the body-limit wrapper) without opening a socket.
func TestHealth(t *testing.T) {
	srv, err := NewServer(false, option.HTTP{Host: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	srv.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"success":true`) || !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("unexpected envelope body: %s", body)
	}
}

// TestNotFound confirms unknown routes return a bare 404 with no body, so the
// browser renders its own default page.
func TestNotFound(t *testing.T) {
	srv, err := NewServer(false, option.HTTP{Host: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	srv.http.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty body, got %q", rec.Body.String())
	}
}

// TestStartupShutdown exercises the real lifecycle: the server binds a port,
// serves /healthz, and shuts down cleanly.
func TestStartupShutdown(t *testing.T) {
	port := freePort(t)
	srv, err := NewServer(false, option.HTTP{Host: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Startup() }()

	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	resp := getWithRetry(t, url)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	_ = resp.Body.Close()

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-errc; err != nil {
		t.Errorf("Startup returned: %v", err)
	}
}

// freePort returns a currently-free TCP port on the loopback interface.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// getWithRetry polls url until the server is accepting connections.
func getWithRetry(t *testing.T, url string) *http.Response {
	t.Helper()
	var lastErr error
	for i := 0; i < 100; i++ {
		resp, err := http.Get(url)
		if err == nil {
			return resp
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server never became ready: %v", lastErr)
	return nil
}
