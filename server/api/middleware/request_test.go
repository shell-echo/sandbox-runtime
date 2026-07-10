package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// serveRequestID runs a request through the RequestID and AccessLog middleware
// and a handler that echoes the seen request ID into the response body.
func serveRequestID(t *testing.T, inbound string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	e := gonic.New()
	e.Use(RequestID())
	e.Use(AccessLog())
	e.GET("/", func(c *gonic.Context) { c.String(http.StatusOK, c.RequestID()) })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if inbound != "" {
		req.Header.Set(requestIDHeader, inbound)
	}
	e.Handler().ServeHTTP(rec, req)
	return rec
}

// TestRequestIDGenerated confirms a request without an ID gets one, echoed on
// the response header and visible to the handler.
func TestRequestIDGenerated(t *testing.T) {
	rec := serveRequestID(t, "")

	got := rec.Header().Get(requestIDHeader)
	if got == "" {
		t.Fatal("expected a generated X-Request-ID header")
	}
	if len(got) != 32 { // 16 random bytes as hex
		t.Errorf("request ID %q has length %d, want 32 hex chars", got, len(got))
	}
	if rec.Body.String() != got {
		t.Errorf("handler saw request ID %q, response header %q — they must match", rec.Body.String(), got)
	}
}

// TestRequestIDPreserved confirms an inbound X-Request-ID is adopted, not
// replaced.
func TestRequestIDPreserved(t *testing.T) {
	const inbound = "trace-abc-123"
	rec := serveRequestID(t, inbound)

	if got := rec.Header().Get(requestIDHeader); got != inbound {
		t.Errorf("X-Request-ID = %q, want the inbound %q", got, inbound)
	}
	if rec.Body.String() != inbound {
		t.Errorf("handler saw %q, want inbound %q", rec.Body.String(), inbound)
	}
}
