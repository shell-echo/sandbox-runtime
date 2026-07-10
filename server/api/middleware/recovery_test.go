package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/internal"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// servePanic runs a handler that panics through the Recovery and Response
// middleware, returning the recorded status and decoded envelope.
func servePanic(t *testing.T, debug bool, panicVal any) (int, ResponseJSON) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	e := gonic.New()
	e.Use(Recovery(debug))
	e.Use(Response(debug))
	e.GET("/", func(c *gonic.Context) { panic(panicVal) })

	rec := httptest.NewRecorder()
	e.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	var resp ResponseJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid envelope %q: %v", rec.Body.String(), err)
	}
	return rec.Code, resp
}

// TestRecoveryRendersEnvelope confirms a panic is converted into the uniform
// 500 error envelope, without leaking the panic detail in production mode.
func TestRecoveryRendersEnvelope(t *testing.T) {
	code, resp := servePanic(t, false, "boom")

	if code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", code)
	}
	if resp.Success {
		t.Error("panic envelope should have success=false")
	}
	if resp.Code != string(internal.ErrSystem.Code) {
		t.Errorf("code = %q, want %q", resp.Code, internal.ErrSystem.Code)
	}
	if strings.Contains(resp.Message, "boom") {
		t.Error("panic detail leaked in production mode")
	}
}

// TestRecoveryDebugIncludesPanic confirms the panic detail is surfaced in the
// message when debug is true.
func TestRecoveryDebugIncludesPanic(t *testing.T) {
	_, resp := servePanic(t, true, "boom")

	if !strings.Contains(resp.Message, "boom") {
		t.Errorf("debug message = %q, want it to contain the panic value", resp.Message)
	}
}
