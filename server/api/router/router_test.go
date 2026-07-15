package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/driver/fake"
	"github.com/shell-echo/sandbox-runtime/instance"
	"github.com/shell-echo/sandbox-runtime/instance/memory"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// TestInit confirms the routes are registered: /health resolves, and an unknown
// route falls through to the bare-404 NoRoute handler.
func TestInit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := gonic.New()
	e.HandleMethodNotAllowed = true
	service, err := instance.NewService(memory.NewRepository(), fake.NewDriver())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	Init(e, service)
	h := e.Handler()

	// /health is registered (its handler stores a payload via Resp; without the
	// response middleware nothing writes the body, so the status is a bare 200).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health code = %d, want 200", rec.Code)
	}

	// Unknown route -> NoRoute -> bare 404, empty body.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown route code = %d, want 404", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty 404 body, got %q", rec.Body.String())
	}
}
