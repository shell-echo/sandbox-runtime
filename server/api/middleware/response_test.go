package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/internal"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// newTestHandler builds an http.Handler with the Response middleware and a
// single route running the given gonic handler.
func newTestHandler(debug bool, handler gonic.HandlerFunc) http.Handler {
	gin.SetMode(gin.TestMode)
	e := gonic.New()
	e.Use(Response(debug))
	e.GET("/", handler)
	return e.Handler()
}

func do(t *testing.T, h http.Handler) (int, ResponseJSON) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var resp ResponseJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid envelope %q: %v", rec.Body.String(), err)
	}
	return rec.Code, resp
}

// TestResponseSuccess confirms a value passed to Context.Resp is wrapped in a
// success envelope.
func TestResponseSuccess(t *testing.T) {
	h := newTestHandler(false, func(c *gonic.Context) { c.Resp(gin.H{"k": "v"}) })
	code, resp := do(t, h)

	if code != http.StatusOK {
		t.Errorf("status = %d, want 200", code)
	}
	if !resp.Success || resp.Message != "success" {
		t.Errorf("unexpected envelope: %+v", resp)
	}
	if m, ok := resp.Data.(map[string]any); !ok || m["k"] != "v" {
		t.Errorf("data not carried through: %+v", resp.Data)
	}
}

// TestResponseErrorHidesMessageInProduction confirms an error passed to
// Context.Resp yields a failure envelope with HTTP 500 and a generic message
// when debug is false.
func TestResponseErrorHidesMessageInProduction(t *testing.T) {
	h := newTestHandler(false, func(c *gonic.Context) { c.Resp(errors.New("secret detail")) })
	code, resp := do(t, h)

	if code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", code)
	}
	if resp.Success {
		t.Error("error envelope should have success=false")
	}
	if resp.Message == "secret detail" {
		t.Error("internal error detail leaked in production mode")
	}
}

// TestResponseErrorShowsMessageInDebug confirms the error detail is surfaced
// when debug is true.
func TestResponseErrorShowsMessageInDebug(t *testing.T) {
	h := newTestHandler(true, func(c *gonic.Context) { c.Resp(errors.New("boom detail")) })
	code, resp := do(t, h)

	if code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", code)
	}
	if resp.Message != "boom detail" {
		t.Errorf("debug message = %q, want boom detail", resp.Message)
	}
}

// TestResponseTypedError confirms a typed internal.Error is rendered with its
// own code, status and message, regardless of debug mode.
func TestResponseTypedError(t *testing.T) {
	h := newTestHandler(false, func(c *gonic.Context) { c.Resp(internal.ErrBadRequest.New()) })
	code, resp := do(t, h)

	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
	if resp.Success {
		t.Error("typed error envelope should have success=false")
	}
	if resp.Code != string(internal.ErrBadRequest.Code) {
		t.Errorf("code = %q, want %q", resp.Code, internal.ErrBadRequest.Code)
	}
	if resp.Message != internal.ErrBadRequest.Message {
		t.Errorf("message = %q, want %q", resp.Message, internal.ErrBadRequest.Message)
	}
}

// TestResponsePassthrough confirms the middleware leaves a directly-written
// response untouched (no envelope).
func TestResponsePassthrough(t *testing.T) {
	h := newTestHandler(false, func(c *gonic.Context) { c.String(http.StatusTeapot, "raw") })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTeapot || rec.Body.String() != "raw" {
		t.Errorf("passthrough response altered: code=%d body=%q", rec.Code, rec.Body.String())
	}
}
