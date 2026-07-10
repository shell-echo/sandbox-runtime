package gonic

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestContextHelpers covers Wrap and the Resp/RequestID storage helpers.
func TestContextHelpers(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx := Wrap(c)

	if _, ok := ctx.RespData(); ok {
		t.Error("RespData should be absent before Resp")
	}
	ctx.Resp("payload")
	if v, ok := ctx.RespData(); !ok || v != "payload" {
		t.Errorf("RespData() = %v, %v; want payload, true", v, ok)
	}

	if ctx.RequestID() != "" {
		t.Error("RequestID should be empty before SetRequestID")
	}
	ctx.SetRequestID("req-1")
	if ctx.RequestID() != "req-1" {
		t.Errorf("RequestID() = %q, want req-1", ctx.RequestID())
	}
}

// TestEngineVerbs confirms every verb wrapper adapts a gonic HandlerFunc onto
// gin and injects the typed Context, and that NoRoute/NoMethod are wired.
func TestEngineVerbs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := New()
	e.HandleMethodNotAllowed = true

	hit := ""
	handlerFor := func(method string) HandlerFunc {
		return func(c *Context) { hit = method; c.Status(http.StatusOK) }
	}
	e.GET("/r", handlerFor(http.MethodGet))
	e.POST("/r", handlerFor(http.MethodPost))
	e.PUT("/r", handlerFor(http.MethodPut))
	e.PATCH("/r", handlerFor(http.MethodPatch))
	e.DELETE("/r", handlerFor(http.MethodDelete))
	e.GET("/get-only", handlerFor(http.MethodGet))
	e.NoRoute(func(c *Context) { c.Status(http.StatusNotFound) })
	e.NoMethod(func(c *Context) { c.Status(http.StatusMethodNotAllowed) })

	h := e.Handler()

	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/r", nil))
		if rec.Code != http.StatusOK || hit != m {
			t.Errorf("%s /r: code=%d hit=%q", m, rec.Code, hit)
		}
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("NoRoute: code=%d, want 404", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/get-only", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("NoMethod: code=%d, want 405", rec.Code)
	}
}
