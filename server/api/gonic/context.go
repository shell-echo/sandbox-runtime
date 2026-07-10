// Package gonic wraps gin with a typed Context so handlers are written as
// func(*Context) and return their result via Context.Resp, which the response
// middleware renders into the uniform envelope. It is also the natural home for
// per-request helpers (auth user, bearer token, ...) added later.
package gonic

import "github.com/gin-gonic/gin"

// Context wraps *gin.Context with response helpers.
type Context struct {
	*gin.Context
}

// HandlerFunc is a gonic route handler.
type HandlerFunc func(*Context)

// Wrap adapts a *gin.Context into a *Context, for use in plain gin middleware
// that needs the gonic helpers.
func Wrap(c *gin.Context) *Context {
	return &Context{Context: c}
}

// respDataKey is the gin context key under which Resp stashes the payload.
const respDataKey = "api.response.data"

// Resp stores the handler's result — a value on success, or an error — for the
// response middleware to wrap into the envelope. Handlers call this instead of
// writing the response body themselves.
func (c *Context) Resp(data any) {
	c.Context.Set(respDataKey, data)
}

// RespData returns the value stored by Resp, if any.
func (c *Context) RespData() (any, bool) {
	return c.Context.Get(respDataKey)
}

// requestIDKey is the gin context key under which the request ID is stored.
const requestIDKey = "api.request.id"

// SetRequestID stores the request's correlation ID.
func (c *Context) SetRequestID(id string) {
	c.Context.Set(requestIDKey, id)
}

// RequestID returns the request's correlation ID, or "" if none was set.
func (c *Context) RequestID() string {
	if v, ok := c.Context.Get(requestIDKey); ok {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}
