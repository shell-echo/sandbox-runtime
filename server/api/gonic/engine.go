package gonic

import "github.com/gin-gonic/gin"

// Engine wraps *gin.Engine so route handlers are gonic HandlerFuncs. Middleware
// registration (Use), Handler, SetTrustedProxies, etc. are promoted unchanged
// from the embedded *gin.Engine.
type Engine struct {
	*gin.Engine
}

// New returns a gonic Engine wrapping a bare gin engine (no default middleware).
func New() *Engine {
	return &Engine{Engine: gin.New()}
}

// wrap adapts gonic handlers to gin handlers by injecting the typed Context.
func wrap(handlers []HandlerFunc) []gin.HandlerFunc {
	out := make([]gin.HandlerFunc, len(handlers))
	for i, h := range handlers {
		h := h
		out[i] = func(c *gin.Context) { h(&Context{Context: c}) }
	}
	return out
}

func (e *Engine) GET(path string, handlers ...HandlerFunc) gin.IRoutes {
	return e.Engine.GET(path, wrap(handlers)...)
}

func (e *Engine) POST(path string, handlers ...HandlerFunc) gin.IRoutes {
	return e.Engine.POST(path, wrap(handlers)...)
}

func (e *Engine) PUT(path string, handlers ...HandlerFunc) gin.IRoutes {
	return e.Engine.PUT(path, wrap(handlers)...)
}

func (e *Engine) PATCH(path string, handlers ...HandlerFunc) gin.IRoutes {
	return e.Engine.PATCH(path, wrap(handlers)...)
}

func (e *Engine) DELETE(path string, handlers ...HandlerFunc) gin.IRoutes {
	return e.Engine.DELETE(path, wrap(handlers)...)
}

// NoRoute sets the handlers invoked when no route matches (HTTP 404).
func (e *Engine) NoRoute(handlers ...HandlerFunc) {
	e.Engine.NoRoute(wrap(handlers)...)
}

// NoMethod sets the handlers invoked when the path exists but the method is not
// allowed (HTTP 405). Requires HandleMethodNotAllowed to be enabled.
func (e *Engine) NoMethod(handlers ...HandlerFunc) {
	e.Engine.NoMethod(wrap(handlers)...)
}
