// Package router registers the API's HTTP routes on a gonic engine.
package router

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/instance"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// Init wires all routes and the not-found / method-not-allowed handlers onto
// engine. Application handlers return their payload (or an error) through the
// uniform response envelope via Context.Resp; add them here.
func Init(engine *gonic.Engine, instances instance.Service) {
	// Unknown route / method: return only the status code with an empty body so
	// the browser shows its own default page.
	engine.NoRoute(func(c *gonic.Context) { c.AbortWithStatus(http.StatusNotFound) })
	engine.NoMethod(func(c *gonic.Context) { c.AbortWithStatus(http.StatusMethodNotAllowed) })

	engine.GET("/health", func(c *gonic.Context) {
		c.Resp(gin.H{"status": "ok"})
	})

	h := instanceHandler{service: instances}
	engine.POST("/instances", h.create)
	engine.GET("/instances", h.list)
	engine.GET("/instances/:id", h.inspect)
	engine.POST("/instances/:id/start", h.start)
	engine.POST("/instances/:id/stop", h.stop)
	engine.DELETE("/instances/:id", h.remove)
}
