package middleware

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/logger"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// AccessLog logs one line per request after it completes, at Info level,
// including the request ID, method, path, client IP, final status and latency.
// Access logs are therefore visible when the logger level is info or lower.
func AccessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		logger.With(
			logger.String("request_id", gonic.Wrap(c).RequestID()),
			logger.String("method", c.Request.Method),
			logger.String("path", c.Request.URL.Path),
			logger.String("query", c.Request.URL.RawQuery),
			logger.String("client_ip", c.ClientIP()),
			logger.Any("status", c.Writer.Status()),
			logger.Any("latency_ms", time.Since(start).Milliseconds()),
		).Info("api.request")
	}
}
