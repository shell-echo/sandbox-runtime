package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit caps bytes read from every request body. Handlers receive
// *http.MaxBytesError when the limit is exceeded and can render a 413 response.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
