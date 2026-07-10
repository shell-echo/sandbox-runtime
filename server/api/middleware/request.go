package middleware

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// requestIDHeader is the header carrying the request correlation ID, both
// inbound (to adopt an upstream ID) and outbound (echoed on the response).
const requestIDHeader = "X-Request-ID"

// RequestID ensures every request has a correlation ID: it adopts an inbound
// X-Request-ID when present, otherwise generates one, stores it on the context
// for handlers and later middleware, and echoes it on the response.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(requestIDHeader)
		if id == "" {
			id = newRequestID()
		}
		gonic.Wrap(c).SetRequestID(id)
		c.Header(requestIDHeader, id)
		c.Next()
	}
}

// newRequestID returns a random 128-bit hex ID. crypto/rand.Read does not fail
// in practice; on the astronomically unlikely error the zeroed value is used.
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
