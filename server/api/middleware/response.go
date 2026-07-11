// Package middleware holds the gin middleware for the API server: request-id
// propagation, access logging, and the uniform response envelope.
package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/internal"
	"github.com/shell-echo/sandbox-runtime/logger"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// ResponseJSON is the uniform JSON envelope returned by all API endpoints,
// matching the shape used across the platform.
type ResponseJSON struct {
	Code    string    `json:"code"`
	Message string    `json:"message"`
	Success bool      `json:"success"`
	Data    any       `json:"data"`
	Time    time.Time `json:"time"`
	Latency int64     `json:"latency"` // handler duration, milliseconds
}

// Response wraps whatever a handler stored via gonic.Context.Resp into the
// uniform envelope, recording the handler latency. A stored error becomes a
// failure envelope (see errorEnvelope); any other value becomes a success
// envelope. Handlers that write the response directly are left untouched.
func Response(debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		if c.Writer.Written() {
			return
		}
		data, ok := gonic.Wrap(c).RespData()
		if !ok {
			return
		}

		now := time.Now()
		latency := now.Sub(start).Milliseconds()

		if err, ok := data.(error); ok {
			c.JSON(errorEnvelope(c, err, debug, now, latency))
			return
		}

		c.JSON(http.StatusOK, ResponseJSON{
			Code:    "ok",
			Message: "success",
			Success: true,
			Data:    data,
			Time:    now,
			Latency: latency,
		})
	}
}

// errorEnvelope maps err to an HTTP status and failure envelope. A typed
// internal.Error carries its own code, status and message; any other error is
// logged as unexpected and rendered as a generic 500 whose detail is shown only
// when debug is true, so production responses never leak internals.
func errorEnvelope(c *gin.Context, err error, debug bool, now time.Time, latency int64) (int, ResponseJSON) {
	var typed *internal.Error
	if errors.As(err, &typed) {
		status := typed.Status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		return status, ResponseJSON{
			Code:    string(typed.Code),
			Message: typed.Message(),
			Success: false,
			Time:    now,
			Latency: latency,
		}
	}

	logger.With(
		logger.String("method", c.Request.Method),
		logger.String("path", c.Request.URL.Path),
		logger.String("error", err.Error()),
	).Error("unhandled response error")

	message := internal.ErrSystem.Message
	if debug {
		message = err.Error()
	}
	return http.StatusInternalServerError, ResponseJSON{
		Code:    string(internal.ErrSystem.Code),
		Message: message,
		Success: false,
		Time:    now,
		Latency: latency,
	}
}
