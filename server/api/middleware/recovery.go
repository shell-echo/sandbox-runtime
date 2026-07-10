package middleware

import (
	"errors"
	"fmt"
	"net/http"
	rdebug "runtime/debug"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shell-echo/sandbox-runtime/internal"
	"github.com/shell-echo/sandbox-runtime/logger"
	"github.com/shell-echo/sandbox-runtime/server/api/gonic"
)

// Recovery recovers from panics in downstream middleware and handlers. It logs
// the panic with a stack trace (correlated by request ID) and, unless the
// client connection is broken or a response was already written, renders the
// uniform 500 error envelope. When debug is true the panic value is included in
// the response message; otherwise a generic message is returned so internals
// are not leaked in production.
func Recovery(debug bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				handlePanic(c, r, debug)
			}
		}()
		c.Next()
	}
}

func handlePanic(c *gin.Context, r any, debug bool) {
	log := logger.With(
		logger.String("request_id", gonic.Wrap(c).RequestID()),
		logger.String("method", c.Request.Method),
		logger.String("path", c.Request.URL.Path),
		logger.Any("panic", r),
	)

	// A broken client connection is not our fault and cannot be written to.
	if err, ok := r.(error); ok && isBrokenPipe(err) {
		log.Error("recovered broken connection")
		_ = c.Error(err)
		c.Abort()
		return
	}

	log.With(logger.String("stack", string(rdebug.Stack()))).Error("recovered panic")

	// If the handler already started writing, the response cannot be replaced.
	if c.Writer.Written() {
		c.Abort()
		return
	}

	message := internal.ErrSystem.Message
	if debug {
		message = fmt.Sprintf("panic: %v", r)
	}
	c.JSON(http.StatusInternalServerError, ResponseJSON{
		Code:    string(internal.ErrSystem.Code),
		Message: message,
		Success: false,
		Time:    time.Now(),
	})
	c.Abort()
}

// isBrokenPipe reports whether err is a broken client connection, for which no
// response can be written.
func isBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, http.ErrAbortHandler)
}
