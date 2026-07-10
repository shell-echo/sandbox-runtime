// Package internal holds application-internal types shared across packages,
// notably the typed error model that drives consistent API error responses.
package internal

import (
	"fmt"
	"net/http"
)

// ErrorCode is a stable, machine-readable error identifier, e.g. "system.error".
type ErrorCode string

// ErrorDef defines a kind of error: its stable code, the HTTP status to return,
// and a message (a fmt template when combined with Newf/Wrap args). Declare one
// per error via def in error_codes.go.
type ErrorDef struct {
	Code    ErrorCode
	Status  int
	Message string
}

// New returns a fresh Error of this kind.
func (d ErrorDef) New() *Error {
	return &Error{Code: d.Code, Status: d.Status, message: d.Message}
}

// Newf returns an Error whose message template is formatted with args.
func (d ErrorDef) Newf(args ...any) *Error {
	return &Error{Code: d.Code, Status: d.Status, message: d.Message, args: args}
}

// Wrap returns an Error of this kind wrapping cause (retrievable via errors.Unwrap).
func (d ErrorDef) Wrap(cause error, args ...any) *Error {
	return &Error{Code: d.Code, Status: d.Status, message: d.Message, args: args, cause: cause}
}

// Error is a typed application error carrying a code, HTTP status and message.
// It satisfies the error interface and supports errors.As/errors.Unwrap.
type Error struct {
	Code    ErrorCode
	Status  int
	message string
	args    []any
	cause   error
}

// Error renders "[code] message" plus the wrapped cause, for logs and %w chains.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	out := fmt.Sprintf("[%s] %s", e.Code, e.Message())
	if e.cause != nil {
		out += ": " + e.cause.Error()
	}
	return out
}

// Unwrap returns the wrapped cause, if any.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Message returns the human-readable message, formatted with any Newf/Wrap args.
func (e *Error) Message() string {
	if e == nil {
		return ""
	}
	if len(e.args) == 0 {
		return e.message
	}
	return fmt.Sprintf(e.message, e.args...)
}

// registeredCodes guards against duplicate error codes across the codebase.
var registeredCodes = map[ErrorCode]struct{}{}

// def registers an error definition, panicking on an empty or duplicate code so
// collisions surface at startup rather than in production.
func def(code ErrorCode, status int, message string) ErrorDef {
	if code == "" {
		panic("internal: empty error code")
	}
	if _, dup := registeredCodes[code]; dup {
		panic(fmt.Sprintf("internal: duplicate error code %q", code))
	}
	registeredCodes[code] = struct{}{}
	return ErrorDef{Code: code, Status: status, Message: message}
}

func defBadRequest(code ErrorCode, message string) ErrorDef {
	return def(code, http.StatusBadRequest, message)
}

func defUnauthorized(code ErrorCode, message string) ErrorDef {
	return def(code, http.StatusUnauthorized, message)
}
