package internal

import "net/http"

// System-level errors. Add domain-specific errors below as the API grows,
// grouped by area and using dotted codes (e.g. "sandbox.not_found").
var (
	ErrSystem       = def("system.error", http.StatusInternalServerError, "internal server error")
	ErrBadRequest   = defBadRequest("system.bad_request", "bad request")
	ErrUnauthorized = defUnauthorized("system.unauthorized", "unauthorized")
)
