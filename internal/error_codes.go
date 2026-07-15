package internal

import "net/http"

// System-level errors. Add domain-specific errors below as the API grows,
// grouped by area and using dotted codes (e.g. "sandbox.not_found").
var (
	ErrSystem          = def("system.error", http.StatusInternalServerError, "internal server error")
	ErrBadRequest      = defBadRequest("system.bad_request", "bad request")
	ErrUnauthorized    = defUnauthorized("system.unauthorized", "unauthorized")
	ErrPayloadTooLarge = def("system.payload_too_large", http.StatusRequestEntityTooLarge, "request body too large")

	ErrInstanceInvalidSpec   = defBadRequest("instance.invalid_spec", "invalid instance spec")
	ErrInstanceNotFound      = def("instance.not_found", http.StatusNotFound, "instance not found")
	ErrInstanceAlreadyExists = def("instance.already_exists", http.StatusConflict, "instance already exists")
	ErrInstanceInvalidState  = def("instance.invalid_state", http.StatusConflict, "invalid instance state")
	ErrInstanceLimitExceeded = def("instance.limit_exceeded", http.StatusTooManyRequests, "instance limit exceeded")
)
