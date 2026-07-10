package logger

import (
	"log/slog"
)

// Field is a single structured key/value pair attached to a log record. It is
// an alias for slog.Attr, so any slog attribute constructor may also be used.
type Field = slog.Attr

// String returns a Field carrying a string value.
func String(key string, val string) Field { return slog.String(key, val) }

// Any returns a Field carrying a value of any type, resolved by slog.
func Any(key string, value any) Field { return slog.Any(key, value) }
