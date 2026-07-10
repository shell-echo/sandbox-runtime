package logger

import (
	"fmt"
	"log/slog"
)

// Level is the configured minimum severity, expressed as a lowercase string so
// it maps directly to config values.
type Level string

// The supported levels, in increasing severity.
const (
	DebugLevel Level = "debug"
	InfoLevel  Level = "info"
	WarnLevel  Level = "warn"
	ErrorLevel Level = "error"
	FatalLevel Level = "fatal"
)

// Validate reports whether the level is one of the known values. An empty level
// is treated as invalid; callers must set one explicitly. The slog mapping is
// the single source of truth for validity.
func (l *Level) Validate() error {
	if _, err := l.slog(); err != nil {
		return fmt.Errorf(
			"logger.level %q invalid (%s|%s|%s|%s|%s)", *l,
			DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel,
		)
	}
	return nil
}

// slogFatalLevel is the custom slog severity used for Fatal, placed above
// slog.LevelError so fatal records are never filtered by a configured level.
const slogFatalLevel = slog.LevelError + 4

// slog maps the level to its slog.Level, returning an error for unknown values.
func (l Level) slog() (slog.Level, error) {
	switch l {
	case DebugLevel:
		return slog.LevelDebug, nil
	case InfoLevel:
		return slog.LevelInfo, nil
	case WarnLevel:
		return slog.LevelWarn, nil
	case ErrorLevel:
		return slog.LevelError, nil
	case FatalLevel:
		return slogFatalLevel, nil
	}
	return slog.LevelError, fmt.Errorf("logger.level %q invalid", l)
}
