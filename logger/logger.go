// Package logger provides a small structured-logging facade over log/slog.
//
// It exposes leveled logging (Debug through Fatal, plus formatted -f variants),
// structured fields, and a process-wide logger configured once via Init. Output
// is JSON, written to stderr and optionally to a size-rotated file. Log records
// can include the source location of the calling application code.
//
// The package-level functions (Debug, Info, With, Sync, ...) operate on a
// global logger; before Init they safely fall back to a no-op logger.
package logger

import (
	"sync"
)

// Logger is the logging interface used throughout the application. The plain
// level methods (Debug, Info, ...) take a leading message followed by
// structured fields; see splitArgs for how the arguments are interpreted. The
// -f methods format the message with fmt rules. Fatal/Fatalf terminate the
// process after logging.
type Logger interface {
	With(fields ...Field) Logger

	Debug(a ...any)
	Info(a ...any)
	Warn(a ...any)
	Error(a ...any)
	Fatal(a ...any)

	Debugf(format string, a ...any)
	Infof(format string, a ...any)
	Warnf(format string, a ...any)
	Errorf(format string, a ...any)
	Fatalf(format string, a ...any)

	Sync() error
}

// mu guards the global logger, allowing Init to swap it while other goroutines
// read it through Get.
var (
	mu     sync.RWMutex
	logger Logger
)

// Init builds a logger from opts and installs it as the global logger,
// returning any construction/validation error without changing the current
// logger. A previously installed logger is flushed after the swap. Init is
// safe to call concurrently with logging, though it is normally called once at
// startup.
func Init(opts Options) error {
	next, err := NewSlogLogger(opts)
	if err != nil {
		return err
	}

	mu.Lock()
	old := logger
	logger = next
	mu.Unlock()

	if old != nil {
		if serr := old.Sync(); serr != nil {
			next.Warnf("previous logger sync failed: %v", serr)
		}
	}
	return nil
}

// Get returns the global logger, or a no-op logger if Init has not run.
func Get() Logger {
	mu.RLock()
	l := logger
	mu.RUnlock()
	if l == nil {
		return NewNopLogger()
	}
	return l
}

// With returns a child of the global logger carrying the given fields.
func With(fields ...Field) Logger {
	return Get().With(fields...)
}

// log dispatches to the matching level method on the global logger.
func log(level Level, a []any) {
	l := Get()
	switch level {
	case DebugLevel:
		l.Debug(a...)
	case InfoLevel:
		l.Info(a...)
	case WarnLevel:
		l.Warn(a...)
	case ErrorLevel:
		l.Error(a...)
	case FatalLevel:
		l.Fatal(a...)
	}
}

// Debug through Fatal log a message with optional fields on the global logger.
// Fatal additionally terminates the process.
func Debug(a ...any) { log(DebugLevel, a) }
func Info(a ...any)  { log(InfoLevel, a) }
func Warn(a ...any)  { log(WarnLevel, a) }
func Error(a ...any) { log(ErrorLevel, a) }
func Fatal(a ...any) { log(FatalLevel, a) }

// logf dispatches to the matching formatted level method on the global logger.
func logf(level Level, format string, a []any) {
	l := Get()
	switch level {
	case DebugLevel:
		l.Debugf(format, a...)
	case InfoLevel:
		l.Infof(format, a...)
	case WarnLevel:
		l.Warnf(format, a...)
	case ErrorLevel:
		l.Errorf(format, a...)
	case FatalLevel:
		l.Fatalf(format, a...)
	}
}

// Debugf through Fatalf are the formatted counterparts of Debug through Fatal.
func Debugf(format string, a ...any) { logf(DebugLevel, format, a) }
func Infof(format string, a ...any)  { logf(InfoLevel, format, a) }
func Warnf(format string, a ...any)  { logf(WarnLevel, format, a) }
func Errorf(format string, a ...any) { logf(ErrorLevel, format, a) }
func Fatalf(format string, a ...any) { logf(FatalLevel, format, a) }

// Sync flushes the global logger. It is a no-op if Init has not run and should
// be called (e.g. deferred in main) before the process exits.
func Sync() error {
	mu.RLock()
	l := logger
	mu.RUnlock()
	if l == nil {
		return nil
	}
	return l.Sync()
}
