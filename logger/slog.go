package logger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// SlogLogger is the default Logger implementation, backed by the standard
// library's log/slog with JSON output. A logger built by NewSlogLogger writes
// to stderr and, optionally, to a rotating file; loggers derived via With share
// the parent's sinks. Instances are immutable after construction and safe for
// concurrent use.
type SlogLogger struct {
	l          *slog.Logger
	stderr     *os.File    // the stderr sink, synced on Sync; nil for the nop logger
	closers    []io.Closer // sinks to close on Sync (e.g. the rotating file)
	ownClosers bool        // whether this instance is responsible for closing closers
	addSource  bool        // whether to attach the caller source to each record
}

// With returns a child logger that includes the given fields on every record.
// The child shares the parent's sinks but does not own them, so closing it does
// not close the parent's file. A nil receiver yields a no-op logger.
func (l *SlogLogger) With(fields ...Field) Logger {
	if l == nil || l.l == nil {
		return NewNopLogger()
	}

	return &SlogLogger{
		l:          l.l.With(fieldsToArgs(fields)...),
		stderr:     l.stderr,
		closers:    l.closers,
		ownClosers: false,
		addSource:  l.addSource,
	}
}

func (l *SlogLogger) Debug(a ...any) { l.log(slog.LevelDebug, a...) }
func (l *SlogLogger) Info(a ...any)  { l.log(slog.LevelInfo, a...) }
func (l *SlogLogger) Warn(a ...any)  { l.log(slog.LevelWarn, a...) }
func (l *SlogLogger) Error(a ...any) { l.log(slog.LevelError, a...) }

// Fatal logs at the fatal level, flushes, and terminates the process with exit
// code 1. It always emits regardless of the configured level.
func (l *SlogLogger) Fatal(a ...any) {
	message, fields := splitArgs(a)

	l.logSlogLevel(slogFatalLevel, message, fields...)

	l.exit()
}

func (l *SlogLogger) Debugf(format string, a ...any) { l.logf(slog.LevelDebug, format, a...) }
func (l *SlogLogger) Infof(format string, a ...any)  { l.logf(slog.LevelInfo, format, a...) }
func (l *SlogLogger) Warnf(format string, a ...any)  { l.logf(slog.LevelWarn, format, a...) }
func (l *SlogLogger) Errorf(format string, a ...any) { l.logf(slog.LevelError, format, a...) }

// Fatalf is the formatted counterpart of Fatal: it logs, flushes, and exits.
func (l *SlogLogger) Fatalf(format string, a ...any) {
	l.logSlogLevel(slogFatalLevel, fmt.Sprintf(format, a...))

	l.exit()
}

// exit flushes and terminates the process; it is the shared tail of Fatal and
// Fatalf so the sync/exit sequence stays identical.
func (l *SlogLogger) exit() {
	if err := l.Sync(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "logger sync failed: %v\n", err)
	}

	os.Exit(1)
}

// Sync flushes stderr and closes any owned sinks, returning the joined error of
// all failures. Sync errors from targets that simply cannot be synced (a
// terminal or pipe) are ignored. It is safe to call on a nil receiver.
func (l *SlogLogger) Sync() error {
	var err error

	if l == nil {
		return nil
	}

	if l.stderr != nil {
		if serr := l.stderr.Sync(); serr != nil && !isBenignSyncErr(serr) {
			err = errors.Join(err, serr)
		}
	}

	// Only the owning logger closes the sinks; With-derived children borrow them.
	if l.ownClosers {
		for _, c := range l.closers {
			if c == nil {
				continue
			}
			err = errors.Join(err, c.Close())
		}
	}

	return err
}

// NewNopLogger returns a Logger that discards everything. It is used as a safe
// fallback before Init has run.
func NewNopLogger() Logger {
	return &SlogLogger{
		l: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
}

// NewSlogLogger builds a JSON logger from opts. It always writes to stderr and,
// when opts.File.Name is set, additionally to a size-rotated file (created
// eagerly so a bad path or permissions fail here rather than on first log). The
// returned logger owns the file sink and closes it on Sync.
func NewSlogLogger(opts Options) (*SlogLogger, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	level, err := opts.Level.slog()
	if err != nil {
		return nil, err
	}

	stderr := os.Stderr
	output := io.Writer(stderr)
	var closers []io.Closer

	if opts.File.Name != "" {
		if err := os.MkdirAll(filepath.Dir(opts.File.Name), 0o750); err != nil {
			return nil, err
		}

		file := &lumberjack.Logger{
			Filename:   opts.File.Name,
			MaxSize:    opts.File.MaxSize,
			MaxBackups: opts.File.MaxBackups,
			MaxAge:     opts.File.MaxAge,
			Compress:   opts.File.Compress,
		}

		// Force-create the file now so misconfiguration surfaces at construction
		// rather than on the first log call. lumberjack creates all files it
		// manages (active + backups) with 0600.
		if _, err := file.Write(nil); err != nil {
			_ = file.Close()
			return nil, err
		}

		// fanoutWriter (not io.MultiWriter) so a broken stderr cannot stop the
		// file sink from receiving log lines.
		output = newFanoutWriter(stderr, file)
		closers = append(closers, file)
	}

	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level: level,
		// Source is attached manually in logSlogLevel; see callerFrame.
		AddSource:   false,
		ReplaceAttr: replaceSlogAttr,
	})

	return &SlogLogger{
		l:          slog.New(handler),
		stderr:     stderr,
		closers:    closers,
		ownClosers: true,
		addSource:  opts.AddSource,
	}, nil
}

// replaceSlogAttr renders the custom fatal level as "FATAL"; all other
// attributes pass through unchanged. It is installed as the handler's
// ReplaceAttr hook.
func replaceSlogAttr(groups []string, attr slog.Attr) slog.Attr {
	if attr.Key != slog.LevelKey {
		return attr
	}

	level, ok := attr.Value.Any().(slog.Level)
	if !ok {
		return attr
	}

	if level == slogFatalLevel {
		attr.Value = slog.StringValue("FATAL")
	}

	return attr
}

// enabled reports whether the handler will emit at level. It is checked before
// any message formatting so a filtered-out call costs nothing more.
func (l *SlogLogger) enabled(level slog.Level) bool {
	if l == nil || l.l == nil {
		return false
	}
	return l.l.Handler().Enabled(context.Background(), level)
}

func (l *SlogLogger) log(level slog.Level, a ...any) {
	if !l.enabled(level) {
		return
	}
	message, fields := splitArgs(a)
	l.logSlogLevel(level, message, fields...)
}

func (l *SlogLogger) logf(level slog.Level, format string, a ...any) {
	if !l.enabled(level) {
		return
	}
	l.logSlogLevel(level, fmt.Sprintf(format, a...))
}

// logSlogLevel builds and dispatches a record at level. It attaches the caller
// source and recovers from any panic raised while encoding a field value, so a
// misbehaving field can never bring down the caller.
func (l *SlogLogger) logSlogLevel(level slog.Level, message string, fields ...Field) {
	if l == nil || l.l == nil {
		return
	}

	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(os.Stderr, "logger: recovered from panic while logging: %v\n", r)
		}
	}()

	record := slog.NewRecord(time.Now(), level, message, 0)

	if l.addSource {
		if frame, ok := callerFrame(); ok {
			record.AddAttrs(slog.Group(slog.SourceKey,
				slog.String("function", frame.Function),
				slog.String("file", frame.File),
				slog.Int("line", frame.Line),
			))
		}
	}

	record.Add(fieldsToArgs(fields)...)

	if err := l.l.Handler().Handle(context.Background(), record); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "logger handle failed: %v\n", err)
	}
}

// callerFrame returns the first stack frame outside this package — the
// application code that invoked the logger — walking past all logger frames.
// ok is false when no such frame exists (e.g. the stack is all logger
// internals). The frame's fields are used directly for the source attribute
// because slog's Record.PC mechanism cannot round-trip a frame selected this
// way (inlining and pc-1 symbolization would mis-resolve it).
func callerFrame() (runtime.Frame, bool) {
	var pcs [32]uintptr

	n := runtime.Callers(3, pcs[:])
	if n == 0 {
		return runtime.Frame{}, false
	}

	frames := runtime.CallersFrames(pcs[:n])

	for {
		frame, more := frames.Next()

		if !isLoggerFrame(frame.Function) {
			return frame, true
		}

		if !more {
			return runtime.Frame{}, false
		}
	}
}

// loggerPkgPrefix is this package's fully-qualified symbol prefix (e.g.
// "github.com/shell-echo/sandbox-runtime/logger."). It is derived at init from
// a real symbol so it stays correct if the package moves, and so an unrelated
// package merely named "logger" is not mistaken for ours.
var loggerPkgPrefix = loggerFramePrefix()

func loggerFramePrefix() string {
	pc, _, _, ok := runtime.Caller(0)
	if !ok {
		return "logger."
	}
	name := runtime.FuncForPC(pc).Name()
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[:i+1]
	}
	return "logger."
}

// isLoggerFrame reports whether a function symbol belongs to this package.
func isLoggerFrame(function string) bool {
	return strings.HasPrefix(function, loggerPkgPrefix)
}

// splitArgs interprets the variadic arguments of the Debug/Info/... methods as
// a leading message string followed by structured fields (Field or error). If
// the first argument is not a string, or any trailing argument is neither a
// Field nor an error, it degrades to a single fmt.Sprint'd message with no
// fields.
func splitArgs(a []any) (string, []Field) {
	if len(a) == 0 {
		return "", nil
	}

	msg, ok := a[0].(string)
	if !ok {
		return fmt.Sprint(a...), nil
	}

	if len(a) == 1 {
		return msg, nil
	}

	fields := make([]Field, 0, len(a)-1)

	for _, item := range a[1:] {
		switch v := item.(type) {
		case Field:
			fields = append(fields, v)

		case error:
			fields = append(fields, Any("error", v))

		default:
			return fmt.Sprint(a...), nil
		}
	}

	return msg, fields
}

// fieldsToArgs flattens fields into the key/value sequence slog expects,
// skipping any field with an empty key.
func fieldsToArgs(fields []Field) []any {
	if len(fields) == 0 {
		return nil
	}

	args := make([]any, 0, len(fields)*2)

	for _, field := range fields {
		if field.Key == "" {
			continue
		}

		args = append(args, field.Key, field.Value)
	}

	return args
}

// isBenignSyncErr reports whether a Sync error just means the target does not
// support flushing (a terminal, pipe, /dev/null, or some virtual filesystems)
// rather than a genuine failure to persist data.
func isBenignSyncErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTTY) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, os.ErrInvalid)
}

// fanoutWriter writes each payload to every underlying writer. Unlike
// io.MultiWriter it does not stop at the first failing writer, so a broken
// stderr (e.g. a closed pipe) cannot prevent the file sink — the durable
// target — from receiving the log line. Errors from all writers are joined.
type fanoutWriter struct {
	writers []io.Writer
}

func newFanoutWriter(w ...io.Writer) *fanoutWriter {
	return &fanoutWriter{writers: w}
}

func (f *fanoutWriter) Write(p []byte) (int, error) {
	var errs error
	for _, w := range f.writers {
		if _, err := w.Write(p); err != nil {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		return 0, errs
	}
	return len(p), nil
}
