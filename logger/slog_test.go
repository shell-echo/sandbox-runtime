package logger

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// newTestLogger builds a *SlogLogger that writes JSON to buf at the given level.
// It mirrors NewSlogLogger's handler configuration (manual source via
// callerFrame + the FATAL-rendering ReplaceAttr) so behaviour can be asserted
// against an in-memory buffer instead of stderr or a file.
func newTestLogger(buf io.Writer, level slog.Level) *SlogLogger {
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{
		Level:       level,
		AddSource:   false,
		ReplaceAttr: replaceSlogAttr,
	})
	return &SlogLogger{l: slog.New(h)}
}

// decode unmarshals a single JSON log line into a map for field assertions.
func decode(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("invalid JSON log line %q: %v", line, err)
	}
	return m
}

// silenceStderr redirects os.Stderr to a temp file for the duration of the
// test. Logger output always fans out to stderr, so without this the test log
// would be polluted; it must run before constructing a logger because
// NewSlogLogger captures os.Stderr at build time.
func silenceStderr(t *testing.T) {
	t.Helper()
	orig := os.Stderr
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("temp stderr: %v", err)
	}
	os.Stderr = f
	t.Cleanup(func() {
		os.Stderr = orig
		_ = f.Close()
	})
}

// TestSlogLoggerAllLevels exercises every non-fatal level method (both the
// plain and formatted variants) and confirms each message reaches the sink.
func TestSlogLoggerAllLevels(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, slog.LevelDebug)

	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
	l.Debugf("%s", "df")
	l.Infof("%s", "iff")
	l.Warnf("%s", "wf")
	l.Errorf("%s", "ef")

	out := buf.String()
	for _, want := range []string{`"msg":"d"`, `"msg":"i"`, `"msg":"w"`, `"msg":"e"`, `"df"`, `"iff"`, `"wf"`, `"ef"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

// stringerSpy records whether its String method ran, so a test can prove that a
// filtered-out log line never formats its arguments.
type stringerSpy struct{ called *bool }

func (s stringerSpy) String() string { *s.called = true; return "spy" }

// TestLevelShortCircuit verifies that when a level is disabled, the formatted
// variants do not even evaluate their arguments (no wasted Sprintf).
func TestLevelShortCircuit(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, slog.LevelError) // Debug/Info are filtered out

	called := false
	l.Debugf("%v", stringerSpy{called: &called})

	if called {
		t.Error("Debugf formatted its args even though Debug is disabled")
	}
	if buf.Len() != 0 {
		t.Errorf("filtered log still produced output: %q", buf.String())
	}
}

// panicMarshaler panics during JSON encoding to simulate a misbehaving field.
type panicMarshaler struct{}

func (panicMarshaler) MarshalJSON() ([]byte, error) { panic("boom") }

// TestLoggingPanicIsContained ensures a panic while encoding a field is
// recovered inside the logger and never propagates to the caller, and that the
// logger remains usable afterwards.
func TestLoggingPanicIsContained(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, slog.LevelInfo)

	l.Info("with bad field", Any("bad", panicMarshaler{}))

	l.Info("still alive")
	if !strings.Contains(buf.String(), "still alive") {
		t.Errorf("logger unusable after recovered panic; got %q", buf.String())
	}
}

// TestReplaceSlogAttr covers every branch of the level-rewriting attribute
// replacer: unrelated keys, a level key holding a non-Level value, a normal
// level, and the fatal sentinel that must render as "FATAL".
func TestReplaceSlogAttr(t *testing.T) {
	if got := replaceSlogAttr(nil, slog.String("foo", "bar")); got.Value.String() != "bar" {
		t.Errorf("non-level attr modified: %v", got)
	}

	weird := slog.Attr{Key: slog.LevelKey, Value: slog.StringValue("x")}
	if got := replaceSlogAttr(nil, weird); got.Value.String() != "x" {
		t.Errorf("non-Level level value modified: %v", got)
	}

	normal := slog.Attr{Key: slog.LevelKey, Value: slog.AnyValue(slog.LevelError)}
	if got := replaceSlogAttr(nil, normal); got.Value.Any() != slog.LevelError {
		t.Errorf("error level rewritten: %v", got)
	}

	fatal := slog.Attr{Key: slog.LevelKey, Value: slog.AnyValue(slogFatalLevel)}
	if got := replaceSlogAttr(nil, fatal); got.Value.String() != "FATAL" {
		t.Errorf("fatal level rendered as %q, want FATAL", got.Value.String())
	}
}

// TestWithFieldsPropagate checks that fields attached via With appear on every
// subsequent record from the derived logger.
func TestWithFieldsPropagate(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, slog.LevelDebug)

	l.With(String("request_id", "abc123")).Info("handled")
	m := decode(t, buf.Bytes())
	if m["request_id"] != "abc123" {
		t.Errorf("With field missing/incorrect: %v", m)
	}
}

// TestEmptyKeyFieldSkipped verifies fieldsToArgs drops fields with an empty key
// while keeping the rest.
func TestEmptyKeyFieldSkipped(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, slog.LevelDebug)

	l.Info("msg", String("", "dropped"), String("keep", "yes"))
	m := decode(t, buf.Bytes())

	if _, exists := m[""]; exists {
		t.Error("field with empty key should be skipped")
	}
	if m["keep"] != "yes" {
		t.Errorf("non-empty field missing: %v", m)
	}
}

// TestNilReceiverSafe verifies every method except Fatal/Fatalf (which exit) is
// a safe no-op on a nil *SlogLogger, covering the nil guards in With, enabled,
// logSlogLevel and Sync.
func TestNilReceiverSafe(t *testing.T) {
	var l *SlogLogger

	if got := l.With(String("k", "v")); got == nil {
		t.Error("nil.With should return a usable logger")
	}

	l.Debug("x")
	l.Info("x")
	l.Warn("x")
	l.Error("x")
	l.Debugf("%d", 1)
	l.Infof("%d", 1)
	l.Warnf("%d", 1)
	l.Errorf("%d", 1)

	// Direct call to exercise logSlogLevel's own nil guard.
	l.logSlogLevel(slog.LevelInfo, "direct")

	if err := l.Sync(); err != nil {
		t.Errorf("nil.Sync = %v, want nil", err)
	}
}

// TestNopLogger confirms the no-op logger accepts all calls, syncs cleanly, and
// derives usable children.
func TestNopLogger(t *testing.T) {
	l := NewNopLogger()

	l.Debug("x")
	l.Info("y")
	l.Warn("z")
	l.Error("e")
	l.Infof("%d", 1)

	if err := l.Sync(); err != nil {
		t.Errorf("nop Sync: %v", err)
	}
	if child := l.With(String("k", "v")); child == nil {
		t.Error("nop With returned nil")
	}
}

// TestNewSlogLoggerWithFile drives the file sink end to end: nested directory
// creation, that the file receives the log line, and that its permissions are
// the expected 0600.
func TestNewSlogLoggerWithFile(t *testing.T) {
	silenceStderr(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "app.log") // exercises MkdirAll

	l, err := NewSlogLogger(Options{
		Level: InfoLevel,
		File:  File{Name: path, MaxSize: 1, MaxBackups: 1, MaxAge: 1},
	})
	if err != nil {
		t.Fatalf("NewSlogLogger: %v", err)
	}

	l.Info("hello file")
	if err := l.Sync(); err != nil {
		t.Errorf("Sync: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("log file not created/readable: %v", err)
	}
	if !strings.Contains(string(data), `"hello file"`) {
		t.Errorf("file sink missing log line: %s", data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("log file perm = %o, want 600", perm)
	}
}

// TestNewSlogLoggerInvalidLevel confirms the constructor rejects both an
// unknown level and an empty level (empty is intentionally an error).
func TestNewSlogLoggerInvalidLevel(t *testing.T) {
	if _, err := NewSlogLogger(Options{Level: "bogus"}); err == nil {
		t.Error("expected error for invalid level")
	}
	if _, err := NewSlogLogger(Options{Level: ""}); err == nil {
		t.Error("expected error for empty level")
	}
}

// TestNewSlogLoggerBadPath confirms the constructor surfaces an error when the
// log file's parent directory cannot be created.
func TestNewSlogLoggerBadPath(t *testing.T) {
	silenceStderr(t)

	dir := t.TempDir()
	notADir := filepath.Join(dir, "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewSlogLogger(Options{
		Level: InfoLevel,
		File:  File{Name: filepath.Join(notADir, "app.log"), MaxSize: 1},
	})
	if err == nil {
		t.Error("expected error when parent directory cannot be created")
	}
}

// TestSplitArgs pins down the message/field splitting rules, including the
// graceful degradation to fmt.Sprint when arguments are not structured.
func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []any
		wantMsg string
		wantLen int // number of extracted fields
	}{
		{"empty", nil, "", 0},
		{"msg only", []any{"hi"}, "hi", 0},
		{"msg + field", []any{"hi", String("k", "v")}, "hi", 1},
		{"msg + error", []any{"oops", errors.New("bad")}, "oops", 1},
		{"non-string head", []any{42}, "42", 0},
		{"unstructured tail degrades", []any{"hi", 42}, "hi42", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, fields := splitArgs(tc.args)
			if msg != tc.wantMsg {
				t.Errorf("msg = %q, want %q", msg, tc.wantMsg)
			}
			if len(fields) != tc.wantLen {
				t.Errorf("len(fields) = %d, want %d", len(fields), tc.wantLen)
			}
		})
	}
}

// TestIsBenignSyncErr checks that Sync errors meaning "target cannot be synced"
// are treated as benign while a genuine error is not.
func TestIsBenignSyncErr(t *testing.T) {
	for _, err := range []error{syscall.EINVAL, syscall.ENOTTY, syscall.ENOTSUP, os.ErrInvalid} {
		if !isBenignSyncErr(err) {
			t.Errorf("%v should be benign", err)
		}
	}
	if isBenignSyncErr(errors.New("disk failure")) {
		t.Error("arbitrary error must not be treated as benign")
	}
}

// failCloser is an io.Closer that always fails, used to check Sync error joins.
type failCloser struct{}

func (failCloser) Close() error { return errors.New("close boom") }

// TestSyncClosers verifies Sync closes owned closers (skipping nils and joining
// errors) but leaves closers untouched when the logger does not own them.
func TestSyncClosers(t *testing.T) {
	owning := &SlogLogger{
		l:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
		closers:    []io.Closer{nil, failCloser{}}, // nil skipped, failCloser errors
		ownClosers: true,
	}
	if err := owning.Sync(); err == nil {
		t.Error("expected Sync to surface the closer error")
	}

	borrowing := &SlogLogger{
		l:          slog.New(slog.NewJSONHandler(io.Discard, nil)),
		closers:    []io.Closer{failCloser{}},
		ownClosers: false,
	}
	if err := borrowing.Sync(); err != nil {
		t.Errorf("non-owning Sync should not close: %v", err)
	}
}

// errWriter always fails, standing in for a broken stderr pipe.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("pipe broken") }

// TestFanoutWriterKeepsWritingAfterFailure verifies fanoutWriter, unlike
// io.MultiWriter, still writes to healthy sinks when an earlier one fails.
func TestFanoutWriterKeepsWritingAfterFailure(t *testing.T) {
	var good bytes.Buffer
	w := newFanoutWriter(errWriter{}, &good) // failing sink first

	n, err := w.Write([]byte("payload"))
	if err == nil {
		t.Error("expected error to be reported from the failing writer")
	}
	if n != 0 {
		t.Errorf("n = %d, want 0 on partial failure", n)
	}
	if good.String() != "payload" {
		t.Errorf("healthy sink got %q, want payload — a failing sink blocked it", good.String())
	}
}

// TestLoggerPkgPrefix guards the runtime-derived package prefix used to
// recognise (and skip) logger's own frames during caller attribution.
func TestLoggerPkgPrefix(t *testing.T) {
	if !strings.HasSuffix(loggerPkgPrefix, "/logger.") {
		t.Errorf("loggerPkgPrefix = %q, want it to end with /logger.", loggerPkgPrefix)
	}
	if !isLoggerFrame(loggerPkgPrefix + "SomeFunc") {
		t.Error("isLoggerFrame should match our own package symbols")
	}
	if isLoggerFrame("github.com/other/mylogger.Foo") {
		t.Error("isLoggerFrame must not match an unrelated package named mylogger")
	}
}

// TestConcurrentLogging runs the race detector over many goroutines sharing one
// logger to confirm there is no data race on the shared handler.
func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	l := newTestLogger(&buf, slog.LevelDebug)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Info("concurrent", String("k", "v"))
			l.With(String("child", "yes")).Warn("nested")
		}()
	}
	wg.Wait()
}
