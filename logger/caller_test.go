package logger_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/logger"
)

// logInfoOnce builds a file-backed logger with the given AddSource setting, logs
// a single Info line from this (external) package, and returns the decoded
// record. Silencing stderr keeps the test output clean.
func logInfoOnce(t *testing.T, addSource bool) map[string]any {
	t.Helper()
	dir := t.TempDir()

	orig := os.Stderr
	quiet, err := os.CreateTemp(dir, "stderr")
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = quiet
	t.Cleanup(func() {
		os.Stderr = orig
		_ = quiet.Close()
	})

	logPath := filepath.Join(dir, "app.log")
	l, err := logger.NewSlogLogger(logger.Options{
		Level:     logger.DebugLevel,
		AddSource: addSource,
		File:      logger.File{Name: logPath, MaxSize: 1},
	})
	if err != nil {
		t.Fatalf("NewSlogLogger: %v", err)
	}

	l.Info("hello")

	if err := l.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("invalid JSON log line %q: %v", data, err)
	}
	return m
}

// TestCallerAttribution runs from an external package (logger_test) so the
// calling frame genuinely lives outside the logger package. With AddSource on,
// it guards callerFrame + isLoggerFrame end to end through the public API: the
// "source" recorded in the log line must point at this test file, never at
// logger internals. Using the public API with a file sink keeps the caller
// frame authentic — an in-package helper would be skipped as a logger frame and
// mis-resolve the attribution.
func TestCallerAttribution(t *testing.T) {
	m := logInfoOnce(t, true)

	src, ok := m["source"].(map[string]any)
	if !ok {
		t.Fatalf("no source in record: %v", m)
	}
	file, _ := src["file"].(string)
	if filepath.Base(file) != "caller_test.go" {
		t.Errorf("caller attributed to %q, want caller_test.go", file)
	}
	if strings.Contains(file, "slog.go") {
		t.Errorf("caller leaked into logger internals: %q", file)
	}
}

// TestCallerSourceDisabled confirms that with AddSource off, no source is
// attached to the record.
func TestCallerSourceDisabled(t *testing.T) {
	m := logInfoOnce(t, false)

	if _, ok := m["source"]; ok {
		t.Errorf("source attached despite AddSource=false: %v", m["source"])
	}
}
