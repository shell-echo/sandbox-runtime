package logger

import (
	"log/slog"
	"testing"
)

// TestLevelValidate confirms the five known levels validate, while empty and
// unknown/mis-cased values are rejected.
func TestLevelValidate(t *testing.T) {
	for _, lv := range []Level{DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel} {
		if err := lv.Validate(); err != nil {
			t.Errorf("valid level %q rejected: %v", lv, err)
		}
	}
	for _, bad := range []Level{"", "nope", "INFO"} {
		if err := bad.Validate(); err == nil {
			t.Errorf("invalid level %q accepted", bad)
		}
	}
}

// TestLevelSlog checks each level maps to the expected slog.Level, that fatal
// maps to the custom sentinel above Error, and that an unknown level errors.
func TestLevelSlog(t *testing.T) {
	cases := map[Level]slog.Level{
		DebugLevel: slog.LevelDebug,
		InfoLevel:  slog.LevelInfo,
		WarnLevel:  slog.LevelWarn,
		ErrorLevel: slog.LevelError,
		FatalLevel: slogFatalLevel,
	}
	for lv, want := range cases {
		got, err := lv.slog()
		if err != nil {
			t.Errorf("%q.slog() error: %v", lv, err)
		}
		if got != want {
			t.Errorf("%q.slog() = %v, want %v", lv, got, want)
		}
	}

	if slogFatalLevel <= slog.LevelError {
		t.Errorf("slogFatalLevel (%v) must be above LevelError (%v)", slogFatalLevel, slog.LevelError)
	}

	if _, err := Level("mystery").slog(); err == nil {
		t.Error("unknown level should return an error from slog()")
	}
}
