package logger

import (
	"log/slog"
	"testing"
)

// TestFieldConstructors verifies the thin wrappers produce slog attributes with
// the expected key and value.
func TestFieldConstructors(t *testing.T) {
	s := String("k", "v")
	if s.Key != "k" || s.Value.String() != "v" {
		t.Errorf("String() = %+v, want key=k value=v", s)
	}

	a := Any("n", 42)
	if a.Key != "n" || a.Value.Kind() != slog.KindInt64 || a.Value.Int64() != 42 {
		t.Errorf("Any() = %+v, want key=n value=42", a)
	}
}
