package internal

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// errTestNewf is registered once at package init (not inside a test) so the
// suite stays safe under -count>1, where re-registering a code would panic.
var errTestNewf = def("test.newf", http.StatusBadRequest, "value %d invalid")

// TestErrorDefConstructors checks New/Newf/Wrap carry code, status, message,
// formatted args, and the wrapped cause.
func TestErrorDefConstructors(t *testing.T) {
	e := ErrBadRequest.New()
	if e.Code != ErrBadRequest.Code || e.Status != http.StatusBadRequest {
		t.Errorf("New() = %+v, want code/status of ErrBadRequest", e)
	}
	if e.Message() != ErrBadRequest.Message {
		t.Errorf("Message() = %q, want %q", e.Message(), ErrBadRequest.Message)
	}

	// Newf formats the message template with args.
	if got := errTestNewf.Newf(42).Message(); got != "value 42 invalid" {
		t.Errorf("Newf message = %q, want 'value 42 invalid'", got)
	}

	// Wrap attaches a cause reachable via errors.Unwrap / errors.Is.
	cause := errors.New("boom")
	w := ErrSystem.Wrap(cause)
	if !errors.Is(w, cause) {
		t.Error("Wrap: errors.Is(w, cause) = false, want true")
	}
	if !strings.Contains(w.Error(), "boom") || !strings.Contains(w.Error(), string(ErrSystem.Code)) {
		t.Errorf("Error() = %q, want it to contain code and cause", w.Error())
	}
}

// TestErrorAs confirms a typed error is recoverable via errors.As through a wrap.
func TestErrorAs(t *testing.T) {
	err := error(ErrUnauthorized.New())
	var target *Error
	if !errors.As(err, &target) || target.Code != ErrUnauthorized.Code {
		t.Errorf("errors.As failed to recover typed error: %v", err)
	}
}

// TestDefDuplicatePanics confirms registering a duplicate code panics.
func TestDefDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate error code")
		}
	}()
	def("test.dup.code", 500, "x")
	def("test.dup.code", 500, "x") // duplicate -> panic
}
