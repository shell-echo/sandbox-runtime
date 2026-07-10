package logger

import "testing"

// TestOptionsValidate confirms Options.Validate delegates to both the level and
// file validators: valid options pass, an invalid level fails, and an invalid
// file fails.
func TestOptionsValidate(t *testing.T) {
	if err := (&Options{Level: InfoLevel}).Validate(); err != nil {
		t.Errorf("valid options rejected: %v", err)
	}
	if err := (&Options{Level: "bad"}).Validate(); err == nil {
		t.Error("invalid level accepted")
	}
	if err := (&Options{Level: InfoLevel, File: File{Name: "x.log", MaxSize: -1}}).Validate(); err == nil {
		t.Error("invalid file accepted")
	}
}
