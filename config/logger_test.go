package config

import "testing"

// TestDefaultLoggerConfig confirms the built-in logger defaults are populated
// and pass validation (which delegates to logger.Options.Validate).
func TestDefaultLoggerConfig(t *testing.T) {
	lg := defaultLoggerConfig()
	if lg.Level != "info" || lg.File.Name != "" || lg.File.MaxSize <= 0 || lg.AddSource {
		t.Errorf("unexpected default logger config: %+v", lg)
	}
	if err := lg.Validate(); err != nil {
		t.Errorf("default logger config should be valid: %v", err)
	}
}

// TestLoggerConfigValidate confirms validation rejects an invalid embedded
// level and accepts a valid one.
func TestLoggerConfigValidate(t *testing.T) {
	good := defaultLoggerConfig()
	if err := good.Validate(); err != nil {
		t.Errorf("valid logger config rejected: %v", err)
	}

	bad := defaultLoggerConfig()
	bad.Level = "screaming"
	if err := bad.Validate(); err == nil {
		t.Error("invalid embedded level accepted")
	}
}
