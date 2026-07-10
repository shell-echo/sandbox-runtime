package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// snapshotGlobals saves and restores the mutable package globals that Load and
// its commit callbacks mutate (Application, Logger, time.Local), so tests do
// not leak state into one another.
func snapshotGlobals(t *testing.T) {
	t.Helper()
	app := Application
	lg := Logger
	srv := Server
	loc := time.Local
	t.Cleanup(func() {
		Application = app
		Logger = lg
		Server = srv
		time.Local = loc
	})
}

// writeConfig writes body to a temp config.toml and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// validConfig is a complete, well-formed configuration used by the happy-path
// Load test.
const validConfig = `
[application]
name = "test-app"
mode = "development"
[application.timezone]
name = "UTC"

[logger]
level = "info"
[logger.file]
name = "./logs/test.log"
max_size = 10
max_backups = 3
max_age = 7
compress = true
`

// TestLoadSuccess loads a valid file and confirms both registered loaders
// (application and logger) parsed, validated and committed their config into
// the package globals.
func TestLoadSuccess(t *testing.T) {
	snapshotGlobals(t)

	if err := Load(writeConfig(t, validConfig)); err != nil {
		t.Fatalf("Load: %v", err)
	}

	if Application.Name != "test-app" {
		t.Errorf("Application.Name = %q, want test-app", Application.Name)
	}
	if !Application.IsDevelopment() {
		t.Errorf("Application.Mode = %q, want development", Application.Mode)
	}
	if Application.TimeLocation == nil || Application.TimeLocation.String() != "UTC" {
		t.Errorf("TimeLocation = %v, want UTC", Application.TimeLocation)
	}
	if Logger.Level != "info" {
		t.Errorf("Logger.Level = %q, want info", Logger.Level)
	}
}

// TestLoadMissingExplicitFile confirms Load errors when an explicitly requested
// config file does not exist.
func TestLoadMissingExplicitFile(t *testing.T) {
	snapshotGlobals(t)
	if err := Load(filepath.Join(t.TempDir(), "nope.toml")); err == nil {
		t.Error("expected error for missing explicit config file")
	}
}

// chdirTemp switches the working directory to a fresh empty temp dir for the
// test so the default config file (config.toml) is guaranteed absent.
func chdirTemp(t *testing.T) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// TestLoadNoFileUsesDefaults confirms that with an empty path and no default
// file present, Load succeeds and applies the built-in defaults instead of
// erroring. It checks every logger field (not just Level) to prove defaults
// flow through SetDefault even though the loader starts from an empty struct.
func TestLoadNoFileUsesDefaults(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)

	if err := Load(""); err != nil {
		t.Fatalf("Load(\"\") should succeed with defaults, got %v", err)
	}

	want := defaultLoggerConfig()
	// Load validates, which normalises File.Name via filepath.Clean; validate
	// the expected value the same way before comparing.
	if err := want.Validate(); err != nil {
		t.Fatalf("default should validate: %v", err)
	}
	if *Logger != *want {
		t.Errorf("Logger = %+v, want full defaults %+v", *Logger, *want)
	}
	if Application.Name != defaultApplicationConfig().Name {
		t.Errorf("Application.Name = %q, want default", Application.Name)
	}
	if Application.Mode != defaultApplicationConfig().Mode {
		t.Errorf("Application.Mode = %q, want default", Application.Mode)
	}
}

// TestLoadEnvOverridesDefaults confirms environment variables populate config
// when there is no file, including type conversion for int and bool fields.
func TestLoadEnvOverridesDefaults(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)

	t.Setenv("SANDBOX_RUNTIME_LOGGER_LEVEL", "debug")
	t.Setenv("SANDBOX_RUNTIME_LOGGER_FILE_MAX_SIZE", "250")
	t.Setenv("SANDBOX_RUNTIME_LOGGER_FILE_COMPRESS", "false")
	t.Setenv("SANDBOX_RUNTIME_LOGGER_ADD_SOURCE", "true")
	t.Setenv("SANDBOX_RUNTIME_APPLICATION_NAME", "envapp")

	if err := Load(""); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Logger.Level != "debug" {
		t.Errorf("Logger.Level = %q, want debug (from env)", Logger.Level)
	}
	if Logger.File.MaxSize != 250 {
		t.Errorf("Logger.File.MaxSize = %d, want 250 (from env)", Logger.File.MaxSize)
	}
	if Logger.File.Compress {
		t.Error("Logger.File.Compress = true, want false (from env)")
	}
	if !Logger.AddSource {
		t.Error("Logger.AddSource = false, want true (from env)")
	}
	if Application.Name != "envapp" {
		t.Errorf("Application.Name = %q, want envapp (from env)", Application.Name)
	}
}

// TestLoadEnvOverridesFile confirms env values take precedence over file values,
// while unset file values are still honoured.
func TestLoadEnvOverridesFile(t *testing.T) {
	snapshotGlobals(t)

	path := writeConfig(t, "[application]\nname = 'fileapp'\nmode = 'production'\n\n[logger]\nlevel = 'info'\n")
	t.Setenv("SANDBOX_RUNTIME_LOGGER_LEVEL", "warn")

	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Logger.Level != "warn" {
		t.Errorf("Logger.Level = %q, want warn (env over file)", Logger.Level)
	}
	if Application.Name != "fileapp" {
		t.Errorf("Application.Name = %q, want fileapp (from file)", Application.Name)
	}
}

// TestLoadEnvDeepNestedKey confirms a deeply nested key (four levels:
// application.timezone.fixed_zone.offset) can be overridden by an environment
// variable, exercising the flattened key derivation and string->int conversion
// at depth.
func TestLoadEnvDeepNestedKey(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)

	t.Setenv("SANDBOX_RUNTIME_APPLICATION_TIMEZONE_FIXED_ZONE_NAME", "UTC")
	t.Setenv("SANDBOX_RUNTIME_APPLICATION_TIMEZONE_FIXED_ZONE_OFFSET", "3600")

	if err := Load(""); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Defaults are CST / 28800; env must override both, proving the deep-nested
	// keys are bound.
	if got := Application.TimeZone.FixedZone.Offset; got != 3600 {
		t.Errorf("FixedZone.Offset = %d, want 3600 (deep-nested env int)", got)
	}
	if got := Application.TimeZone.FixedZone.Name; got != "UTC" {
		t.Errorf("FixedZone.Name = %q, want UTC (deep-nested env string)", got)
	}
}

// TestLoadInvalidApplicationMode confirms a loader validation failure
// (unknown application.mode) propagates out of Load.
func TestLoadInvalidApplicationMode(t *testing.T) {
	snapshotGlobals(t)
	body := `
[application]
name = "x"
mode = "bogus"

[logger]
level = "info"
`
	if err := Load(writeConfig(t, body)); err == nil {
		t.Error("expected error for invalid application mode")
	}
}

// TestLoadInvalidLoggerLevel confirms a logger-loader validation failure
// (unknown level) propagates out of Load.
func TestLoadInvalidLoggerLevel(t *testing.T) {
	snapshotGlobals(t)
	body := `
[application]
name = "x"
mode = "production"

[logger]
level = "louder"
`
	if err := Load(writeConfig(t, body)); err == nil {
		t.Error("expected error for invalid logger level")
	}
}

// TestLoadInvalidTimezone drives the timezone-resolution error branch inside
// application.load via an unresolvable zone name.
func TestLoadInvalidTimezone(t *testing.T) {
	snapshotGlobals(t)
	body := `
[application]
name = "x"
mode = "production"
[application.timezone]
name = "Bogus/Zone"

[logger]
level = "info"
`
	if err := Load(writeConfig(t, body)); err == nil {
		t.Error("expected error for invalid timezone in application.load")
	}
}

// TestLoadMalformedSections drives the UnmarshalKey decode-error branches: a
// scalar where a table is expected (application) and a type mismatch on a
// numeric field (logger.file.max_size).
func TestLoadMalformedSections(t *testing.T) {
	snapshotGlobals(t)

	if err := Load(writeConfig(t, "application = \"oops\"\n")); err == nil {
		t.Error("expected UnmarshalKey error for scalar application")
	}

	body := `
[application]
name = "x"
mode = "production"

[logger.file]
max_size = "not-a-number"
`
	if err := Load(writeConfig(t, body)); err == nil {
		t.Error("expected UnmarshalKey error for non-numeric logger.file.max_size")
	}
}
