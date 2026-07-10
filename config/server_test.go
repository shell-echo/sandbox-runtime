package config

import "testing"

// TestDefaultServerConfig confirms the built-in server defaults are valid.
func TestDefaultServerConfig(t *testing.T) {
	s := defaultServerConfig()
	if s.API.Host != defaultServerAPIHost || s.API.Port != defaultServerAPIPort {
		t.Errorf("unexpected default server config: %+v", s)
	}
	if err := s.API.Validate(); err != nil {
		t.Errorf("default server config should be valid: %v", err)
	}
}

// TestLoadServerDefaults confirms Load applies the server defaults when no file
// or env is present.
func TestLoadServerDefaults(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)

	if err := Load(""); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Server.API.Host != defaultServerAPIHost || Server.API.Port != defaultServerAPIPort {
		t.Errorf("server defaults not applied: %+v", Server)
	}
}

// TestLoadServerEnvOverride confirms SANDBOX_SERVER_API_* environment variables
// override the server config, including string->int for the port.
func TestLoadServerEnvOverride(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)

	t.Setenv("SANDBOX_SERVER_API_HOST", "127.0.0.1")
	t.Setenv("SANDBOX_SERVER_API_PORT", "9090")

	if err := Load(""); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Server.API.Host != "127.0.0.1" {
		t.Errorf("Server.API.Host = %q, want 127.0.0.1 (from env)", Server.API.Host)
	}
	if Server.API.Port != 9090 {
		t.Errorf("Server.API.Port = %d, want 9090 (from env)", Server.API.Port)
	}
}

// TestLoadServerInvalidPort confirms an out-of-range port in the file fails Load.
func TestLoadServerInvalidPort(t *testing.T) {
	snapshotGlobals(t)

	body := `
[application]
name = "x"
mode = "production"

[server.api]
port = 70000
`
	if err := Load(writeConfig(t, body)); err == nil {
		t.Error("expected error for out-of-range server.api.port")
	}
}
