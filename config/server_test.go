package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/option"
)

// TestDefaultServerConfig confirms the built-in server defaults are valid.
func TestDefaultServerConfig(t *testing.T) {
	s := defaultServerConfig()
	if s.API.Host != defaultServerAPIHost || s.API.Port != defaultServerAPIPort {
		t.Errorf("unexpected default server config: %+v", s)
	}
	if err := s.API.Validate(); err != nil {
		t.Errorf("default server config should be valid: %v", err)
	}
	if s.Provider.Transport.Enabled {
		t.Error("Provider listener is enabled by default")
	}
	if err := s.Provider.Validate(); err != nil {
		t.Errorf("disabled Provider defaults should be valid: %v", err)
	}
}

func TestLoadProviderEnabledTOML(t *testing.T) {
	snapshotGlobals(t)

	if err := Load(writeConfig(t, validEnabledProviderTOML())); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !Server.Provider.Transport.Enabled {
		t.Fatal("Provider transport is disabled, want enabled")
	}
	if got := Server.Provider.Transport.Address.Addr(); got != "127.0.0.1:9443" {
		t.Fatalf("Provider address = %q, want 127.0.0.1:9443", got)
	}
	if got := Server.Provider.Transport.AllowedClientURIIdentities; !reflect.DeepEqual(got, []string{"spiffe://agent-platform/provider-client"}) {
		t.Fatalf("allowed identities = %#v", got)
	}
	if Server.Provider.Capability.ProviderRevisionID != "provider-revision-1" {
		t.Fatalf("provider revision = %q", Server.Provider.Capability.ProviderRevisionID)
	}
	if got := Server.Provider.Capability.Limits.MaxGPUCount; got == nil || *got != 0 {
		t.Fatalf("max GPU count = %v, want explicit zero", got)
	}
	if got := Server.Provider.Capability.SnapshotRestoreProfiles; len(got) != 1 || got[0].Level != "workspace" {
		t.Fatalf("compatibility profiles = %#v", got)
	}
	if Server.API.Host != defaultServerAPIHost || Server.API.Port != defaultServerAPIPort {
		t.Fatalf("server.api changed by Provider config: %+v", Server.API)
	}
}

func TestLoadProviderScalarEnvOverrides(t *testing.T) {
	snapshotGlobals(t)
	t.Setenv("SANDBOX_RUNTIME_SERVER_PROVIDER_TRANSPORT_ADDRESS_PORT", "9553")
	t.Setenv("SANDBOX_RUNTIME_SERVER_PROVIDER_CAPABILITY_PROVIDER_REVISION_ID", "provider-revision-env")
	t.Setenv("SANDBOX_RUNTIME_SERVER_PROVIDER_CAPABILITY_LIMITS_MAX_CPU_MILLIS", "2000")
	t.Setenv("SANDBOX_RUNTIME_SERVER_API_PORT", "9090")

	if err := Load(writeConfig(t, validEnabledProviderTOML())); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Server.Provider.Transport.Address.Port != 9553 || Server.Provider.Capability.ProviderRevisionID != "provider-revision-env" || Server.Provider.Capability.Limits.MaxCPUMillis != 2000 {
		t.Fatalf("Provider scalar env overrides not applied: %+v", Server.Provider)
	}
	if Server.API.Port != 9090 {
		t.Fatalf("server.api port = %d, want independent env override 9090", Server.API.Port)
	}
}

func TestLoadProviderRejectsEmptyHost(t *testing.T) {
	snapshotGlobals(t)
	body := strings.Replace(validEnabledProviderTOML(), `host = "127.0.0.1"`, `host = ""`, 1)
	if err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("Load accepted enabled Provider with an empty host")
	}
}

func TestLoadProviderRejectsLocalAPIPortCollision(t *testing.T) {
	t.Run("TOML", func(t *testing.T) {
		snapshotGlobals(t)
		body := strings.Replace(validEnabledProviderTOML(), "port = 9443", "port = 8080", 1)
		if err := Load(writeConfig(t, body)); err == nil {
			t.Fatal("Load accepted enabled Provider on the local API port")
		}
	})
	t.Run("environment", func(t *testing.T) {
		snapshotGlobals(t)
		t.Setenv("SANDBOX_RUNTIME_SERVER_PROVIDER_TRANSPORT_ADDRESS_PORT", "8080")
		if err := Load(writeConfig(t, validEnabledProviderTOML())); err == nil {
			t.Fatal("Load accepted Provider environment override on the local API port")
		}
	})
}

func TestDisabledProviderAcceptsPlaceholders(t *testing.T) {
	config := ProviderConfig{
		Transport: ProviderTransportConfig{
			Enabled:                    false,
			Address:                    optionHTTP("bad host", -1),
			AllowedClientURIIdentities: []string{"not a URI", "not a URI"},
		},
		Capability: ProviderCapabilityConfig{
			ProviderRevisionID: "",
			Limits:             ProviderLimitsConfig{},
			SnapshotRestoreProfiles: []ProviderCompatibilityProfile{{
				ProfileID: "", Level: "invalid", SuiteID: "invalid",
			}},
		},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("disabled Provider placeholders rejected: %v", err)
	}
}

func TestLoadDisabledProviderAcceptsPlaceholders(t *testing.T) {
	snapshotGlobals(t)
	body := `
[server.provider.transport]
enabled = false
server_certificate_file = ""
server_private_key_file = ""
client_ca_bundle_file = ""
allowed_client_uri_identities = ["not a URI", "not a URI"]

[server.provider.transport.address]
host = "bad host"
port = -1

[server.provider.capability]
provider_revision_id = ""

[server.provider.capability.limits]
max_cpu_millis = 0
max_memory_bytes = 0
max_ephemeral_storage_bytes = 0
max_workspace_bytes = 0
max_gpu_count = -1
max_lease_seconds = 0
max_exec_seconds = 0
`
	if err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("Load disabled Provider placeholders: %v", err)
	}
	if Server.Provider.Transport.Enabled {
		t.Fatal("disabled Provider became enabled")
	}
}

func TestEnabledProviderRejectsMissingAndInvalidTransport(t *testing.T) {
	tests := map[string]func(*ProviderConfig){
		"empty host":          func(c *ProviderConfig) { c.Transport.Address.Host = "" },
		"address":             func(c *ProviderConfig) { c.Transport.Address.Port = 0 },
		"server certificate":  func(c *ProviderConfig) { c.Transport.ServerCertificateFile = " " },
		"server private key":  func(c *ProviderConfig) { c.Transport.ServerPrivateKeyFile = "" },
		"client CA":           func(c *ProviderConfig) { c.Transport.ClientCABundleFile = "" },
		"empty identity list": func(c *ProviderConfig) { c.Transport.AllowedClientURIIdentities = nil },
		"relative identity":   func(c *ProviderConfig) { c.Transport.AllowedClientURIIdentities = []string{"agent/client"} },
		"fragment identity": func(c *ProviderConfig) {
			c.Transport.AllowedClientURIIdentities = []string{"urn:agent:client#fragment"}
		},
		"surrounding whitespace": func(c *ProviderConfig) { c.Transport.AllowedClientURIIdentities = []string{" spiffe://agent/client"} },
		"invalid UTF-8 identity": func(c *ProviderConfig) {
			c.Transport.AllowedClientURIIdentities = []string{string([]byte{0xff})}
		},
		"oversized identity": func(c *ProviderConfig) {
			c.Transport.AllowedClientURIIdentities = []string{"urn:" + strings.Repeat("a", 2045)}
		},
		"oversized identity list": func(c *ProviderConfig) {
			c.Transport.AllowedClientURIIdentities = testURIIdentities(33)
		},
		"duplicate identity": func(c *ProviderConfig) {
			c.Transport.AllowedClientURIIdentities = []string{"spiffe://agent/client", "spiffe://agent/client"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validEnabledProviderConfig()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want transport rejection")
			}
		})
	}
}

func testURIIdentities(count int) []string {
	identities := make([]string, count)
	for index := range identities {
		identities[index] = fmt.Sprintf("urn:test:client:%d", index)
	}
	return identities
}

func TestEnabledProviderRejectsRequiredLimitBoundaries(t *testing.T) {
	tests := map[string]func(*ProviderLimitsConfig){
		"CPU/zero":           func(c *ProviderLimitsConfig) { c.MaxCPUMillis = 0 },
		"CPU/negative":       func(c *ProviderLimitsConfig) { c.MaxCPUMillis = -1 },
		"memory/zero":        func(c *ProviderLimitsConfig) { c.MaxMemoryBytes = 0 },
		"memory/negative":    func(c *ProviderLimitsConfig) { c.MaxMemoryBytes = -1 },
		"ephemeral/zero":     func(c *ProviderLimitsConfig) { c.MaxEphemeralStorageBytes = 0 },
		"ephemeral/negative": func(c *ProviderLimitsConfig) { c.MaxEphemeralStorageBytes = -1 },
		"lease/zero":         func(c *ProviderLimitsConfig) { c.MaxLeaseSeconds = 0 },
		"lease/negative":     func(c *ProviderLimitsConfig) { c.MaxLeaseSeconds = -1 },
		"exec/zero":          func(c *ProviderLimitsConfig) { c.MaxExecSeconds = 0 },
		"exec/negative":      func(c *ProviderLimitsConfig) { c.MaxExecSeconds = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validEnabledProviderConfig()
			mutate(&config.Capability.Limits)
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want required limit rejection")
			}
		})
	}
}

func TestEnabledProviderOptionalLimitSemantics(t *testing.T) {
	tests := []struct {
		name      string
		workspace *int64
		gpu       *int64
		wantError bool
	}{
		{name: "omitted"},
		{name: "workspace positive", workspace: serverInt64Pointer(1)},
		{name: "workspace zero", workspace: serverInt64Pointer(0), wantError: true},
		{name: "workspace negative", workspace: serverInt64Pointer(-1), wantError: true},
		{name: "GPU zero", gpu: serverInt64Pointer(0)},
		{name: "GPU positive", gpu: serverInt64Pointer(1)},
		{name: "GPU negative", gpu: serverInt64Pointer(-1), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validEnabledProviderConfig()
			config.Capability.Limits.MaxWorkspaceBytes = test.workspace
			config.Capability.Limits.MaxGPUCount = test.gpu
			if err := config.Validate(); (err != nil) != test.wantError {
				t.Fatalf("Validate() error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestEnabledProviderProfileValidation(t *testing.T) {
	tests := map[string]func(*ProviderCompatibilityProfile){
		"empty ID":         func(p *ProviderCompatibilityProfile) { p.ProfileID = "" },
		"blank ID":         func(p *ProviderCompatibilityProfile) { p.ProfileID = " \t" },
		"invalid UTF-8 ID": func(p *ProviderCompatibilityProfile) { p.ProfileID = string([]byte{0xff}) },
		"invalid level":    func(p *ProviderCompatibilityProfile) { p.Level = "memory" },
		"invalid suite":    func(p *ProviderCompatibilityProfile) { p.SuiteID = "other" },
		"invalid version":  func(p *ProviderCompatibilityProfile) { p.SuiteVersion = "v1" },
		"uppercase digest": func(p *ProviderCompatibilityProfile) { p.SuiteDigest = "sha256:" + strings.Repeat("A", 64) },
		"short digest":     func(p *ProviderCompatibilityProfile) { p.SuiteDigest = "sha256:abcd" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := validEnabledProviderConfig()
			mutate(&config.Capability.SnapshotRestoreProfiles[0])
			if err := config.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want profile rejection")
			}
		})
	}
}

func TestEnabledProviderProfileCharacterAndCountBoundaries(t *testing.T) {
	for _, test := range []struct {
		name      string
		id        string
		wantError bool
	}{
		{name: "200 Unicode characters", id: strings.Repeat("界", 200)},
		{name: "201 Unicode characters", id: strings.Repeat("界", 201), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validEnabledProviderConfig()
			config.Capability.SnapshotRestoreProfiles[0].ProfileID = test.id
			if err := config.Validate(); (err != nil) != test.wantError {
				t.Fatalf("Validate() error = %v, wantError %t", err, test.wantError)
			}
		})
	}

	for _, count := range []int{1, 32} {
		config := validEnabledProviderConfig()
		config.Capability.SnapshotRestoreProfiles = distinctProfiles(count)
		if err := config.Validate(); err != nil {
			t.Fatalf("%d profiles rejected: %v", count, err)
		}
	}
	for _, count := range []int{0, 33} {
		config := validEnabledProviderConfig()
		config.Capability.SnapshotRestoreProfiles = distinctProfiles(count)
		if err := config.Validate(); err == nil {
			t.Fatalf("%d profiles accepted, want rejection", count)
		}
	}
}

func TestEnabledProviderRejectsDuplicateAndConflictingProfiles(t *testing.T) {
	config := validEnabledProviderConfig()
	profile := config.Capability.SnapshotRestoreProfiles[0]
	config.Capability.SnapshotRestoreProfiles = []ProviderCompatibilityProfile{profile, profile}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}

	config = validEnabledProviderConfig()
	conflict := config.Capability.SnapshotRestoreProfiles[0]
	conflict.Level = "filesystem"
	config.Capability.SnapshotRestoreProfiles = append(config.Capability.SnapshotRestoreProfiles, conflict)
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict error = %v", err)
	}
}

func TestEnabledProviderRejectsEmptyRevision(t *testing.T) {
	for _, revision := range []string{" \t", string([]byte{0xff})} {
		config := validEnabledProviderConfig()
		config.Capability.ProviderRevisionID = revision
		if err := config.Validate(); err == nil {
			t.Fatal("Validate() error = nil, want revision rejection")
		}
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
	if Server.Provider.Transport.Enabled {
		t.Error("Provider listener is enabled after loading defaults")
	}
}

// TestLoadServerEnvOverride confirms SANDBOX_RUNTIME_SERVER_API_* environment variables
// override the server config, including string->int for the port.
func TestLoadServerEnvOverride(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)

	t.Setenv("SANDBOX_RUNTIME_SERVER_API_HOST", "127.0.0.1")
	t.Setenv("SANDBOX_RUNTIME_SERVER_API_PORT", "9090")

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

func validEnabledProviderConfig() ProviderConfig {
	return ProviderConfig{
		Transport: ProviderTransportConfig{
			Enabled:                    true,
			Address:                    option.HTTP{Host: "127.0.0.1", Port: 9443},
			ServerCertificateFile:      "provider.crt",
			ServerPrivateKeyFile:       "provider.key",
			ClientCABundleFile:         "client-ca.pem",
			AllowedClientURIIdentities: []string{"spiffe://agent-platform/provider-client"},
		},
		Capability: ProviderCapabilityConfig{
			ProviderRevisionID: "provider-revision-1",
			Limits: ProviderLimitsConfig{
				MaxCPUMillis:             1000,
				MaxMemoryBytes:           1 << 30,
				MaxEphemeralStorageBytes: 1 << 30,
				MaxLeaseSeconds:          3600,
				MaxExecSeconds:           300,
			},
			SnapshotRestoreProfiles: []ProviderCompatibilityProfile{{
				ProfileID:    "sandbox-snapshot-workspace-v1",
				Level:        "workspace",
				SuiteID:      "sandbox-provider",
				SuiteVersion: "1.0.0",
				SuiteDigest:  "sha256:" + strings.Repeat("a", 64),
			}},
		},
	}
}

func distinctProfiles(count int) []ProviderCompatibilityProfile {
	profiles := make([]ProviderCompatibilityProfile, count)
	for index := range profiles {
		profiles[index] = validEnabledProviderConfig().Capability.SnapshotRestoreProfiles[0]
		profiles[index].ProfileID = fmt.Sprintf("profile-%d", index)
	}
	return profiles
}

func validEnabledProviderTOML() string {
	return `
[server.provider.transport]
enabled = true
server_certificate_file = "provider.crt"
server_private_key_file = "provider.key"
client_ca_bundle_file = "client-ca.pem"
allowed_client_uri_identities = ["spiffe://agent-platform/provider-client"]

[server.provider.transport.address]
host = "127.0.0.1"
port = 9443

[server.provider.capability]
provider_revision_id = "provider-revision-1"

[server.provider.capability.limits]
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_ephemeral_storage_bytes = 1073741824
max_workspace_bytes = 4096
max_gpu_count = 0
max_lease_seconds = 3600
max_exec_seconds = 300

[[server.provider.capability.snapshot_restore_profiles]]
profile_id = "sandbox-snapshot-workspace-v1"
level = "workspace"
suite_id = "sandbox-provider"
suite_version = "1.0.0"
suite_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`
}

func optionHTTP(host string, port int) option.HTTP {
	return option.HTTP{Host: host, Port: port}
}

func serverInt64Pointer(value int64) *int64 {
	return &value
}
