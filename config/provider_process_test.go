package config

import (
	"path/filepath"
	"strings"
	"testing"

	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
)

func TestProviderProcessDisabledDefaultsAreInert(t *testing.T) {
	candidate := defaultProviderProcessConfig()
	if candidate.Enabled || candidate.Validate() != nil {
		t.Fatalf("disabled Provider process defaults = %#v", candidate)
	}
}

func TestProviderProcessValidatesExactDesktopProfile(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	candidate.Profile = ProviderProcessDesktopProfile
	candidate.Coding.Lifecycle.Image = ""
	candidate.Desktop.Architecture = "arm64"
	candidate.Desktop.Docker.Image = desktopimage.LockedPublication().Image()
	candidate.Desktop.Docker.DataRoot = path("desktop-runtime")
	candidate.Desktop.Docker.ManifestPath = path("desktop-manifest.json")
	candidate.Desktop.Docker.Namespace = "desktop-production"
	candidate.Desktop.Docker.ControllerID = "desktop-controller-1"
	candidate.Desktop.Docker.NetworkPolicyReference = "desktop-egress-policy-1"
	candidate.Desktop.Provenance.ExecutablePath = path("gh")
	candidate.Desktop.Provenance.ExecutableDigest = "sha256:" + strings.Repeat("c", 64)
	candidate.Desktop.RestrictedNetwork.GatewayImage = "sha256:" + strings.Repeat("d", 64)
	candidate.Desktop.RestrictedNetwork.UplinkNetwork = "desktop-production-uplink"
	candidate.Desktop.RestrictedNetwork.Namespace = candidate.Desktop.Docker.Namespace
	candidate.Desktop.RestrictedNetwork.ControllerID = candidate.Desktop.Docker.ControllerID
	candidate.Desktop.RestrictedNetwork.Policies = []ProviderBrowserNetworkPolicyConfig{{Reference: candidate.Desktop.Docker.NetworkPolicyReference, AllowedHosts: []string{"packages.example.test"}}}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Desktop Provider process: %v", err)
	}

	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"unlocked image": func(c *ProviderProcessConfig) {
			c.Desktop.Docker.Image = "example.test/desktop@sha256:" + strings.Repeat("e", 64)
		},
		"mixed coding": func(c *ProviderProcessConfig) {
			c.Coding.Lifecycle.Image = "example.test/coding@sha256:" + strings.Repeat("f", 64)
		},
		"ownership drift": func(c *ProviderProcessConfig) {
			c.Desktop.RestrictedNetwork.ControllerID = "different-controller"
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := *candidate
			copy.Coding = candidate.Coding
			copy.Desktop = candidate.Desktop
			mutate(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("unsafe Desktop Provider process configuration was accepted")
			}
		})
	}
}

func TestProviderProcessValidatesExactCodingProfile(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Provider process: %v", err)
	}
	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"development":      func(c *ProviderProcessConfig) { c.DeploymentLevel = "development" },
		"local transport":  func(c *ProviderProcessConfig) { c.Transport.Enabled = false },
		"public probe":     func(c *ProviderProcessConfig) { c.Probe.Host = "0.0.0.0" },
		"same db role":     func(c *ProviderProcessConfig) { c.Postgres.RuntimeRole = c.Postgres.MigrationRole },
		"relative secret":  func(c *ProviderProcessConfig) { c.Postgres.RuntimeDSNFile = "runtime.dsn" },
		"shared authority": func(c *ProviderProcessConfig) { c.Postgres.RuntimeDSNFile = c.Transport.ServerPrivateKeyFile },
		"missing scanners": func(c *ProviderProcessConfig) { c.Coding.Artifact.MalwareCommand = nil },
		"desktop mixture":  func(c *ProviderProcessConfig) { c.Desktop.Architecture = "amd64" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *candidate
			copy.Postgres = candidate.Postgres
			copy.Transport = candidate.Transport
			copy.Coding = candidate.Coding
			copy.Desktop = candidate.Desktop
			mutate(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("unsafe Provider process configuration was accepted")
			}
		})
	}
}

func TestLoadProviderProcessRejectsUnknownField(t *testing.T) {
	snapshotGlobals(t)
	err := Load(writeConfig(t, "[provider_process]\nunknown = true\n"))
	if err == nil || !strings.Contains(err.Error(), "invalid keys") {
		t.Fatalf("unknown Provider field error = %v", err)
	}
}

func validProviderProcessConfig(t *testing.T) *ProviderProcessConfig {
	t.Helper()
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	candidate := defaultProviderProcessConfig()
	candidate.Enabled = true
	candidate.Profile = ProviderProcessCodingShellProfile
	candidate.Transport.Enabled = true
	candidate.Transport.ServerCertificateFile = path("provider.crt")
	candidate.Transport.ServerPrivateKeyFile = path("provider.key")
	candidate.Transport.ClientCABundleFile = path("client-ca.pem")
	candidate.Transport.AllowedClientURIIdentities = []string{"spiffe://product.example.test/provider-client"}
	candidate.Capability.ProviderRevisionID = "provider-revision-1"
	candidate.Capability.Limits = ProviderLimitsConfig{MaxCPUMillis: 1000, MaxMemoryBytes: 1 << 30, MaxEphemeralStorageBytes: 1 << 30, MaxLeaseSeconds: 3600, MaxExecSeconds: 300}
	candidate.Capability.SnapshotRestoreProfiles = []ProviderCompatibilityProfile{{ProfileID: "snapshot-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0", SuiteDigest: "sha256:" + strings.Repeat("a", 64)}}
	candidate.ProtectedAdmission.Issuer = "https://caller.example.test"
	candidate.ProtectedAdmission.ProviderInstanceAudience = "urn:shell-echo:sandbox-runtime:provider-instance:production-1"
	candidate.ProtectedAdmission.TrustedVerificationKeys = []ProviderTrustedVerificationKeyConfig{{ID: "caller-1", Algorithm: "EdDSA", PublicKeyFile: path("caller.pem")}}
	candidate.Postgres.MigrationDSNFile = path("migration.dsn")
	candidate.Postgres.RuntimeDSNFile = path("runtime.dsn")
	candidate.Postgres.MigrationRole = "provider_migrator"
	candidate.Postgres.RuntimeRole = "provider_runtime"
	candidate.Coding.Lifecycle.Image = "example.test/runtime@sha256:" + strings.Repeat("b", 64)
	candidate.Coding.Lifecycle.DataRoot = path("runtime")
	candidate.Coding.Lifecycle.ControllerID = "provider-1"
	candidate.Coding.Terminal.BrokerPath = ProviderCodingShellTerminalBrokerPath
	candidate.Coding.Artifact.StagingRoot = path("staging")
	candidate.Coding.Artifact.ActiveContentCommand = []string{"/bin/true"}
	candidate.Coding.Artifact.MalwareCommand = []string{"/bin/true"}
	return candidate
}
