package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
)

func TestProviderProcessDisabledDefaultsAreInert(t *testing.T) {
	candidate := defaultProviderProcessConfig()
	if candidate.Enabled || candidate.Validate() != nil {
		t.Fatalf("disabled Provider process defaults = %#v", candidate)
	}
}

func TestProviderProcessProductionV2RejectsRuntimeMigrationAndRawAuthority(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	candidate.SchemaVersion = ProviderProductionSchemaV2
	candidate.Transport.ServerCertificateFile = ""
	candidate.Transport.ServerPrivateKeyFile = ""
	candidate.Transport.ClientCABundleFile = ""
	candidate.Transport.ServerCertificateBindingID = "provider-server-certificate"
	candidate.Transport.ServerPrivateKeyBindingID = "provider-server-key"
	candidate.Transport.ClientCABundleBindingID = "provider-client-ca"
	candidate.Transport.ExpectedServerName = "provider.example.test"
	candidate.Postgres.MigrationDSNFile = ""
	candidate.Postgres.RuntimeDSNFile = ""
	candidate.Postgres.MigrationRole = ""
	candidate.Postgres.MigrationMaxConnections = 0
	candidate.Postgres.RuntimeDSNBindingID = "provider-runtime-dsn"
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyFile = ""
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyBindingID = "provider-admission-key"
	candidate.Materials.Provider = RoleMaterialProviderConfig{
		Type: UnixWorkloadMaterialProviderV1, Alias: "provider-agent", SocketPath: "/tmp/sandbox-runtime-provider-agent.sock",
		ExpectedUID: 501, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30,
	}
	for _, item := range []struct {
		id      string
		purpose secretref.Purpose
	}{
		{"provider-server-certificate", secretref.PurposeTLSCertificate},
		{"provider-server-key", secretref.PurposeTLSPrivateKey},
		{"provider-client-ca", secretref.PurposeCABundle},
		{"provider-runtime-dsn", secretref.PurposePostgresRuntimeDSN},
		{"provider-admission-key", secretref.PurposeAdmissionVerification},
	} {
		document, err := json.Marshal(secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://vault/kv/" + item.id), Version: "v1", Purpose: item.purpose,
			TenantID: secretref.SystemTenant, Role: secretref.RoleProvider})
		if err != nil {
			t.Fatal(err)
		}
		candidate.Materials.Bindings = append(candidate.Materials.Bindings, RoleMaterialBindingConfig{ID: item.id, Provider: "provider-agent", Document: string(document)})
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Provider production v2 configuration: %v", err)
	}

	unsafe := *candidate
	unsafe.Postgres = candidate.Postgres
	unsafe.Postgres.MigrationRole = "provider_migrator"
	if err := unsafe.Validate(); err == nil {
		t.Fatal("Provider runtime accepted migration authority")
	}
	unsafe = *candidate
	unsafe.Transport = candidate.Transport
	unsafe.Transport.ServerPrivateKeyFile = "/tmp/provider.key"
	if err := unsafe.Validate(); err == nil {
		t.Fatal("Provider production v2 accepted a raw private-key path")
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
	candidate.Desktop.Docker.ProductionManifestPath = path("phase5-production-release-manifest.json")
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
		"candidate manifest in production": func(c *ProviderProcessConfig) {
			c.Desktop.Docker.CandidateManifestPath = path("phase6-local-candidate-manifest.json")
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

func TestProviderProcessSeparatesLocalDesktopCandidateFromProduction(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	candidate.DeploymentLevel = ProviderLocalCandidateLevel
	candidate.Profile = ProviderProcessDesktopProfile
	candidate.Coding.Lifecycle.Image = ""
	candidate.Desktop.Architecture = "arm64"
	candidate.Desktop.Docker.Image = "sha256:" + strings.Repeat("9", 64)
	candidate.Desktop.Docker.PullPolicy = "never"
	candidate.Desktop.Docker.DataRoot = path("desktop-runtime")
	candidate.Desktop.Docker.CandidateManifestPath = path("phase6-local-candidate-manifest.json")
	candidate.Desktop.Docker.Namespace = "desktop-candidate"
	candidate.Desktop.Docker.ControllerID = "desktop-controller-1"
	candidate.Desktop.Docker.NetworkPolicyReference = "desktop-egress-policy-1"
	candidate.Desktop.LocalCandidateManifestFile = path("local-candidate.json")
	candidate.Desktop.ExecutorURL = "wss://127.0.0.1:9444/executor"
	candidate.Desktop.BrokerMuxSocketPath = path("desktop-broker-11111111111111111111111111111111.sock")
	candidate.Desktop.ExecutorCABundleFile = path("executor-ca.pem")
	candidate.Desktop.ExecutorCertificateFile = path("executor.crt")
	candidate.Desktop.ExecutorPrivateKeyFile = path("executor.key")
	candidate.Desktop.ExecutorIdentity = "executor-desktop-1"
	candidate.Desktop.ExecutorBridgeKeyID = "provider-desktop-v2"
	candidate.Desktop.ExecutorBridgePrivateKeyFile = path("bridge.key")
	candidate.Desktop.Provenance = ProviderBrowserProvenanceConfig{}
	candidate.Desktop.RestrictedNetwork.GatewayImage = "sha256:" + strings.Repeat("d", 64)
	candidate.Desktop.RestrictedNetwork.UplinkNetwork = "desktop-candidate-uplink"
	candidate.Desktop.RestrictedNetwork.Namespace = candidate.Desktop.Docker.Namespace
	candidate.Desktop.RestrictedNetwork.ControllerID = candidate.Desktop.Docker.ControllerID
	candidate.Desktop.RestrictedNetwork.Policies = []ProviderBrowserNetworkPolicyConfig{{Reference: candidate.Desktop.Docker.NetworkPolicyReference, AllowedHosts: []string{"packages.example.test"}}}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid local candidate: %v", err)
	}

	production := *candidate
	production.DeploymentLevel = ProviderProductionLevel
	production.Desktop = candidate.Desktop
	production.Desktop.Docker.Image = desktopimage.LockedPublication().Image()
	production.Desktop.Docker.PullPolicy = "if_not_present"
	production.Desktop.Docker.CandidateManifestPath = ""
	production.Desktop.Docker.ProductionManifestPath = path("phase5-production-release-manifest.json")
	production.Desktop.LocalCandidateManifestFile = ""
	production.Desktop.Provenance = ProviderBrowserProvenanceConfig{ExecutablePath: path("gh"), ExecutableDigest: "sha256:" + strings.Repeat("c", 64)}
	if err := production.Validate(); err == nil {
		t.Fatal("production accepted the unpublished Desktop v2 executor runtime")
	}

	missingExecutor := *candidate
	missingExecutor.Desktop = candidate.Desktop
	missingExecutor.Desktop.ExecutorURL = ""
	if err := missingExecutor.Validate(); err == nil {
		t.Fatal("local candidate without Desktop executor was accepted")
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
