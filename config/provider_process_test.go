package config

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
)

func TestProviderProcessV3BrowserProductionClosedMatrix(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	defaults := defaultProviderProcessConfig()
	candidate.SchemaVersion = ProviderProductionSchemaV3
	candidate.DeploymentLevel = ProviderProductionLevel
	candidate.Profile = ProviderProcessBrowserProfile
	candidate.Coding = defaults.Coding
	candidate.Desktop = defaults.Desktop
	candidate.Transport.ServerCertificateFile = ""
	candidate.Transport.ServerPrivateKeyFile = ""
	candidate.Transport.ClientCABundleFile = ""
	candidate.Transport.AllowedClientURIIdentities = []string{"spiffe://sandbox-runtime.test/product-runtime"}
	candidate.Transport.SecurityProfilePath = path("security-profile.json")
	candidate.Transport.SecurityProfileDigest = "sha256:" + strings.Repeat("a", 64)
	candidate.Transport.PeerCRLRoleFile = path("peer-crl-role.json")
	candidate.Transport.PeerCRLRoleDigest = "sha256:" + strings.Repeat("b", 64)
	candidate.Transport.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("c", 64)
	candidate.Transport.AgentSocket = path("browser-provider-tls-agent.sock")
	candidate.Transport.AgentUID, candidate.Transport.AgentGID = 501, 20
	candidate.Transport.OperationTimeoutMillis = 3000
	candidate.Transport.Private = ProviderPrivateTransportConfig{
		Enabled: true, Address: providerDefaultHTTP("127.0.0.1", 8448),
		AllowedClientURIIdentities: []string{"spiffe://sandbox-runtime.test/browser-action-ingress-runtime"},
		RoutePolicy:                []string{ProviderPrivateRouteBrowser}, ReadHeaderTimeoutMillis: 5000,
		ReadTimeoutMillis: 30000, WriteTimeoutMillis: 30000, IdleTimeoutMillis: 60000,
		MaxHeaderBytes: 32 << 10, MaxBodyBytes: 256 << 10,
	}
	candidate.Postgres.MigrationDSNFile = ""
	candidate.Postgres.RuntimeDSNFile = ""
	candidate.Postgres.MigrationRole = ""
	candidate.Postgres.MigrationMaxConnections = 0
	candidate.Postgres.RuntimeDSNBindingID = "browser-provider-runtime-dsn"
	candidate.Postgres.ClientAgentSocket = path("browser-provider-postgres-tls-agent.sock")
	candidate.Postgres.ClientAgentUID, candidate.Postgres.ClientAgentGID = 503, 21
	candidate.Postgres.PeerCRLRoleFile = path("browser-provider-postgres-peer-crl-role.json")
	candidate.Postgres.PeerCRLRoleDigest = "sha256:" + strings.Repeat("e", 64)
	candidate.Postgres.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("f", 64)
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyFile = ""
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyBindingID = "browser-provider-admission-key"
	candidate.Materials.Provider = RoleMaterialProviderConfig{
		Type: UnixWorkloadMaterialProviderV1, Alias: "browser-provider-agent", SocketPath: "/tmp/browser-provider-material-agent-test.sock",
		ExpectedUID: 502, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30,
	}
	for _, item := range []struct {
		id      string
		purpose secretref.Purpose
	}{
		{"browser-provider-runtime-dsn", secretref.PurposePostgresRuntimeDSN},
		{"browser-provider-admission-key", secretref.PurposeAdmissionVerification},
	} {
		document, err := json.Marshal(secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://vault/kv/" + item.id), Version: "v1", Purpose: item.purpose,
			TenantID: secretref.SystemTenant, Role: secretref.RoleProvider})
		if err != nil {
			t.Fatal(err)
		}
		candidate.Materials.Bindings = append(candidate.Materials.Bindings, RoleMaterialBindingConfig{ID: item.id, Provider: "browser-provider-agent", Document: string(document)})
	}
	candidate.Browser = ProviderProcessBrowserConfig{
		ExecutorURL: "wss://127.0.0.1:9444/executor", MuxSocketPath: filepath.Join(phase6security.BrowserMuxSocketDirectory, "browser-mux-11111111111111111111111111111111.sock"),
		UsageRetentionSeconds: 3600, ShutdownCleanupSeconds: 10,
		Docker: ProviderBrowserDockerConfig{
			Image: browserimage.LockedPublication().Image(), PullPolicy: "never", MemoryBytes: 1 << 30,
			NanoCPUs: 1_000_000_000, PidsLimit: 256, InputsBytes: 16 << 20, TmpfsBytes: 256 << 20,
			WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20, OperationTimeoutSeconds: 90,
			ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
			DataRoot: path("browser-runtime"), ManifestPath: path("browser-image-manifest.json"),
			SeccompPath: path("browser-seccomp.json"), Namespace: "browser-production",
			ControllerID: "browser-provider-1", NetworkPolicyReference: "browser-egress-policy-1",
			MaxSessionsPerSandbox: 1, MaxSessionsPerController: 16,
		},
		Provenance: ProviderBrowserProvenanceConfig{ExecutablePath: path("gh"), ExecutableDigest: "sha256:" + strings.Repeat("d", 64)},
		RestrictedNetwork: ProviderBrowserNetworkConfig{
			GatewayImage: "sha256:" + strings.Repeat("e", 64), UplinkNetwork: "browser-production-uplink",
			Namespace: "browser-production", ControllerID: "browser-provider-1",
			Policies:    []ProviderBrowserNetworkPolicyConfig{{Reference: "browser-egress-policy-1", AllowedHosts: []string{"packages.example.test"}}},
			MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
			OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10,
		},
	}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Browser v3 production configuration: %v", err)
	}
	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"coding authority":  func(value *ProviderProcessConfig) { value.Coding.Lifecycle.Image = "other-image" },
		"desktop authority": func(value *ProviderProcessConfig) { value.Desktop.ExecutorURL = "wss://127.0.0.1:9555/executor" },
		"wrong route": func(value *ProviderProcessConfig) {
			value.Transport.Private.RoutePolicy = []string{ProviderPrivateRouteTerminal}
		},
		"direct Gateway peer": func(value *ProviderProcessConfig) {
			value.Transport.Private.AllowedClientURIIdentities = []string{"spiffe://sandbox-runtime.test/gateway-runtime"}
		},
		"extra route": func(value *ProviderProcessConfig) {
			value.Transport.Private.RoutePolicy = []string{ProviderPrivateRouteBrowser, ProviderPrivateRouteDesktop}
		},
		"wrong image": func(value *ProviderProcessConfig) {
			value.Browser.Docker.Image = "example.test/browser@sha256:" + strings.Repeat("a", 64)
		},
		"mutable image":       func(value *ProviderProcessConfig) { value.Browser.Docker.Image = "example.test/browser:latest" },
		"raw executor":        func(value *ProviderProcessConfig) { value.Browser.ExecutorURL = "ws://127.0.0.1:9444/executor" },
		"wrong executor path": func(value *ProviderProcessConfig) { value.Browser.ExecutorURL = "wss://127.0.0.1:9444/private/browser" },
		"noncanonical socket": func(value *ProviderProcessConfig) { value.Browser.MuxSocketPath = path("browser-mux.sock") },
		"wrong mux owner directory": func(value *ProviderProcessConfig) {
			value.Browser.MuxSocketPath = path("browser-mux-11111111111111111111111111111111.sock")
		},
		"wrong network owner":       func(value *ProviderProcessConfig) { value.Browser.RestrictedNetwork.ControllerID = "other-controller" },
		"candidate relabel":         func(value *ProviderProcessConfig) { value.DeploymentLevel = ProviderLocalCandidateLevel },
		"legacy schema":             func(value *ProviderProcessConfig) { value.SchemaVersion = ProviderProductionSchemaV2 },
		"missing PostgreSQL signer": func(value *ProviderProcessConfig) { value.Postgres.ClientAgentSocket = "" },
		"ordinary signer reused":    func(value *ProviderProcessConfig) { value.Postgres.ClientAgentSocket = value.Transport.AgentSocket },
		"ordinary UID reused":       func(value *ProviderProcessConfig) { value.Postgres.ClientAgentUID = value.Transport.AgentUID },
		"ordinary GID reused":       func(value *ProviderProcessConfig) { value.Postgres.ClientAgentGID = value.Transport.AgentGID },
	} {
		t.Run(name, func(t *testing.T) {
			value := *candidate
			value.Coding = candidate.Coding
			value.Desktop = candidate.Desktop
			value.Browser = candidate.Browser
			value.Transport = candidate.Transport
			value.Transport.Private = candidate.Transport.Private
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe Browser v3 production configuration was accepted")
			}
		})
	}
}

func TestProviderProcessDisabledDefaultsAreInert(t *testing.T) {
	candidate := defaultProviderProcessConfig()
	if candidate.Enabled || candidate.Validate() != nil {
		t.Fatalf("disabled Provider process defaults = %#v", candidate)
	}
}

func TestProviderLegacyRejectsUnreleasedPeerCRLBinding(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	if err := candidate.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"role file": func(value *ProviderProcessConfig) { value.Transport.PeerCRLRoleFile = "/tmp/peer-role.json" },
		"role digest": func(value *ProviderProcessConfig) {
			value.Transport.PeerCRLRoleDigest = "sha256:" + strings.Repeat("a", 64)
		},
		"mapping digest": func(value *ProviderProcessConfig) {
			value.Transport.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := *candidate
			value.Transport = candidate.Transport
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("legacy Provider accepted peer CRL role binding")
			}
		})
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
	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"role file": func(value *ProviderProcessConfig) { value.Transport.PeerCRLRoleFile = "/tmp/peer-role.json" },
		"role digest": func(value *ProviderProcessConfig) {
			value.Transport.PeerCRLRoleDigest = "sha256:" + strings.Repeat("a", 64)
		},
		"mapping digest": func(value *ProviderProcessConfig) {
			value.Transport.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("b", 64)
		},
	} {
		t.Run("v2 rejects "+name, func(t *testing.T) {
			value := *candidate
			value.Transport = candidate.Transport
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("v2 accepted peer CRL role binding")
			}
		})
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

func TestProviderProcessV3RequiresTwoLiveListenersAndOnlyNonTLSMaterials(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	candidate.SchemaVersion = ProviderProductionSchemaV3
	candidate.Transport.ServerCertificateFile = ""
	candidate.Transport.ServerPrivateKeyFile = ""
	candidate.Transport.ClientCABundleFile = ""
	candidate.Transport.AllowedClientURIIdentities = []string{"spiffe://sandbox-runtime.test/product-runtime"}
	candidate.Transport.SecurityProfilePath = filepath.Join(t.TempDir(), "profile.json")
	candidate.Transport.SecurityProfileDigest = "sha256:" + strings.Repeat("a", 64)
	candidate.Transport.PeerCRLRoleFile = filepath.Join(filepath.Dir(candidate.Transport.SecurityProfilePath), "peer-crl-role.json")
	candidate.Transport.PeerCRLRoleDigest = "sha256:" + strings.Repeat("b", 64)
	candidate.Transport.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("c", 64)
	candidate.Transport.AgentSocket = "/tmp/provider-tls-agent-test.sock"
	candidate.Transport.AgentUID, candidate.Transport.AgentGID = 501, 20
	candidate.Transport.OperationTimeoutMillis = 3000
	candidate.Transport.Private = ProviderPrivateTransportConfig{
		Enabled: true, Address: providerDefaultHTTP("127.0.0.1", 8448),
		AllowedClientURIIdentities: []string{"spiffe://sandbox-runtime.test/gateway-runtime"},
		RoutePolicy:                []string{ProviderPrivateRouteTerminal}, ReadHeaderTimeoutMillis: 5000,
		ReadTimeoutMillis: 30000, WriteTimeoutMillis: 30000, IdleTimeoutMillis: 60000,
		MaxHeaderBytes: 32 << 10, MaxBodyBytes: 256 << 10,
	}
	candidate.Postgres.MigrationDSNFile = ""
	candidate.Postgres.RuntimeDSNFile = ""
	candidate.Postgres.MigrationRole = ""
	candidate.Postgres.MigrationMaxConnections = 0
	candidate.Postgres.RuntimeDSNBindingID = "provider-runtime-dsn"
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyFile = ""
	candidate.Postgres.ClientAgentSocket = "/tmp/provider-postgres-tls-agent-test.sock"
	candidate.Postgres.ClientAgentUID, candidate.Postgres.ClientAgentGID = 503, 21
	candidate.Postgres.PeerCRLRoleFile = "/tmp/provider-postgres-peer-crl-role-test.json"
	candidate.Postgres.PeerCRLRoleDigest = "sha256:" + strings.Repeat("e", 64)
	candidate.Postgres.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("f", 64)
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyBindingID = "provider-admission-key"
	candidate.Materials.Provider = RoleMaterialProviderConfig{
		Type: UnixWorkloadMaterialProviderV1, Alias: "provider-agent", SocketPath: "/tmp/provider-material-agent-test.sock",
		ExpectedUID: 502, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30,
	}
	for _, item := range []struct {
		id      string
		purpose secretref.Purpose
	}{
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
		t.Fatalf("valid coding-shell Provider v3: %v", err)
	}
	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"missing peer role":           func(value *ProviderProcessConfig) { value.Transport.PeerCRLRoleFile = "" },
		"missing role digest":         func(value *ProviderProcessConfig) { value.Transport.PeerCRLRoleDigest = "" },
		"missing mapping digest":      func(value *ProviderProcessConfig) { value.Transport.PeerCRLSourceMappingDigest = "" },
		"malformed role digest":       func(value *ProviderProcessConfig) { value.Transport.PeerCRLRoleDigest = "sha256:ABC" },
		"malformed map digest":        func(value *ProviderProcessConfig) { value.Transport.PeerCRLSourceMappingDigest = "sha256:ABC" },
		"missing PostgreSQL signer":   func(value *ProviderProcessConfig) { value.Postgres.ClientAgentSocket = "" },
		"shared PostgreSQL signer":    func(value *ProviderProcessConfig) { value.Postgres.ClientAgentSocket = value.Transport.AgentSocket },
		"missing PostgreSQL peer CRL": func(value *ProviderProcessConfig) { value.Postgres.PeerCRLRoleFile = "" },
		"old v3 all absent": func(value *ProviderProcessConfig) {
			value.Transport.PeerCRLRoleFile = ""
			value.Transport.PeerCRLRoleDigest = ""
			value.Transport.PeerCRLSourceMappingDigest = ""
		},
		"raw certificate":        func(value *ProviderProcessConfig) { value.Transport.ServerCertificateFile = "/tmp/provider.pem" },
		"static binding":         func(value *ProviderProcessConfig) { value.Transport.ServerPrivateKeyBindingID = "old-key" },
		"private static binding": func(value *ProviderProcessConfig) { value.Transport.Private.ClientCABundleBindingID = "old-ca" },
		"private disabled":       func(value *ProviderProcessConfig) { value.Transport.Private.Enabled = false },
		"crossed identity":       func(value *ProviderProcessConfig) { value.Transport.Private.AllowedClientURIIdentities = nil },
		"extra route": func(value *ProviderProcessConfig) {
			value.Transport.Private.RoutePolicy = append(value.Transport.Private.RoutePolicy, ProviderPrivateRouteDesktop)
		},
		"wrong signer digest": func(value *ProviderProcessConfig) { value.Transport.SecurityProfileDigest = "sha256:abc" },
		"extra material": func(value *ProviderProcessConfig) {
			value.Materials.Bindings = append(value.Materials.Bindings, value.Materials.Bindings[0])
		},
		"Desktop executor authority": func(value *ProviderProcessConfig) { value.Desktop.ExecutorURL = "wss://desktop.example.test/executor" },
		"Desktop v3":                 func(value *ProviderProcessConfig) { value.Profile = ProviderProcessDesktopProfile },
	} {
		t.Run(name, func(t *testing.T) {
			value := *candidate
			value.Transport = candidate.Transport
			value.Transport.Private = candidate.Transport.Private
			value.Transport.Private.RoutePolicy = append([]string(nil), candidate.Transport.Private.RoutePolicy...)
			value.Materials = candidate.Materials
			value.Materials.Bindings = append([]RoleMaterialBindingConfig(nil), candidate.Materials.Bindings...)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe Provider v3 configuration was accepted")
			}
		})
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
	ignoredSourceRoot := *candidate
	ignoredSourceRoot.Desktop = candidate.Desktop
	ignoredSourceRoot.Desktop.LocalCandidateSourceRoot = path("source")
	if err := ignoredSourceRoot.Validate(); err == nil {
		t.Fatal("legacy candidate accepted an ignored v3 source root")
	}
}

func TestProviderProcessV3DesktopCandidateClosedMatrix(t *testing.T) {
	candidate := validProviderProcessConfig(t)
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	candidate.SchemaVersion = ProviderProductionSchemaV3
	candidate.DeploymentLevel = ProviderLocalCandidateLevel
	candidate.Profile = ProviderProcessDesktopProfile
	candidate.Coding.Lifecycle.Image = ""
	candidate.Transport.ServerCertificateFile = ""
	candidate.Transport.ServerPrivateKeyFile = ""
	candidate.Transport.ClientCABundleFile = ""
	candidate.Transport.AllowedClientURIIdentities = []string{"spiffe://sandbox-runtime.test/product-runtime"}
	candidate.Transport.SecurityProfilePath = path("security-profile.json")
	candidate.Transport.SecurityProfileDigest = "sha256:" + strings.Repeat("a", 64)
	candidate.Transport.PeerCRLRoleFile = path("peer-crl-role.json")
	candidate.Transport.PeerCRLRoleDigest = "sha256:" + strings.Repeat("b", 64)
	candidate.Transport.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("c", 64)
	candidate.Transport.AgentSocket = path("desktop-provider-tls-agent.sock")
	candidate.Transport.AgentUID, candidate.Transport.AgentGID = 501, 20
	candidate.Transport.OperationTimeoutMillis = 3000
	candidate.Transport.Private = ProviderPrivateTransportConfig{
		Enabled: true, Address: providerDefaultHTTP("127.0.0.1", 8448),
		AllowedClientURIIdentities: []string{"spiffe://sandbox-runtime.test/gateway-runtime"},
		RoutePolicy:                []string{ProviderPrivateRouteDesktop}, ReadHeaderTimeoutMillis: 5000,
		ReadTimeoutMillis: 30000, WriteTimeoutMillis: 30000, IdleTimeoutMillis: 60000,
		MaxHeaderBytes: 32 << 10, MaxBodyBytes: 256 << 10,
	}
	candidate.Postgres.MigrationDSNFile = ""
	candidate.Postgres.RuntimeDSNFile = ""
	candidate.Postgres.MigrationRole = ""
	candidate.Postgres.MigrationMaxConnections = 0
	candidate.Postgres.RuntimeDSNBindingID = "desktop-provider-runtime-dsn"
	candidate.Postgres.ClientAgentSocket = path("desktop-provider-postgres-tls-agent.sock")
	candidate.Postgres.ClientAgentUID, candidate.Postgres.ClientAgentGID = 503, 21
	candidate.Postgres.PeerCRLRoleFile = path("desktop-provider-postgres-peer-crl-role.json")
	candidate.Postgres.PeerCRLRoleDigest = "sha256:" + strings.Repeat("e", 64)
	candidate.Postgres.PeerCRLSourceMappingDigest = "sha256:" + strings.Repeat("f", 64)
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyFile = ""
	candidate.ProtectedAdmission.TrustedVerificationKeys[0].PublicKeyBindingID = "desktop-provider-admission-key"
	candidate.Materials.Provider = RoleMaterialProviderConfig{
		Type: UnixWorkloadMaterialProviderV1, Alias: "desktop-provider-agent", SocketPath: "/tmp/desktop-provider-material-agent-test.sock",
		ExpectedUID: 502, ExpectedGID: 20, OperationTimeoutSeconds: 3, CacheSeconds: 30,
	}
	for _, item := range []struct {
		id      string
		purpose secretref.Purpose
	}{
		{"desktop-provider-runtime-dsn", secretref.PurposePostgresRuntimeDSN},
		{"desktop-provider-admission-key", secretref.PurposeAdmissionVerification},
		{"desktop-provider-bridge-key", secretref.PurposeExecutorBridgeKey},
	} {
		document, err := json.Marshal(secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://vault/kv/" + item.id), Version: "v1", Purpose: item.purpose,
			TenantID: secretref.SystemTenant, Role: secretref.RoleProvider})
		if err != nil {
			t.Fatal(err)
		}
		candidate.Materials.Bindings = append(candidate.Materials.Bindings, RoleMaterialBindingConfig{ID: item.id, Provider: "desktop-provider-agent", Document: string(document)})
	}
	candidate.Desktop.Architecture = "arm64"
	candidate.Desktop.Docker.Image = "sha256:" + strings.Repeat("9", 64)
	candidate.Desktop.Docker.PullPolicy = "never"
	candidate.Desktop.Docker.DataRoot = path("desktop-runtime")
	candidate.Desktop.Docker.CandidateManifestPath = path("desktop-candidate-image-manifest.json")
	candidate.Desktop.Docker.Namespace = "desktop-candidate"
	candidate.Desktop.Docker.ControllerID = "desktop-controller-1"
	candidate.Desktop.Docker.NetworkPolicyReference = "desktop-egress-policy-1"
	candidate.Desktop.LocalCandidateManifestFile = path("desktop-candidate-source-manifest.json")
	candidate.Desktop.LocalCandidateSourceRoot = path("source")
	candidate.Desktop.ExecutorURL = "wss://127.0.0.1:9444/executor"
	candidate.Desktop.BrokerMuxSocketPath = path("desktop-broker-11111111111111111111111111111111.sock")
	candidate.Desktop.ExecutorIdentity = "executor-desktop-1"
	candidate.Desktop.ExecutorBridgeKeyID = "provider-desktop-v2"
	candidate.Desktop.ExecutorBridgePrivateKeyBindingID = "desktop-provider-bridge-key"
	candidate.Desktop.RestrictedNetwork.GatewayImage = "sha256:" + strings.Repeat("d", 64)
	candidate.Desktop.RestrictedNetwork.UplinkNetwork = "desktop-candidate-uplink"
	candidate.Desktop.RestrictedNetwork.Namespace = candidate.Desktop.Docker.Namespace
	candidate.Desktop.RestrictedNetwork.ControllerID = candidate.Desktop.Docker.ControllerID
	candidate.Desktop.RestrictedNetwork.Policies = []ProviderBrowserNetworkPolicyConfig{{Reference: candidate.Desktop.Docker.NetworkPolicyReference, AllowedHosts: []string{"packages.example.test"}}}
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid Desktop v3 local candidate: %v", err)
	}
	for name, mutate := range map[string]func(*ProviderProcessConfig){
		"missing candidate source":         func(value *ProviderProcessConfig) { value.Desktop.LocalCandidateManifestFile = "" },
		"missing source root":              func(value *ProviderProcessConfig) { value.Desktop.LocalCandidateSourceRoot = "" },
		"missing candidate image manifest": func(value *ProviderProcessConfig) { value.Desktop.Docker.CandidateManifestPath = "" },
		"mutable image":                    func(value *ProviderProcessConfig) { value.Desktop.Docker.Image = "example.test/desktop:latest" },
		"remote pull":                      func(value *ProviderProcessConfig) { value.Desktop.Docker.PullPolicy = "if_not_present" },
		"crossed production manifest": func(value *ProviderProcessConfig) {
			value.Desktop.Docker.ProductionManifestPath = path("production.json")
		},
		"production relabel":  func(value *ProviderProcessConfig) { value.DeploymentLevel = ProviderProductionLevel },
		"raw executor key":    func(value *ProviderProcessConfig) { value.Desktop.ExecutorPrivateKeyFile = path("executor.key") },
		"static executor key": func(value *ProviderProcessConfig) { value.Desktop.ExecutorPrivateKeyBindingID = "old-executor-key" },
		"static private key": func(value *ProviderProcessConfig) {
			value.Transport.Private.ServerPrivateKeyBindingID = "old-private-key"
		},
		"terminal route": func(value *ProviderProcessConfig) {
			value.Transport.Private.RoutePolicy = []string{ProviderPrivateRouteTerminal}
		},
		"extra route": func(value *ProviderProcessConfig) {
			value.Transport.Private.RoutePolicy = []string{ProviderPrivateRouteDesktop, ProviderPrivateRouteBrowser}
		},
		"attach route drift":        func(value *ProviderProcessConfig) { value.Desktop.ExecutorURL = "wss://127.0.0.1:9444/private/browser" },
		"missing PostgreSQL signer": func(value *ProviderProcessConfig) { value.Postgres.ClientAgentSocket = "" },
		"ordinary signer reused":    func(value *ProviderProcessConfig) { value.Postgres.ClientAgentSocket = value.Transport.AgentSocket },
	} {
		t.Run(name, func(t *testing.T) {
			value := *candidate
			value.Transport = candidate.Transport
			value.Transport.Private = candidate.Transport.Private
			value.Desktop = candidate.Desktop
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("unsafe Desktop v3 candidate configuration was accepted")
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
