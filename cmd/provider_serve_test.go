package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/spf13/cobra"
)

func TestProductionProviderCapabilityAdvertisementIsExact(t *testing.T) {
	cfg := &config.ProviderProcessConfig{
		Capability: config.ProviderProcessCapabilityConfig{
			ProviderRevisionID: "provider-revision-1",
			Limits: config.ProviderLimitsConfig{
				MaxCPUMillis: 1000, MaxMemoryBytes: 1 << 30, MaxEphemeralStorageBytes: 1 << 30,
				MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
			},
			SnapshotRestoreProfiles: []config.ProviderCompatibilityProfile{{
				ProfileID: "snapshot-v1", Level: "workspace", SuiteID: "sandbox-provider", SuiteVersion: "1.0.0",
				SuiteDigest: "sha256:" + strings.Repeat("a", 64),
			}},
		},
	}
	ready := providerCapabilityReadiness{
		ProtectedAdmission: true, MutationGuard: true, LifecyclePersistence: true, RuntimeLifecycle: true,
		LifecycleControl: true, LeaseExpiry: true, LifecycleEventReads: true, StableMounts: true,
		ExecAcceptance: true, ExecExecutor: true, ExecCancellation: true, ExecResultRetention: true, ExecReconciliation: true,
		UsageCollection: true, TerminalAuthority: true, TerminalAllocator: true, OpaqueHandoff: true, TerminalControl: true, TerminalWebSocket: true,
		ArtifactAcceptance: true, OutputStaging: true, ContentChecks: true, RetainedEvidence: true, OperationAggregation: true,
	}
	source, err := newProviderCapabilitySource(providerProcessCapability(cfg, true), ready)
	if err != nil {
		t.Fatal(err)
	}
	assertProviderAdvertisement(t, source, []string{
		"sandbox.exec", "sandbox.lifecycle-control", "sandbox.terminal", "sandbox.terminal-connect", "sandbox.terminal-control",
	}, config.ProviderCodingShellRuntimeProfileID, []string{
		config.ProviderCodingShellExecProfileID, config.ProviderCodingShellTerminalProfileID,
		config.ProviderLifecycleControlProfileID, config.ProviderTerminalControlProfileID, config.ProviderTerminalConnectProfileID,
	})

	cfg.Desktop.Architecture = "arm64"
	desktopSource, err := newDesktopCapabilitySource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assertProviderAdvertisement(t, desktopSource, []string{"sandbox.desktop"}, lifecycle.DesktopRuntimeProfile, []string{providerdesktop.CapabilityProfileID})
	desktopSnapshot, err := desktopSource.CapabilitySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(desktopSnapshot.RuntimeProfiles[0].Architecture, []string{"arm64"}) {
		t.Fatalf("Desktop architecture = %#v", desktopSnapshot.RuntimeProfiles[0].Architecture)
	}
	cfg.Profile = config.ProviderProcessBrowserProfile
	browserSource, err := newBrowserCapabilitySource(cfg, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	assertProviderAdvertisement(t, browserSource, []string{"sandbox.browser"}, lifecycle.BrowserRuntimeProfile,
		[]string{providerbrowser.CapabilityProfileID})
	browserSnapshot, err := browserSource.CapabilitySnapshot(context.Background())
	if err != nil || !reflect.DeepEqual(browserSnapshot.RuntimeProfiles[0].Architecture, []string{"amd64"}) {
		t.Fatalf("Browser architecture = %#v, err=%v", browserSnapshot.RuntimeProfiles, err)
	}
	if _, err := newBrowserCapabilitySource(cfg, "unknown"); err == nil {
		t.Fatal("Browser Provider advertised an unverified Docker architecture")
	}
}

func assertProviderAdvertisement(t *testing.T, source provider.CapabilityReader, wantCapabilities []string, wantRuntime string, wantProfiles []string) {
	t.Helper()
	snapshot, err := source.CapabilitySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gotCapabilities := make([]string, len(snapshot.Capabilities))
	for index := range snapshot.Capabilities {
		gotCapabilities[index] = snapshot.Capabilities[index].ID
	}
	sort.Strings(gotCapabilities)
	sort.Strings(wantCapabilities)
	if !reflect.DeepEqual(gotCapabilities, wantCapabilities) {
		t.Fatalf("capabilities = %#v, want %#v", gotCapabilities, wantCapabilities)
	}
	if len(snapshot.RuntimeProfiles) != 1 || snapshot.RuntimeProfiles[0].ID != wantRuntime {
		t.Fatalf("runtime profiles = %#v, want only %q", snapshot.RuntimeProfiles, wantRuntime)
	}
	gotProfiles := append([]string(nil), snapshot.RuntimeProfiles[0].CapabilityProfileIDs...)
	sort.Strings(gotProfiles)
	sort.Strings(wantProfiles)
	if !reflect.DeepEqual(gotProfiles, wantProfiles) {
		t.Fatalf("capability profiles = %#v, want %#v", gotProfiles, wantProfiles)
	}
}

func TestRoleCommandsRejectMixedProcessAuthority(t *testing.T) {
	previousApplication, previousProduct, previousProvider := config.Application, config.ProductProcess, config.ProviderProcess
	t.Cleanup(func() {
		config.Application, config.ProductProcess, config.ProviderProcess = previousApplication, previousProduct, previousProvider
	})
	config.Application = &config.ApplicationConfig{Mode: config.ApplicationProductionMode}
	config.ProductProcess = &config.ProductProcessConfig{Enabled: true}
	config.ProviderProcess = &config.ProviderProcessConfig{Enabled: true}
	command := &cobra.Command{}

	if err := runServe(command, nil); err == nil || !strings.Contains(err.Error(), "product_process.enabled") {
		t.Fatalf("root serve mixed authority error = %v", err)
	}
	if err := runProductServe(command, nil); err == nil || !strings.Contains(err.Error(), "cannot share") {
		t.Fatalf("Product serve mixed authority error = %v", err)
	}
	if err := runProviderServe(command, nil); err == nil || !strings.Contains(err.Error(), "cannot share") {
		t.Fatalf("Provider serve mixed authority error = %v", err)
	}

	config.ProductProcess.Enabled = false
	if err := runServe(command, nil); err == nil || !strings.Contains(err.Error(), "provider_process.enabled") {
		t.Fatalf("root serve Provider boundary error = %v", err)
	}
}

func TestBrowserProviderCannotFallThroughToCodingComposition(t *testing.T) {
	composition, err := newProductionProvider(context.Background(), &config.ProviderProcessConfig{
		Profile: config.ProviderProcessBrowserProfile, SchemaVersion: config.ProviderProductionSchemaV3,
	}, nil, nil, nil)
	if err == nil || composition != nil || !strings.Contains(err.Error(), "Browser Provider production dependencies") {
		t.Fatalf("Browser route bypassed its real composition guard = %v, %v", composition, err)
	}
	composition, err = newProductionProvider(context.Background(), &config.ProviderProcessConfig{
		Profile: config.ProviderProcessDesktopProfile, SchemaVersion: config.ProviderProductionSchemaV3,
		DeploymentLevel: config.ProviderLocalCandidateLevel,
	}, nil, nil, nil)
	if err == nil || composition != nil || !strings.Contains(err.Error(), "Desktop Provider production dependencies") {
		t.Fatalf("Desktop route bypassed its real composition guard = %v, %v", composition, err)
	}
}

func TestDesktopV3ProductionCannotBypassCommandMatrix(t *testing.T) {
	composition, err := newProductionProvider(context.Background(), &config.ProviderProcessConfig{
		Profile: config.ProviderProcessDesktopProfile, SchemaVersion: config.ProviderProductionSchemaV3,
		DeploymentLevel: config.ProviderProductionLevel,
	}, nil, nil, nil)
	if err == nil || composition != nil || !strings.Contains(err.Error(), "production artifact admission is unavailable") {
		t.Fatalf("Desktop v3 production reached composition = %v, %v", composition, err)
	}
}

func TestProviderServeSchemaMatrix(t *testing.T) {
	for _, sample := range []struct {
		schema  string
		profile config.ProviderProcessProfile
		level   config.ProviderDeploymentLevel
		allowed bool
	}{
		{config.ProviderProductionSchemaV3, config.ProviderProcessCodingShellProfile, config.ProviderProductionLevel, true},
		{config.ProviderProductionSchemaV3, config.ProviderProcessBrowserProfile, config.ProviderProductionLevel, true},
		{config.ProviderProductionSchemaV3, config.ProviderProcessDesktopProfile, config.ProviderLocalCandidateLevel, true},
		{config.ProviderProductionSchemaV3, config.ProviderProcessDesktopProfile, config.ProviderProductionLevel, false},
		{config.ProviderProductionSchemaV3, config.ProviderProcessBrowserProfile, config.ProviderLocalCandidateLevel, false},
		{config.ProviderProductionSchemaV3, config.ProviderProcessCodingShellProfile, config.ProviderLocalCandidateLevel, false},
		{"sandbox-runtime.provider-process.v1", config.ProviderProcessDesktopProfile, config.ProviderLocalCandidateLevel, false},
	} {
		candidate := &config.ProviderProcessConfig{SchemaVersion: sample.schema, Profile: sample.profile, DeploymentLevel: sample.level}
		if got := providerServeSchemaAllowed(candidate); got != sample.allowed {
			t.Fatalf("Provider command schema/profile/level = %s/%s/%s: %v", sample.schema, sample.profile, sample.level, got)
		}
	}
	if providerServeSchemaAllowed(nil) {
		t.Fatal("nil Provider command configuration was admitted")
	}
}

func TestProviderExecutorReadinessRequiresExactVerifiedEndpoint(t *testing.T) {
	status := http.StatusNoContent
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(status)
	}))
	defer server.Close()
	endpoint := strings.Replace(server.URL, "https://", "wss://", 1) + "/executor"
	if err := probeProviderExecutorBackend(t.Context(), server.Client(), endpoint, time.Second); err != nil {
		t.Fatalf("verified backend ready: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := probeProviderExecutorBackend(t.Context(), server.Client(), endpoint, time.Second); err == nil {
		t.Fatal("unavailable backend became ready")
	}
	if err := probeProviderExecutorBackend(t.Context(), server.Client(), endpoint+"?fallback=1", time.Second); err == nil {
		t.Fatal("backend readiness accepted a noncanonical endpoint")
	}
}

func TestProviderAdmissionReadinessStaysClosedUntilBound(t *testing.T) {
	gate := &providerAdmissionReadiness{}
	if err := gate.Ready(t.Context()); err == nil {
		t.Fatal("unbound Provider admission became ready")
	}
	if err := gate.Bind(func(context.Context) error { return errors.New("dependency down") }); err != nil {
		t.Fatal(err)
	}
	if err := gate.Ready(t.Context()); err == nil {
		t.Fatal("failed Provider dependency became ready")
	}
	if err := gate.Bind(func(context.Context) error { return nil }); err == nil {
		t.Fatal("Provider admission readiness was rebound")
	}
}
