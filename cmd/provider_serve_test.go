package cmd

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/provider"
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
