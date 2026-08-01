package providerapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func TestMapCapabilitiesProjectsHonestDocument(t *testing.T) {
	workspace := int64(4096)
	gpu := int64(0)
	snapshot := validSnapshot(t, &workspace, &gpu)

	document := mapCapabilities(snapshot)
	if document.ProviderRevisionID != "revision-1" || document.APIVersion != providerv1.APIVersionV1 {
		t.Fatalf("identity fields = %#v", document)
	}
	if document.Capabilities == nil || len(document.Capabilities) != 0 {
		t.Fatalf("capabilities = %#v, want non-nil empty", document.Capabilities)
	}
	if document.RuntimeProfiles == nil || len(document.RuntimeProfiles) != 0 {
		t.Fatalf("runtime profiles = %#v, want non-nil empty", document.RuntimeProfiles)
	}
	if len(document.SnapshotRestoreProfile) != 1 {
		t.Fatalf("snapshot/restore profiles = %#v", document.SnapshotRestoreProfile)
	}
	profile := document.SnapshotRestoreProfile[0]
	if profile.ProfileID != "sandbox-snapshot-workspace-v1" || profile.Level != providerv1.SnapshotWorkspace ||
		profile.SuiteID != providerv1.SandboxSuiteProvider || profile.SuiteVersion != "1.0.0" ||
		profile.SuiteDigest != providerv1.SHA256Digest("sha256:"+strings.Repeat("a", 64)) {
		t.Fatalf("mapped profile = %#v", profile)
	}
	if document.Limits.MaxCPUMillis != 1000 || document.Limits.MaxMemoryBytes != 1<<30 ||
		document.Limits.MaxEphemeralStorageBytes != 1<<30 || document.Limits.MaxLeaseSeconds != 3600 ||
		document.Limits.MaxExecSeconds != 300 || document.Limits.MaxWorkspaceBytes == nil ||
		*document.Limits.MaxWorkspaceBytes != 4096 || document.Limits.MaxGPUCount == nil || *document.Limits.MaxGPUCount != 0 {
		t.Fatalf("mapped limits = %#v", document.Limits)
	}
}

func TestMapCapabilitiesDefensivelyCopiesPointersAndProfiles(t *testing.T) {
	workspace := int64(4096)
	gpu := int64(0)
	snapshot := validSnapshot(t, &workspace, &gpu)
	document := mapCapabilities(snapshot)

	*snapshot.Limits.MaxWorkspaceBytes = 1
	*snapshot.Limits.MaxGPUCount = 2
	snapshot.SnapshotRestoreProfiles[0].ProfileID = "mutated"
	if *document.Limits.MaxWorkspaceBytes != 4096 || *document.Limits.MaxGPUCount != 0 ||
		document.SnapshotRestoreProfile[0].ProfileID != "sandbox-snapshot-workspace-v1" {
		t.Fatalf("snapshot mutation changed mapped document: %#v", document)
	}
}

func TestValidateCapabilitiesRejectsInvalidDocuments(t *testing.T) {
	valid := mapCapabilities(validSnapshot(t, int64Pointer(4096), int64Pointer(0)))
	tests := map[string]func(*providerv1.Capabilities){
		"empty revision": func(d *providerv1.Capabilities) { d.ProviderRevisionID = " " },
		"invalid revision UTF-8": func(d *providerv1.Capabilities) {
			d.ProviderRevisionID = string([]byte{0xff})
		},
		"API version":      func(d *providerv1.Capabilities) { d.APIVersion = "v2" },
		"nil capabilities": func(d *providerv1.Capabilities) { d.Capabilities = nil },
		"advertised capability": func(d *providerv1.Capabilities) {
			d.Capabilities = []providerv1.Capability{{ID: providerv1.CapabilityExec}}
		},
		"nil runtime profiles": func(d *providerv1.Capabilities) { d.RuntimeProfiles = nil },
		"advertised runtime": func(d *providerv1.Capabilities) {
			d.RuntimeProfiles = []providerv1.RuntimeProfile{{ID: "runtime-1", IsolationClass: providerv1.IsolationContainer}}
		},
		"zero CPU":         func(d *providerv1.Capabilities) { d.Limits.MaxCPUMillis = 0 },
		"negative memory":  func(d *providerv1.Capabilities) { d.Limits.MaxMemoryBytes = -1 },
		"zero ephemeral":   func(d *providerv1.Capabilities) { d.Limits.MaxEphemeralStorageBytes = 0 },
		"zero lease":       func(d *providerv1.Capabilities) { d.Limits.MaxLeaseSeconds = 0 },
		"zero exec":        func(d *providerv1.Capabilities) { d.Limits.MaxExecSeconds = 0 },
		"zero workspace":   func(d *providerv1.Capabilities) { d.Limits.MaxWorkspaceBytes = int64Pointer(0) },
		"negative GPU":     func(d *providerv1.Capabilities) { d.Limits.MaxGPUCount = int64Pointer(-1) },
		"empty profiles":   func(d *providerv1.Capabilities) { d.SnapshotRestoreProfile = nil },
		"blank profile ID": func(d *providerv1.Capabilities) { d.SnapshotRestoreProfile[0].ProfileID = " " },
		"invalid profile UTF-8": func(d *providerv1.Capabilities) {
			d.SnapshotRestoreProfile[0].ProfileID = string([]byte{0xff})
		},
		"long profile ID": func(d *providerv1.Capabilities) { d.SnapshotRestoreProfile[0].ProfileID = strings.Repeat("界", 201) },
		"invalid level":   func(d *providerv1.Capabilities) { d.SnapshotRestoreProfile[0].Level = "memory" },
		"invalid suite":   func(d *providerv1.Capabilities) { d.SnapshotRestoreProfile[0].SuiteID = "other" },
		"invalid semver":  func(d *providerv1.Capabilities) { d.SnapshotRestoreProfile[0].SuiteVersion = "v1" },
		"uppercase digest": func(d *providerv1.Capabilities) {
			d.SnapshotRestoreProfile[0].SuiteDigest = providerv1.SHA256Digest("sha256:" + strings.Repeat("A", 64))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			document := cloneDocument(valid)
			mutate(&document)
			if err := validateCapabilities(document); err == nil {
				t.Fatal("validateCapabilities() error = nil")
			}
		})
	}

	t.Run("200 Unicode characters", func(t *testing.T) {
		document := cloneDocument(valid)
		document.SnapshotRestoreProfile[0].ProfileID = strings.Repeat("界", 200)
		if err := validateCapabilities(document); err != nil {
			t.Fatalf("validateCapabilities() error = %v", err)
		}
	})
	t.Run("explicit zero GPU", func(t *testing.T) {
		if err := validateCapabilities(valid); err != nil {
			t.Fatalf("validateCapabilities() error = %v", err)
		}
	})
}

func TestValidateCapabilitiesProfileCountAndIdentityUniqueness(t *testing.T) {
	document := mapCapabilities(validSnapshot(t, nil, nil))
	document.SnapshotRestoreProfile = make([]providerv1.SnapshotRestoreProfile, maxSnapshotRestoreProfiles)
	for index := range document.SnapshotRestoreProfile {
		document.SnapshotRestoreProfile[index] = validWireProfile(fmt.Sprintf("profile-%d", index))
	}
	if err := validateCapabilities(document); err != nil {
		t.Fatalf("%d profiles rejected: %v", maxSnapshotRestoreProfiles, err)
	}
	document.SnapshotRestoreProfile = append(document.SnapshotRestoreProfile, validWireProfile("overflow"))
	if err := validateCapabilities(document); err == nil {
		t.Fatalf("%d profiles accepted", maxSnapshotRestoreProfiles+1)
	}

	document = mapCapabilities(validSnapshot(t, nil, nil))
	profile := document.SnapshotRestoreProfile[0]
	document.SnapshotRestoreProfile = append(document.SnapshotRestoreProfile, profile)
	if err := validateCapabilities(document); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
	conflict := profile
	conflict.Level = providerv1.SnapshotFilesystem
	document.SnapshotRestoreProfile[1] = conflict
	if err := validateCapabilities(document); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict error = %v", err)
	}
}

func validSnapshot(t *testing.T, workspace, gpu *int64) provider.CapabilitySnapshot {
	t.Helper()
	snapshot, err := provider.NewCapabilitySnapshot("revision-1", provider.Limits{
		MaxCPUMillis:             1000,
		MaxMemoryBytes:           1 << 30,
		MaxEphemeralStorageBytes: 1 << 30,
		MaxWorkspaceBytes:        workspace,
		MaxGPUCount:              gpu,
		MaxLeaseSeconds:          3600,
		MaxExecSeconds:           300,
	}, []provider.SnapshotRestoreProfile{{
		ProfileID:    "sandbox-snapshot-workspace-v1",
		Level:        provider.SnapshotLevelWorkspace,
		SuiteID:      provider.CompatibilitySuiteSandboxProvider,
		SuiteVersion: "1.0.0",
		SuiteDigest:  provider.SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func validWireProfile(id string) providerv1.SnapshotRestoreProfile {
	return providerv1.SnapshotRestoreProfile{
		ProfileID: id, Level: providerv1.SnapshotWorkspace, SuiteID: providerv1.SandboxSuiteProvider,
		SuiteVersion: "1.0.0", SuiteDigest: providerv1.SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}
}

func cloneDocument(document providerv1.Capabilities) providerv1.Capabilities {
	capabilities := make([]providerv1.Capability, len(document.Capabilities))
	copy(capabilities, document.Capabilities)
	document.Capabilities = capabilities
	runtimeProfiles := make([]providerv1.RuntimeProfile, len(document.RuntimeProfiles))
	copy(runtimeProfiles, document.RuntimeProfiles)
	document.RuntimeProfiles = runtimeProfiles
	document.SnapshotRestoreProfile = append([]providerv1.SnapshotRestoreProfile(nil), document.SnapshotRestoreProfile...)
	document.Limits.MaxWorkspaceBytes = cloneInt64(document.Limits.MaxWorkspaceBytes)
	document.Limits.MaxGPUCount = cloneInt64(document.Limits.MaxGPUCount)
	return document
}

func int64Pointer(value int64) *int64 { return &value }
