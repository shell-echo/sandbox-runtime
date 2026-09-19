package productphase5evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyAcceptsExactManifestAndRejectsDrift(t *testing.T) {
	manifest := validManifest()
	document, _ := json.Marshal(manifest)
	if _, err := Verify(document); err != nil {
		t.Fatal(err)
	}
	manifest.Scenarios = manifest.Scenarios[:len(manifest.Scenarios)-1]
	document, _ = json.Marshal(manifest)
	if _, err := Verify(document); err == nil || !strings.Contains(err.Error(), "scenario set") {
		t.Fatalf("missing scenario error=%v", err)
	}
	manifest = validManifest()
	manifest.DesktopRuntime.PlatformDigest = "sha256:" + strings.Repeat("f", 64)
	document, _ = json.Marshal(manifest)
	if _, err := Verify(document); err == nil || !strings.Contains(err.Error(), "platform identity") {
		t.Fatalf("platform drift error=%v", err)
	}
}

func TestVerifyRejectsPrivateCoordinatesAndIncompleteCleanup(t *testing.T) {
	manifest := validManifest()
	manifest.RunID = "ref:desktop-session:private"
	document, _ := json.Marshal(manifest)
	if _, err := Verify(document); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("private coordinate error=%v", err)
	}
	manifest = validManifest()
	manifest.Cleanup.RuntimeRemoved = false
	document, _ = json.Marshal(manifest)
	if _, err := Verify(document); err == nil || !strings.Contains(err.Error(), "cleanup") {
		t.Fatalf("cleanup error=%v", err)
	}
}

func validManifest() Manifest {
	digest := "sha256:" + strings.Repeat("a", 64)
	processes := make([]ProcessEvidence, 0, len(requiredRoles))
	for _, role := range requiredRoles {
		processes = append(processes, ProcessEvidence{Role: role, ExecutableDigest: digest, IndependentOSProcess: true})
	}
	scenarios := make([]ScenarioEvidence, 0, len(requiredCases))
	for _, id := range requiredCases {
		scenarios = append(scenarios, ScenarioEvidence{ID: id, Status: "passed"})
	}
	return Manifest{
		SchemaVersion: 1, RunID: "20260920T000000.000000000Z", Result: "passed", EvidenceTier: "same-repository-independent-process",
		SourceRevision: strings.Repeat("b", 40), StartedAt: "2026-09-20T00:00:00Z", CompletedAt: "2026-09-20T00:01:00Z",
		BaseProvider: ProviderIdentity{Revision: BaseProviderRevision, Tree: BaseProviderTree}, DesktopProvider: ProviderIdentity{Revision: DesktopProviderRevision, Tree: DesktopProviderTree},
		Product:    ProductIdentity{Tree: ProductTree, ResourceCount: 9, OperationCount: 27, ConformanceCases: 3},
		PostgreSQL: ServiceIdentity{Profile: PostgresImage, Fresh: true}, ObjectStorage: ServiceIdentity{Profile: ObjectStore, Fresh: true},
		DesktopRuntime:      RuntimeIdentity{Profile: DesktopProfile, Image: DesktopImage, IndexDigest: DesktopImageDigest, Platform: "linux/arm64/v8", PlatformDigest: "sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505", SourceRevision: DesktopSourceRevision, Signed: true},
		DevelopmentTemplate: TemplateIdentity{TemplateID: DevelopmentTemplate, Image: DevelopmentImage, IndexDigest: DevelopmentImageDigest, Selected: true},
		Processes:           processes, Scenarios: scenarios,
		Cleanup:   CleanupEvidence{ChildProcessesReaped: true, ContainersRemoved: true, ScopedRowsRemoved: true, ObjectContentRemoved: true, GuestStateRemoved: true, RuntimeRemoved: true},
		NonClaims: append([]string(nil), requiredNonClaims...),
	}
}
