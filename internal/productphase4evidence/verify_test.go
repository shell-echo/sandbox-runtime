package productphase4evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyRejectsMissingScenarioAndSecrets(t *testing.T) {
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
	manifest.StartedAt = "Bearer secret"
	document, _ = json.Marshal(manifest)
	if _, err := Verify(document); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("secret error=%v", err)
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
		SchemaVersion: 1, RunID: "20260918T000000Z", Result: "passed", EvidenceTier: "same-repository-separate-process",
		SourceRevision: strings.Repeat("b", 40), StartedAt: "2026-09-18T00:00:00Z", CompletedAt: "2026-09-18T00:01:00Z",
		Provider:   ProviderIdentity{Revision: ProviderRevision, Tree: ProviderTree},
		Product:    ProductIdentity{Tree: ProductTree, ResourceCount: 9, OperationCount: 27, ConformanceCases: 3},
		PostgreSQL: ServiceIdentity{Profile: PostgresImage, Fresh: true}, Coordination: ServiceIdentity{Profile: ValkeyImage, Fresh: true}, ObjectStorage: ServiceIdentity{Profile: ObjectStore, Fresh: true},
		Processes: processes, Scenarios: scenarios,
		Cleanup:   CleanupEvidence{ChildProcessesReaped: true, ContainersRemoved: true, ScopedRowsRemoved: true, ObjectContentRemoved: true, CoordinationDrained: true},
		NonClaims: append([]string(nil), requiredNonClaims...),
	}
}
