package productphase3evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVerifyAcceptsExactBoundedEnvelope(t *testing.T) {
	document, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(document); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsMissingScenarioAndSecret(t *testing.T) {
	manifest := validManifest()
	manifest.Scenarios = manifest.Scenarios[:len(manifest.Scenarios)-1]
	document, _ := json.Marshal(manifest)
	if _, err := Verify(document); err == nil {
		t.Fatal("missing scenario accepted")
	}
	document = []byte(strings.Replace(string(mustJSON(t, validManifest())), `"run_id":"run-1"`, `"run_id":"Bearer secret"`, 1))
	if _, err := Verify(document); err == nil {
		t.Fatal("secret-bearing evidence accepted")
	}
}

func validManifest() Manifest {
	processes := make([]ProcessEvidence, 0, len(requiredRoles))
	for _, role := range requiredRoles {
		processes = append(processes, ProcessEvidence{Role: role, ExecutableDigest: "sha256:" + strings.Repeat("a", 64), IndependentOSProcess: true})
	}
	scenarios := make([]ScenarioEvidence, 0, len(requiredCases))
	for _, id := range requiredCases {
		scenarios = append(scenarios, ScenarioEvidence{ID: id, Status: "passed"})
	}
	return Manifest{
		SchemaVersion: 1, RunID: "run-1", Result: "passed", EvidenceTier: "same-repository-separate-process",
		SourceRevision: strings.Repeat("b", 40), StartedAt: "2026-09-18T00:00:00Z", CompletedAt: "2026-09-18T00:01:00Z",
		Provider:   ProviderIdentity{Revision: ProviderRevision, Tree: ProviderTree},
		Product:    ProductIdentity{Tree: ProductTree, ResourceCount: 9, OperationCount: 27, ConformanceCases: 3},
		PostgreSQL: PostgreSQLIdentity{Image: PostgresImage, FreshSchema: true}, Processes: processes, Scenarios: scenarios,
		Cleanup:   CleanupEvidence{ChildProcessesReaped: true, ContainerRemoved: true, ScopedRowsRemoved: true},
		NonClaims: append([]string(nil), requiredNonClaims...),
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}
