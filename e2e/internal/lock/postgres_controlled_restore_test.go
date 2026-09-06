package lock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostgresControlledRestoreLock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		locked, err := LoadPostgresControlledRestore(root, platform)
		if err != nil {
			t.Fatalf("LoadPostgresControlledRestore(%q): %v", platform, err)
		}
		if locked.EvidenceProfile != PostgresControlledRestoreProfile ||
			locked.Base.EvidenceProfile != DownstreamFencingV2Profile || locked.Contract.SuiteExercised ||
			locked.PostgreSQL.SelectedPlatform != platform || !locked.PostgreSQL.SameRunner ||
			locked.PostgreSQL.IndependentFailureDomain || !locked.PostgreSQL.ProvenanceNotEstablished ||
			locked.Witness.CredentialsExposedToGateways || locked.Witness.CredentialsExposedToCallers ||
			!locked.RestoreControl.ResumeRequiresExactMatch || locked.RestoreControl.RestoresWitness ||
			locked.RestoreControl.VerificationMutatesWitness {
			t.Fatalf("LoadPostgresControlledRestore(%q) returned the wrong boundary: %#v", platform, locked)
		}
		if got := locked.Scenarios; len(got) != 18 ||
			got[10] != "unique ingress is quarantined before restore and Gateways have no bypass" ||
			got[17] != "sanitized PostgreSQL restore evidence records its same-runner boundary and unexercised Contract Suite" {
			t.Fatalf("LoadPostgresControlledRestore(%q) scenarios = %#v", platform, got)
		}
	}
	if _, err := LoadPostgresControlledRestore(root, "linux/ppc64le"); err == nil || !strings.Contains(err.Error(), "is not locked") {
		t.Fatalf("unsupported LoadPostgresControlledRestore() error = %v", err)
	}
}

func TestPostgresControlledRestoreLockRequiresExplicitBoundaryFields(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, PostgresControlledRestoreLockPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, fieldPath := range [][]string{
		{"postgresql", "independent_failure_domain"},
		{"witness", "credentials_exposed_to_gateways"},
		{"restore_control", "verification_mutates_witness"},
		{"restore_control", "restores_witness"},
	} {
		fieldPath := fieldPath
		t.Run(strings.Join(fieldPath, "."), func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(original, &document); err != nil {
				t.Fatal(err)
			}
			delete(document[fieldPath[0]].(map[string]any), fieldPath[1])
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			temporaryRoot := t.TempDir()
			for _, path := range []string{DownstreamFencingLockPath, DownstreamFencingV2LockPath, PostgresControlledRestoreLockPath, PostgresWitnessMigrationPath} {
				content := encoded
				if path != PostgresControlledRestoreLockPath {
					content, err = os.ReadFile(filepath.Join(root, path))
					if err != nil {
						t.Fatal(err)
					}
				}
				target := filepath.Join(temporaryRoot, path)
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadPostgresControlledRestore(temporaryRoot, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "missing required field") {
				t.Fatalf("LoadPostgresControlledRestore() error = %v", err)
			}
		})
	}
}

func TestPostgresControlledRestoreScenarioNamesReturnsCopy(t *testing.T) {
	first := PostgresControlledRestoreScenarioNames()
	first[0] = "changed"
	if second := PostgresControlledRestoreScenarioNames(); second[0] == "changed" {
		t.Fatal("PostgresControlledRestoreScenarioNames returned mutable package state")
	}
}
