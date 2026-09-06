package lock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownstreamFencingV2Lock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		locked, err := LoadDownstreamFencingV2(root, platform)
		if err != nil {
			t.Fatalf("LoadDownstreamFencingV2(%q): %v", platform, err)
		}
		if locked.EvidenceProfile != DownstreamFencingV2Profile || locked.Sources.ProviderRevision != ProviderCommit ||
			locked.Base.EvidenceProfile != DownstreamFencingProfile || locked.Contract.SuiteExercised ||
			locked.ActionFence.PolicyFormat != "browser-downstream-action-fence-v2" ||
			!locked.Witness.OutsideValkeyRestoreDomain || locked.RestoreControl.ExposedToGateways ||
			locked.RestoreControl.ExposedToCallers || !locked.RestoreControl.SeparateCredential {
			t.Fatalf("LoadDownstreamFencingV2(%q) returned the wrong boundary: %#v", platform, locked)
		}
		if got := locked.Scenarios; len(got) != len(downstreamFencingV2ScenarioInventory) ||
			got[0] != "ordinary bounded real-CDP mutation through the unique ingress" ||
			got[len(got)-1] != "sanitized v2 evidence pins identities and records Contract Suite as unexercised" {
			t.Fatalf("LoadDownstreamFencingV2(%q) scenarios = %#v", platform, got)
		}
	}
	if _, err := LoadDownstreamFencingV2(root, "linux/ppc64le"); err == nil || !strings.Contains(err.Error(), "is not locked") {
		t.Fatalf("unsupported LoadDownstreamFencingV2() error = %v", err)
	}
}

func TestDownstreamFencingV2LockRequiresExplicitZeroValueFields(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, DownstreamFencingV2LockPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, fieldPath := range [][]string{
		{"contract", "suite_exercised"},
		{"restore_control", "exposed_to_gateways"},
		{"restore_control", "exposed_to_callers"},
		{"restore_control", "restores_witness"},
	} {
		fieldPath := fieldPath
		t.Run(strings.Join(fieldPath, "."), func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(original, &document); err != nil {
				t.Fatal(err)
			}
			object := document[fieldPath[0]].(map[string]any)
			delete(object, fieldPath[1])
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			temporaryRoot := t.TempDir()
			for _, name := range []string{DownstreamFencingLockPath, DownstreamFencingV2LockPath} {
				path := filepath.Join(temporaryRoot, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				content := original
				if name == DownstreamFencingLockPath {
					content, err = os.ReadFile(filepath.Join(root, name))
					if err != nil {
						t.Fatal(err)
					}
				} else {
					content = encoded
				}
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := LoadDownstreamFencingV2(temporaryRoot, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "missing required field") {
				t.Fatalf("LoadDownstreamFencingV2() error = %v", err)
			}
		})
	}
}

func TestDownstreamFencingV2ScenarioNamesReturnsCopy(t *testing.T) {
	first := DownstreamFencingV2ScenarioNames()
	first[0] = "changed"
	if second := DownstreamFencingV2ScenarioNames(); second[0] == "changed" {
		t.Fatal("DownstreamFencingV2ScenarioNames returned mutable package state")
	}
}
