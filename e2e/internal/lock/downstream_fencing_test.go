package lock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownstreamFencingLock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		locked, err := LoadDownstreamFencing(root, platform)
		if err != nil {
			t.Fatalf("LoadDownstreamFencing(%q): %v", platform, err)
		}
		if locked.Sources.ProviderRevision != ProviderCommit || locked.Sources.HarnessBaseline != DownstreamFencingHarnessBaseline ||
			locked.Contract.SuiteExercised || !locked.Contract.ContractMetadataOnly ||
			!locked.BrowserImage.Provenance.Established || !locked.Valkey.ProvenanceNotEstablished ||
			!locked.PrivateWire.ResolveMetadataOnly || !locked.PrivateWire.HighWaterActivationOnly ||
			len(locked.PrivateWire.ErrorCodes) != 3 || locked.Topology.GatewayProcesses != 2 ||
			locked.Topology.ProviderIngressProcesses != 1 || locked.Topology.CallerProcesses != 2 || locked.Topology.SessionCapacityLimit != 1 ||
			!locked.PrivateWire.ActionFenceClaimActivationOnly || !locked.Topology.GatewayAccessesIngressOnly || !locked.Topology.IngressIsOnlyChromiumPath ||
			locked.Topology.GatewayDirectChromiumAccess || locked.Topology.GatewayDirectProviderAttacherAccess {
			t.Fatalf("LoadDownstreamFencing(%q) returned the wrong boundary: %#v", platform, locked)
		}
		if locked.Valkey.SelectedPlatform != platform || locked.Valkey.SelectedDigest == "" ||
			locked.BrowserImage.SelectedPlatform == "" || locked.BrowserImage.SelectedDigest == "" {
			t.Fatalf("LoadDownstreamFencing(%q) did not select both images: %#v", platform, locked)
		}
		if got := locked.Scenarios; len(got) != len(downstreamFencingScenarioInventory) ||
			got[0] != "ordinary bounded real-CDP mutation through the unique ingress" ||
			got[len(got)-1] != "sanitized evidence pins every locked identity without private material" {
			t.Fatalf("LoadDownstreamFencing(%q) scenarios = %#v", platform, got)
		}
	}
	if _, err := LoadDownstreamFencing(root, "linux/ppc64le"); err == nil || !strings.Contains(err.Error(), "is not locked") {
		t.Fatalf("unsupported LoadDownstreamFencing() error = %v", err)
	}
}

func TestDownstreamFencingLockRequiresExplicitZeroValueFields(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, DownstreamFencingLockPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, fieldPath := range [][]string{
		{"contract", "suite_exercised"},
		{"valkey", "database_index"},
		{"private_wire", "resolve_advances_high_water"},
		{"private_wire", "url_query_allowed"},
		{"private_wire", "url_fragment_allowed"},
		{"private_wire", "url_userinfo_allowed"},
		{"private_wire", "private_material_in_url_or_header"},
		{"topology", "gateway_direct_chromium_access"},
		{"topology", "gateway_direct_provider_attacher_access"},
	} {
		fieldPath := fieldPath
		t.Run(strings.Join(fieldPath, "."), func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(original, &document); err != nil {
				t.Fatal(err)
			}
			object := document
			for _, name := range fieldPath[:len(fieldPath)-1] {
				object = object[name].(map[string]any)
			}
			delete(object, fieldPath[len(fieldPath)-1])
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			temporaryRoot := t.TempDir()
			lockPath := filepath.Join(temporaryRoot, DownstreamFencingLockPath)
			if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDownstreamFencing(temporaryRoot, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "missing required field") {
				t.Fatalf("LoadDownstreamFencing() error = %v", err)
			}
		})
	}
}

func TestDownstreamFencingLockRejectsNullRequiredField(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(root, DownstreamFencingLockPath))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(original, &document); err != nil {
		t.Fatal(err)
	}
	document["contract"].(map[string]any)["suite_exercised"] = nil
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	temporaryRoot := t.TempDir()
	lockPath := filepath.Join(temporaryRoot, DownstreamFencingLockPath)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDownstreamFencing(temporaryRoot, "linux/amd64"); err == nil || !strings.Contains(err.Error(), "is null") {
		t.Fatalf("LoadDownstreamFencing() error = %v", err)
	}
}

func TestDownstreamFencingScenarioNamesReturnsCopy(t *testing.T) {
	first := DownstreamFencingScenarioNames()
	first[0] = "changed"
	if second := DownstreamFencingScenarioNames(); second[0] == "changed" {
		t.Fatal("DownstreamFencingScenarioNames returned mutable package state")
	}
}

func TestDownstreamFencingNormalizedConfigurationDigests(t *testing.T) {
	if got, want := normalizedSHA256(DownstreamFencingServerConfig), "sha256:12a690a249f1c28c5d3617bcc051216c3261270237035494dcb17764aa2111d2"; got != want {
		t.Fatalf("server config digest = %s, want %s", got, want)
	}
	if got, want := normalizedSHA256(DownstreamFencingACLTemplate), "sha256:84488d76e44e0fe4b2e3f67c943d83c02ff993db0b8af003c5cd2cc998f1293e"; got != want {
		t.Fatalf("ACL template digest = %s, want %s", got, want)
	}
}

func TestDownstreamFencingActionTimeoutFitsCapacitySafetyWindow(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	locked, err := LoadDownstreamFencing(root, "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	available := locked.CapacityPolicy.LeaseTTLMillis - locked.CapacityPolicy.RenewIntervalMillis -
		locked.CapacityPolicy.RenewalSafetyMarginMillis - locked.CapacityPolicy.OperationTimeoutMillis
	if locked.Ingress.ActionTimeoutMillis >= available {
		t.Fatalf("action timeout %dms does not fit below %dms capacity safety window", locked.Ingress.ActionTimeoutMillis, available)
	}
}

func TestDownstreamFencingHarnessPathIsNarrow(t *testing.T) {
	for path, want := range map[string]bool{
		"e2e/cmd/downstream-fencing-e2e/main.go":       true,
		"docs/STATUS.md":                               true,
		".github/workflows/downstream-fencing-e2e.yml": true,
		".github/workflows/browser-e2e.yml":            false,
		"README.md":                                    true,
		"gateway/cdpfence/ingress.go":                  false,
		"e2e/../gateway/cdpfence/ingress.go":           false,
	} {
		if got := downstreamFencingHarnessPath(path); got != want {
			t.Errorf("downstreamFencingHarnessPath(%q) = %t, want %t", path, got, want)
		}
	}
}
