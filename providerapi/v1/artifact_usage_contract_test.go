package v1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLockedArtifactAndUsageProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	for _, fixture := range []struct {
		name   string
		schema string
		value  any
	}{
		{"artifact-staging-request.json", "artifact-staging-request.schema.json", &ArtifactStagingRequest{}},
		{"artifact-staging-evidence.json", "artifact-staging-evidence.schema.json", &ArtifactStagingEvidence{}},
		{"usage-evidence.json", "usage-evidence.schema.json", &UsageEvidence{}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			document, err := projection.ReadExample(fixture.name)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate(fixture.schema, document); err != nil {
				t.Fatalf("fixture is invalid: %v", err)
			}
			if err := DecodeStrict(bytes.NewReader(document), 1<<20, fixture.value); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			projected, err := json.Marshal(fixture.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate(fixture.schema, projected); err != nil {
				t.Fatalf("wire DTO projection is invalid: %v", err)
			}
		})
	}

	operation, err := projection.ReadExample("provider-operation.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", operation); err != nil {
		t.Fatalf("operation fixture is invalid: %v", err)
	}
}

func TestLocalContractArtifactAndUsageSemanticRules(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	data, err := os.ReadFile(filepath.Join(sourceRoot, "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Rules []struct {
			ID       string   `json:"id"`
			Method   string   `json:"method"`
			Path     string   `json:"path"`
			Scope    string   `json:"scope"`
			Requires []string `json:"requires"`
			Forbids  []string `json:"forbids"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		method, path, scope string
		required            []string
		forbidden           string
	}{
		"artifact-staging-request-bounded":  {"POST", "/v1/sandboxes/{sandbox_id}/artifacts:stage", "artifact-staging", []string{"artifact-reference-is-opaque", "source-path-under-outputs", "digest-media-type-and-size-bounds", "tenant-binding-from-admission-context", "active-content-check-before-stage", "malware-check-before-stage", "expiry-bound"}, "public-artifact-url"},
		"artifact-staging-evidence-bounded": {"GET", "/v1/operations/{operation_id}/artifact-staging-evidence", "artifact-staging-evidence", []string{"expected-digest-media-type-and-size-binding", "tenant-binding-check-evidence", "active-content-check-evidence", "malware-check-evidence", "opaque-staging-reference", "expired-evidence-is-410"}, "artifact-authority"},
		"usage-evidence-bounded":            {"GET", "/v1/operations/{operation_id}/usage-evidence", "usage-evidence", []string{"operation-and-sandbox-correlation", "bounded-meter-dimensions", "reconciliation-status-explicit", "expired-evidence-is-410"}, "billing-total"},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] {
			t.Fatalf("duplicate rule %q", rule.ID)
		}
		found[rule.ID] = true
		if rule.Method != expected.method || rule.Path != expected.path || rule.Scope != expected.scope {
			t.Fatalf("rule %q identity mismatch", rule.ID)
		}
		requires := make(map[string]bool, len(rule.Requires))
		for _, requirement := range rule.Requires {
			requires[requirement] = true
		}
		for _, requirement := range expected.required {
			if !requires[requirement] {
				t.Fatalf("rule %q missing %q", rule.ID, requirement)
			}
		}
		forbidden := false
		for _, value := range rule.Forbids {
			if value == expected.forbidden {
				forbidden = true
			}
		}
		if !forbidden {
			t.Fatalf("rule %q missing forbidden assertion %q", rule.ID, expected.forbidden)
		}
	}
	for id := range want {
		if !found[id] {
			t.Fatalf("local Contract is missing rule %q", id)
		}
	}
}

func TestArtifactStagingRejectionFixtures(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("artifact-staging-rejections.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name     string          `json:"name"`
			Schema   string          `json:"schema"`
			Document json.RawMessage `json:"document"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(document, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 5 {
		t.Fatalf("rejection fixture count = %d, want at least 5", len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			if err := projection.Validate(testCase.Schema, testCase.Document); err == nil {
				t.Fatal("rejection fixture unexpectedly validates")
			}
		})
	}
}
