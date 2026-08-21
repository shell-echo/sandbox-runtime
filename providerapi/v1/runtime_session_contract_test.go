package v1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLockedRuntimeSessionOpenRequestProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("runtime-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("runtime-session-open-request.schema.json", document); err != nil {
		t.Fatalf("runtime session open request fixture is invalid: %v", err)
	}
	var request RuntimeSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(document), MaxRuntimeSessionOpenRequestBytes, &request); err != nil {
		t.Fatalf("decode runtime session open request: %v", err)
	}
	projected, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("runtime-session-open-request.schema.json", projected); err != nil {
		t.Fatalf("runtime session open request DTO projection is invalid: %v", err)
	}
}

func TestLockedRuntimeSessionOperationProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("provider-operation-runtime-session.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", document); err != nil {
		t.Fatalf("runtime session operation fixture is invalid: %v", err)
	}
	var operation Operation
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &operation); err != nil {
		t.Fatalf("decode runtime session operation: %v", err)
	}
	projected, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", projected); err != nil {
		t.Fatalf("runtime session operation DTO projection is invalid: %v", err)
	}
}

func TestLockedRuntimeSessionHandoffProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("runtime-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("runtime-session-handoff.schema.json", document); err != nil {
		t.Fatalf("runtime session handoff fixture is invalid: %v", err)
	}
	var handoff RuntimeSessionHandoff
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &handoff); err != nil {
		t.Fatalf("decode runtime session handoff: %v", err)
	}
	projected, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("runtime-session-handoff.schema.json", projected); err != nil {
		t.Fatalf("runtime session handoff DTO projection is invalid: %v", err)
	}
}

func TestLocalContractRuntimeSessionSemanticRules(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	data, err := os.ReadFile(filepath.Join(sourceRoot, "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatalf("read local semantic rules: %v", err)
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
		t.Fatalf("decode local semantic rules: %v", err)
	}
	want := map[string]struct {
		method    string
		path      string
		scope     string
		required  []string
		forbidden string
	}{
		"runtime-session-open-bounded": {
			method: "POST", path: "/v1/sandboxes/{sandbox_id}/runtime-sessions", scope: "terminal-sessions",
			required:  []string{"terminal-capability-and-profile-required", "provider-revision-sandbox-generation-binding", "deadline-and-expiry-bound"},
			forbidden: "gateway-user-scope",
		},
		"runtime-session-gateway-handoff": {
			method: "GET", path: "/v1/operations/{operation_id}/runtime-session", scope: "terminal-sessions",
			required:  []string{"opaque-internal-endpoint-reference", "gateway-resolves-reference-under-independent-user-authorization", "expired-handoff-is-410"},
			forbidden: "provider-access-token-reference",
		},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] {
			t.Fatalf("duplicate runtime session rule %q", rule.ID)
		}
		found[rule.ID] = true
		if rule.Method != expected.method || rule.Path != expected.path || rule.Scope != expected.scope {
			t.Fatalf("rule %q identity = (%q, %q, %q), want (%q, %q, %q)", rule.ID, rule.Method, rule.Path, rule.Scope, expected.method, expected.path, expected.scope)
		}
		requires := make(map[string]bool, len(rule.Requires))
		for _, requirement := range rule.Requires {
			requires[requirement] = true
		}
		for _, requirement := range expected.required {
			if !requires[requirement] {
				t.Fatalf("rule %q is missing required semantic assertion %q", rule.ID, requirement)
			}
		}
		forbidden := false
		for _, value := range rule.Forbids {
			if value == expected.forbidden {
				forbidden = true
			}
		}
		if !forbidden {
			t.Fatalf("rule %q is missing forbidden assertion %q", rule.ID, expected.forbidden)
		}
	}
	for id := range want {
		if !found[id] {
			t.Fatalf("local Contract is missing runtime session rule %q", id)
		}
	}
}

func TestRuntimeSessionRejectionFixtures(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("runtime-session-rejections.json")
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
		t.Fatalf("decode runtime session rejection fixtures: %v", err)
	}
	if len(fixture.Cases) < 4 {
		t.Fatalf("runtime session rejection fixture count = %d, want at least 4", len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.Schema == "" || len(testCase.Document) == 0 {
				t.Fatal("rejection fixture must contain schema and document")
			}
			if err := projection.Validate(testCase.Schema, testCase.Document); err == nil {
				t.Fatal("rejection fixture unexpectedly validates")
			}
		})
	}
}
