package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
)

func lockedExecProjection(t *testing.T) *providercontract.Projection {
	t.Helper()
	sourceRoot := localContractSourceRoot(t)
	lockPath := filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json")
	projection, err := providercontract.Load(context.Background(), lockPath, sourceRoot)
	if err != nil {
		t.Fatalf("load local Provider projection: %v", err)
	}
	return projection
}

func TestLockedExecRequestProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("exec-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("exec-request.schema.json", document); err != nil {
		t.Fatalf("exec request fixture is invalid: %v", err)
	}
	var request ExecRequest
	if err := DecodeStrict(bytes.NewReader(document), MaxExecRequestBytes, &request); err != nil {
		t.Fatalf("decode exec request fixture: %v", err)
	}
	projected, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("exec-request.schema.json", projected); err != nil {
		t.Fatalf("exec request DTO projection is invalid: %v", err)
	}
}

func TestLockedCancelExecRequestProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("cancel-exec-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("cancel-exec-request.schema.json", document); err != nil {
		t.Fatalf("cancel exec fixture is invalid: %v", err)
	}
	var request CancelExecRequest
	if err := DecodeStrict(bytes.NewReader(document), MaxCancelExecRequestBytes, &request); err != nil {
		t.Fatalf("decode cancel exec fixture: %v", err)
	}
	projected, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("cancel-exec-request.schema.json", projected); err != nil {
		t.Fatalf("cancel exec DTO projection is invalid: %v", err)
	}
}

func TestLockedExecResultProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	for _, fixtureName := range []string{"exec-result.json", "exec-result-unknown.json"} {
		t.Run(fixtureName, func(t *testing.T) {
			resultDocument, err := projection.ReadExample(fixtureName)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate("exec-result.schema.json", resultDocument); err != nil {
				t.Fatalf("exec result fixture is invalid: %v", err)
			}
			var result ExecResult
			if err := DecodeStrict(bytes.NewReader(resultDocument), 1<<20, &result); err != nil {
				t.Fatalf("decode exec result fixture: %v", err)
			}
			projected, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate("exec-result.schema.json", projected); err != nil {
				t.Fatalf("exec result DTO projection is invalid: %v", err)
			}
		})
	}

	operationDocument, err := projection.ReadExample("provider-operation-exec.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", operationDocument); err != nil {
		t.Fatalf("exec operation fixture is invalid: %v", err)
	}
	var operation Operation
	if err := DecodeStrict(bytes.NewReader(operationDocument), 1<<20, &operation); err != nil {
		t.Fatalf("decode exec operation fixture: %v", err)
	}
	projectedOperation, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", projectedOperation); err != nil {
		t.Fatalf("exec operation DTO projection is invalid: %v", err)
	}
}

func TestLocalContractExecSemanticRules(t *testing.T) {
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
		"exec-request-bounded": {
			method: "POST", path: "/v1/sandboxes/{sandbox_id}/exec", scope: "exec-operations",
			required:  []string{"structured-argv-command-array", "working-directory-under-stable-mount", "environment-values-are-opaque-references", "stdin-is-none-or-opaque-reference", "deadline-required", "bounded-output-capture", "result-retention-bound"},
			forbidden: "plaintext-secret",
		},
		"exec-cancellation-intent": {
			method: "POST", path: "/v1/sandboxes/{sandbox_id}/exec:cancel", scope: "exec-operations",
			required:  []string{"cancellation-is-intent", "target-operation-and-attempt-binding", "fail-before-dispatch-on-stale-fencing"},
			forbidden: "unconfirmed-cancelled-claim",
		},
		"exec-result-retention": {
			method: "GET", path: "/v1/operations/{operation_id}/exec-result", scope: "exec-results",
			required:  []string{"outcome-unknown-is-explicit", "retained-until-expiry", "expired-result-is-410", "opaque-result-references", "no-backend-leakage"},
			forbidden: "host-path",
		},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] {
			t.Fatalf("duplicate exec rule %q", rule.ID)
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
			t.Fatalf("local Contract is missing exec rule %q", id)
		}
	}
}

func TestExecRejectionFixtures(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("exec-rejections.json")
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
		t.Fatalf("decode exec rejection fixtures: %v", err)
	}
	if len(fixture.Cases) < 5 {
		t.Fatalf("exec rejection fixture count = %d, want at least 5", len(fixture.Cases))
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
