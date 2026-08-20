package admission

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalContractProtectedOperationBindings(t *testing.T) {
	type operationBinding struct {
		Operation     string `json:"operation"`
		ContractID    string `json:"contract_id"`
		DigestProfile string `json:"digest_profile"`
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve local Contract path")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatalf("read local semantic rules: %v", err)
	}
	var document struct {
		Rules []struct {
			ID                string             `json:"id"`
			OperationBindings []operationBinding `json:"operation_bindings"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode local semantic rules: %v", err)
	}
	var bindings []operationBinding
	for _, rule := range document.Rules {
		if rule.ID == "protected-admission-contract-ids" {
			bindings = rule.OperationBindings
			break
		}
	}
	if len(bindings) != len(requestBindings) {
		t.Fatalf("local Contract protected bindings = %d, implementation = %d", len(bindings), len(requestBindings))
	}
	for _, binding := range bindings {
		operation := Operation(binding.Operation)
		expected, ok := requestBindings[operation]
		if !ok {
			t.Fatalf("local Contract declares unsupported operation %q", binding.Operation)
		}
		if expected.contractID != binding.ContractID || string(expected.profile) != binding.DigestProfile {
			t.Fatalf("binding %q = (%q, %q), implementation = (%q, %q)", binding.Operation, binding.ContractID, binding.DigestProfile, expected.contractID, expected.profile)
		}
	}
}
