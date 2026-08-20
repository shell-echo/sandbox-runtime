package v1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLocalContractLifecycleSemanticRules(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve local Contract path")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatalf("read local semantic rules: %v", err)
	}
	var document struct {
		Namespace string `json:"namespace"`
		Version   string `json:"version"`
		Rules     []struct {
			ID       string   `json:"id"`
			Method   string   `json:"method"`
			Path     string   `json:"path"`
			Scope    string   `json:"scope"`
			Requires []string `json:"requires"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode local semantic rules: %v", err)
	}
	if document.Namespace != "urn:shell-echo:sandbox-runtime:provider-v1" || document.Version != "1.0.0" {
		t.Fatalf("semantic rule identity = (%q, %q)", document.Namespace, document.Version)
	}
	want := map[string]struct {
		method string
		path   string
		scope  string
	}{
		"lifecycle-create-request":       {method: "POST", path: "/v1/sandboxes"},
		"lifecycle-create-idempotency":   {method: "POST", path: "/v1/sandboxes"},
		"lifecycle-generation-fencing":   {scope: "lifecycle-mutations"},
		"lifecycle-deadline-and-outcome": {scope: "lifecycle-mutations"},
		"lifecycle-read-is-bounded":      {scope: "lifecycle-reads"},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] {
			t.Fatalf("duplicate lifecycle rule %q", rule.ID)
		}
		found[rule.ID] = true
		if rule.Method != expected.method || rule.Path != expected.path || rule.Scope != expected.scope {
			t.Fatalf("rule %q identity = (%q, %q, %q), want (%q, %q, %q)", rule.ID, rule.Method, rule.Path, rule.Scope, expected.method, expected.path, expected.scope)
		}
		if len(rule.Requires) == 0 {
			t.Fatalf("rule %q has no required semantic assertions", rule.ID)
		}
	}
	for id := range want {
		if !found[id] {
			t.Fatalf("local Contract is missing lifecycle rule %q", id)
		}
	}
}
