package conformance

import (
	"os"
	"strings"
	"testing"
)

func TestValidateCasesRequiresKnownUniqueIDs(t *testing.T) {
	if err := validateCases([]string{"capability-discovery-mtls-only", "protected-admission-expiry"}); err != nil {
		t.Fatalf("validateCases(valid) = %v", err)
	}
	for name, ids := range map[string][]string{
		"empty":     nil,
		"blank":     {" "},
		"duplicate": {"capability-discovery-mtls-only", "capability-discovery-mtls-only"},
		"unknown":   {"future-case"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateCases(ids); err == nil {
				t.Fatal("validateCases() error = nil")
			}
		})
	}
}

func TestLocalSuiteCasesHaveRunnerMappings(t *testing.T) {
	ids := []string{
		"capability-discovery-mtls-only",
		"capability-discovery-admitted-identity",
		"capability-discovery-immutable-schema",
		"capability-discovery-terminal-profile-advertisement",
		"capability-discovery-terminal-session-contract-consistency",
		"capability-discovery-empty-request",
		"capability-discovery-no-mutation-routes",
		"protected-admission-context-schema",
		"protected-admission-token-binding",
		"protected-admission-digest-substitution",
		"protected-admission-expiry",
		"protected-admission-replay-and-fencing",
		"lifecycle-create-request-schema",
		"lifecycle-operation-state-schema",
		"lifecycle-idempotency-generation-fencing",
		"lifecycle-deadline-outcome",
		"exec-request-schema",
		"exec-cancel-schema",
		"exec-result-schema",
		"exec-semantic-bounds",
		"exec-rejection-fixtures",
		"runtime-session-open-schema",
		"runtime-session-operation-schema",
		"runtime-session-handoff-schema",
		"runtime-session-semantic-bounds",
		"runtime-session-rejection-fixtures",
		"artifact-staging-request-schema",
		"artifact-staging-evidence-schema",
		"artifact-staging-semantic-bounds",
		"artifact-staging-rejection-fixtures",
		"usage-evidence-schema",
		"usage-evidence-semantic-bounds",
		"artifact-usage-protected-admission-bindings",
		"artifact-operation-read-schema",
		"artifact-usage-read-state-matrix",
	}
	if err := validateCases(ids); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleSuiteCasesExecuteBehaviorPackages(t *testing.T) {
	want := map[string]testCase{
		"lifecycle-create-request-schema":                            {Package: "./providerapi"},
		"lifecycle-operation-state-schema":                           {Package: "./providerapi"},
		"lifecycle-idempotency-generation-fencing":                   {Package: "./provider/lifecycle/coordinator"},
		"lifecycle-deadline-outcome":                                 {Package: "./provider/lifecycle/coordinator"},
		"capability-discovery-terminal-profile-advertisement":        {Package: "./providerapi"},
		"capability-discovery-terminal-session-contract-consistency": {Package: "./providerapi/v1"},
		"exec-request-schema":                                        {Package: "./providerapi/v1"},
		"exec-cancel-schema":                                         {Package: "./providerapi/v1"},
		"exec-result-schema":                                         {Package: "./providerapi/v1"},
		"exec-semantic-bounds":                                       {Package: "./providerapi/v1"},
		"exec-rejection-fixtures":                                    {Package: "./providerapi/v1"},
		"runtime-session-open-schema":                                {Package: "./providerapi/v1"},
		"runtime-session-operation-schema":                           {Package: "./providerapi/v1"},
		"runtime-session-handoff-schema":                             {Package: "./providerapi/v1"},
		"runtime-session-semantic-bounds":                            {Package: "./providerapi/v1"},
		"runtime-session-rejection-fixtures":                         {Package: "./providerapi/v1"},
		"artifact-staging-request-schema":                            {Package: "./providerapi/v1"},
		"artifact-staging-evidence-schema":                           {Package: "./providerapi/v1"},
		"artifact-staging-semantic-bounds":                           {Package: "./providerapi/v1"},
		"artifact-staging-rejection-fixtures":                        {Package: "./providerapi/v1"},
		"usage-evidence-schema":                                      {Package: "./providerapi/v1"},
		"usage-evidence-semantic-bounds":                             {Package: "./providerapi/v1"},
		"artifact-usage-protected-admission-bindings":                {Package: "./provider/admission"},
		"artifact-operation-read-schema":                             {Package: "./providerapi/v1"},
		"artifact-usage-read-state-matrix":                           {Package: "./providerapi/v1"},
	}
	for id, expected := range want {
		got := testCases[id]
		if got.Package != expected.Package || got.Run == "" {
			t.Fatalf("Suite case %q mapping = %#v, want package %q and a behavior pattern", id, got, expected.Package)
		}
	}
}

func TestWithSourceRootEnvReplacesExistingValue(t *testing.T) {
	const key = "SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT="
	original := os.Getenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT")
	if err := os.Setenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT", "/wrong"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if original == "" {
			_ = os.Unsetenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT")
			return
		}
		_ = os.Setenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT", original)
	})
	values := withSourceRootEnv("/right")
	var matches []string
	for _, value := range values {
		if strings.HasPrefix(value, key) {
			matches = append(matches, value)
		}
	}
	if len(matches) != 1 || matches[0] != key+"/right" {
		t.Fatalf("Contract source-root environment = %#v", matches)
	}
}
