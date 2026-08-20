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
		"capability-discovery-empty-request",
		"capability-discovery-no-mutation-routes",
		"protected-admission-context-schema",
		"protected-admission-token-binding",
		"protected-admission-digest-substitution",
		"protected-admission-expiry",
		"protected-admission-replay-and-fencing",
	}
	if err := validateCases(ids); err != nil {
		t.Fatal(err)
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
