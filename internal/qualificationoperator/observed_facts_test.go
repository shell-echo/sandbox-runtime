package qualificationoperator

import (
	"net/http"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

type acceptingProviderDocuments struct{}

func (acceptingProviderDocuments) Validate(string, []byte) error { return nil }

func TestNewJTIReplayAcceptsCurrentSuccessfulOperationState(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"accepted", "running", "succeeded"} {
		event := HTTPObservation{
			StatusCode: http.StatusAccepted, MutationWriteObserved: true,
			ResponseJSON: map[string]any{
				"operation_id": "operation", "attempt_id": "attempt", "fencing_token": float64(1),
				"sandbox_id": "sandbox", "type": "create", "status": status,
			},
		}
		if !validateProviderSubject("new-jti-idempotency-replay", []HTTPObservation{event}, acceptingProviderDocuments{}) {
			t.Fatalf("idempotent replay state %q was rejected", status)
		}
	}
}

func TestObservedSandboxResourcesComeFromEveryCreateRequest(t *testing.T) {
	t.Parallel()
	limits := qualificationprofile.RuntimeLimits{
		SandboxCPUMillis: 500, SandboxMemoryBytes: 268435456,
		SandboxEphemeralStorageBytes: 268435456, SandboxPIDs: 64,
	}
	request := func(cpu float64) map[string]any {
		return map[string]any{"spec": map[string]any{"resources": map[string]any{
			"cpu_millis": cpu, "memory_bytes": float64(268435456),
			"ephemeral_storage_bytes": float64(268435456), "pids_limit": float64(64),
		}}}
	}
	groups := map[string][]HTTPObservation{
		"create-sandbox":             {{RequestJSON: request(500)}},
		"exact-jti-replay":           {{RequestJSON: request(500)}},
		"new-jti-idempotency-replay": {{RequestJSON: request(500)}},
	}
	got, ok := observedSandboxResources(groups, limits)
	if !ok || got == nil || *got != (qualificationharness.SandboxResourceObservation{CPUMillis: 500, MemoryBytes: 268435456, EphemeralStorageBytes: 268435456, PIDs: 64}) {
		t.Fatalf("observedSandboxResources() = %#v, %t", got, ok)
	}
	groups["new-jti-idempotency-replay"][0].RequestJSON = request(501)
	if got, ok := observedSandboxResources(groups, limits); ok || got != nil {
		t.Fatalf("mismatched request resources accepted: %#v, %t", got, ok)
	}
}

func TestTranscriptSanitizationRejectsCorrelationKeysRecursively(t *testing.T) {
	t.Parallel()
	if !transcriptContainsOnlySanitizedBindings([]byte(`{"phases":[{"phase_id":"initial","message_counts":{"scenario_result":15}}]}`)) {
		t.Fatal("sanitized transcript rejected")
	}
	if transcriptContainsOnlySanitizedBindings([]byte(`{"phases":[{"nested":{"operation_id":"secret"}}]}`)) {
		t.Fatal("forbidden correlation key accepted")
	}
}

func TestValidCodingShellCapabilitiesRequiresExactAtomicProfiles(t *testing.T) {
	t.Parallel()
	value := map[string]any{
		"provider_revision_id": ProviderRevision, "api_version": "v1",
		"runtime_profiles": []any{map[string]any{
			"id":                     "sandbox-runtime-coding-shell-v1",
			"capability_profile_ids": []any{"terminal-v1", "terminal-connect-v1", "exec-v1"},
		}},
	}
	if !validCodingShellCapabilities(value) {
		t.Fatal("exact coding-shell profile rejected")
	}
	value["runtime_profiles"].([]any)[0].(map[string]any)["capability_profile_ids"] = []any{"terminal-v1", "exec-v1"}
	if validCodingShellCapabilities(value) {
		t.Fatal("partial coding-shell profile accepted")
	}
}
