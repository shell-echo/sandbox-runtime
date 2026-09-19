package admission

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLocalContractDesktopSessionAdmissionBindings(t *testing.T) {
	data, err := os.ReadFile(artifactUsageContractFixturePath(t, "desktop-session-admission-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bindings []artifactUsageAdmissionBinding `json:"bindings"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	want := map[Operation]struct {
		method, path, contractID string
		profile                  DigestProfile
		mutation                 bool
		fixture                  string
	}{
		OperationOpenDesktopSession: {
			"POST", "/v1/sandboxes/desktop-sandbox-1/desktop-sessions",
			"urn:shell-echo:sandbox-runtime:request:open-desktop-session:v1",
			DigestProfileRequestExcludingDigest, true, "desktop-session-open-request.json",
		},
		OperationCloseDesktopSession: {
			"POST", "/v1/sandboxes/desktop-sandbox-1/desktop-sessions/desktop-session-1:close",
			"urn:shell-echo:sandbox-runtime:request:close-desktop-session:v1",
			DigestProfileRequestExcludingDigest, true, "desktop-session-close-request.json",
		},
		OperationReadDesktopSession: {
			"GET", "/v1/operations/desktop-session-operation-1/desktop-session",
			"urn:shell-echo:sandbox-runtime:descriptor:desktop-session:v1",
			DigestProfileFullDocument, false, "",
		},
	}
	if len(fixture.Bindings) != len(want) {
		t.Fatalf("desktop admission bindings = %d, want %d", len(fixture.Bindings), len(want))
	}
	schemaOperations := admissionContextSchemaOperations(t)
	seen := make(map[Operation]bool, len(want))
	for _, binding := range fixture.Bindings {
		expected, ok := want[binding.Operation]
		if !ok || seen[binding.Operation] || binding.Method != expected.method || binding.Path != expected.path ||
			binding.RequestContractID != expected.contractID || binding.RequestDigestProfile != expected.profile || binding.Mutation != expected.mutation ||
			binding.RequestFixture != expected.fixture {
			t.Fatalf("desktop binding %q = %#v", binding.Operation, binding)
		}
		seen[binding.Operation] = true
		implementation, ok := requestBindings[binding.Operation]
		if !ok || implementation.contractID != expected.contractID || implementation.profile != expected.profile ||
			!binding.Operation.Supported() || binding.Operation.Mutation() != expected.mutation || !schemaOperations[binding.Operation] {
			t.Fatalf("desktop operation %q implementation = %#v", binding.Operation, implementation)
		}
		if !expected.mutation && len(binding.DescriptorDocument) == 0 {
			t.Fatal("desktop read binding must carry its exact descriptor document")
		}
		assertArtifactUsageContextAndGuard(t, binding)
	}
}
