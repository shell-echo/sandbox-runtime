package admission

import (
	"encoding/json"
	"os"
	"testing"
)

func TestLocalContractBrowserSessionAdmissionBindings(t *testing.T) {
	data, err := os.ReadFile(artifactUsageContractFixturePath(t, "browser-session-admission-bindings.json"))
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
		method     string
		path       string
		contractID string
		profile    DigestProfile
		mutation   bool
	}{
		OperationOpenBrowserSession: {
			"POST", "/v1/sandboxes/browser-sandbox-1/browser-sessions",
			"urn:shell-echo:sandbox-runtime:request:open-browser-session:v1",
			DigestProfileRequestExcludingDigest, true,
		},
		OperationReadBrowserSession: {
			"GET", "/v1/operations/browser-session-operation-1/browser-session",
			"urn:shell-echo:sandbox-runtime:descriptor:browser-session:v1",
			DigestProfileFullDocument, false,
		},
	}
	if len(fixture.Bindings) != len(want) {
		t.Fatalf("browser admission bindings = %d, want %d", len(fixture.Bindings), len(want))
	}
	schemaOperations := admissionContextSchemaOperations(t)
	seen := make(map[Operation]bool, len(want))
	for _, binding := range fixture.Bindings {
		expected, ok := want[binding.Operation]
		if !ok {
			t.Fatalf("unexpected browser operation %q", binding.Operation)
		}
		if seen[binding.Operation] || binding.Method != expected.method || binding.Path != expected.path ||
			binding.RequestContractID != expected.contractID || binding.RequestDigestProfile != expected.profile || binding.Mutation != expected.mutation {
			t.Fatalf("browser binding %q = %#v", binding.Operation, binding)
		}
		seen[binding.Operation] = true
		implementation, ok := requestBindings[binding.Operation]
		if !ok || implementation.contractID != expected.contractID || implementation.profile != expected.profile ||
			!binding.Operation.Supported() || binding.Operation.Mutation() != expected.mutation || !schemaOperations[binding.Operation] {
			t.Fatalf("browser operation %q implementation = %#v", binding.Operation, implementation)
		}
		if expected.mutation && binding.RequestFixture != "browser-session-open-request.json" {
			t.Fatalf("browser open request fixture = %q", binding.RequestFixture)
		}
		if !expected.mutation && len(binding.DescriptorDocument) == 0 {
			t.Fatal("browser read binding must carry its exact descriptor document")
		}
		assertArtifactUsageContextAndGuard(t, binding)
	}
}
