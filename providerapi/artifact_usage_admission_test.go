package providerapi

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

func TestArtifactUsageReadDescriptorsMatchLockedFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(localContractSourceRoot(t), "contract/fixtures/artifact-usage-admission-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Bindings []struct {
			Operation          admission.Operation `json:"operation"`
			Method             string              `json:"method"`
			Path               string              `json:"path"`
			DescriptorDocument json.RawMessage     `json:"descriptor_document"`
			RequestDigest      string              `json:"request_digest"`
			Mutation           bool                `json:"mutation"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, binding := range fixture.Bindings {
		if binding.Mutation {
			continue
		}
		t.Run(string(binding.Operation), func(t *testing.T) {
			var lockedDescriptor struct {
				SandboxID    string `json:"sandbox_id"`
				OperationID  string `json:"operation_id"`
				AttemptID    string `json:"attempt_id"`
				FencingToken int64  `json:"fencing_token"`
			}
			if err := json.Unmarshal(binding.DescriptorDocument, &lockedDescriptor); err != nil {
				t.Fatal(err)
			}
			contextValue := admission.AdmissionContext{
				Operation: binding.Operation, SandboxID: lockedDescriptor.SandboxID,
				OperationID: lockedDescriptor.OperationID, AttemptID: lockedDescriptor.AttemptID,
				FencingToken: lockedDescriptor.FencingToken,
			}
			request, err := http.NewRequest(binding.Method, "https://provider.test"+binding.Path, nil)
			if err != nil {
				t.Fatal(err)
			}
			document, status := readDescriptor(contextValue, request, map[string]string{"operation_id": lockedDescriptor.OperationID})
			if status != 0 {
				t.Fatalf("readDescriptor() status = %d", status)
			}
			if err := admission.VerifyRequestDigest(admission.DigestProfileFullDocument, binding.RequestDigest, document); err != nil {
				t.Fatalf("descriptor digest mismatch: %v; document=%s", err, document)
			}
			var got, want any
			if err := json.Unmarshal(document, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(binding.DescriptorDocument, &want); err != nil {
				t.Fatal(err)
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("descriptor = %s, want %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestArtifactUsageRoutesAreTransportBoundaries(t *testing.T) {
	tests := []struct {
		method, path string
		operation    admission.Operation
	}{
		{http.MethodPost, "/v1/sandboxes/sandbox-1/artifacts:stage", admission.OperationStageArtifact},
		{http.MethodGet, "/v1/operations/artifact-operation-1/artifact-staging-evidence", admission.OperationReadArtifactStagingEvidence},
		{http.MethodGet, "/v1/operations/exec-operation-1/usage-evidence", admission.OperationReadUsageEvidence},
	}
	for _, test := range tests {
		route, _, ok := matchProtectedRoute(mustProviderRequest(t, test.method, test.path))
		if !ok || route.operation != test.operation {
			t.Fatalf("route %s %s = %#v, %v; want operation %q", test.method, test.path, route, ok, test.operation)
		}
	}
}

func mustProviderRequest(t *testing.T, method, path string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "https://provider.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
