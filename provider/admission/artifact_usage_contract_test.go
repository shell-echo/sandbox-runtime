package admission

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

type artifactUsageAdmissionBinding struct {
	Operation            Operation       `json:"operation"`
	Method               string          `json:"method"`
	Path                 string          `json:"path"`
	RequestContractID    string          `json:"request_contract_id"`
	RequestDigestProfile DigestProfile   `json:"request_digest_profile"`
	RequestFixture       string          `json:"request_fixture"`
	DescriptorDocument   json.RawMessage `json:"descriptor_document"`
	RequestDigest        string          `json:"request_digest"`
	Mutation             bool            `json:"mutation"`
}

type artifactUsageAdmissionFixture struct {
	Bindings            []artifactUsageAdmissionBinding  `json:"bindings"`
	RejectedOperations  []Operation                      `json:"rejected_operations"`
	AcceptanceSemantics artifactUsageAcceptanceSemantics `json:"acceptance_semantics"`
}

type artifactUsageAcceptanceSemantics struct {
	EncodedBodyTooLargeStatus                  int                  `json:"encoded_body_too_large_status"`
	UnsafeOrUnprojectableInternalFailureStatus int                  `json:"unsafe_or_unprojectable_internal_failure_status"`
	ForbiddenPreAcceptStatuses                 []int                `json:"forbidden_pre_accept_statuses"`
	Staged                                     artifactUsageOutcome `json:"staged"`
	ContentRejected                            artifactUsageOutcome `json:"content_rejected"`
	SourceMissing                              artifactUsageOutcome `json:"source_missing"`
}

type artifactUsageOutcome struct {
	OperationStatus    string `json:"operation_status"`
	EvidenceStatus     string `json:"evidence_status"`
	EvidenceReadStatus int    `json:"evidence_read_status"`
}

func TestLocalContractArtifactUsageAdmissionBindings(t *testing.T) {
	fixture := loadArtifactUsageAdmissionFixture(t)
	assertArtifactUsageAuthoritySemantics(t, fixture.AcceptanceSemantics)
	want := map[Operation]struct {
		contractID string
		profile    DigestProfile
		mutation   bool
	}{
		OperationStageArtifact:               {"urn:shell-echo:sandbox-runtime:request:stage-artifact:v1", DigestProfileRequestExcludingDigest, true},
		OperationReadArtifactStagingEvidence: {"urn:shell-echo:sandbox-runtime:descriptor:artifact-staging-evidence:v1", DigestProfileFullDocument, false},
		OperationReadUsageEvidence:           {"urn:shell-echo:sandbox-runtime:descriptor:usage-evidence:v1", DigestProfileFullDocument, false},
	}
	if len(fixture.Bindings) != len(want) {
		t.Fatalf("artifact/usage bindings = %d, want %d", len(fixture.Bindings), len(want))
	}

	schemaOperations := admissionContextSchemaOperations(t)
	seen := make(map[Operation]bool, len(fixture.Bindings))
	for _, binding := range fixture.Bindings {
		expected, ok := want[binding.Operation]
		if !ok {
			t.Fatalf("unexpected artifact/usage operation %q", binding.Operation)
		}
		if !binding.Operation.Supported() || binding.Operation.Mutation() != binding.Mutation || binding.Mutation != expected.mutation {
			t.Fatalf("operation %q supported=%t mutation=%t, fixture mutation=%t", binding.Operation, binding.Operation.Supported(), binding.Operation.Mutation(), binding.Mutation)
		}
		implementation, ok := requestBindings[binding.Operation]
		if !ok || implementation.contractID != binding.RequestContractID || implementation.profile != binding.RequestDigestProfile || implementation.contractID != expected.contractID || implementation.profile != expected.profile {
			t.Fatalf("operation %q binding = %#v, fixture=(%q,%q)", binding.Operation, implementation, binding.RequestContractID, binding.RequestDigestProfile)
		}
		if !schemaOperations[binding.Operation] {
			t.Fatalf("admission-context Schema omits operation %q", binding.Operation)
		}
		if seen[binding.Operation] {
			t.Fatalf("duplicate artifact/usage operation %q", binding.Operation)
		}
		seen[binding.Operation] = true
		assertArtifactUsageContextAndGuard(t, binding)
	}

	for _, operation := range fixture.RejectedOperations {
		if operation.Supported() || operation.Mutation() {
			t.Fatalf("rejected operation %q is accepted", operation)
		}
		if _, ok := requestBindings[operation]; ok {
			t.Fatalf("rejected operation %q has a request binding", operation)
		}
		if schemaOperations[operation] {
			t.Fatalf("admission-context Schema accepts rejected operation %q", operation)
		}
	}
}

func assertArtifactUsageAuthoritySemantics(t *testing.T, fixture artifactUsageAcceptanceSemantics) {
	t.Helper()
	if fixture.EncodedBodyTooLargeStatus != http.StatusBadRequest || fixture.UnsafeOrUnprojectableInternalFailureStatus != http.StatusServiceUnavailable || !slices.Equal(fixture.ForbiddenPreAcceptStatuses, []int{http.StatusRequestEntityTooLarge, http.StatusInternalServerError}) {
		t.Fatalf("artifact staging pre-accept fixture = %#v", fixture)
	}
	wantOutcomes := map[string]artifactUsageOutcome{
		"staged":           {OperationStatus: "succeeded", EvidenceStatus: "staged", EvidenceReadStatus: http.StatusOK},
		"content_rejected": {OperationStatus: "failed", EvidenceStatus: "rejected", EvidenceReadStatus: http.StatusOK},
		"source_missing":   {OperationStatus: "failed", EvidenceStatus: "absent", EvidenceReadStatus: http.StatusNotFound},
	}
	gotOutcomes := map[string]artifactUsageOutcome{"staged": fixture.Staged, "content_rejected": fixture.ContentRejected, "source_missing": fixture.SourceMissing}
	for name, expected := range wantOutcomes {
		if gotOutcomes[name] != expected {
			t.Fatalf("artifact staging outcome %q = %#v, want %#v", name, gotOutcomes[name], expected)
		}
	}

	data, err := os.ReadFile(artifactUsageContractPath(t, "semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var semantic struct {
		Rules []struct {
			ID              string `json:"id"`
			PreAcceptErrors struct {
				EncodedBodyTooLarge                  int   `json:"encoded_body_too_large"`
				UnsafeOrUnprojectableInternalFailure int   `json:"unsafe_or_unprojectable_internal_failure"`
				ForbiddenStatuses                    []int `json:"forbidden_statuses"`
			} `json:"pre_accept_errors"`
			TerminalOutcomes map[string]artifactUsageOutcome `json:"terminal_outcomes"`
			Descriptor       struct {
				Fields           []string `json:"fields"`
				AdditionalFields string   `json:"additional_fields"`
			} `json:"descriptor"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &semantic); err != nil {
		t.Fatal(err)
	}
	foundOutcomes, foundDescriptor := false, false
	for _, rule := range semantic.Rules {
		switch rule.ID {
		case "artifact-staging-asynchronous-outcomes":
			foundOutcomes = true
			if rule.PreAcceptErrors.EncodedBodyTooLarge != fixture.EncodedBodyTooLargeStatus || rule.PreAcceptErrors.UnsafeOrUnprojectableInternalFailure != fixture.UnsafeOrUnprojectableInternalFailureStatus || !slices.Equal(rule.PreAcceptErrors.ForbiddenStatuses, fixture.ForbiddenPreAcceptStatuses) {
				t.Fatalf("semantic pre-accept errors do not match fixture")
			}
			for name, expected := range wantOutcomes {
				if rule.TerminalOutcomes[name] != expected {
					t.Fatalf("semantic outcome %q = %#v, want %#v", name, rule.TerminalOutcomes[name], expected)
				}
			}
		case "artifact-usage-read-descriptor-digests":
			foundDescriptor = true
			if !slices.Equal(rule.Descriptor.Fields, []string{"operation", "sandbox_id", "operation_id", "attempt_id", "fencing_token"}) || rule.Descriptor.AdditionalFields != "forbidden" {
				t.Fatalf("read descriptor rule = %#v", rule.Descriptor)
			}
		}
	}
	if !foundOutcomes || !foundDescriptor {
		t.Fatalf("artifact/usage semantic rules found outcomes=%t descriptor=%t", foundOutcomes, foundDescriptor)
	}

	openAPI, err := os.ReadFile(artifactUsageContractPath(t, "openapi/sandbox-runtime-provider-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Post struct {
				Responses map[string]any `yaml:"responses"`
			} `yaml:"post"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPI, &document); err != nil {
		t.Fatal(err)
	}
	responses := document.Paths["/v1/sandboxes/{sandbox_id}/artifacts:stage"].Post.Responses
	for _, status := range []string{"202", "400", "401", "403", "409", "410", "422", "503"} {
		if _, ok := responses[status]; !ok {
			t.Fatalf("artifact staging OpenAPI omits status %s", status)
		}
	}
	for _, status := range []string{"413", "500"} {
		if _, ok := responses[status]; ok {
			t.Fatalf("artifact staging OpenAPI unexpectedly authorizes status %s", status)
		}
	}
}

func assertArtifactUsageContextAndGuard(t *testing.T, binding artifactUsageAdmissionBinding) {
	t.Helper()
	operationID, attemptID, fencingToken := "artifact-operation-1", "artifact-attempt-1", int64(3)
	if binding.Operation == OperationReadUsageEvidence {
		operationID, attemptID, fencingToken = "exec-operation-1", "exec-attempt-1", 2
	}
	requestDigest := binding.RequestDigest
	document := []byte(binding.DescriptorDocument)
	if binding.Mutation {
		var err error
		document, err = os.ReadFile(artifactUsageContractFixturePath(t, binding.RequestFixture))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyRequestDigest(binding.RequestDigestProfile, requestDigest, document); err != nil {
		t.Fatalf("verify locked request/descriptor digest for %q: %v", binding.Operation, err)
	}

	value := validAdmissionContextForTest()
	value.Operation = binding.Operation
	value.SandboxID = "sandbox-1"
	value.OperationID = operationID
	value.AttemptID = attemptID
	value.FencingToken = fencingToken
	value.RequestContractID = binding.RequestContractID
	value.RequestDigestProfile = binding.RequestDigestProfile
	value.RequestDigest = requestDigest
	value.PolicyDecidedAt = time.Unix(105, 0).UTC().Format(time.RFC3339Nano)
	value.DeadlineAt = time.Unix(200, 0).UTC().Format(time.RFC3339Nano)
	value.HTTPTarget = AdmissionTarget{Method: binding.Method, Path: binding.Path, NormalizedQuery: []AdmissionQuery{}}
	digest, err := DigestForAdmissionContext(value)
	if err != nil {
		t.Fatal(err)
	}
	value.ContextDigest = digest
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAdmissionContextCarrier(base64.RawURLEncoding.EncodeToString(encoded))
	if err != nil {
		t.Fatalf("decode %q Admission Context: %v", binding.Operation, err)
	}
	httpRequest, err := http.NewRequest(binding.Method, "https://provider.test"+binding.Path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateTarget(httpRequest); err != nil {
		t.Fatalf("validate %q target: %v", binding.Operation, err)
	}

	fixture := newEdDSAFixture(t)
	tokenClaims := validTokenClaims()
	tokenClaims.IssuedAt = 100
	tokenClaims.NotBefore = 110
	tokenClaims.ExpiresAt = 180
	tokenClaims.Operation = binding.Operation
	tokenClaims.OperationID = operationID
	tokenClaims.AttemptID = attemptID
	tokenClaims.FencingToken = fencingToken
	tokenClaims.RequestContractID = binding.RequestContractID
	tokenClaims.RequestDigestProfile = binding.RequestDigestProfile
	tokenClaims.RequestDigest = requestDigest
	tokenClaims.PolicyDecidedAt = value.PolicyDecidedAt
	tokenClaims.DeadlineAt = value.DeadlineAt
	tokenClaims.AdmissionContextContractID = value.ContextContractID
	tokenClaims.AdmissionContextDigestProfile = value.ContextDigestProfile
	tokenClaims.AdmissionContextDigest = value.ContextDigest
	token := fixture.token(t, JWSHeader{Algorithm: fixture.algorithm, KeyID: fixture.keyID, Type: expectedJWSAdmissionType}, tokenClaims)
	clock := fixedClock{now: time.Unix(150, 0).UTC()}
	guard := &recordingMutationGuard{}
	gate, err := NewProtectedOperationGate(fixture.keys, &clock, guard)
	if err != nil {
		t.Fatal(err)
	}
	request := ProtectedOperationRequest{CompactToken: token, Binding: value.TokenBinding(value.ControllerSubject), Document: document}
	if err := gate.Admit(context.Background(), request); err != nil {
		t.Fatalf("admit %q: %v", binding.Operation, err)
	}
	wantGuardCalls := 0
	if binding.Mutation {
		wantGuardCalls = 1
	}
	if calls := len(guard.Requests()); calls != wantGuardCalls {
		t.Fatalf("operation %q guard calls = %d, want %d", binding.Operation, calls, wantGuardCalls)
	}
}

func loadArtifactUsageAdmissionFixture(t *testing.T) artifactUsageAdmissionFixture {
	t.Helper()
	data, err := os.ReadFile(artifactUsageContractFixturePath(t, "artifact-usage-admission-bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture artifactUsageAdmissionFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func artifactUsageContractFixturePath(t *testing.T, name string) string {
	t.Helper()
	return artifactUsageContractPath(t, filepath.Join("fixtures", name))
}

func artifactUsageContractPath(t *testing.T, relative string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve Contract path")
	}
	return filepath.Join(filepath.Dir(file), "../../contract", relative)
}

func admissionContextSchemaOperations(t *testing.T) map[Operation]bool {
	t.Helper()
	data, err := os.ReadFile(artifactUsageContractPath(t, "schemas/admission-context.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Operation struct {
				Enum []Operation `json:"enum"`
			} `json:"operation"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	operations := make(map[Operation]bool, len(schema.Properties.Operation.Enum))
	for _, operation := range schema.Properties.Operation.Enum {
		operations[operation] = true
	}
	return operations
}
