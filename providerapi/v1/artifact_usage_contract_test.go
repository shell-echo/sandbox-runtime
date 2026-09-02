package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type evidenceReadState struct {
	OperationStatus        string `json:"operation_status"`
	OperationReadStatus    int    `json:"operation_read_status"`
	Status                 int    `json:"status"`
	Code                   string `json:"code"`
	Retryable              bool   `json:"retryable"`
	RetryAfterRequired     bool   `json:"retry_after_required"`
	ReconciliationRequired bool   `json:"reconciliation_required"`
	EvidenceStatus         string `json:"evidence_status"`
}

type usageAvailableState struct {
	Values []string `json:"values"`
	Status int      `json:"status"`
}

type evidenceReadMatrix struct {
	ProviderOperationRead struct {
		Route                              string   `json:"route"`
		OperationTypes                     []string `json:"operation_types"`
		ArtifactStageKnownStatus           int      `json:"artifact_stage_known_status"`
		UnknownAfterAllFamilyReadersStatus int      `json:"unknown_after_all_family_readers_status"`
	} `json:"provider_operation_read"`
	ArtifactEvidence map[string]evidenceReadState `json:"artifact_evidence"`
	UsageEvidence    struct {
		UnknownOrAbsent                 evidenceReadState   `json:"unknown_or_absent"`
		KnownNotYetReadable             evidenceReadState   `json:"known_not_yet_readable"`
		TemporarilyUnavailable          evidenceReadState   `json:"temporarily_unavailable"`
		AvailableReconciliationStatuses usageAvailableState `json:"available_reconciliation_statuses"`
		Expired                         evidenceReadState   `json:"expired"`
	} `json:"usage_evidence"`
	ReadAdmission struct {
		DescriptorFields      []string `json:"descriptor_fields"`
		MutationGuardConsumed bool     `json:"mutation_guard_consumed"`
	} `json:"read_admission"`
}

type openAPIErrorCode struct {
	Code                   string   `yaml:"code"`
	Retryable              bool     `yaml:"retryable"`
	ReconciliationRequired bool     `yaml:"reconciliation_required"`
	Conditions             []string `yaml:"conditions"`
}

func TestLockedArtifactAndUsageProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	for _, fixture := range []struct {
		name   string
		schema string
		value  any
	}{
		{"artifact-staging-request.json", "artifact-staging-request.schema.json", &ArtifactStagingRequest{}},
		{"artifact-staging-evidence.json", "artifact-staging-evidence.schema.json", &ArtifactStagingEvidence{}},
		{"usage-evidence.json", "usage-evidence.schema.json", &UsageEvidence{}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			document, err := projection.ReadExample(fixture.name)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate(fixture.schema, document); err != nil {
				t.Fatalf("fixture is invalid: %v", err)
			}
			if err := DecodeStrict(bytes.NewReader(document), 1<<20, fixture.value); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			projected, err := json.Marshal(fixture.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate(fixture.schema, projected); err != nil {
				t.Fatalf("wire DTO projection is invalid: %v", err)
			}
		})
	}

	operation, err := projection.ReadExample("provider-operation.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", operation); err != nil {
		t.Fatalf("operation fixture is invalid: %v", err)
	}
}

func TestLockedArtifactOperationReadProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("provider-operation-artifact-stage-outcome-unknown.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", document); err != nil {
		t.Fatalf("artifact outcome-unknown operation fixture is invalid: %v", err)
	}
	var operation Operation
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &operation); err != nil {
		t.Fatalf("decode artifact outcome-unknown operation: %v", err)
	}
	if operation.Type != OperationArtifactStage || operation.Status != OperationOutcomeUnknown || operation.Error == nil ||
		operation.Error.Code != "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN" || !operation.Error.Retryable || operation.Error.Outcome != OutcomeUnknownFailure {
		t.Fatalf("artifact outcome-unknown operation = %#v", operation)
	}
	projected, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", projected); err != nil {
		t.Fatalf("artifact outcome-unknown DTO projection is invalid: %v", err)
	}
}

func TestLocalContractArtifactUsageReadStateMatrix(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("artifact-usage-read-state-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture evidenceReadMatrix
	if err := json.Unmarshal(document, &fixture); err != nil {
		t.Fatal(err)
	}
	assertEvidenceReadFixture(t, fixture)
	assertEvidenceReadSemanticRules(t, fixture)
	assertEvidenceReadOpenAPI(t)
}

func assertEvidenceReadFixture(t *testing.T, fixture evidenceReadMatrix) {
	t.Helper()
	wantOperationTypes := []string{"create", "exec", "cancel_exec", "open_runtime_session", "open_browser_session", "artifact_stage"}
	if fixture.ProviderOperationRead.Route != "GET /v1/operations/{operation_id}" ||
		!slices.Equal(fixture.ProviderOperationRead.OperationTypes, wantOperationTypes) ||
		fixture.ProviderOperationRead.ArtifactStageKnownStatus != http.StatusOK ||
		fixture.ProviderOperationRead.UnknownAfterAllFamilyReadersStatus != http.StatusNotFound {
		t.Fatalf("provider operation read fixture = %#v", fixture.ProviderOperationRead)
	}
	wantArtifact := map[string]evidenceReadState{
		"unknown_operation": {Status: http.StatusNotFound, Code: "SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND"},
		"source_missing":    {OperationStatus: "failed", OperationReadStatus: http.StatusOK, Status: http.StatusNotFound, Code: "SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND"},
		"accepted":          {OperationStatus: "accepted", OperationReadStatus: http.StatusOK, Status: http.StatusServiceUnavailable, Code: "SANDBOX_ARTIFACT_EVIDENCE_PENDING", Retryable: true, RetryAfterRequired: true},
		"running":           {OperationStatus: "running", OperationReadStatus: http.StatusOK, Status: http.StatusServiceUnavailable, Code: "SANDBOX_ARTIFACT_EVIDENCE_PENDING", Retryable: true, RetryAfterRequired: true},
		"outcome_unknown":   {OperationStatus: "outcome_unknown", OperationReadStatus: http.StatusOK, Status: http.StatusServiceUnavailable, Code: "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN", Retryable: true, RetryAfterRequired: true, ReconciliationRequired: true},
		"staged":            {OperationStatus: "succeeded", OperationReadStatus: http.StatusOK, Status: http.StatusOK, EvidenceStatus: "staged"},
		"content_rejected":  {OperationStatus: "failed", OperationReadStatus: http.StatusOK, Status: http.StatusOK, EvidenceStatus: "rejected"},
		"expired":           {Status: http.StatusGone, Code: "SANDBOX_ARTIFACT_EVIDENCE_EXPIRED"},
	}
	if !reflect.DeepEqual(fixture.ArtifactEvidence, wantArtifact) {
		t.Fatalf("artifact evidence read matrix = %#v, want %#v", fixture.ArtifactEvidence, wantArtifact)
	}
	wantUsageErrors := []evidenceReadState{
		{Status: http.StatusNotFound, Code: "SANDBOX_USAGE_EVIDENCE_NOT_FOUND"},
		{Status: http.StatusServiceUnavailable, Code: "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", Retryable: true, RetryAfterRequired: true},
		{Status: http.StatusServiceUnavailable, Code: "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", Retryable: true, RetryAfterRequired: true},
		{Status: http.StatusGone, Code: "SANDBOX_USAGE_EVIDENCE_EXPIRED"},
	}
	gotUsageErrors := []evidenceReadState{fixture.UsageEvidence.UnknownOrAbsent, fixture.UsageEvidence.KnownNotYetReadable, fixture.UsageEvidence.TemporarilyUnavailable, fixture.UsageEvidence.Expired}
	if !reflect.DeepEqual(gotUsageErrors, wantUsageErrors) || !slices.Equal(fixture.UsageEvidence.AvailableReconciliationStatuses.Values, []string{"complete", "partial", "unknown"}) || fixture.UsageEvidence.AvailableReconciliationStatuses.Status != http.StatusOK {
		t.Fatalf("usage evidence read matrix = %#v", fixture.UsageEvidence)
	}
	if !slices.Equal(fixture.ReadAdmission.DescriptorFields, []string{"operation", "sandbox_id", "operation_id", "attempt_id", "fencing_token"}) || fixture.ReadAdmission.MutationGuardConsumed {
		t.Fatalf("evidence read admission fixture = %#v", fixture.ReadAdmission)
	}
}

func assertEvidenceReadSemanticRules(t *testing.T, fixture evidenceReadMatrix) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(localContractSourceRoot(t), "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var semantic struct {
		Rules []struct {
			ID               string                       `json:"id"`
			Requires         []string                     `json:"requires"`
			OperationTypes   []string                     `json:"operation_types"`
			ArtifactEvidence map[string]evidenceReadState `json:"artifact_evidence"`
			UsageEvidence    struct {
				UnknownOrAbsent                 evidenceReadState   `json:"unknown_or_absent"`
				KnownNotYetReadable             evidenceReadState   `json:"known_not_yet_readable"`
				TemporarilyUnavailable          evidenceReadState   `json:"temporarily_unavailable"`
				AvailableReconciliationStatuses usageAvailableState `json:"available_reconciliation_statuses"`
				Expired                         evidenceReadState   `json:"expired"`
			} `json:"usage_evidence"`
			NotFound struct {
				Status    int    `json:"status"`
				Condition string `json:"condition"`
			} `json:"not_found"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &semantic); err != nil {
		t.Fatal(err)
	}
	foundAggregation, foundMatrix := false, false
	for _, rule := range semantic.Rules {
		switch rule.ID {
		case "provider-operation-read-aggregation":
			foundAggregation = true
			if !slices.Equal(rule.OperationTypes, fixture.ProviderOperationRead.OperationTypes) || rule.NotFound.Status != fixture.ProviderOperationRead.UnknownAfterAllFamilyReadersStatus || rule.NotFound.Condition != "operation-is-unknown-to-every-composed-family-authority" {
				t.Fatalf("operation aggregation rule = %#v", rule)
			}
		case "artifact-usage-evidence-read-state-matrix":
			foundMatrix = true
			if !reflect.DeepEqual(rule.ArtifactEvidence, fixture.ArtifactEvidence) || !reflect.DeepEqual(rule.UsageEvidence, fixture.UsageEvidence) {
				t.Fatalf("semantic evidence matrix does not match fixture")
			}
			for _, requirement := range []string{"descriptor-binding-before-read", "evidence-read-does-not-consume-mutation-guard", "positive-retry-after-on-503", "caller-safe-standard-errors"} {
				if !slices.Contains(rule.Requires, requirement) {
					t.Fatalf("evidence matrix rule is missing %q", requirement)
				}
			}
		}
	}
	if !foundAggregation || !foundMatrix {
		t.Fatalf("semantic rules found aggregation=%t matrix=%t", foundAggregation, foundMatrix)
	}
}

func assertEvidenceReadOpenAPI(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(localContractSourceRoot(t), "contract/openapi/sandbox-runtime-provider-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Get struct {
				Responses map[string]struct {
					Description string             `yaml:"description"`
					ErrorCodes  []openAPIErrorCode `yaml:"x-error-codes"`
					Headers     map[string]struct {
						Schema struct {
							Minimum int `yaml:"minimum"`
						} `yaml:"schema"`
					} `yaml:"headers"`
				} `yaml:"responses"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	operationResponses := document.Paths["/v1/operations/{operation_id}"].Get.Responses
	if !strings.Contains(operationResponses["200"].Description, "artifact_stage") || !strings.Contains(operationResponses["200"].Description, "open_browser_session") || !strings.Contains(operationResponses["404"].Description, "any composed operation-family authority") {
		t.Fatalf("generic operation OpenAPI descriptions do not bind aggregation")
	}
	artifactResponses := document.Paths["/v1/operations/{operation_id}/artifact-staging-evidence"].Get.Responses
	assertOpenAPIErrorCodes(t, artifactResponses["404"].ErrorCodes, []openAPIErrorCode{{Code: "SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND", Conditions: []string{"unknown_operation", "source_missing"}}})
	assertOpenAPIErrorCodes(t, artifactResponses["410"].ErrorCodes, []openAPIErrorCode{{Code: "SANDBOX_ARTIFACT_EVIDENCE_EXPIRED", Conditions: []string{"expired"}}})
	assertOpenAPIErrorCodes(t, artifactResponses["503"].ErrorCodes, []openAPIErrorCode{
		{Code: "SANDBOX_ARTIFACT_EVIDENCE_PENDING", Retryable: true, Conditions: []string{"accepted", "running"}},
		{Code: "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN", Retryable: true, ReconciliationRequired: true, Conditions: []string{"outcome_unknown"}},
	})
	if artifactResponses["503"].Headers["Retry-After"].Schema.Minimum != 1 {
		t.Fatal("artifact evidence 503 does not require a positive Retry-After")
	}
	usageResponses := document.Paths["/v1/operations/{operation_id}/usage-evidence"].Get.Responses
	assertOpenAPIErrorCodes(t, usageResponses["404"].ErrorCodes, []openAPIErrorCode{{Code: "SANDBOX_USAGE_EVIDENCE_NOT_FOUND", Conditions: []string{"unknown_operation", "no_evidence"}}})
	assertOpenAPIErrorCodes(t, usageResponses["410"].ErrorCodes, []openAPIErrorCode{{Code: "SANDBOX_USAGE_EVIDENCE_EXPIRED", Conditions: []string{"expired"}}})
	assertOpenAPIErrorCodes(t, usageResponses["503"].ErrorCodes, []openAPIErrorCode{{Code: "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", Retryable: true, Conditions: []string{"known_not_yet_readable", "temporarily_unavailable"}}})
	if usageResponses["503"].Headers["Retry-After"].Schema.Minimum != 1 {
		t.Fatal("usage evidence 503 does not require a positive Retry-After")
	}
}

func assertOpenAPIErrorCodes(t *testing.T, got, want []openAPIErrorCode) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenAPI error codes = %#v, want %#v", got, want)
	}
}

func TestLocalContractArtifactAndUsageSemanticRules(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	data, err := os.ReadFile(filepath.Join(sourceRoot, "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	want := map[string]struct {
		method, path, scope string
		required            []string
		forbidden           string
	}{
		"artifact-staging-request-bounded":  {"POST", "/v1/sandboxes/{sandbox_id}/artifacts:stage", "artifact-staging", []string{"artifact-reference-is-opaque", "source-path-under-outputs", "digest-media-type-and-size-bounds", "tenant-binding-from-admission-context", "active-content-check-before-stage", "malware-check-before-stage", "expiry-bound"}, "public-artifact-url"},
		"artifact-staging-evidence-bounded": {"GET", "/v1/operations/{operation_id}/artifact-staging-evidence", "artifact-staging-evidence", []string{"expected-digest-media-type-and-size-binding", "tenant-binding-check-evidence", "active-content-check-evidence", "malware-check-evidence", "opaque-staging-reference", "expired-evidence-is-410"}, "artifact-authority"},
		"usage-evidence-bounded":            {"GET", "/v1/operations/{operation_id}/usage-evidence", "usage-evidence", []string{"operation-and-sandbox-correlation", "bounded-meter-dimensions", "reconciliation-status-explicit", "expired-evidence-is-410"}, "billing-total"},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] {
			t.Fatalf("duplicate rule %q", rule.ID)
		}
		found[rule.ID] = true
		if rule.Method != expected.method || rule.Path != expected.path || rule.Scope != expected.scope {
			t.Fatalf("rule %q identity mismatch", rule.ID)
		}
		requires := make(map[string]bool, len(rule.Requires))
		for _, requirement := range rule.Requires {
			requires[requirement] = true
		}
		for _, requirement := range expected.required {
			if !requires[requirement] {
				t.Fatalf("rule %q missing %q", rule.ID, requirement)
			}
		}
		forbidden := false
		for _, value := range rule.Forbids {
			if value == expected.forbidden {
				forbidden = true
			}
		}
		if !forbidden {
			t.Fatalf("rule %q missing forbidden assertion %q", rule.ID, expected.forbidden)
		}
	}
	for id := range want {
		if !found[id] {
			t.Fatalf("local Contract is missing rule %q", id)
		}
	}
}

func TestArtifactStagingRejectionFixtures(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("artifact-staging-rejections.json")
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
		t.Fatal(err)
	}
	if len(fixture.Cases) < 5 {
		t.Fatalf("rejection fixture count = %d, want at least 5", len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			if err := projection.Validate(testCase.Schema, testCase.Document); err == nil {
				t.Fatal("rejection fixture unexpectedly validates")
			}
		})
	}
}
