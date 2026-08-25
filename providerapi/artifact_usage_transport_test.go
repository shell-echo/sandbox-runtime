package providerapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func TestProtectedArtifactStageAcceptsAfterAdmissionWithoutDispatch(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
	app := &transportArtifactApp{}
	handler := newArtifactTransportHandler(t, identity, publicKey, guard, app, nil, nil)
	request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/artifacts:stage", operation: admission.OperationStageArtifact, allowUnavailable: true}, privateKey, material.client, "jti-stage-0000001")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || app.acceptCalls != 1 || app.evidenceCalls != 0 {
		t.Fatalf("stage response=%d accept_calls=%d evidence_calls=%d body=%s", response.Code, app.acceptCalls, app.evidenceCalls, response.Body.String())
	}
	var projected providerv1.Operation
	if err := jsonDecode(response, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Type != providerv1.OperationArtifactStage || projected.Status != providerv1.OperationAccepted {
		t.Fatalf("operation projection=%#v", projected)
	}
}

func TestProtectedArtifactAdmissionFailureDoesNotCallApplication(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
	app := &transportArtifactApp{}
	handler := newArtifactTransportHandler(t, identity, publicKey, guard, app, nil, nil)
	request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/artifacts:stage", operation: admission.OperationStageArtifact, allowUnavailable: true}, privateKey, material.client, "jti-stage-invalid-0001")
	request.Header.Set("Content-Type", "application/json")
	request.Body = ioNopCloser(strings.NewReader(`{"unknown":true}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || app.acceptCalls != 0 || guard.Calls() != 0 {
		t.Fatalf("invalid stage response=%d accept_calls=%d guard_calls=%d body=%s", response.Code, app.acceptCalls, guard.Calls(), response.Body.String())
	}
}

func TestProtectedArtifactStrictDocumentErrorsAreBadRequest(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown member", body: `{"unknown":true}`},
		{name: "duplicate member", body: `{"operation_id":"operation-1","operation_id":"operation-1"}`},
		{name: "malformed", body: `{"operation_id":`},
		{name: "oversized", body: `{"operation_id":"` + strings.Repeat("x", int(providerv1.MaxArtifactStagingRequestBytes)) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			app := &transportArtifactApp{}
			handler := newArtifactTransportHandler(t, identity, publicKey, guard, app, nil, nil)
			request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/artifacts:stage", operation: admission.OperationStageArtifact, allowUnavailable: true}, privateKey, material.client, "jti-stage-strict-"+test.name+"-1")
			request.Body = ioNopCloser(strings.NewReader(test.body))
			request.ContentLength = int64(len(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || app.acceptCalls != 0 || guard.Calls() != 0 {
				t.Fatalf("response=%d accept_calls=%d guard_calls=%d body=%s", response.Code, app.acceptCalls, guard.Calls(), response.Body.String())
			}
		})
	}
}

func TestProtectedArtifactSchemaInvalidDocumentDoesNotReserveMutation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
	app := &transportArtifactApp{}
	handler := newArtifactTransportHandler(t, identity, publicKey, guard, app, nil, nil)
	request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/artifacts:stage", operation: admission.OperationStageArtifact, allowUnavailable: true}, privateKey, material.client, "jti-stage-schema-invalid-1")
	contextValue := admissionContextFromReleaseRequest(t, request)
	withoutDigest := []byte(`{"unknown":true}`)
	digest := releaseFullDocumentDigest(t, withoutDigest)
	body := []byte(`{"unknown":true,"request_digest":"` + digest + `"}`)
	contextValue.RequestDigest = digest
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	claims := admissionTokenClaimsForTest(contextValue)
	claims["jti"] = "jti-stage-schema-invalid-1"
	request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	request.Body = ioNopCloser(strings.NewReader(string(body)))
	request.ContentLength = int64(len(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || app.acceptCalls != 0 || guard.Calls() != 0 {
		t.Fatalf("schema-invalid stage response=%d accept_calls=%d guard_calls=%d body=%s", response.Code, app.acceptCalls, guard.Calls(), response.Body.String())
	}
}

func TestProtectedArtifactEvidenceStateMatrix(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		err  error
		want int
		code string
	}{
		{"missing", artifact.ErrEvidenceNotFound, http.StatusNotFound, "SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND"},
		{"pending", artifact.ErrEvidencePending, http.StatusServiceUnavailable, "SANDBOX_ARTIFACT_EVIDENCE_PENDING"},
		{"unknown", artifact.ErrOutcomeUnknown, http.StatusServiceUnavailable, "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN"},
		{"expired", artifact.ErrEvidenceExpired, http.StatusGone, "SANDBOX_ARTIFACT_EVIDENCE_EXPIRED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			app := &transportArtifactApp{evidenceErr: test.err}
			handler := newArtifactTransportHandler(t, identity, publicKey, guard, app, nil, nil)
			request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1/artifact-staging-evidence", operation: admission.OperationReadArtifactStagingEvidence, allowUnavailable: true}, privateKey, material.client, "jti-read-artifact-"+test.name+"-1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("response=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			var standard providerv1.StandardError
			if err := jsonDecode(response, &standard); err != nil || standard.Code != test.code {
				t.Fatalf("error=%#v decode=%v", standard, err)
			}
		})
	}
}

func TestProtectedUsageEvidenceProjectionAndOperationAggregation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &transportArtifactApp{evidence: validTransportArtifactEvidence()}
	app.operation = validTransportArtifactOperation()
	usageReader := &transportUsageReader{evidence: validTransportUsageEvidence()}
	reader, err := provideroperation.NewArtifactReader(app)
	if err != nil {
		t.Fatal(err)
	}
	aggregator, err := provideroperation.NewAggregator(reader)
	if err != nil {
		t.Fatal(err)
	}
	handler := newArtifactTransportHandler(t, identity, publicKey, &releaseGateGuard{decision: admission.MutationGuardAccepted}, app, usageReader, aggregator)

	artifactRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1/artifact-staging-evidence", operation: admission.OperationReadArtifactStagingEvidence, allowUnavailable: true}, privateKey, material.client, "jti-read-artifact-success1")
	artifactResponse := httptest.NewRecorder()
	handler.ServeHTTP(artifactResponse, artifactRequest)
	if artifactResponse.Code != http.StatusOK {
		t.Fatalf("artifact response=%d body=%s", artifactResponse.Code, artifactResponse.Body.String())
	}
	var artifactDocument providerv1.ArtifactStagingEvidence
	if err := jsonDecode(artifactResponse, &artifactDocument); err != nil || artifactDocument.Status != providerv1.ArtifactStaged {
		t.Fatalf("artifact document=%#v decode=%v", artifactDocument, err)
	}

	usageRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1/usage-evidence", operation: admission.OperationReadUsageEvidence, allowUnavailable: true}, privateKey, material.client, "jti-read-usage-success1")
	usageResponse := httptest.NewRecorder()
	handler.ServeHTTP(usageResponse, usageRequest)
	if usageResponse.Code != http.StatusOK {
		t.Fatalf("usage response=%d body=%s", usageResponse.Code, usageResponse.Body.String())
	}
	var usageDocument providerv1.UsageEvidence
	if err := jsonDecode(usageResponse, &usageDocument); err != nil || usageDocument.EvidenceID != "usage-evidence-1" {
		t.Fatalf("usage document=%#v decode=%v", usageDocument, err)
	}

	operationRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true}, privateKey, material.client, "jti-read-operation-success1")
	operationResponse := httptest.NewRecorder()
	handler.ServeHTTP(operationResponse, operationRequest)
	if operationResponse.Code != http.StatusOK {
		t.Fatalf("operation response=%d body=%s", operationResponse.Code, operationResponse.Body.String())
	}
	var operationDocument providerv1.Operation
	if err := jsonDecode(operationResponse, &operationDocument); err != nil || operationDocument.Type != providerv1.OperationArtifactStage {
		t.Fatalf("operation document=%#v decode=%v", operationDocument, err)
	}
}

type transportArtifactApp struct {
	mu            sync.Mutex
	acceptCalls   int
	evidenceCalls int
	operation     artifact.Operation
	evidence      artifact.Evidence
	evidenceErr   error
}

func (a *transportArtifactApp) Accept(_ context.Context, request artifact.Request) (artifact.Reservation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.acceptCalls++
	operation, err := artifact.NewOperation(request, releaseGateTestTime())
	if err != nil {
		return artifact.Reservation{}, err
	}
	a.operation = operation
	return artifact.Reservation{Operation: operation}, nil
}

func (a *transportArtifactApp) GetOperation(_ context.Context, _ string) (artifact.Operation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.operation.Request.OperationID == "" {
		return artifact.Operation{}, artifact.ErrNotFound
	}
	return a.operation.Clone(), nil
}

func (a *transportArtifactApp) GetEvidence(_ context.Context, _ string) (artifact.Evidence, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.evidenceCalls++
	if a.evidenceErr != nil {
		return artifact.Evidence{}, a.evidenceErr
	}
	return a.evidence, nil
}

type transportUsageReader struct {
	evidence usage.Evidence
	err      error
}

func (r *transportUsageReader) GetEvidence(_ context.Context, _ string, _ time.Time) (usage.Evidence, error) {
	if r.err != nil {
		return usage.Evidence{}, r.err
	}
	return r.evidence.Clone(), nil
}

func newArtifactTransportHandler(t *testing.T, identity *clientIdentityAdmission, publicKey ed25519.PublicKey, guard *releaseGateGuard, app ArtifactApplication, usageReader usage.EvidenceReader, operationReader provideroperation.Reader) http.Handler {
	t.Helper()
	gate, err := admission.NewProtectedOperationGate(mustTestTrustedKeySource(t, publicKey), testAdmissionClock{now: releaseGateTestTime()}, guard)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate, ArtifactApplication: app, UsageEvidenceReader: usageReader, OperationReader: operationReader, Now: func() time.Time { return releaseGateTestTime() }})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func validTransportArtifactEvidence() artifact.Evidence {
	now := releaseGateTestTime()
	check := artifact.Check{Status: artifact.CheckPassed, CheckedAt: now}
	return artifact.Evidence{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		ArtifactReference: "artifact-ref:artifact-1", StagingReference: "ref:staging/operation-1", Status: artifact.StatusStaged,
		ContentDigest: "sha256:" + strings.Repeat("a", 64), MediaType: "text/plain", SizeBytes: 10,
		TenantBindingCheck: check, ActiveContentCheck: check, MalwareCheck: check,
		ObservedAt: now, ExpiresAt: now.Add(time.Hour), EvidenceDigest: "sha256:" + strings.Repeat("b", 64),
	}
}

func validTransportArtifactOperation() artifact.Operation {
	now := releaseGateTestTime()
	request := artifact.Request{
		SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, ExpectedGeneration: 1,
		IdempotencyKey: "artifact-idempotency-1", RequestDigest: "sha256:" + strings.Repeat("d", 64), Deadline: now.Add(4 * time.Minute),
		ArtifactReference: "artifact-ref:artifact-1", SourcePath: "/outputs/result.txt", ExpectedDigest: "sha256:" + strings.Repeat("a", 64),
		ExpectedMediaType: "text/plain", MaxBytes: 1024, Retention: time.Minute,
	}
	operation, _ := artifact.NewOperation(request, now)
	return operation
}

func validTransportUsageEvidence() usage.Evidence {
	now := releaseGateTestTime()
	return usage.Evidence{
		EvidenceID: "usage-evidence-1", SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
		Entries:              []usage.Entry{{EntryID: "usage-entry-1", SandboxID: "sandbox-1", OperationID: "operation-1", Meter: usage.MeterExecCount, Quantity: 1, Unit: "count", MeterSource: usage.SourceRuntime, EvidenceReference: "ref:usage/operation-1", OccurredAt: now}},
		ReconciliationStatus: usage.ReconciliationComplete, ObservedAt: now, RetainedUntil: now.Add(time.Hour), EvidenceDigest: "sha256:" + strings.Repeat("c", 64),
	}
}

func jsonDecode(response *httptest.ResponseRecorder, destination any) error {
	return json.Unmarshal(response.Body.Bytes(), destination)
}

type ioNopCloserType struct{ *strings.Reader }

func (ioNopCloserType) Close() error { return nil }

func ioNopCloser(reader *strings.Reader) *ioNopCloserType { return &ioNopCloserType{Reader: reader} }

var _ ArtifactApplication = (*transportArtifactApp)(nil)
var _ usage.EvidenceReader = (*transportUsageReader)(nil)
