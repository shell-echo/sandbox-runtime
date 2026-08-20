package providerapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

func TestProtectedHandlerRejectsMissingContextBeforeGuard(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &testAdmissionGuard{}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: newTestProtectedGate(t, guard)})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://provider.test/v1/sandboxes/sandbox-1/exec", strings.NewReader(`{}`))
	state := verifiedState(t, material.client)
	request.TLS = &state
	request.Header.Set("Authorization", "Bearer invalid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || guard.Calls() != 0 {
		t.Fatalf("missing context response=%d guard_calls=%d body=%s", response.Code, guard.Calls(), response.Body.String())
	}
}

func TestProtectedHandlerAdmitsV2ContextThenStopsBeforeLifecycle(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &testAdmissionGuard{}
	body, requestDigest := testRequestDocument(t)
	contextValue := admission.AdmissionContext{
		ContextContractID:        admission.AdmissionContextContractID,
		ContextDigestProfile:     admission.AdmissionContextDigestProfile,
		ControllerSubject:        testAllowedIdentity,
		ProviderRevisionID:       "provider-revision-1",
		ProviderInstanceAudience: "urn:agent-platform:provider-instance:provider-1",
		TenantID:                 "tenant-1", WorkOrderID: "work-order-1",
		PolicyDigest: testDigest('a'), PolicyDecidedAt: "2026-08-20T00:00:00Z",
		Operation: admission.OperationExec, SandboxID: "sandbox-1", OperationID: "operation-1",
		AttemptID: "attempt-1", FencingToken: 1, DeadlineAt: "2026-08-20T00:05:00Z",
		RequestContractID:    "urn:agent-platform:sandbox-exec-request:v1",
		RequestDigestProfile: admission.DigestProfileRequestExcludingDigest, RequestDigest: requestDigest,
		HTTPTarget: admission.AdmissionTarget{Method: http.MethodPost, Path: "/v1/sandboxes/sandbox-1/exec", NormalizedQuery: []admission.AdmissionQuery{}},
	}
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := admission.NewStaticTrustedKeySource([]admission.StaticTrustedKey{{ID: "test", Algorithm: admission.AlgorithmEdDSA, PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := admission.NewProtectedOperationGate(keys, testAdmissionClock{now: time.Date(2026, 8, 20, 0, 1, 0, 0, time.UTC)}, guard)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"jti": "jti-000000000000", "iss": "agent-platform", "sub": testAllowedIdentity,
		"aud": contextValue.ProviderInstanceAudience, "iat": time.Date(2026, 8, 20, 0, 0, 30, 0, time.UTC).Unix(), "nbf": time.Date(2026, 8, 20, 0, 0, 30, 0, time.UTC).Unix(), "exp": time.Date(2026, 8, 20, 0, 4, 0, 0, time.UTC).Unix(),
		"operation": "exec", "provider_revision_id": contextValue.ProviderRevisionID,
		"sandbox_id": contextValue.SandboxID, "operation_id": contextValue.OperationID, "attempt_id": contextValue.AttemptID,
		"fencing_token": 1, "tenant_id": contextValue.TenantID, "work_order_id": contextValue.WorkOrderID,
		"policy_digest": contextValue.PolicyDigest, "policy_decided_at": contextValue.PolicyDecidedAt,
		"request_contract_id": contextValue.RequestContractID, "request_digest_profile": string(contextValue.RequestDigestProfile), "request_digest": requestDigest,
		"deadline_at": contextValue.DeadlineAt, "admission_context_contract_id": contextValue.ContextContractID,
		"admission_context_digest_profile": contextValue.ContextDigestProfile, "admission_context_digest": contextValue.ContextDigest,
	}
	token := signTestAdmissionToken(t, privateKey, claims)
	verified, err := admission.VerifyCompactJWS(context.Background(), token, keys)
	if err != nil {
		t.Fatalf("verify token error = %v", err)
	}
	binding := contextValue.TokenBinding(testAllowedIdentity)
	clock := testAdmissionClock{now: time.Date(2026, 8, 20, 0, 1, 0, 0, time.UTC)}
	if err := admission.ValidateTokenBinding(verified, binding, clock); err != nil {
		t.Fatalf("validate binding error = %v claims=%#v binding=%#v", err, verified.Claims, binding)
	}
	if err := admission.VerifyRequestDigest(verified.Claims.RequestDigestProfile, verified.Claims.RequestDigest, body); err != nil {
		t.Fatalf("verify request digest error = %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://provider.test/v1/sandboxes/sandbox-1/exec", strings.NewReader(string(body)))
	state := verifiedState(t, material.client)
	request.TLS = &state
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || guard.Calls() != 1 {
		t.Fatalf("admitted response=%d guard_calls=%d body=%s", response.Code, guard.Calls(), response.Body.String())
	}
}

func TestProtectedHandlerRejectsContextSubjectMismatchBeforeGuard(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &testAdmissionGuard{}
	gate := newTestProtectedGate(t, guard)
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	contextValue := validProtectedContextForTest(t, admission.OperationExec, "/v1/sandboxes/sandbox-1/exec", "sandbox-1")
	contextValue.ControllerSubject = "spiffe://controller/other"
	contextValue.ContextDigest = ""
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	request := httptest.NewRequest(http.MethodPost, "https://provider.test/v1/sandboxes/sandbox-1/exec", strings.NewReader(`{"operation":"exec","request_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	state := verifiedState(t, material.client)
	request.TLS = &state
	request.Header.Set("Authorization", "Bearer invalid")
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || guard.Calls() != 0 {
		t.Fatalf("mismatched context response=%d guard_calls=%d body=%s", response.Code, guard.Calls(), response.Body.String())
	}
}

func validProtectedContextForTest(t *testing.T, operation admission.Operation, path, sandboxID string) admission.AdmissionContext {
	t.Helper()
	value := admission.AdmissionContext{
		ContextContractID:        admission.AdmissionContextContractID,
		ContextDigestProfile:     admission.AdmissionContextDigestProfile,
		ControllerSubject:        testAllowedIdentity,
		ProviderRevisionID:       "provider-revision-1",
		ProviderInstanceAudience: "urn:agent-platform:provider-instance:provider-1",
		TenantID:                 "tenant-1", WorkOrderID: "work-order-1",
		PolicyDigest: testDigest('a'), PolicyDecidedAt: "2026-08-20T00:00:00Z",
		Operation: operation, SandboxID: sandboxID, OperationID: "operation-1",
		AttemptID: "attempt-1", FencingToken: 1, DeadlineAt: "2026-08-20T00:05:00Z",
		RequestContractID:    "urn:agent-platform:sandbox-exec-request:v1",
		RequestDigestProfile: admission.DigestProfileRequestExcludingDigest, RequestDigest: testDigest('b'),
		HTTPTarget: admission.AdmissionTarget{Method: http.MethodPost, Path: path, NormalizedQuery: []admission.AdmissionQuery{}},
	}
	digest, err := admission.DigestForAdmissionContext(value)
	if err != nil {
		t.Fatal(err)
	}
	value.ContextDigest = digest
	return value
}

type testAdmissionClock struct{ now time.Time }

func (c testAdmissionClock) Now() time.Time { return c.now }

type testAdmissionGuard struct {
	mu    sync.Mutex
	calls int
}

func (g *testAdmissionGuard) Reserve(_ context.Context, _ admission.MutationGuardRequest) (admission.MutationGuardDecision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	return admission.MutationGuardAccepted, nil
}

func (g *testAdmissionGuard) Calls() int { g.mu.Lock(); defer g.mu.Unlock(); return g.calls }

func newTestProtectedGate(t *testing.T, guard *testAdmissionGuard) *admission.ProtectedOperationGate {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := admission.NewStaticTrustedKeySource([]admission.StaticTrustedKey{{ID: "test", Algorithm: admission.AlgorithmEdDSA, PublicKey: publicKey}})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := admission.NewProtectedOperationGate(keys, testAdmissionClock{now: time.Now().UTC()}, guard)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func testRequestDocument(t *testing.T) ([]byte, string) {
	t.Helper()
	encoded, _ := json.Marshal(map[string]any{"operation": "exec"})
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	requestDigest := "sha256:" + hex.EncodeToString(digest[:])
	body, err := json.Marshal(map[string]any{"operation": "exec", "request_digest": requestDigest})
	if err != nil {
		t.Fatal(err)
	}
	return body, requestDigest
}

func signTestAdmissionToken(t *testing.T, privateKey ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "test", "typ": "agent-sandbox-operation-admission+jwt"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
}

func encodeTestAdmissionContext(t *testing.T, context admission.AdmissionContext) string {
	t.Helper()
	encoded, err := json.Marshal(context)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func testDigest(character rune) string { return "sha256:" + strings.Repeat(string(character), 64) }
