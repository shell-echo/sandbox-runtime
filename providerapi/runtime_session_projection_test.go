package providerapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type runtimeSessionApplicationSpy struct {
	operation sessionapplication.Operation
	handoff   sessionapplication.Handoff
	err       error
	open      session.OpenRequest
	openCalls int
}

func (s *runtimeSessionApplicationSpy) Open(_ context.Context, request session.OpenRequest) (sessionapplication.Operation, error) {
	s.openCalls++
	s.open = request
	if s.err != nil {
		return sessionapplication.Operation{}, s.err
	}
	return s.operation, nil
}

func (s *runtimeSessionApplicationSpy) GetHandoff(context.Context, string) (sessionapplication.Handoff, error) {
	if s.err != nil {
		return sessionapplication.Handoff{}, s.err
	}
	return s.handoff, nil
}

var _ RuntimeSessionApplication = (*runtimeSessionApplicationSpy)(nil)

func TestProtectedRuntimeSessionOpenProjectsAcceptedOperation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &runtimeSessionApplicationSpy{operation: sessionapplication.Operation{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		Status: session.StatusAccepted, ObservedAt: releaseGateTestTime(),
	}}
	handler := newRuntimeSessionHandler(t, material, publicKey, app)
	body, digest := validRuntimeSessionOpenDocument(t)
	request := newRuntimeSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/runtime-sessions", admission.OperationOpenRuntimeSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || app.openCalls != 1 {
		t.Fatalf("response=%d open_calls=%d body=%s", response.Code, app.openCalls, response.Body.String())
	}
	if app.open.SandboxID != "sandbox-1" || app.open.ProviderRevisionID != "provider-revision-1" || app.open.RuntimeType != session.RuntimeTerminal || app.open.ExpiresAt.IsZero() {
		t.Fatalf("open request=%#v", app.open)
	}
	var operation providerv1.Operation
	if err := json.Unmarshal(response.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Type != providerv1.OperationOpenRuntimeSession || operation.Status != providerv1.OperationAccepted {
		t.Fatalf("operation=%#v", operation)
	}
}

func TestProtectedRuntimeSessionOpenRejectsUnknownFieldsBeforeApplication(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &runtimeSessionApplicationSpy{operation: sessionapplication.Operation{OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", Status: session.StatusAccepted, ObservedAt: releaseGateTestTime()}}
	handler := newRuntimeSessionHandler(t, material, publicKey, app)
	body, _ := validRuntimeSessionOpenDocument(t)
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	document["scopes"] = []string{"terminal.write"}
	delete(document, "request_digest")
	withoutDigest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := runtimeRequestDigest(t, withoutDigest)
	document["request_digest"] = digest
	body, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request := newRuntimeSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/runtime-sessions", admission.OperationOpenRuntimeSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || app.openCalls != 0 {
		t.Fatalf("response=%d open_calls=%d body=%s", response.Code, app.openCalls, response.Body.String())
	}
}

func TestProtectedRuntimeSessionHandoffProjectsOpaqueDocument(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &runtimeSessionApplicationSpy{handoff: sessionapplication.Handoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", RuntimeSessionID: "session-1",
		RuntimeType: session.RuntimeTerminal, CapabilityProfileID: "terminal-v1", Protocol: session.ProtocolWebSocket,
		InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1, ExpiresAt: releaseGateTestTime().Add(time.Minute),
	}}
	handler := newRuntimeSessionHandler(t, material, publicKey, app)
	request := newRuntimeSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/runtime-session", admission.OperationReadRuntimeSession, nil, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
	var handoff providerv1.RuntimeSessionHandoff
	if err := json.Unmarshal(response.Body.Bytes(), &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff.InternalEndpointReference != "ref:session:opaque-1" || handoff.Protocol != providerv1.TerminalProtocolWebSocket {
		t.Fatalf("handoff=%#v", handoff)
	}
	for _, forbidden := range []string{"wss://", "127.0.0.1", "10.0.0.1", "8443", "container-id", "pod-name", "host-path", "credential", "provider_access_token"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("handoff contains forbidden detail %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestProtectedRuntimeSessionHandoffMapsTerminalStates(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{name: "pending", err: sessionapplication.ErrHandoffPending, status: http.StatusServiceUnavailable, code: "SANDBOX_RUNTIME_SESSION_PENDING", retryable: true},
		{name: "expired", err: session.ErrHandoffExpired, status: http.StatusGone, code: "SANDBOX_RUNTIME_SESSION_EXPIRED"},
		{name: "unknown outcome", err: session.ErrHandoffUnavailable, status: http.StatusNotFound, code: "SANDBOX_RUNTIME_SESSION_UNAVAILABLE"},
		{name: "missing", err: session.ErrNotFound, status: http.StatusNotFound, code: "SANDBOX_NOT_FOUND"},
	}
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := &runtimeSessionApplicationSpy{err: test.err}
			handler := newRuntimeSessionHandler(t, material, publicKey, app)
			request := newRuntimeSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/runtime-session", admission.OperationReadRuntimeSession, nil, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			var standard providerv1.StandardError
			if err := json.Unmarshal(response.Body.Bytes(), &standard); err != nil {
				t.Fatal(err)
			}
			if standard.Code != test.code || standard.Retryable != test.retryable {
				t.Fatalf("error=%#v", standard)
			}
		})
	}
}

func TestProtectedRuntimeSessionRouteRequiresMatchingAdmissionOperation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &runtimeSessionApplicationSpy{}
	handler := newRuntimeSessionHandler(t, material, publicKey, app)
	request := newRuntimeSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/runtime-session", admission.OperationReadRuntimeSession, nil, "")
	contextValue := admissionContextFromReleaseRequest(t, request)
	contextValue.Operation = admission.OperationReadOperation
	contextValue.RequestContractID, contextValue.RequestDigestProfile = protectedReleaseRequestBinding(admission.OperationReadOperation)
	contextValue.HTTPTarget.Path = "/v1/operations/operation-1"
	contextValue.ContextDigest = ""
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, admissionTokenClaimsForTest(contextValue)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || app.openCalls != 0 {
		t.Fatalf("response=%d open_calls=%d body=%s", response.Code, app.openCalls, response.Body.String())
	}
}

func newRuntimeSessionHandler(t *testing.T, material testMTLSMaterial, publicKey ed25519.PublicKey, app RuntimeSessionApplication) http.Handler {
	t.Helper()
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	gate := newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{})
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: gate, SessionApplication: app, Now: func() time.Time { return releaseGateTestTime() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func validRuntimeSessionOpenDocument(t *testing.T) ([]byte, string) {
	t.Helper()
	withoutDigest := map[string]any{
		"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": 1, "idempotency_key": "session-open-1",
		"deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano), "expected_generation": 1,
		"runtime_session_id": "session-1", "runtime_type": "terminal", "capability_profile_id": "terminal-v1",
		"expires_at": releaseGateTestTime().Add(3 * time.Minute).Format(time.RFC3339Nano),
	}
	encoded, err := json.Marshal(withoutDigest)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(encoded)
	if err != nil {
		t.Fatal(err)
	}
	digest := releaseCanonicalDigest(canonical)
	withDigest := withoutDigest
	withDigest["request_digest"] = digest
	body, err := json.Marshal(withDigest)
	if err != nil {
		t.Fatal(err)
	}
	return body, digest
}

func newRuntimeSessionRequest(t *testing.T, certificate tls.Certificate, privateKey ed25519.PrivateKey, method, path string, operation admission.Operation, body []byte, digest string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://provider.test"+path, bytes.NewReader(body))
	if method == http.MethodGet {
		request = httptest.NewRequest(method, "https://provider.test"+path, nil)
	}
	values := strings.Split(strings.Trim(path, "/"), "/")
	pathValues := map[string]string{}
	if operation == admission.OperationOpenRuntimeSession {
		pathValues["sandbox_id"] = values[2]
	} else {
		pathValues["operation_id"] = values[2]
	}
	contextValue := newProtectedReleaseContext(protectedReleaseRoute{method: method, path: path, operation: operation, allowUnavailable: true})
	if method == http.MethodGet {
		document, status := readDescriptor(contextValue, request, pathValues)
		if status != 0 {
			t.Fatalf("read descriptor status=%d", status)
		}
		digest = releaseFullDocumentDigest(t, document)
	}
	contextValue.RequestDigest = digest
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	state := verifiedState(t, certificate)
	request.TLS = &state
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, admissionTokenClaimsForTest(contextValue)))
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	return request
}

func runtimeRequestDigest(t *testing.T, body []byte) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "request_digest")
	withoutDigest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(withoutDigest)
	if err != nil {
		t.Fatal(err)
	}
	return releaseCanonicalDigest(canonical)
}
