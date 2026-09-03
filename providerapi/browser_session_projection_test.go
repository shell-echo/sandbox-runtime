package providerapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserrepository "github.com/shell-echo/sandbox-runtime/provider/browser/repository"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type browserSessionApplicationSpy struct {
	operation      browserapplication.Operation
	handoff        browserapplication.Handoff
	openErr        error
	handoffErr     error
	operationErr   error
	open           browser.OpenRequest
	handoffID      string
	operationID    string
	openCalls      int
	handoffCalls   int
	operationCalls int
}

func (s *browserSessionApplicationSpy) Open(_ context.Context, request browser.OpenRequest) (browserapplication.Operation, error) {
	s.openCalls++
	s.open = request
	return s.operation, s.openErr
}

func (s *browserSessionApplicationSpy) GetHandoff(_ context.Context, operationID string) (browserapplication.Handoff, error) {
	s.handoffCalls++
	s.handoffID = operationID
	return s.handoff, s.handoffErr
}

func (s *browserSessionApplicationSpy) GetOperation(_ context.Context, operationID string) (browserapplication.Operation, error) {
	s.operationCalls++
	s.operationID = operationID
	return s.operation, s.operationErr
}

var _ BrowserApplication = (*browserSessionApplicationSpy)(nil)

func TestProtectedBrowserRoutesFailClosedWithoutApplication(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []protectedReleaseRoute{
		{name: "open", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/browser-sessions", operation: admission.OperationOpenBrowserSession, allowUnavailable: true},
		{name: "handoff", method: http.MethodGet, path: "/v1/operations/operation-1/browser-session", operation: admission.OperationReadBrowserSession, allowUnavailable: true},
	} {
		t.Run(route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-browser-nil-0001")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
			}
			wantGuardCalls := 0
			if route.operation.Mutation() {
				wantGuardCalls = 1
			}
			if guard.Calls() != wantGuardCalls {
				t.Fatalf("guard calls=%d want=%d", guard.Calls(), wantGuardCalls)
			}
		})
	}
}

func TestProtectedBrowserOpenProjectsAcceptedOperation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &browserSessionApplicationSpy{operation: validBrowserApplicationOperation()}
	handler, guard := newBrowserSessionHandler(t, material, publicKey, app)
	body, digest := validBrowserSessionOpenDocument(t)
	request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/browser-sessions", admission.OperationOpenBrowserSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || guard.Calls() != 1 || app.openCalls != 1 {
		t.Fatalf("response=%d guard_calls=%d open_calls=%d body=%s", response.Code, guard.Calls(), app.openCalls, response.Body.String())
	}
	if app.open.SandboxID != "sandbox-1" || app.open.ProviderRevisionID != "provider-revision-1" ||
		app.open.BrowserSessionID != "browser-session-1" || app.open.CapabilityProfileID != browser.CapabilityProfileID || app.open.ExpiresAt.IsZero() {
		t.Fatalf("open request=%#v", app.open)
	}
	var operation providerv1.Operation
	if err := json.Unmarshal(response.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Type != providerv1.OperationOpenBrowserSession || operation.Status != providerv1.OperationAccepted || operation.ProviderOperationID != "operation-1" {
		t.Fatalf("operation=%#v", operation)
	}
}

func TestProtectedBrowserOpenRejectsUnknownFieldsBeforeGuardAndApplication(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &browserSessionApplicationSpy{operation: validBrowserApplicationOperation()}
	handler, guard := newBrowserSessionHandler(t, material, publicKey, app)
	body, _ := validBrowserSessionOpenDocument(t)
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	document["initial_url"] = "https://example.invalid"
	delete(document, "request_digest")
	withoutDigest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := browserRequestDigest(t, withoutDigest)
	document["request_digest"] = digest
	body, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/browser-sessions", admission.OperationOpenBrowserSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || guard.Calls() != 0 || app.openCalls != 0 {
		t.Fatalf("response=%d guard_calls=%d open_calls=%d body=%s", response.Code, guard.Calls(), app.openCalls, response.Body.String())
	}
}

func TestProtectedBrowserOpenStopsAtAdmissionFailure(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &browserSessionApplicationSpy{operation: validBrowserApplicationOperation()}
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardStaleFencing}
	gate := newBrowserProtectedGate(t, publicKey, guard)
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate, BrowserApplication: app, Now: releaseGateTestTime})
	if err != nil {
		t.Fatal(err)
	}
	body, digest := validBrowserSessionOpenDocument(t)
	request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/browser-sessions", admission.OperationOpenBrowserSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || guard.Calls() != 1 || app.openCalls != 0 {
		t.Fatalf("response=%d guard_calls=%d open_calls=%d body=%s", response.Code, guard.Calls(), app.openCalls, response.Body.String())
	}
}

func TestProtectedBrowserOpenRejectsApplicationIdentityDrift(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := validBrowserApplicationOperation()
	operation.SandboxID = "other-sandbox"
	app := &browserSessionApplicationSpy{operation: operation}
	handler, _ := newBrowserSessionHandler(t, material, publicKey, app)
	body, digest := validBrowserSessionOpenDocument(t)
	request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/browser-sessions", admission.OperationOpenBrowserSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SANDBOX_PROVIDER_UNAVAILABLE") {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestProtectedBrowserHandoffProjectsOnlyOpaqueDocument(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &browserSessionApplicationSpy{handoff: validBrowserApplicationHandoff()}
	handler, guard := newBrowserSessionHandler(t, material, publicKey, app)
	request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/browser-session", admission.OperationReadBrowserSession, nil, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || guard.Calls() != 0 || app.handoffCalls != 1 || app.handoffID != "operation-1" {
		t.Fatalf("response=%d guard_calls=%d handoff_calls=%d handoff_id=%q body=%s", response.Code, guard.Calls(), app.handoffCalls, app.handoffID, response.Body.String())
	}
	var handoff providerv1.BrowserSessionHandoff
	if err := json.Unmarshal(response.Body.Bytes(), &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff.InternalEndpointReference != "ref:browser-session:opaque-1" || handoff.Protocol != providerv1.BrowserProtocolWebSocket || handoff.ConnectionGeneration != 1 {
		t.Fatalf("handoff=%#v", handoff)
	}
	for _, forbidden := range []string{"ws://", "wss://", "127.0.0.1", "10.0.0.1", "9222", "container-id", "pod-name", "host-path", "credential", "provider_access_token", "devtools/browser"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("handoff contains forbidden detail %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestProtectedBrowserHandoffMapsReadStates(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{name: "pending", err: browserapplication.ErrHandoffPending, status: http.StatusServiceUnavailable, code: "SANDBOX_BROWSER_SESSION_PENDING", retryable: true},
		{name: "expired", err: browser.ErrHandoffExpired, status: http.StatusGone, code: "SANDBOX_BROWSER_SESSION_EXPIRED"},
		{name: "unavailable", err: browser.ErrHandoffUnavailable, status: http.StatusNotFound, code: "SANDBOX_BROWSER_SESSION_UNAVAILABLE"},
		{name: "missing", err: browserrepository.ErrNotFound, status: http.StatusNotFound, code: "SANDBOX_NOT_FOUND"},
		{name: "durability", err: browserrepository.ErrDurability, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE", retryable: true},
	}
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := &browserSessionApplicationSpy{handoffErr: test.err}
			handler, _ := newBrowserSessionHandler(t, material, publicKey, app)
			request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/browser-session", admission.OperationReadBrowserSession, nil, "")
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

func TestProtectedBrowserHandoffRejectsExpiryAndIdentityDrift(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*browserapplication.Handoff)
		status int
		code   string
	}{
		{name: "expired", mutate: func(h *browserapplication.Handoff) { h.ExpiresAt = releaseGateTestTime() }, status: http.StatusGone, code: "SANDBOX_BROWSER_SESSION_EXPIRED"},
		{name: "operation drift", mutate: func(h *browserapplication.Handoff) { h.OperationID = "other-operation" }, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE"},
		{name: "sandbox drift", mutate: func(h *browserapplication.Handoff) { h.SandboxID = "other-sandbox" }, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handoff := validBrowserApplicationHandoff()
			test.mutate(&handoff)
			app := &browserSessionApplicationSpy{handoff: handoff}
			handler, _ := newBrowserSessionHandler(t, material, publicKey, app)
			request := newBrowserSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/browser-session", admission.OperationReadBrowserSession, nil, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestProtectedOperationReadAggregatesBrowserFamily(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &browserSessionApplicationSpy{operation: validBrowserApplicationOperation()}
	browserReader, err := provideroperation.NewBrowserSessionReader(app)
	if err != nil {
		t.Fatal(err)
	}
	aggregator, err := provideroperation.NewAggregator(browserReader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{}), BrowserApplication: app,
		OperationReader: aggregator, Now: releaseGateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	route := protectedReleaseRoute{name: "read browser operation", method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true}
	request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-browser-operation-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || app.operationCalls != 1 || app.operationID != "operation-1" {
		t.Fatalf("response=%d operation_calls=%d operation_id=%q body=%s", response.Code, app.operationCalls, app.operationID, response.Body.String())
	}
	var operation providerv1.Operation
	if err := json.Unmarshal(response.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Type != providerv1.OperationOpenBrowserSession || operation.Status != providerv1.OperationAccepted {
		t.Fatalf("operation=%#v", operation)
	}
}

func TestMapBrowserSessionOpenErrors(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{name: "idempotency", err: browserrepository.ErrIdempotencyConflict, status: http.StatusConflict, code: "SANDBOX_IDEMPOTENCY_CONFLICT"},
		{name: "generation", err: browser.ErrGenerationConflict, status: http.StatusConflict, code: "SANDBOX_GENERATION_CONFLICT"},
		{name: "fencing", err: browser.ErrStaleFencingToken, status: http.StatusConflict, code: "SANDBOX_STALE_FENCING_TOKEN"},
		{name: "revision", err: browser.ErrProviderRevisionConflict, status: http.StatusConflict, code: "SANDBOX_PROVIDER_REVISION_CONFLICT"},
		{name: "network policy", err: browser.ErrNetworkPolicyConflict, status: http.StatusConflict, code: "SANDBOX_CONFLICT"},
		{name: "capability", err: browser.ErrCapabilityUnsupported, status: http.StatusUnprocessableEntity, code: "SANDBOX_CAPABILITY_UNSUPPORTED"},
		{name: "invalid", err: browser.ErrInvalidRequest, status: http.StatusBadRequest, code: "SANDBOX_INVALID_REQUEST"},
		{name: "canceled", err: context.Canceled, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE", retryable: true},
		{name: "unknown", err: errors.New("unknown"), status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE", retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, code, retryable := mapBrowserSessionError(test.err)
			if status != test.status || code != test.code || retryable != test.retryable {
				t.Fatalf("map=(%d,%q,%t) want=(%d,%q,%t)", status, code, retryable, test.status, test.code, test.retryable)
			}
		})
	}
}

func newBrowserSessionHandler(t *testing.T, material testMTLSMaterial, publicKey ed25519.PublicKey, app BrowserApplication) (http.Handler, *releaseGateGuard) {
	t.Helper()
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
	gate := newBrowserProtectedGate(t, publicKey, guard)
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate, BrowserApplication: app, Now: releaseGateTestTime})
	if err != nil {
		t.Fatal(err)
	}
	return handler, guard
}

func validBrowserSessionOpenDocument(t *testing.T) ([]byte, string) {
	t.Helper()
	withoutDigest := map[string]any{
		"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": int64(1), "idempotency_key": "browser-open-1",
		"deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano), "expected_generation": int64(1),
		"browser_session_id": "browser-session-1", "capability_profile_id": browser.CapabilityProfileID,
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
	withoutDigest["request_digest"] = digest
	body, err := json.Marshal(withoutDigest)
	if err != nil {
		t.Fatal(err)
	}
	return body, digest
}

func newBrowserSessionRequest(t *testing.T, certificate tls.Certificate, privateKey ed25519.PrivateKey, method, path string, operation admission.Operation, body []byte, digest string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://provider.test"+path, bytes.NewReader(body))
	if method == http.MethodGet {
		request = httptest.NewRequest(method, "https://provider.test"+path, nil)
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	pathValues := map[string]string{}
	if operation == admission.OperationOpenBrowserSession {
		pathValues["sandbox_id"] = parts[2]
	} else {
		pathValues["operation_id"] = parts[2]
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

func browserRequestDigest(t *testing.T, body []byte) string {
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

func validBrowserApplicationOperation() browserapplication.Operation {
	return browserapplication.Operation{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		Status: browser.StatusAccepted, ObservedAt: releaseGateTestTime(),
	}
}

func validBrowserApplicationHandoff() browserapplication.Handoff {
	return browserapplication.Handoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		BrowserSessionID: "browser-session-1", CapabilityProfileID: browser.CapabilityProfileID,
		Protocol: browser.ProtocolWebSocket, InternalEndpointReference: "ref:browser-session:opaque-1",
		ConnectionGeneration: 1, ExpiresAt: releaseGateTestTime().Add(time.Minute),
	}
}

func newBrowserProtectedGate(t *testing.T, publicKey ed25519.PublicKey, guard admission.MutationGuard) *admission.ProtectedOperationGate {
	t.Helper()
	gate, err := admission.NewProtectedOperationGate(mustTestTrustedKeySource(t, publicKey), testAdmissionClock{now: releaseGateTestTime()}, guard)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}
