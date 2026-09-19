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
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type desktopSessionApplicationSpy struct {
	operation      desktopapplication.Operation
	handoff        desktopapplication.Handoff
	openErr        error
	handoffErr     error
	operationErr   error
	open           desktop.OpenRequest
	close          desktop.CloseRequest
	handoffID      string
	operationID    string
	openCalls      int
	closeCalls     int
	handoffCalls   int
	operationCalls int
}

func (s *desktopSessionApplicationSpy) Open(_ context.Context, request desktop.OpenRequest) (desktopapplication.Operation, error) {
	s.openCalls++
	s.open = request
	return s.operation, s.openErr
}

func (s *desktopSessionApplicationSpy) CloseDesktopSession(_ context.Context, request desktop.CloseRequest) (desktopapplication.Operation, error) {
	s.closeCalls++
	s.close = request
	return s.operation, s.openErr
}

func (s *desktopSessionApplicationSpy) GetHandoff(_ context.Context, operationID string) (desktopapplication.Handoff, error) {
	s.handoffCalls++
	s.handoffID = operationID
	return s.handoff, s.handoffErr
}

func (s *desktopSessionApplicationSpy) GetOperation(_ context.Context, operationID string) (desktopapplication.Operation, error) {
	s.operationCalls++
	s.operationID = operationID
	return s.operation, s.operationErr
}

var _ DesktopApplication = (*desktopSessionApplicationSpy)(nil)

func TestProtectedDesktopRoutesFailClosedWithoutApplication(t *testing.T) {
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
		{name: "open", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/desktop-sessions", operation: admission.OperationOpenDesktopSession, allowUnavailable: true},
		{name: "close", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/desktop-sessions/desktop-session-1:close", operation: admission.OperationCloseDesktopSession, allowUnavailable: true},
		{name: "handoff", method: http.MethodGet, path: "/v1/operations/operation-1/desktop-session", operation: admission.OperationReadDesktopSession, allowUnavailable: true},
	} {
		t.Run(route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-desktop-nil-0001")
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

func TestProtectedDesktopCloseProjectsAcceptedOperation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := validDesktopApplicationOperation()
	operation.Type = desktopapplication.OperationCloseDesktopSession
	app := &desktopSessionApplicationSpy{operation: operation}
	handler, guard := newDesktopSessionHandler(t, material, publicKey, app)
	body, digest := validDesktopSessionCloseDocument(t)
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/desktop-sessions/desktop-session-1:close", admission.OperationCloseDesktopSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || guard.Calls() != 1 || app.closeCalls != 1 {
		t.Fatalf("response=%d guard_calls=%d close_calls=%d body=%s", response.Code, guard.Calls(), app.closeCalls, response.Body.String())
	}
	if app.close.DesktopSessionID != "desktop-session-1" || app.close.ConnectionGeneration != 1 || app.close.ProviderRevisionID != "provider-revision-1" {
		t.Fatalf("close request=%#v", app.close)
	}
	var projected providerv1.Operation
	if err := json.Unmarshal(response.Body.Bytes(), &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Type != providerv1.OperationCloseDesktopSession {
		t.Fatalf("operation=%#v", projected)
	}
}

func TestProtectedDesktopOpenProjectsAcceptedOperation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &desktopSessionApplicationSpy{operation: validDesktopApplicationOperation()}
	handler, guard := newDesktopSessionHandler(t, material, publicKey, app)
	body, digest := validDesktopSessionOpenDocument(t)
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/desktop-sessions", admission.OperationOpenDesktopSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || guard.Calls() != 1 || app.openCalls != 1 {
		t.Fatalf("response=%d guard_calls=%d open_calls=%d body=%s", response.Code, guard.Calls(), app.openCalls, response.Body.String())
	}
	if app.open.SandboxID != "sandbox-1" || app.open.ProviderRevisionID != "provider-revision-1" ||
		app.open.DesktopSessionID != "desktop-session-1" || app.open.CapabilityProfileID != desktop.CapabilityProfileID || app.open.ExpiresAt.IsZero() {
		t.Fatalf("open request=%#v", app.open)
	}
	var operation providerv1.Operation
	if err := json.Unmarshal(response.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Type != providerv1.OperationOpenDesktopSession || operation.Status != providerv1.OperationAccepted || operation.ProviderOperationID != "operation-1" {
		t.Fatalf("operation=%#v", operation)
	}
}

func TestProtectedDesktopOpenRejectsUnknownFieldsBeforeGuardAndApplication(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &desktopSessionApplicationSpy{operation: validDesktopApplicationOperation()}
	handler, guard := newDesktopSessionHandler(t, material, publicKey, app)
	body, _ := validDesktopSessionOpenDocument(t)
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
	digest := desktopRequestDigest(t, withoutDigest)
	document["request_digest"] = digest
	body, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/desktop-sessions", admission.OperationOpenDesktopSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || guard.Calls() != 0 || app.openCalls != 0 {
		t.Fatalf("response=%d guard_calls=%d open_calls=%d body=%s", response.Code, guard.Calls(), app.openCalls, response.Body.String())
	}
}

func TestProtectedDesktopOpenStopsAtAdmissionFailure(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &desktopSessionApplicationSpy{operation: validDesktopApplicationOperation()}
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardStaleFencing}
	gate := newDesktopProtectedGate(t, publicKey, guard)
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate, DesktopApplication: app, Now: releaseGateTestTime})
	if err != nil {
		t.Fatal(err)
	}
	body, digest := validDesktopSessionOpenDocument(t)
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/desktop-sessions", admission.OperationOpenDesktopSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || guard.Calls() != 1 || app.openCalls != 0 {
		t.Fatalf("response=%d guard_calls=%d open_calls=%d body=%s", response.Code, guard.Calls(), app.openCalls, response.Body.String())
	}
}

func TestProtectedDesktopOpenRejectsApplicationIdentityDrift(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	operation := validDesktopApplicationOperation()
	operation.SandboxID = "other-sandbox"
	app := &desktopSessionApplicationSpy{operation: operation}
	handler, _ := newDesktopSessionHandler(t, material, publicKey, app)
	body, digest := validDesktopSessionOpenDocument(t)
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/desktop-sessions", admission.OperationOpenDesktopSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SANDBOX_PROVIDER_UNAVAILABLE") {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestProtectedDesktopErrorsDoNotDiscloseBackendDetails(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &desktopSessionApplicationSpy{openErr: errors.New("dial 10.0.0.7:5900 with credential super-secret failed")}
	handler, _ := newDesktopSessionHandler(t, material, publicKey, app)
	body, digest := validDesktopSessionOpenDocument(t)
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodPost, "/v1/sandboxes/sandbox-1/desktop-sessions", admission.OperationOpenDesktopSession, body, digest)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SANDBOX_PROVIDER_UNAVAILABLE") {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"10.0.0.7", "5900", "credential", "super-secret", "dial"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("safe error disclosed %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestProtectedDesktopHandoffProjectsOnlyOpaqueDocument(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &desktopSessionApplicationSpy{handoff: validDesktopApplicationHandoff()}
	handler, guard := newDesktopSessionHandler(t, material, publicKey, app)
	request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/desktop-session", admission.OperationReadDesktopSession, nil, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || guard.Calls() != 0 || app.handoffCalls != 1 || app.handoffID != "operation-1" {
		t.Fatalf("response=%d guard_calls=%d handoff_calls=%d handoff_id=%q body=%s", response.Code, guard.Calls(), app.handoffCalls, app.handoffID, response.Body.String())
	}
	var handoff providerv1.DesktopSessionHandoff
	if err := json.Unmarshal(response.Body.Bytes(), &handoff); err != nil {
		t.Fatal(err)
	}
	if handoff.InternalEndpointReference != "ref:desktop-session:opaque-1" || handoff.Protocol != providerv1.DesktopProtocolWebRTC ||
		handoff.MediaProfileID != desktop.MediaProfileID || handoff.ControlProfileID != desktop.ControlProfileID || handoff.ConnectionGeneration != 1 {
		t.Fatalf("handoff=%#v", handoff)
	}
	for _, forbidden := range []string{"ws://", "wss://", "127.0.0.1", "10.0.0.1", "9222", "container-id", "pod-name", "host-path", "credential", "provider_access_token", "devtools/desktop"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("handoff contains forbidden detail %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestProtectedDesktopHandoffMapsReadStates(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{name: "pending", err: desktopapplication.ErrHandoffPending, status: http.StatusServiceUnavailable, code: "SANDBOX_DESKTOP_SESSION_PENDING", retryable: true},
		{name: "expired", err: desktop.ErrHandoffExpired, status: http.StatusGone, code: "SANDBOX_DESKTOP_SESSION_EXPIRED"},
		{name: "revoked", err: desktop.ErrHandoffRevoked, status: http.StatusGone, code: "SANDBOX_DESKTOP_SESSION_REVOKED"},
		{name: "unavailable", err: desktop.ErrHandoffUnavailable, status: http.StatusNotFound, code: "SANDBOX_DESKTOP_SESSION_UNAVAILABLE"},
		{name: "missing", err: desktoprepository.ErrNotFound, status: http.StatusNotFound, code: "SANDBOX_NOT_FOUND"},
		{name: "durability", err: desktoprepository.ErrDurability, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE", retryable: true},
	}
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app := &desktopSessionApplicationSpy{handoffErr: test.err}
			handler, _ := newDesktopSessionHandler(t, material, publicKey, app)
			request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/desktop-session", admission.OperationReadDesktopSession, nil, "")
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

func TestProtectedDesktopHandoffRejectsExpiryAndIdentityDrift(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*desktopapplication.Handoff)
		status int
		code   string
	}{
		{name: "expired", mutate: func(h *desktopapplication.Handoff) { h.ExpiresAt = releaseGateTestTime() }, status: http.StatusGone, code: "SANDBOX_DESKTOP_SESSION_EXPIRED"},
		{name: "operation drift", mutate: func(h *desktopapplication.Handoff) { h.OperationID = "other-operation" }, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE"},
		{name: "sandbox drift", mutate: func(h *desktopapplication.Handoff) { h.SandboxID = "other-sandbox" }, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handoff := validDesktopApplicationHandoff()
			test.mutate(&handoff)
			app := &desktopSessionApplicationSpy{handoff: handoff}
			handler, _ := newDesktopSessionHandler(t, material, publicKey, app)
			request := newDesktopSessionRequest(t, material.client, privateKey, http.MethodGet, "/v1/operations/operation-1/desktop-session", admission.OperationReadDesktopSession, nil, "")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestProtectedOperationReadAggregatesDesktopFamily(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &desktopSessionApplicationSpy{operation: validDesktopApplicationOperation()}
	desktopReader, err := provideroperation.NewDesktopSessionReader(app)
	if err != nil {
		t.Fatal(err)
	}
	aggregator, err := provideroperation.NewAggregator(desktopReader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{}), Application: operationReadAuthorizationApplication(), DesktopApplication: app,
		OperationReader: aggregator, Now: releaseGateTestTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	route := protectedReleaseRoute{name: "read desktop operation", method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true}
	request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-desktop-operation-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || app.operationCalls != 1 || app.operationID != "operation-1" {
		t.Fatalf("response=%d operation_calls=%d operation_id=%q body=%s", response.Code, app.operationCalls, app.operationID, response.Body.String())
	}
	var operation providerv1.Operation
	if err := json.Unmarshal(response.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Type != providerv1.OperationOpenDesktopSession || operation.Status != providerv1.OperationAccepted {
		t.Fatalf("operation=%#v", operation)
	}
}

func TestMapDesktopSessionOpenErrors(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		status    int
		code      string
		retryable bool
	}{
		{name: "idempotency", err: desktoprepository.ErrIdempotencyConflict, status: http.StatusConflict, code: "SANDBOX_IDEMPOTENCY_CONFLICT"},
		{name: "generation", err: desktop.ErrGenerationConflict, status: http.StatusConflict, code: "SANDBOX_GENERATION_CONFLICT"},
		{name: "fencing", err: desktop.ErrStaleFencingToken, status: http.StatusConflict, code: "SANDBOX_STALE_FENCING_TOKEN"},
		{name: "revision", err: desktop.ErrProviderRevisionConflict, status: http.StatusConflict, code: "SANDBOX_PROVIDER_REVISION_CONFLICT"},
		{name: "network policy", err: desktop.ErrNetworkPolicyConflict, status: http.StatusConflict, code: "SANDBOX_CONFLICT"},
		{name: "capability", err: desktop.ErrCapabilityUnsupported, status: http.StatusUnprocessableEntity, code: "SANDBOX_CAPABILITY_UNSUPPORTED"},
		{name: "capacity", err: desktop.ErrDesktopCapacity, status: http.StatusTooManyRequests, code: "SANDBOX_CAPACITY_EXHAUSTED", retryable: true},
		{name: "invalid", err: desktop.ErrInvalidRequest, status: http.StatusBadRequest, code: "SANDBOX_INVALID_REQUEST"},
		{name: "canceled", err: context.Canceled, status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE", retryable: true},
		{name: "unknown", err: errors.New("unknown"), status: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE", retryable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, code, retryable := mapDesktopSessionError(test.err)
			if status != test.status || code != test.code || retryable != test.retryable {
				t.Fatalf("map=(%d,%q,%t) want=(%d,%q,%t)", status, code, retryable, test.status, test.code, test.retryable)
			}
		})
	}
}

func newDesktopSessionHandler(t *testing.T, material testMTLSMaterial, publicKey ed25519.PublicKey, app DesktopApplication) (http.Handler, *releaseGateGuard) {
	t.Helper()
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
	gate := newDesktopProtectedGate(t, publicKey, guard)
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate, DesktopApplication: app, Now: releaseGateTestTime})
	if err != nil {
		t.Fatal(err)
	}
	return handler, guard
}

func validDesktopSessionOpenDocument(t *testing.T) ([]byte, string) {
	t.Helper()
	withoutDigest := map[string]any{
		"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": int64(1), "idempotency_key": "desktop-open-1",
		"deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano), "expected_generation": int64(1),
		"desktop_session_id": "desktop-session-1", "capability_profile_id": desktop.CapabilityProfileID,
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

func newDesktopSessionRequest(t *testing.T, certificate tls.Certificate, privateKey ed25519.PrivateKey, method, path string, operation admission.Operation, body []byte, digest string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, "https://provider.test"+path, bytes.NewReader(body))
	if method == http.MethodGet {
		request = httptest.NewRequest(method, "https://provider.test"+path, nil)
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	pathValues := map[string]string{}
	if operation == admission.OperationOpenDesktopSession || operation == admission.OperationCloseDesktopSession {
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

func validDesktopSessionCloseDocument(t *testing.T) ([]byte, string) {
	t.Helper()
	withoutDigest := map[string]any{
		"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": int64(1),
		"idempotency_key": "desktop-close-1", "deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano),
		"expected_generation": int64(1), "desktop_session_id": "desktop-session-1", "connection_generation": int64(1),
		"reason": "caller_complete",
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

func desktopRequestDigest(t *testing.T, body []byte) string {
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

func validDesktopApplicationOperation() desktopapplication.Operation {
	return desktopapplication.Operation{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		Status: desktop.StatusAccepted, ObservedAt: releaseGateTestTime(), Type: desktopapplication.OperationOpenDesktopSession,
	}
}

func validDesktopApplicationHandoff() desktopapplication.Handoff {
	return desktopapplication.Handoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		DesktopSessionID: "desktop-session-1", CapabilityProfileID: desktop.CapabilityProfileID,
		Protocol: desktop.ProtocolWebRTC, MediaProfileID: desktop.MediaProfileID, ControlProfileID: desktop.ControlProfileID,
		InternalEndpointReference: "ref:desktop-session:opaque-1",
		ConnectionGeneration:      1, ExpiresAt: releaseGateTestTime().Add(time.Minute),
	}
}

func newDesktopProtectedGate(t *testing.T, publicKey ed25519.PublicKey, guard admission.MutationGuard) *admission.ProtectedOperationGate {
	t.Helper()
	gate, err := admission.NewProtectedOperationGate(mustTestTrustedKeySource(t, publicKey), mustTestAdmissionAuthority(t), testAdmissionClock{now: releaseGateTestTime()}, guard)
	if err != nil {
		t.Fatal(err)
	}
	return gate
}
