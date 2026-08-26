package providerapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const releaseGateTestTimeUnix = int64(1_787_184_060)

type protectedReleaseRoute struct {
	name             string
	method           string
	path             string
	query            string
	operation        admission.Operation
	allowUnavailable bool
}

func allProtectedReleaseRoutes() []protectedReleaseRoute {
	return []protectedReleaseRoute{
		{name: "create sandbox", method: http.MethodPost, path: "/v1/sandboxes", operation: admission.OperationCreate, allowUnavailable: true},
		{name: "restore sandbox", method: http.MethodPost, path: "/v1/sandboxes:restore", operation: admission.OperationRestore, allowUnavailable: true},
		{name: "read sandbox", method: http.MethodGet, path: "/v1/sandboxes/sandbox-1", operation: admission.OperationReadSandbox, allowUnavailable: true},
		{name: "set desired state", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/desired-state", operation: admission.OperationSetDesiredState, allowUnavailable: true},
		{name: "extend lease", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/lease", operation: admission.OperationExtendLease, allowUnavailable: true},
		{name: "execute", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec", operation: admission.OperationExec, allowUnavailable: true},
		{name: "cancel execute", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec:cancel", operation: admission.OperationCancelExec},
		{name: "open runtime session", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/runtime-sessions", operation: admission.OperationOpenRuntimeSession, allowUnavailable: true},
		{name: "create snapshot", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/snapshots", operation: admission.OperationSnapshot, allowUnavailable: true},
		{name: "terminate sandbox", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1:terminate", operation: admission.OperationTerminate, allowUnavailable: true},
		{name: "read operation", method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true},
		{name: "read execute result", method: http.MethodGet, path: "/v1/operations/operation-1/exec-result", operation: admission.OperationReadResult},
		{name: "read runtime session handoff", method: http.MethodGet, path: "/v1/operations/operation-1/runtime-session", operation: admission.OperationReadRuntimeSession, allowUnavailable: true},
		{name: "read snapshot manifest", method: http.MethodGet, path: "/v1/operations/operation-1/snapshot-manifest", operation: admission.OperationReadSnapshotManifest, allowUnavailable: true},
		{name: "stage artifact", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/artifacts:stage", operation: admission.OperationStageArtifact, allowUnavailable: true},
		{name: "read artifact evidence", method: http.MethodGet, path: "/v1/operations/operation-1/artifact-staging-evidence", operation: admission.OperationReadArtifactStagingEvidence, allowUnavailable: true},
		{name: "read usage evidence", method: http.MethodGet, path: "/v1/operations/operation-1/usage-evidence", operation: admission.OperationReadUsageEvidence, allowUnavailable: true},
		{name: "read events", method: http.MethodGet, path: "/v1/sandboxes/sandbox-1/events", query: "?after_sequence=2", operation: admission.OperationReadEvents, allowUnavailable: true},
	}
}

func TestProtectedHandlerReleaseGateCoversAllProtectedRoutes(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, route := range allProtectedReleaseRoutes() {
		route := route
		t.Run(route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-release-0001")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			wantStatus := http.StatusInternalServerError
			if route.allowUnavailable {
				wantStatus = http.StatusServiceUnavailable
			}
			if response.Code != wantStatus {
				t.Fatalf("valid %s response=%d, want %d body=%s", route.operation, response.Code, wantStatus, response.Body.String())
			}
			assertAdmissionErrorHeaders(t, response, route.allowUnavailable)
			wantGuardCalls := 0
			if route.operation.Mutation() {
				wantGuardCalls = 1
			}
			if got := guard.Calls(); got != wantGuardCalls {
				t.Fatalf("valid %s guard calls=%d, want %d", route.operation, got, wantGuardCalls)
			}
		})
	}
}

func TestProtectedHandlerRejectsDigestConsistentCreateAndSessionDocumentsBeforeGuard(t *testing.T) {
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
		{name: "create sandbox", method: http.MethodPost, path: "/v1/sandboxes", operation: admission.OperationCreate, allowUnavailable: true},
		{name: "open runtime session", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/runtime-sessions", operation: admission.OperationOpenRuntimeSession, allowUnavailable: true},
		{name: "execute", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec", operation: admission.OperationExec, allowUnavailable: true},
		{name: "cancel execute", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec:cancel", operation: admission.OperationCancelExec},
	} {
		route := route
		t.Run(route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-preflight-invalid-1")
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
			claims["jti"] = "jti-preflight-invalid-1"
			request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))
			request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
			request.Body = ioNopCloser(strings.NewReader(string(body)))
			request.ContentLength = int64(len(body))

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || guard.Calls() != 0 {
				t.Fatalf("response=%d guard_calls=%d body=%s", response.Code, guard.Calls(), response.Body.String())
			}
		})
	}
}

func TestProtectedHandlerRejectsOversizedCreateAndSessionDocumentsBeforeGuard(t *testing.T) {
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
		route    protectedReleaseRoute
		maxBytes int64
	}{
		{route: protectedReleaseRoute{name: "create sandbox", method: http.MethodPost, path: "/v1/sandboxes", operation: admission.OperationCreate, allowUnavailable: true}, maxBytes: providerv1.MaxCreateRequestBytes},
		{route: protectedReleaseRoute{name: "open runtime session", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/runtime-sessions", operation: admission.OperationOpenRuntimeSession, allowUnavailable: true}, maxBytes: providerv1.MaxRuntimeSessionOpenRequestBytes},
		{route: protectedReleaseRoute{name: "execute", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec", operation: admission.OperationExec, allowUnavailable: true}, maxBytes: providerv1.MaxExecRequestBytes},
		{route: protectedReleaseRoute{name: "cancel execute", method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec:cancel", operation: admission.OperationCancelExec}, maxBytes: providerv1.MaxCancelExecRequestBytes},
	} {
		test := test
		t.Run(test.route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, test.route, privateKey, material.client, "jti-preflight-oversized-1")
			body := strings.Repeat(" ", int(test.maxBytes)+1)
			request.Body = ioNopCloser(strings.NewReader(body))
			request.ContentLength = int64(len(body))

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || guard.Calls() != 0 {
				t.Fatalf("response=%d guard_calls=%d body=%s", response.Code, guard.Calls(), response.Body.String())
			}
		})
	}
}

func TestProtectedHandlerRejectsRequestDescriptorSubstitutionAcrossAllRoutes(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, route := range allProtectedReleaseRoutes() {
		route := route
		t.Run(route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-substitution-0001")
			contextValue := admissionContextFromReleaseRequest(t, request)
			contextValue.RequestDigest = testDigest('c')
			contextDigest, err := admission.DigestForAdmissionContext(contextValue)
			if err != nil {
				t.Fatal(err)
			}
			contextValue.ContextDigest = contextDigest
			claims := admissionTokenClaimsForTest(contextValue)
			request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
			request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden || guard.Calls() != 0 {
				t.Fatalf("substituted %s response=%d guard_calls=%d body=%s", route.operation, response.Code, guard.Calls(), response.Body.String())
			}
		})
	}
}

func TestProtectedHandlerRejectsInactiveBearerAcrossAllRoutes(t *testing.T) {
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
		name   string
		mutate func(map[string]any)
	}{
		{name: "not yet valid", mutate: func(claims map[string]any) { claims["nbf"] = releaseGateTestTime().Add(time.Second).Unix() }},
		{name: "expired", mutate: func(claims map[string]any) { claims["exp"] = releaseGateTestTime().Unix() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, route := range allProtectedReleaseRoutes() {
				route := route
				t.Run(route.name, func(t *testing.T) {
					guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
					handler := newReleaseGateHandler(t, identity, publicKey, guard)
					request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-inactive-0001")
					claims := admissionTokenClaimsForTest(admissionContextFromReleaseRequest(t, request))
					test.mutate(claims)
					request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != http.StatusUnauthorized || guard.Calls() != 0 {
						t.Fatalf("inactive %s response=%d guard_calls=%d body=%s", route.operation, response.Code, guard.Calls(), response.Body.String())
					}
				})
			}
		})
	}
}

func TestProtectedHandlerRejectsReplayAndStaleFencingAcrossAllMutations(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, decision := range []struct {
		name  string
		value admission.MutationGuardDecision
	}{
		{name: "replayed JTI", value: admission.MutationGuardReplayed},
		{name: "stale fencing", value: admission.MutationGuardStaleFencing},
	} {
		t.Run(decision.name, func(t *testing.T) {
			for _, route := range allProtectedReleaseRoutes() {
				if !route.operation.Mutation() {
					continue
				}
				route := route
				t.Run(route.name, func(t *testing.T) {
					guard := &releaseGateGuard{decision: decision.value}
					handler := newReleaseGateHandler(t, identity, publicKey, guard)
					request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-conflict-0001")
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != http.StatusConflict || guard.Calls() != 1 {
						t.Fatalf("%s %s response=%d guard_calls=%d body=%s", decision.name, route.operation, response.Code, guard.Calls(), response.Body.String())
					}
					assertAdmissionErrorHeaders(t, response, false)
				})
			}
		})
	}
}

func TestProtectedHandlerCancellationStopsAllProtectedRoutesBeforeGuard(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, route := range allProtectedReleaseRoutes() {
		route := route
		t.Run(route.name, func(t *testing.T) {
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-canceled-0001")
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			request = request.WithContext(canceled)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || guard.Calls() != 0 {
				t.Fatalf("canceled %s response=%d guard_calls=%d body=%s", route.operation, response.Code, guard.Calls(), response.Body.String())
			}
			assertAdmissionErrorHeaders(t, response, true)
		})
	}
}

func TestProtectedHandlerConcurrentAdmissionMatrix(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, route := range allProtectedReleaseRoutes() {
		route := route
		t.Run(route.name, func(t *testing.T) {
			const workers = 8
			guard := &releaseGateGuard{decision: admission.MutationGuardAccepted}
			handler := newReleaseGateHandler(t, identity, publicKey, guard)
			results := make(chan int, workers)
			for worker := range workers {
				go func(worker int) {
					request := newProtectedReleaseRequest(t, route, privateKey, material.client, fmt.Sprintf("jti-race-%012d", worker))
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					results <- response.Code
				}(worker)
			}
			wantStatus := http.StatusInternalServerError
			if route.allowUnavailable {
				wantStatus = http.StatusServiceUnavailable
			}
			for range workers {
				if got := <-results; got != wantStatus {
					t.Fatalf("concurrent %s response=%d, want %d", route.operation, got, wantStatus)
				}
			}
			wantCalls := 0
			if route.operation.Mutation() {
				wantCalls = workers
			}
			if got := guard.Calls(); got != wantCalls {
				t.Fatalf("concurrent %s guard calls=%d, want %d", route.operation, got, wantCalls)
			}
		})
	}
}

func newReleaseGateHandler(t *testing.T, identity *clientIdentityAdmission, publicKey ed25519.PublicKey, guard *releaseGateGuard) http.Handler {
	return newReleaseGateHandlerWithClock(t, identity, publicKey, guard, testAdmissionClock{now: releaseGateTestTime()})
}

func newReleaseGateHandlerWithClock(t *testing.T, identity *clientIdentityAdmission, publicKey ed25519.PublicKey, guard *releaseGateGuard, clock admission.Clock) http.Handler {
	t.Helper()
	keys := mustTestTrustedKeySource(t, publicKey)
	gate, err := admission.NewProtectedOperationGate(keys, clock, guard)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newProtectedReleaseRequest(t *testing.T, route protectedReleaseRoute, privateKey ed25519.PrivateKey, clientCertificate tls.Certificate, jti string) *http.Request {
	t.Helper()
	requestURL := "https://provider.test" + route.path + route.query
	var body []byte
	var digest string
	if route.method == http.MethodPost {
		body, digest = releaseMutationDocument(t, route.operation)
	}
	request := httptest.NewRequest(route.method, requestURL, nil)
	matched, pathValues, ok := matchProtectedRoute(request)
	if !ok || matched.operation != route.operation {
		t.Fatalf("release route %s was not matched as %s: %#v %v", route.path, route.operation, matched, ok)
	}
	contextValue := newProtectedReleaseContext(route)
	var document []byte
	if route.method == http.MethodPost {
		contextValue.RequestDigest = digest
	} else {
		var status int
		document, status = readDescriptor(contextValue, request, pathValues)
		if status != 0 {
			t.Fatalf("read descriptor status=%d for %s", status, route.operation)
		}
		contextValue.RequestDigest = releaseFullDocumentDigest(t, document)
	}
	if route.method == http.MethodPost {
		request = httptest.NewRequest(route.method, requestURL, strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
	}
	state := verifiedState(t, clientCertificate)
	request.TLS = &state
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	claims := admissionTokenClaimsForTest(contextValue)
	claims["jti"] = jti
	request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	return request
}

func admissionContextFromReleaseRequest(t *testing.T, request *http.Request) admission.AdmissionContext {
	t.Helper()
	values := request.Header.Values(admission.AdmissionContextHeader)
	if len(values) != 1 {
		t.Fatalf("admission context header values=%d, want 1", len(values))
	}
	contextValue, err := admission.DecodeAdmissionContextCarrier(values[0])
	if err != nil {
		t.Fatal(err)
	}
	return contextValue
}

func newProtectedReleaseContext(route protectedReleaseRoute) admission.AdmissionContext {
	contractID, profile := protectedReleaseRequestBinding(route.operation)
	queries := []admission.AdmissionQuery{}
	if route.operation == admission.OperationReadEvents {
		queries = append(queries, admission.AdmissionQuery{Name: "after_sequence", Value: "2"})
	}
	return admission.AdmissionContext{
		ContextContractID: admission.AdmissionContextContractID, ContextDigestProfile: admission.AdmissionContextDigestProfile,
		ControllerSubject: testAllowedIdentity, ProviderRevisionID: "provider-revision-1", ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:provider-1",
		TenantID: "tenant-1", WorkOrderID: "work-order-1", PolicyDigest: testDigest('a'), PolicyDecidedAt: releaseGateTestTime().Add(-time.Minute).Format(time.RFC3339Nano),
		Operation: route.operation, SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
		DeadlineAt: releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano), RequestContractID: contractID, RequestDigestProfile: profile,
		RequestDigest: testDigest('b'), HTTPTarget: admission.AdmissionTarget{Method: route.method, Path: route.path, NormalizedQuery: queries},
	}
}

func protectedReleaseRequestBinding(operation admission.Operation) (string, admission.DigestProfile) {
	if operation == admission.OperationReadSandbox {
		return "urn:shell-echo:sandbox-runtime:descriptor:status:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadOperation {
		return "urn:shell-echo:sandbox-runtime:descriptor:operation:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadResult {
		return "urn:shell-echo:sandbox-runtime:descriptor:exec-result:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadRuntimeSession {
		return "urn:shell-echo:sandbox-runtime:descriptor:runtime-session:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadSnapshotManifest {
		return "urn:shell-echo:sandbox-runtime:descriptor:snapshot-manifest:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadEvents {
		return "urn:shell-echo:sandbox-runtime:descriptor:events:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadArtifactStagingEvidence {
		return "urn:shell-echo:sandbox-runtime:descriptor:artifact-staging-evidence:v1", admission.DigestProfileFullDocument
	}
	if operation == admission.OperationReadUsageEvidence {
		return "urn:shell-echo:sandbox-runtime:descriptor:usage-evidence:v1", admission.DigestProfileFullDocument
	}
	contractIDs := map[admission.Operation]string{
		admission.OperationCreate:             "urn:shell-echo:sandbox-runtime:request:create:v1",
		admission.OperationRestore:            "urn:shell-echo:sandbox-runtime:request:restore:v1",
		admission.OperationSetDesiredState:    "urn:shell-echo:sandbox-runtime:request:set-desired-state:v1",
		admission.OperationExtendLease:        "urn:shell-echo:sandbox-runtime:request:extend-lease:v1",
		admission.OperationExec:               "urn:shell-echo:sandbox-runtime:request:exec:v1",
		admission.OperationCancelExec:         "urn:shell-echo:sandbox-runtime:request:cancel-exec:v1",
		admission.OperationOpenRuntimeSession: "urn:shell-echo:sandbox-runtime:request:open-runtime-session:v1",
		admission.OperationSnapshot:           "urn:shell-echo:sandbox-runtime:request:snapshot:v1",
		admission.OperationTerminate:          "urn:shell-echo:sandbox-runtime:request:terminate:v1",
		admission.OperationStageArtifact:      "urn:shell-echo:sandbox-runtime:request:stage-artifact:v1",
	}
	return contractIDs[operation], admission.DigestProfileRequestExcludingDigest
}

func releaseMutationDocument(t *testing.T, operation admission.Operation) ([]byte, string) {
	t.Helper()
	var document map[string]any
	switch operation {
	case admission.OperationCreate:
		request, _ := validProjectionCreateRequest(releaseGateTestTime())
		request.OperationID = "operation-1"
		request.DeadlineAt = releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano)
		request.Spec.WorkOrderID = "work-order-1"
		request.Spec.ProviderRevisionID = "provider-revision-1"
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		delete(document, "request_digest")
	case admission.OperationOpenRuntimeSession:
		encoded, _ := validRuntimeSessionOpenDocument(t)
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		delete(document, "request_digest")
	case admission.OperationStageArtifact:
		document = map[string]any{
			"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": int64(1),
			"idempotency_key": "artifact-idempotency-1", "deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano),
			"expected_generation": int64(1), "artifact_reference": "artifact-ref:artifact-1", "source_path": "/outputs/result.txt",
			"expected_digest": "sha256:" + strings.Repeat("a", 64), "expected_media_type": "text/plain", "max_bytes": int64(1024), "retention_seconds": int64(60),
		}
	case admission.OperationExec:
		document = map[string]any{
			"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": int64(1),
			"idempotency_key": "exec-idempotency-1", "deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano),
			"expected_generation": int64(1), "command": []string{"true"}, "working_directory": "/workspace",
			"result_retention_seconds": int64(60),
		}
	case admission.OperationCancelExec:
		document = map[string]any{
			"operation_id": "operation-1", "attempt_id": "attempt-1", "fencing_token": int64(1),
			"idempotency_key": "cancel-idempotency-1", "deadline_at": releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano),
			"expected_generation": int64(1), "target_operation_id": "exec-operation-1", "target_attempt_id": "exec-attempt-1",
			"reason": "caller_requested",
		}
	default:
		document = map[string]any{"operation": string(operation), "local_case": "p1.1d"}
	}
	withoutDigest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(withoutDigest)
	if err != nil {
		t.Fatal(err)
	}
	digest := releaseCanonicalDigest(canonical)
	document["request_digest"] = digest
	withDigest, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return withDigest, digest
}

func releaseFullDocumentDigest(t *testing.T, document []byte) string {
	t.Helper()
	canonical, err := jcs.Transform(document)
	if err != nil {
		t.Fatal(err)
	}
	return releaseCanonicalDigest(canonical)
}

func releaseCanonicalDigest(canonical []byte) string {
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func releaseGateTestTime() time.Time {
	return time.Unix(releaseGateTestTimeUnix, 0).UTC()
}

type releaseGateGuard struct {
	mu       sync.Mutex
	decision admission.MutationGuardDecision
	err      error
	calls    int
}

func (g *releaseGateGuard) Reserve(_ context.Context, _ admission.MutationGuardRequest) (admission.MutationGuardDecision, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	return g.decision, g.err
}

func (g *releaseGateGuard) Calls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

var _ admission.MutationGuard = (*releaseGateGuard)(nil)
