package providerapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type projectionApplication struct {
	accepted  lifecycle.CreateRequest
	operation lifecycle.Operation
	sandbox   lifecycle.Sandbox
}

func (a *projectionApplication) AcceptCreate(_ context.Context, request lifecycle.CreateRequest) (repository.CreateResult, error) {
	a.accepted = request
	return repository.CreateResult{Operation: a.operation}, nil
}
func (a *projectionApplication) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	return a.sandbox, nil
}
func (a *projectionApplication) GetOperation(context.Context, string) (lifecycle.Operation, error) {
	return a.operation, nil
}

func validProjectionCreateRequest(now time.Time) (providerv1.CreateRequest, admission.AdmissionContext) {
	deadline := now.Add(10 * time.Minute).UTC()
	lease := now.Add(time.Hour).UTC()
	request := providerv1.CreateRequest{
		MutationEnvelope: providerv1.MutationEnvelope{
			OperationID: "operation-create-1", AttemptID: "attempt-1", FencingToken: 1,
			IdempotencyKey: "idempotency-1", RequestDigest: providerv1.SHA256Digest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			DeadlineAt: deadline.Format(time.RFC3339Nano),
		},
		ProtocolVersion: providerv1.APIVersionV1,
		Spec: providerv1.SandboxSpec{
			SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
			BranchID: "branch-1", ProviderResolutionID: "resolution-1", ProviderRevisionID: "revision-1",
			Image:          providerv1.SandboxImage{Reference: "registry.invalid/sandbox/base", Digest: providerv1.SHA256Digest("sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")},
			RuntimeProfile: "sandbox-runtime-default-v1",
			Resources:      providerv1.SandboxResources{CPUMillis: 100, MemoryBytes: 1 << 20, EphemeralStorageBytes: 1 << 20, PIDsLimit: 32},
			Network:        providerv1.NetworkPolicy{Mode: providerv1.NetworkNone},
			Workspace:      providerv1.WorkspacePolicy{Mode: providerv1.WorkspaceEphemeral, BaseRevisionID: "base-1", BaseRevisionDigest: providerv1.SHA256Digest("sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"), BaseWorkspaceHeadVersion: 0, CommitMode: providerv1.WorkspaceReadOnly},
			Lease:          providerv1.LeasePolicy{ExpiresAt: lease.Format(time.RFC3339Nano), MaxExtensionSeconds: 0},
			Security:       providerv1.SecurityPolicy{PrivilegeLevel: providerv1.PrivilegeUnprivileged, RootFilesystem: providerv1.RootFilesystemReadOnly, ServiceAccountMode: providerv1.ServiceAccountNone},
			SandboxSlotKey: providerv1.SandboxSlotKey("primary"),
		},
	}
	admitted := admission.AdmissionContext{
		Operation: admission.OperationCreate, SandboxID: "sandbox-1", OperationID: "operation-create-1", AttemptID: "attempt-1", FencingToken: 1,
		TenantID: "tenant-1", WorkOrderID: "work-1", ProviderRevisionID: "revision-1", DeadlineAt: deadline.Format(time.RFC3339Nano),
	}
	return request, admitted
}

func TestDecodeCreateRequestProjectsOnlyAdmittedProviderFields(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	request, admitted := validProjectionCreateRequest(now)
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := decodeCreateRequest(document, admitted, now, provider.CapabilitySnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if projected.OperationID != request.OperationID || projected.Spec.SandboxID != request.Spec.SandboxID || projected.Spec.ProviderRevisionID != request.Spec.ProviderRevisionID || projected.Spec.SandboxSlotKey != string(request.Spec.SandboxSlotKey) {
		t.Fatalf("projected request = %#v", projected)
	}
}

func TestDecodeCreateRequestRejectsUnsupportedCapabilitiesAndContextSubstitution(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	request, admitted := validProjectionCreateRequest(now)
	request.Spec.RequiredCapabilities = []providerv1.CapabilityRequirement{{ID: "sandbox.exec", Version: "1.0.0"}}
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCreateRequest(document, admitted, now, provider.CapabilitySnapshot{}); err == nil || !isProjectionUnsupported(err) {
		t.Fatalf("unsupported capability error = %v", err)
	}
	request.Spec.RequiredCapabilities = nil
	request.Spec.SandboxID = "sandbox-other"
	document, err = json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCreateRequest(document, admitted, now, provider.CapabilitySnapshot{}); err == nil {
		t.Fatal("context substitution was accepted")
	}
}

func TestDecodeCreateRequestBindsAdvertisedCodingShellCapabilities(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	snapshot := validCodingShellSnapshot(t)
	validRequest := func() (providerv1.CreateRequest, admission.AdmissionContext) {
		request, admitted := validProjectionCreateRequest(now)
		request.Spec.RuntimeProfile = "sandbox-runtime-coding-shell-v1"
		request.Spec.RequiredCapabilities = []providerv1.CapabilityRequirement{
			{ID: "sandbox.exec", Version: "1.0.0", Profile: "exec-v1"},
			{ID: "sandbox.terminal", Version: "1.0.0", Profile: "terminal-v1"},
		}
		return request, admitted
	}
	decode := func(t *testing.T, request providerv1.CreateRequest, admitted admission.AdmissionContext) error {
		t.Helper()
		document, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeCreateRequest(document, admitted, now, snapshot)
		return err
	}

	request, admitted := validRequest()
	request.Spec.RequiredCapabilities[0], request.Spec.RequiredCapabilities[1] = request.Spec.RequiredCapabilities[1], request.Spec.RequiredCapabilities[0]
	if err := decode(t, request, admitted); err != nil {
		t.Fatalf("exact advertised requirements were rejected: %v", err)
	}

	tests := map[string]func(*providerv1.CreateRequest, *admission.AdmissionContext){
		"Provider revision": func(request *providerv1.CreateRequest, admitted *admission.AdmissionContext) {
			request.Spec.ProviderRevisionID = "revision-other"
			admitted.ProviderRevisionID = "revision-other"
		},
		"runtime profile": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.RuntimeProfile = "sandbox-runtime-other-v1"
		},
		"missing capability": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.RequiredCapabilities = request.Spec.RequiredCapabilities[:1]
		},
		"duplicate profile": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.RequiredCapabilities[1] = request.Spec.RequiredCapabilities[0]
		},
		"capability ID": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.RequiredCapabilities[0].ID = "sandbox.terminal"
		},
		"capability version": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.RequiredCapabilities[0].Version = "2.0.0"
		},
		"capability profile": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.RequiredCapabilities[0].Profile = "other-v1"
		},
		"optional capability": func(request *providerv1.CreateRequest, _ *admission.AdmissionContext) {
			request.Spec.OptionalCapabilities = []providerv1.CapabilityRequirement{{ID: "sandbox.exec", Version: "1.0.0", Profile: "exec-v1"}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request, admitted := validRequest()
			mutate(&request, &admitted)
			if err := decode(t, request, admitted); err == nil || !isProjectionUnsupported(err) {
				t.Fatalf("capability binding error = %v", err)
			}
		})
	}
}

func validCodingShellSnapshot(t *testing.T) provider.CapabilitySnapshot {
	t.Helper()
	base := validSnapshot(t, nil, nil)
	capabilities, runtimeProfiles := providerCodingShellAdvertisements()
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(
		base.ProviderRevisionID,
		base.Limits,
		capabilities,
		runtimeProfiles,
		base.SnapshotRestoreProfiles,
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestLifecycleProjectionsAreBoundedAndOpaque(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	sandbox := lifecycle.Sandbox{ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1", RuntimeProfile: "profile-1", SandboxSlotKey: "primary", DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady, Generation: 1, ObservedGeneration: 1, LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
	status, err := sandboxProjection(sandbox)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || strings.Contains(string(encoded), "container") || strings.Contains(string(encoded), "host_path") || strings.Contains(string(encoded), "credential") || strings.Contains(string(encoded), "secret") {
		t.Fatalf("status projection exposes forbidden detail: %s", encoded)
	}
	operation := lifecycle.Operation{ID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", Type: lifecycle.OperationCreate, State: lifecycle.OperationFailed, Deadline: now.Add(time.Minute), ObservedAt: now, Failure: &lifecycle.Failure{Code: "runtime_create_failed", Retryable: true, Outcome: lifecycle.FailureKnown}}
	projected, err := operationProjection(operation)
	if err != nil || projected.Error == nil || projected.Error.Code != "RUNTIME_CREATE_FAILED" {
		t.Fatalf("operation projection = %#v, %v", projected, err)
	}
}

func TestLifecycleProjectionsMatchLockedSchemas(t *testing.T) {
	projection, err := providercontract.Load(context.Background(), filepath.Join(localContractSourceRoot(t), "compatibility/sandbox-runtime/contract.lock.json"), localContractSourceRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	sandbox, err := sandboxProjection(lifecycle.Sandbox{
		ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
		ProviderRevisionID: "revision-1", RuntimeProfile: "sandbox-runtime-default-v1", SandboxSlotKey: "primary",
		DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady, Generation: 1,
		ObservedGeneration: 1, LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := operationProjection(lifecycle.Operation{
		ID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		Type: lifecycle.OperationCreate, State: lifecycle.OperationAccepted, Deadline: now.Add(time.Minute), ObservedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for schema, value := range map[string]any{"sandbox-status.schema.json": sandbox, "provider-operation.schema.json": operation} {
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := projection.Validate(schema, document); err != nil {
			t.Fatalf("%s projection is not Contract-valid: %v", schema, err)
		}
	}
}

func TestProtectedCreateProjectsAcceptedOperationAfterAdmission(t *testing.T) {
	now := releaseGateTestTime()
	request, admitted := validProjectionCreateRequest(now)
	request.DeadlineAt = now.Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)
	admitted.DeadlineAt = request.DeadlineAt
	requestDocument, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var withoutDigest map[string]json.RawMessage
	if err := json.Unmarshal(requestDocument, &withoutDigest); err != nil {
		t.Fatal(err)
	}
	delete(withoutDigest, "request_digest")
	withoutDigestDocument, err := json.Marshal(withoutDigest)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(withoutDigestDocument)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	request.RequestDigest = providerv1.SHA256Digest("sha256:" + hex.EncodeToString(digest[:]))
	document, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	admitted.RequestDigest = string(request.RequestDigest)
	admitted.RequestContractID = "urn:shell-echo:sandbox-runtime:request:create:v1"
	admitted.ContextContractID = admission.AdmissionContextContractID
	admitted.ContextDigestProfile = admission.AdmissionContextDigestProfile
	admitted.RequestDigestProfile = admission.DigestProfileRequestExcludingDigest
	admitted.ControllerSubject = testAllowedIdentity
	admitted.ProviderInstanceAudience = "urn:shell-echo:sandbox-runtime:provider-instance:provider-1"
	admitted.PolicyDigest = testDigest('a')
	admitted.PolicyDecidedAt = now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	admitted.HTTPTarget = admission.AdmissionTarget{Method: http.MethodPost, Path: "/v1/sandboxes", NormalizedQuery: []admission.AdmissionQuery{}}
	contextDigest, err := admission.DigestForAdmissionContext(admitted)
	if err != nil {
		t.Fatal(err)
	}
	admitted.ContextDigest = contextDigest
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	app := &projectionApplication{operation: lifecycle.Operation{ID: "operation-create-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", Type: lifecycle.OperationCreate, State: lifecycle.OperationAccepted, Deadline: now.Add(5 * time.Minute), ObservedAt: now}}
	gate := newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{})
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: gate, Application: app, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	claims := admissionTokenClaimsForTest(admitted)
	claims["jti"] = "jti-projection-0001"
	token := signTestAdmissionToken(t, privateKey, claims)
	verified, err := admission.VerifyCompactJWS(context.Background(), token, mustTestTrustedKeySource(t, publicKey))
	if err != nil {
		t.Fatalf("projection bearer verification failed: %v", err)
	}
	if err := admission.ValidateTokenBinding(verified, admitted.TokenBinding(testAllowedIdentity), testAdmissionClock{now: time.Date(2026, 8, 20, 0, 1, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("projection bearer binding failed: %v claims=%#v binding=%#v", err, verified.Claims, admitted.TokenBinding(testAllowedIdentity))
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "https://provider.test/v1/sandboxes", bytes.NewReader(document))
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	state := verifiedState(t, material.client)
	if err := admission.VerifyRequestDigest(verified.Claims.RequestDigestProfile, verified.Claims.RequestDigest, document); err != nil {
		t.Fatalf("projection request digest failed: %v", err)
	}
	httpRequest.TLS = &state
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, admitted))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusAccepted || app.accepted.OperationID != request.OperationID {
		t.Fatalf("create response=%d accepted=%#v body=%s", response.Code, app.accepted, response.Body.String())
	}
}

func TestProtectedLifecycleReadsProjectApplicationValues(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := releaseGateTestTime()
	app := &projectionApplication{
		sandbox: lifecycle.Sandbox{
			ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-order-1", WorkspaceID: "workspace-1",
			ProviderRevisionID: "provider-revision-1", RuntimeProfile: "sandbox-runtime-default-v1", SandboxSlotKey: "primary",
			DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady, Generation: 1, ObservedGeneration: 1,
			LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
		},
		operation: lifecycle.Operation{
			ID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", Type: lifecycle.OperationCreate,
			State: lifecycle.OperationAccepted, Deadline: now.Add(4 * time.Minute), ObservedAt: now,
		},
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{Gate: newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{}), Application: app})
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []protectedReleaseRoute{
		{name: "sandbox", method: http.MethodGet, path: "/v1/sandboxes/sandbox-1", operation: admission.OperationReadSandbox, allowUnavailable: true},
		{name: "operation", method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true},
	} {
		t.Run(route.name, func(t *testing.T) {
			request := newProtectedReleaseRequest(t, route, privateKey, material.client, "jti-read-"+route.name+"-0001")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("read response=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func isProjectionUnsupported(err error) bool { return err == errUnsupportedCreateCapability }
