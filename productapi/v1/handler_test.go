package productapiv1

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const testBearer = "product-api-test-token-0000000000000001"

type handlerStore struct {
	mu        sync.Mutex
	commands  []product.CreateWorkspaceCommand
	sessions  []product.SessionCommand
	slots     []product.SlotCommand
	workspace product.Workspace
	operation product.Operation
}

func (s *handlerStore) CreateWorkspace(_ context.Context, command product.CreateWorkspaceCommand) (product.CreateWorkspaceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, command)
	return product.CreateWorkspaceResult{Operation: s.operation}, nil
}

func (s *handlerStore) GetWorkspace(context.Context, string, string) (product.Workspace, error) {
	return s.workspace, nil
}

func (s *handlerStore) ListWorkspaces(context.Context, string, product.ActorRef, string, int) ([]product.Workspace, string, error) {
	return []product.Workspace{s.workspace}, "", nil
}

func (s *handlerStore) GetOperation(context.Context, string, string) (product.Operation, error) {
	return s.operation, nil
}

func (s *handlerStore) CreateSession(_ context.Context, command product.SessionCommand) (product.Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = append(s.sessions, command)
	operation := s.operation
	operation.Type = "create_session"
	operation.WorkspaceID = command.WorkspaceID
	operation.SlotKey = command.SlotKey
	operation.SessionID = command.SessionID
	return operation, false, nil
}

func (s *handlerStore) CloseSession(context.Context, product.SessionCommand) (product.Operation, bool, error) {
	return product.Operation{}, false, product.ErrCapabilityUnsupported
}

func (s *handlerStore) GetSession(context.Context, string, string) (product.RuntimeSession, error) {
	return product.RuntimeSession{}, product.ErrNotFound
}

func (s *handlerStore) ListSessions(context.Context, string, string, product.ActorRef, int) ([]product.RuntimeSession, error) {
	return nil, nil
}

func (s *handlerStore) PutSlot(_ context.Context, command product.SlotCommand) (product.Operation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.slots = append(s.slots, command)
	operation := s.operation
	operation.Type = "put_slot"
	operation.WorkspaceID = command.WorkspaceID
	operation.SlotKey = command.SlotKey
	return operation, false, nil
}

func (s *handlerStore) GetSlot(context.Context, string, product.ActorRef, string, string) (product.WorkspaceSlot, error) {
	return product.WorkspaceSlot{SlotKey: "browser-main", Kind: "browser", ProfileID: product.BrowserSlotProfile,
		RequiredCapabilities: []product.CapabilityRequirement{{CapabilityID: product.BrowserCapabilityID, Version: product.BrowserCapabilityVersion, ProfileID: product.BrowserCapabilityProfile}},
		DesiredState:         "ready", ObservedState: "requested", Generation: 1, Version: 1, CreatedAt: s.workspace.CreatedAt, UpdatedAt: s.workspace.UpdatedAt}, nil
}

type allowSlot struct{}

func (allowSlot) AuthorizePrimarySlot(context.Context, product.SlotSpec) error { return nil }

type allowProductSession struct{}

func (allowProductSession) AuthorizeSession(context.Context, string, string) error { return nil }

type allowBrowserSlot struct{}

func (allowBrowserSlot) AuthorizeSlot(context.Context, product.SlotSpec) error { return nil }

type handlerGrantStore struct {
	commands []product.ConnectionGrantCommand
}

func (s *handlerGrantStore) MintConnectionGrant(_ context.Context, command product.ConnectionGrantCommand) (product.ConnectionGrant, bool, error) {
	s.commands = append(s.commands, command)
	return product.ConnectionGrant{
		ID:              command.ConnectionID,
		SessionID:       command.SessionID,
		ProtocolProfile: command.Request.ProtocolProfile,
		AccessMode:      command.Request.AccessMode,
		GatewayURI:      command.GatewayURI,
		Ticket:          command.Ticket,
		ExpiresAt:       time.Now().UTC().Add(command.Lifetime),
	}, false, nil
}

func (*handlerGrantStore) ConsumeConnectionGrant(context.Context, string) (product.GatewayBinding, error) {
	return product.GatewayBinding{}, product.ErrNotFound
}

func (*handlerGrantStore) CheckGatewayAuthority(context.Context, product.GatewayBinding) error {
	return nil
}

type catalogStoreStub struct {
	artifact  product.Artifact
	recording product.RecordingRecord
}

func (s *catalogStoreStub) PublishArtifact(context.Context, product.PublishArtifactCommand) (product.Artifact, error) {
	return s.artifact, nil
}
func (s *catalogStoreStub) ListArtifacts(context.Context, string, product.ActorRef, string, string, int) (product.ArtifactPage, error) {
	return product.ArtifactPage{Items: []product.Artifact{s.artifact}}, nil
}
func (s *catalogStoreStub) GetArtifact(context.Context, string, product.ActorRef, string) (product.Artifact, error) {
	return s.artifact, nil
}
func (s *catalogStoreStub) StartRecording(context.Context, product.StartRecordingCommand) (product.RecordingRecord, error) {
	return s.recording, nil
}
func (s *catalogStoreStub) GetRecording(context.Context, string, product.ActorRef, string) (product.RecordingRecord, error) {
	return s.recording, nil
}
func (s *catalogStoreStub) ListRecordings(context.Context, string, product.ActorRef, string, string, int) (product.RecordingPage, error) {
	return product.RecordingPage{Items: []product.Recording{s.recording.Recording}}, nil
}
func (s *catalogStoreStub) AppendRecordingSegment(context.Context, string, string, int64, string, string, string, int64, time.Time, time.Time) (product.RecordingRecord, error) {
	return s.recording, nil
}
func (s *catalogStoreStub) FinalizeRecording(context.Context, string, string, string, int64, time.Time) (product.RecordingRecord, error) {
	return s.recording, nil
}
func (*catalogStoreStub) LeaseExpiredRecordings(context.Context, int) ([]product.RecordingCleanup, error) {
	return nil, nil
}
func (*catalogStoreStub) MarkRecordingDeleted(context.Context, string, string, time.Time) error {
	return nil
}

type handlerIDs struct {
	mu   sync.Mutex
	next int
}

func (g *handlerIDs) NewID(prefix string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	return fmt.Sprintf("%s_%d", prefix, g.next), nil
}

func TestHandlerCreateAndReadWorkspaceContractProjection(t *testing.T) {
	handler, store := newTestHandler(t)
	request := authenticatedRequest(http.MethodPost, "/api/v1/workspaces", `{
  "display_name":"contract workspace",
  "lifetime_seconds":3600,
  "primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}
}`)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("create status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	validateDefinition(t, "ProductOperation", response.Body.Bytes())
	if len(store.commands) != 1 || store.commands[0].TenantID != "tenant-1" || store.commands[0].Actor.ID != "actor-1" {
		t.Fatalf("commands = %#v", store.commands)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/workspaces/wrk_1", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("workspace status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "Workspace", response.Body.Bytes())

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/workspaces?limit=50", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("workspace list status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "WorkspacePage", response.Body.Bytes())

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/operations/op_1", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("operation status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "ProductOperation", response.Body.Bytes())
}

func TestHandlerAcceptsStrictBrowserSessionAuthorityRequest(t *testing.T) {
	base, store := newTestHandler(t)
	sessions, err := product.NewSessionService(store, allowProductSession{}, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandlerWithServices(base.application, nil, sessions, base.authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedRequest(http.MethodPost, "/api/v1/workspaces/wrk_1/sessions", `{
  "expected_workspace_version":1,
  "slot_key":"browser-main",
  "kind":"browser_automation",
  "protocol_profile":"product-browser-automation.v1",
  "expires_in_seconds":900,
  "recording_policy":"metadata_only"
}`)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "browser-session-create-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "ProductOperation", response.Body.Bytes())
	if len(store.sessions) != 1 || store.sessions[0].TenantID != "tenant-1" || store.sessions[0].Actor.ID != "actor-1" ||
		store.sessions[0].Kind != product.SessionKindBrowserAutomation || store.sessions[0].ProtocolProfile != product.SessionProfileBrowserAutomation {
		t.Fatalf("session commands=%#v", store.sessions)
	}

	request = authenticatedRequest(http.MethodPost, "/api/v1/workspaces/wrk_1/sessions", `{
  "expected_workspace_version":1,
  "slot_key":"browser-main",
  "kind":"browser_live",
  "protocol_profile":"product-browser-automation.v1",
  "expires_in_seconds":900,
  "recording_policy":"metadata_only"
}`)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "browser-session-create-2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || len(store.sessions) != 1 {
		t.Fatalf("mismatched profile status=%d calls=%d body=%s", response.Code, len(store.sessions), response.Body.String())
	}

	request = authenticatedRequest(http.MethodPost, "/api/v1/workspaces/wrk_1/sessions", `{
  "expected_workspace_version":1,
  "slot_key":"browser-main",
  "kind":"browser_automation",
  "protocol_profile":"product-browser-automation.v1",
  "expires_in_seconds":900,
  "recording_policy":"metadata_only",
  "unexpected":true
}`)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "browser-session-create-3")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(store.sessions) != 1 {
		t.Fatalf("unknown member status=%d calls=%d body=%s", response.Code, len(store.sessions), response.Body.String())
	}
}

func TestHandlerPutAndGetStrictBrowserSlot(t *testing.T) {
	base, store := newTestHandler(t)
	slots, err := product.NewSlotService(store, allowBrowserSlot{}, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandlerWithSlots(base.application, nil, nil, nil, nil, slots, nil, base.authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := authenticatedRequest(http.MethodPut, "/api/v1/workspaces/wrk_1/slots/browser-main", `{
  "expected_workspace_version":1,
  "kind":"browser",
  "profile_id":"sandbox-runtime-browser-v1",
  "required_capabilities":[{"capability_id":"sandbox.browser","version":"1.0.0","profile_id":"browser-v1"}],
  "desired_state":"ready"
}`)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "slot-put-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || len(store.slots) != 1 {
		t.Fatalf("status=%d body=%s slots=%#v", response.Code, response.Body.String(), store.slots)
	}
	validateDefinition(t, "ProductOperation", response.Body.Bytes())

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/workspaces/wrk_1/slots/browser-main", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "WorkspaceSlot", response.Body.Bytes())

	request = authenticatedRequest(http.MethodPut, "/api/v1/workspaces/wrk_1/slots/browser-main", `{"unknown":true}`)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "slot-put-2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(store.slots) != 1 {
		t.Fatalf("unknown status=%d calls=%d body=%s", response.Code, len(store.slots), response.Body.String())
	}
}

func TestHandlerAuthenticatesBeforeBodyAuthority(t *testing.T) {
	handler, store := newTestHandler(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/workspaces", strings.NewReader(`{"unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(store.commands) != 0 {
		t.Fatalf("status=%d commands=%d body=%s", response.Code, len(store.commands), response.Body.String())
	}
	validateDefinition(t, "ProductError", response.Body.Bytes())
}

func TestHandlerRejectsMalformedCreateWithoutMutation(t *testing.T) {
	handler, store := newTestHandler(t)
	tests := []struct {
		name string
		body string
	}{
		{"unknown", `{"display_name":"x","unknown":true}`},
		{"duplicate", `{"display_name":"x","display_name":"y"}`},
		{"trailing", `{}` + `{}`},
		{"oversized", `{"display_name":"` + strings.Repeat("x", int(maxCreateWorkspaceBytes)) + `"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := authenticatedRequest(http.MethodPost, "/api/v1/workspaces", test.body)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "create-1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			validateDefinition(t, "ProductError", response.Body.Bytes())
		})
	}
	if len(store.commands) != 0 {
		t.Fatalf("invalid requests produced %d commands", len(store.commands))
	}
}

func TestHandlerRejectsDuplicateSecurityHeaders(t *testing.T) {
	handler, store := newTestHandler(t)
	request := authenticatedRequest(http.MethodPost, "/api/v1/workspaces", `{}`)
	request.Header.Add("Authorization", "Bearer "+testBearer)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("Idempotency-Key", "one")
	request.Header.Add("Idempotency-Key", "two")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(store.commands) != 0 {
		t.Fatalf("status=%d commands=%d", response.Code, len(store.commands))
	}
}

func TestCapabilityProjectionMatchesLockedContract(t *testing.T) {
	base, _ := newTestHandler(t)
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{{
		Token:     testBearer,
		Principal: productapi.Principal{TenantID: "tenant-1", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-1"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	source := CapabilitySourceFunc(func(_ context.Context, principal productapi.Principal) ([]ProductCapability, error) {
		if principal.TenantID != "tenant-1" {
			t.Fatalf("principal = %#v", principal)
		}
		return []ProductCapability{{
			CapabilityID: "product.terminal", Version: "1.0.0", Readiness: "ready",
			ProtocolProfiles: []string{"product-terminal.v1"}, MaxSessionSeconds: 3600,
		}}, nil
	})
	handler, err := NewHandlerWithCapabilities(base.application, nil, nil, nil, nil, source, authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/capabilities", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "CapabilityDocument", response.Body.Bytes())
	if strings.Contains(response.Body.String(), "protocol_profile\"") || strings.Contains(response.Body.String(), "limits") {
		t.Fatalf("legacy capability fields leaked: %s", response.Body.String())
	}
}

func TestCapabilityDependencyFailureFailsClosed(t *testing.T) {
	base, _ := newTestHandler(t)
	authenticator, _ := productapi.NewStaticAuthenticator([]productapi.StaticToken{{
		Token:     testBearer,
		Principal: productapi.Principal{TenantID: "tenant-1", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-1"}},
	}})
	handler, err := NewHandlerWithCapabilities(base.application, nil, nil, nil, nil, CapabilitySourceFunc(func(context.Context, productapi.Principal) ([]ProductCapability, error) {
		return nil, product.ErrStoreUnavailable
	}), authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, "/api/v1/capabilities", ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	validateDefinition(t, "ProductError", response.Body.Bytes())
}

func TestConnectionGrantProjectionMatchesLockedContract(t *testing.T) {
	now := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC)
	document, err := json.Marshal(toConnectionGrant(product.ConnectionGrant{
		ID: "con_1", SessionID: "ses_1", ProtocolProfile: "product-terminal.v1",
		AccessMode: product.GrantAccessControl, GatewayURI: "wss://gateway.example.test/connect", Ticket: strings.Repeat("a", 43), ExpiresAt: now,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte(`"ticket"`)) || !bytes.Contains(document, []byte(`"connection_ticket"`)) {
		t.Fatalf("connection grant fields = %s", document)
	}
	validateDefinition(t, "ConnectionGrant", document)
}

func TestViewerCanOnlyMintViewConnectionGrant(t *testing.T) {
	base, sessionStore := newTestHandler(t)
	store := &handlerGrantStore{}
	grants, err := product.NewGrantService(store, &handlerIDs{}, product.CryptoTicketGenerator{}, "wss://gateway.example.test/connect", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := product.NewSessionService(sessionStore, allowProductSession{}, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	const viewerToken = "product-viewer-test-token-000000000000001"
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{{
		Token: viewerToken,
		Principal: productapi.Principal{
			TenantID: "tenant-1",
			Actor:    product.ActorRef{Type: product.ActorHuman, ID: "actor-1"},
			Role:     productapi.RoleViewer,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewCompleteHandler(base.application, nil, sessions, grants, authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/ses_1/connections", strings.NewReader(`{"expected_session_version":1,"protocol_profile":"product-browser-live.v1","access_mode":"view"}`))
	request.Header.Set("Authorization", "Bearer "+viewerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "viewer-grant-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || len(store.commands) != 1 || store.commands[0].Request.AccessMode != product.GrantAccessView {
		t.Fatalf("view status=%d commands=%#v body=%s", response.Code, store.commands, response.Body.String())
	}
	validateDefinition(t, "ConnectionGrant", response.Body.Bytes())

	request = httptest.NewRequest(http.MethodPost, "/api/v1/sessions/ses_1/connections", strings.NewReader(`{"expected_session_version":1,"protocol_profile":"product-browser-live.v1","access_mode":"control","control_lease_id":"ctl_1","control_fence":1}`))
	request.Header.Set("Authorization", "Bearer "+viewerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "viewer-grant-2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(store.commands) != 1 {
		t.Fatalf("control status=%d commands=%#v body=%s", response.Code, store.commands, response.Body.String())
	}
}

func TestCatalogRoutesMatchLockedContract(t *testing.T) {
	base, store := newTestHandler(t)
	now := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "actor-1"}
	catalogStore := &catalogStoreStub{
		artifact:  product.Artifact{ID: "art_1", WorkspaceID: "wrk_1", SlotKey: product.PrimarySlotKey, Name: "result.txt", MediaType: "text/plain", SizeBytes: 12, Digest: "sha256:" + strings.Repeat("a", 64), State: "available", CreatedBy: actor, CreatedAt: now},
		recording: product.RecordingRecord{Recording: product.Recording{ID: "rec_1", WorkspaceID: "wrk_1", SessionID: "ses_1", Type: "terminal", State: "available", Digest: "sha256:" + strings.Repeat("b", 64), SizeBytes: 20, StartedAt: now, CompletedAt: now.Add(time.Minute), RetentionExpiresAt: now.Add(time.Hour)}},
	}
	catalog, err := product.NewCatalogService(catalogStore, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, _ := productapi.NewStaticAuthenticator([]productapi.StaticToken{{Token: testBearer, Principal: productapi.Principal{TenantID: "tenant-1", Actor: actor}}})
	handler, err := NewHandlerWithCatalog(base.application, nil, nil, nil, catalog, authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	_ = store
	tests := []struct{ path, definition string }{
		{"/api/v1/workspaces/wrk_1/artifacts", "ArtifactPage"},
		{"/api/v1/artifacts/art_1", "Artifact"},
		{"/api/v1/workspaces/wrk_1/recordings", "RecordingPage"},
		{"/api/v1/recordings/rec_1", "Recording"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, authenticatedRequest(http.MethodGet, test.path, ""))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", test.path, response.Code, response.Body.String())
		}
		validateDefinition(t, test.definition, response.Body.Bytes())
	}
}

func newTestHandler(t *testing.T) (*Handler, *handlerStore) {
	t.Helper()
	now := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "actor-1"}
	capability := product.CapabilityRequirement{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"}
	store := &handlerStore{
		operation: product.Operation{
			ID: "op_1", Type: "create_workspace", WorkspaceID: "wrk_1", SubmittedBy: actor,
			State: "accepted", ReconciliationStatus: "pending", Version: 1, AcceptedAt: now, UpdatedAt: now,
		},
		workspace: product.Workspace{
			ID: "wrk_1", TenantID: "tenant-1", Owner: actor, DisplayName: "contract workspace",
			PrimarySlotKey: "primary-code", DesiredState: "active", ObservedState: "requested", Version: 1,
			LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
			Slots: []product.WorkspaceSlot{{
				SlotKey: "primary-code", Kind: "code", ProfileID: "coding-shell-v1",
				RequiredCapabilities: []product.CapabilityRequirement{capability}, DesiredState: "ready",
				ObservedState: "requested", Generation: 1, ObservedGeneration: 0, Version: 1,
				CreatedAt: now, UpdatedAt: now,
			}},
		},
	}
	application, err := product.NewApplication(store, allowSlot{}, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{{
		Token: testBearer, Principal: productapi.Principal{TenantID: "tenant-1", Actor: actor},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(application, authenticator, &handlerIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store
}

func authenticatedRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testBearer)
	return request
}

func validateDefinition(t *testing.T, definition string, document []byte) {
	t.Helper()
	schemaPath := filepath.Join(repositoryRoot(t), "product-contract", "schemas", "product-v1alpha1.schema.json")
	schemaDocument, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var decodedSchema any
	if err := json.Unmarshal(schemaDocument, &decodedSchema); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschemaecma.NewCompiler()
	const schemaID = "urn:shell-echo:sandbox-runtime:contract:product-v1alpha1"
	if err := compiler.AddResource(schemaID, decodedSchema); err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(schemaID + "#/$defs/" + definition)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := compiled.Validate(value); err != nil {
		t.Fatalf("%s does not validate as %s: %v", document, definition, err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}
