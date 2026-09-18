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

type allowSlot struct{}

func (allowSlot) AuthorizePrimarySlot(context.Context, product.SlotSpec) error { return nil }

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

func TestConnectionGrantProjectionMatchesLockedContract(t *testing.T) {
	now := time.Date(2026, 9, 18, 1, 2, 3, 0, time.UTC)
	document, err := json.Marshal(toConnectionGrant(product.ConnectionGrant{
		ID: "con_1", SessionID: "ses_1", ProtocolProfile: "product-terminal.v1",
		GatewayURI: "wss://gateway.example.test/connect", Ticket: strings.Repeat("a", 43), ExpiresAt: now,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(document, []byte(`"ticket"`)) || !bytes.Contains(document, []byte(`"connection_ticket"`)) {
		t.Fatalf("connection grant fields = %s", document)
	}
	validateDefinition(t, "ConnectionGrant", document)
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
