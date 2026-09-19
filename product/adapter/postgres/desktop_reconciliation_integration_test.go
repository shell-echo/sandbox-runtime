//go:build integration

package productpostgres

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

	"github.com/shell-echo/sandbox-runtime/product"
	productprovider "github.com/shell-echo/sandbox-runtime/product/adapter/provider"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type integrationDesktopClock struct{ value time.Time }

func (c integrationDesktopClock) Now() time.Time { return c.value }

type integrationDesktopProvider struct {
	t             *testing.T
	mutex         sync.Mutex
	now           time.Time
	operations    map[string]providerv1.Operation
	desktopExpiry map[string]string
	desktopIDs    map[string]string
}

func (p *integrationDesktopProvider) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	write := func(value any) {
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(value); err != nil {
			p.t.Error(err)
		}
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/capabilities":
		write(integrationDesktopCapabilities())
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sandboxes":
		var body providerv1.CreateRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			p.t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.Spec.PlacementConstraints == nil || body.Spec.PlacementConstraints.ResourceClass != providerv1.ResourceDesktop ||
			body.Spec.Network.Mode != providerv1.NetworkRestricted || body.Spec.RuntimeProfile != product.DesktopSlotProfile {
			p.t.Errorf("unexpected Desktop create shape: %#v", body.Spec)
		}
		operation := integrationDesktopOperation(body.OperationID, body.AttemptID, body.Spec.SandboxID, body.FencingToken, providerv1.OperationCreate, p.now)
		p.operations[body.OperationID] = operation
		writer.WriteHeader(http.StatusAccepted)
		write(operation)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/desktop-sessions"):
		var body providerv1.DesktopSessionOpenRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			p.t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.ExpectedGeneration != 7 || body.FencingToken != 1 || body.CapabilityProfileID != product.DesktopCapabilityProfile {
			p.t.Errorf("Product/Provider generation separation lost: %#v", body)
		}
		sandboxID := desktopSandboxIDFromPath(request.URL.Path)
		operation := integrationDesktopOperation(body.OperationID, body.AttemptID, sandboxID, body.FencingToken, providerv1.OperationOpenDesktopSession, p.now)
		p.operations[body.OperationID] = operation
		p.desktopExpiry[body.OperationID] = body.ExpiresAt
		p.desktopIDs[body.OperationID] = body.DesktopSessionID
		writer.WriteHeader(http.StatusAccepted)
		write(operation)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, ":close"):
		var body providerv1.DesktopSessionCloseRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			p.t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if body.ExpectedGeneration != 7 || body.FencingToken != 1 || body.ConnectionGeneration != 11 {
			p.t.Errorf("unexpected Desktop close shape: %#v", body)
		}
		sandboxID := desktopSandboxIDFromPath(request.URL.Path)
		operation := integrationDesktopOperation(body.OperationID, body.AttemptID, sandboxID, body.FencingToken, providerv1.OperationCloseDesktopSession, p.now)
		p.operations[body.OperationID] = operation
		writer.WriteHeader(http.StatusAccepted)
		write(operation)
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/desktop-session"):
		operationID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/operations/"), "/desktop-session")
		operation, ok := p.operations[operationID]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		write(providerv1.DesktopSessionHandoff{OperationID: operation.OperationID, AttemptID: operation.AttemptID,
			FencingToken: operation.FencingToken, SandboxID: operation.SandboxID, DesktopSessionID: p.desktopIDs[operationID],
			CapabilityProfileID: product.DesktopCapabilityProfile, Protocol: providerv1.DesktopProtocolWebRTC,
			MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1",
			InternalEndpointReference: "ref:desktop-session:" + operation.OperationID,
			ConnectionGeneration:      11, ExpiresAt: p.desktopExpiry[operationID]})
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/operations/"):
		operationID := strings.TrimPrefix(request.URL.Path, "/v1/operations/")
		operation, ok := p.operations[operationID]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		operation.Status = providerv1.OperationSucceeded
		operation.ObservedAt = p.now.Add(time.Second).Format(time.RFC3339Nano)
		write(operation)
	default:
		http.NotFound(writer, request)
	}
}

func TestIntegrationDesktopNetworkDispatchObservationRecoveryAndClose(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-network-reconciliation"
	cleanupProductTenant(t, pool, tenantID)

	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-network-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-network-workspace", integrationCreateWorkspaceRequest("desktop network reconciliation"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE sandbox_runtime_product.workspaces SET observed_state='active' WHERE tenant_id=$1`,
		`UPDATE sandbox_runtime_product.workspace_slots SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1 AND slot_key='primary-code'`,
		`UPDATE sandbox_runtime_product.outbox SET state='delivered' WHERE tenant_id=$1 AND message_type='workspace.reconcile'`,
	} {
		if _, err := pool.Exec(context.Background(), statement, tenantID); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	provider := &integrationDesktopProvider{t: t, now: now, operations: map[string]providerv1.Operation{}, desktopExpiry: map[string]string{}, desktopIDs: map[string]string{}}
	server := httptest.NewServer(provider)
	defer server.Close()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newClient := func() *productprovider.Client {
		publication := desktopimage.LockedPublication()
		client, err := productprovider.NewDesktop(productprovider.Config{Origin: server.URL, HTTPClient: server.Client(),
			ExpectedRevisionID: productprovider.LockedDesktopProviderRevision, ExpectedTree: productprovider.LockedDesktopProviderTree,
			ProviderResolutionID: "provider-desktop-integration", AllowHTTPForTests: true, Clock: integrationDesktopClock{now},
			Authority: productprovider.Authority{Issuer: "https://product.example.test/controller", Subject: "spiffe://product/controller",
				Audience: "urn:shell-echo:sandbox-runtime:provider-instance:integration", KeyID: "product-key-integration", PrivateKey: privateKey},
			Profiles: []productprovider.Profile{{ProductProfileID: product.DesktopSlotProfile, RuntimeProfileID: product.DesktopSlotProfile,
				ImageReference: publication.Image(), ImageDigest: publication.Digest, Architecture: providerv1.ArchitectureAMD64,
				CPUMillis: 4000, MemoryBytes: 4 << 30, EphemeralBytes: 8 << 30, WorkspaceBytes: 4 << 30, PIDsLimit: 512,
				BaseRevisionID: "revision-empty", BaseRevisionDigest: "sha256:" + strings.Repeat("e", 64),
				PolicyDigest: "sha256:" + strings.Repeat("b", 64), NetworkPolicyReference: "desktop-egress-policy-1"}}})
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	client := newClient()
	slots, _ := product.NewSlotService(store, client, ids)
	putOperation, _, err := slots.Put(context.Background(), tenantID, actor, created.Operation.WorkspaceID, "desktop-main", "desktop-network-slot", desktopSlotRequest(1))
	if err != nil {
		t.Fatal(err)
	}
	if browserWork, err := store.LeaseBrowserSlotWork(context.Background(), "browser-worker", 10*time.Second, 10); err != nil || len(browserWork) != 0 {
		t.Fatalf("Browser worker consumed Desktop slot work=%#v err=%v", browserWork, err)
	}
	dispatcher, err := product.NewDesktopDispatcher(store, client, "desktop-slot-worker", 10*time.Second, time.Millisecond, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := dispatcher.DispatchOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("Desktop slot dispatch count=%d err=%v", count, err)
	}
	if generic, err := store.LeaseProviderObservations(context.Background(), "generic-observer", 10*time.Second, 10); err != nil || len(generic) != 0 {
		t.Fatalf("generic observer consumed Desktop work=%#v err=%v", generic, err)
	}

	restartedStore, _ := New(pool, 5*time.Second)
	restartedClient := newClient()
	reconciler, err := product.NewDesktopReconciler(restartedStore, restartedClient, ids, "desktop-observer", 10*time.Second, time.Millisecond, 10)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := reconciler.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("Desktop slot reconcile count=%d err=%v", count, err)
	}
	var slotState, operationState string
	if err := pool.QueryRow(context.Background(), `SELECT observed_state FROM sandbox_runtime_product.workspace_slots WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key='desktop-main'`, tenantID, created.Operation.WorkspaceID).Scan(&slotState); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT state FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1 AND operation_id=$2`, tenantID, putOperation.ID).Scan(&operationState); err != nil {
		t.Fatal(err)
	}
	if slotState != "ready" || operationState != "succeeded" {
		t.Fatalf("Desktop slot state=%q operation=%q", slotState, operationState)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.provider_bindings SET provider_generation=7 WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key='desktop-main' AND current`, tenantID, created.Operation.WorkspaceID); err != nil {
		t.Fatal(err)
	}

	workspace, err := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	sessions, _ := product.NewSessionService(restartedStore, restartedClient, ids)
	openOperation, _, err := sessions.Create(context.Background(), tenantID, actor, workspace.ID, "desktop-network-open", product.CreateSessionRequest{
		ExpectedWorkspaceVersion: workspace.Version, SlotKey: "desktop-main", Kind: product.SessionKindDesktop,
		ProtocolProfile: product.SessionProfileDesktop, ExpiresInSeconds: 900, RecordingPolicy: "metadata_only",
	})
	if err != nil {
		t.Fatal(err)
	}
	if terminal, err := restartedStore.LeaseSessionWork(context.Background(), "terminal-worker", 10*time.Second, 10); err != nil || len(terminal) != 0 {
		t.Fatalf("terminal worker consumed Desktop session work=%#v err=%v", terminal, err)
	}
	sessionDispatcher, err := product.NewDesktopSessionDispatcher(restartedStore, restartedClient, "desktop-session-worker", 10*time.Second, time.Millisecond, 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := sessionDispatcher.DispatchOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("Desktop open dispatch count=%d err=%v", count, err)
	}

	recoveredStore, _ := New(pool, 5*time.Second)
	recoveredClient := newClient()
	recoveredReconciler, _ := product.NewDesktopReconciler(recoveredStore, recoveredClient, ids, "desktop-recovery-observer", 10*time.Second, time.Millisecond, 10)
	if count, err := recoveredReconciler.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("Desktop open recovery count=%d err=%v", count, err)
	}
	session, err := sessions.Get(context.Background(), tenantID, actor, openOperation.SessionID)
	if err != nil || session.State != product.SessionStateReady || session.Version < 3 {
		t.Fatalf("ready Desktop session=%#v err=%v", session, err)
	}
	var handoff string
	var connectionGeneration int64
	if err := pool.QueryRow(context.Background(), `SELECT provider_handoff_reference,provider_connection_generation FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2`, tenantID, session.ID).Scan(&handoff, &connectionGeneration); err != nil {
		t.Fatal(err)
	}
	if handoff != "ref:desktop-session:"+openOperation.ID || connectionGeneration != 11 {
		t.Fatalf("persisted Desktop handoff=%q generation=%d", handoff, connectionGeneration)
	}

	closeOperation, _, err := sessions.Close(context.Background(), tenantID, actor, session.ID, "desktop-network-close", product.CloseSessionRequest{ExpectedVersion: session.Version, Reason: "owner_requested_close"})
	if err != nil {
		t.Fatal(err)
	}
	closeDispatcher, _ := product.NewDesktopSessionDispatcher(recoveredStore, recoveredClient, "desktop-close-worker", 10*time.Second, time.Millisecond, 3, 10)
	if count, err := closeDispatcher.DispatchOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("Desktop close dispatch count=%d err=%v", count, err)
	}
	finalStore, _ := New(pool, 5*time.Second)
	finalReconciler, _ := product.NewDesktopReconciler(finalStore, newClient(), ids, "desktop-close-observer", 10*time.Second, time.Millisecond, 10)
	if count, err := finalReconciler.ReconcileOnce(context.Background()); err != nil || count != 1 {
		t.Fatalf("Desktop close reconcile count=%d err=%v", count, err)
	}
	closed, err := sessions.Get(context.Background(), tenantID, actor, session.ID)
	if err != nil || closed.State != product.SessionStateClosed {
		t.Fatalf("closed Desktop session=%#v err=%v", closed, err)
	}
	var current bool
	var productGeneration, providerGeneration int64
	var storedHandoff *string
	if err := pool.QueryRow(context.Background(), `SELECT current,slot_generation,provider_generation FROM sandbox_runtime_product.provider_bindings WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key='desktop-main'`, tenantID, workspace.ID).Scan(&current, &productGeneration, &providerGeneration); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT provider_handoff_reference FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2`, tenantID, session.ID).Scan(&storedHandoff); err != nil {
		t.Fatal(err)
	}
	if !current || productGeneration != 1 || providerGeneration != 7 || storedHandoff != nil {
		t.Fatalf("Desktop close changed slot binding current=%v product=%d provider=%d handoff=%v", current, productGeneration, providerGeneration, storedHandoff)
	}
	var replacementCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND operation_id=$2 AND message_type='slot.reconcile'`, tenantID, closeOperation.ID).Scan(&replacementCount); err != nil || replacementCount != 0 {
		t.Fatalf("Desktop close scheduled slot replacement count=%d err=%v", replacementCount, err)
	}
}

func integrationDesktopCapabilities() providerv1.Capabilities {
	workspaceBytes := int64(16 << 30)
	return providerv1.Capabilities{ProviderRevisionID: productprovider.LockedDesktopProviderRevision, APIVersion: providerv1.APIVersionV1,
		Capabilities: []providerv1.Capability{{ID: providerv1.CapabilityDesktop, Versions: []string{product.DesktopCapabilityVersion}, Profiles: []string{product.DesktopCapabilityProfile}}},
		RuntimeProfiles: []providerv1.RuntimeProfile{{ID: product.DesktopSlotProfile, IsolationClass: providerv1.IsolationContainer,
			RuntimeClassName: desktopimage.RuntimeClassName, Architecture: []providerv1.Architecture{providerv1.ArchitectureAMD64, providerv1.ArchitectureARM64},
			CapabilityProfileIDs: []string{product.DesktopCapabilityProfile}}},
		Limits: providerv1.ProviderLimits{MaxCPUMillis: 16000, MaxMemoryBytes: 16 << 30, MaxEphemeralStorageBytes: 32 << 30,
			MaxWorkspaceBytes: &workspaceBytes, MaxLeaseSeconds: 86400}}
}

func integrationDesktopOperation(operationID, attemptID, sandboxID string, fence int64, operationType providerv1.OperationType, now time.Time) providerv1.Operation {
	return providerv1.Operation{OperationID: operationID, AttemptID: attemptID, FencingToken: fence, SandboxID: sandboxID,
		Type: operationType, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + operationID,
		ObservedAt: now.Format(time.RFC3339Nano)}
}

func desktopSandboxIDFromPath(path string) string {
	value := strings.TrimPrefix(path, "/v1/sandboxes/")
	if index := strings.IndexByte(value, '/'); index >= 0 {
		return value[:index]
	}
	if index := strings.IndexByte(value, ':'); index >= 0 {
		return value[:index]
	}
	return value
}
