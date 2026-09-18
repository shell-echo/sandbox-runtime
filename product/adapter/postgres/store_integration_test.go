//go:build integration

package productpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
	productbloblocal "github.com/shell-echo/sandbox-runtime/product/adapter/blob/local"
	productguest "github.com/shell-echo/sandbox-runtime/product/adapter/guest"
	productrecordinglocal "github.com/shell-echo/sandbox-runtime/product/adapter/recording/local"
	"github.com/shell-echo/sandbox-runtime/productapi"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
)

const productPostgresURLVariable = "SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL"

type allowPrimarySlot struct{}

func (allowPrimarySlot) AuthorizePrimarySlot(context.Context, product.SlotSpec) error { return nil }

type allowTerminalSession struct{}

func (allowTerminalSession) AuthorizeSession(context.Context, string, string) error { return nil }

type allowBrowserSession struct{}

func (allowBrowserSession) AuthorizeSession(_ context.Context, kind, profile string) error {
	if (kind == product.SessionKindBrowserAutomation && profile == product.SessionProfileBrowserAutomation) ||
		(kind == product.SessionKindBrowserLive && profile == product.SessionProfileBrowserLive) {
		return nil
	}
	return product.ErrCapabilityUnsupported
}

type allowBrowserSlot struct{}

func (allowBrowserSlot) AuthorizeSlot(context.Context, product.SlotSpec) error { return nil }

func TestIntegrationBrowserSlotAuthorityReplayQuotaAndNondisclosure(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-browser-slot"
	cleanupProductTenant(t, pool, tenantID)
	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, allowPrimarySlot{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	slots, err := product.NewSlotService(store, allowBrowserSlot{}, ids)
	if err != nil {
		t.Fatal(err)
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: "browser-slot-owner"}
	firstWorkspace, err := application.CreateWorkspace(context.Background(), tenantID, actor, "browser-slot-workspace-1", integrationCreateWorkspaceRequest("browser slot one"))
	if err != nil {
		t.Fatal(err)
	}
	secondWorkspace, err := application.CreateWorkspace(context.Background(), tenantID, actor, "browser-slot-workspace-2", integrationCreateWorkspaceRequest("browser slot two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas
    (tenant_id,max_workspaces,max_sessions,max_active_transfers,max_browser_slots,updated_at)
VALUES($1,100,1000,100,1,clock_timestamp())`, tenantID); err != nil {
		t.Fatal(err)
	}
	request := product.PutSlotRequest{ExpectedWorkspaceVersion: 1, Kind: "browser", ProfileID: product.BrowserSlotProfile,
		RequiredCapabilities: []product.CapabilityRequirement{{CapabilityID: product.BrowserCapabilityID, Version: product.BrowserCapabilityVersion, ProfileID: product.BrowserCapabilityProfile}}, DesiredState: "ready"}
	operation, replay, err := slots.Put(context.Background(), tenantID, actor, firstWorkspace.Operation.WorkspaceID, "browser-main", "browser-slot-put-1", request)
	if err != nil || replay || operation.Type != "put_slot" || operation.SlotKey != "browser-main" {
		t.Fatalf("put operation=%#v replay=%v err=%v", operation, replay, err)
	}
	slot, err := slots.Get(context.Background(), tenantID, actor, firstWorkspace.Operation.WorkspaceID, "browser-main")
	if err != nil || slot.Generation != 1 || slot.DesiredState != "ready" || slot.ObservedState != "requested" {
		t.Fatalf("slot=%#v err=%v", slot, err)
	}
	replayed, replay, err := slots.Put(context.Background(), tenantID, actor, firstWorkspace.Operation.WorkspaceID, "browser-main", "browser-slot-put-1", request)
	if err != nil || !replay || replayed.ID != operation.ID {
		t.Fatalf("replay=%#v replayed=%v err=%v", replayed, replay, err)
	}
	conflict := request
	conflict.DesiredState = "suspended"
	if _, _, err := slots.Put(context.Background(), tenantID, actor, firstWorkspace.Operation.WorkspaceID, "browser-main", "browser-slot-put-1", conflict); !errors.Is(err, product.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict err=%v", err)
	}
	if _, err := slots.Get(context.Background(), tenantID, product.ActorRef{Type: product.ActorHuman, ID: "other-owner"}, firstWorkspace.Operation.WorkspaceID, "browser-main"); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner read err=%v", err)
	}
	if _, _, err := slots.Put(context.Background(), tenantID, actor, secondWorkspace.Operation.WorkspaceID, "browser-main", "browser-slot-put-2", request); !errors.Is(err, product.ErrQuotaExceeded) {
		t.Fatalf("quota err=%v", err)
	}

	terminate := request
	terminate.ExpectedWorkspaceVersion = 2
	terminate.DesiredState = "terminated"
	if _, _, err := slots.Put(context.Background(), tenantID, actor, firstWorkspace.Operation.WorkspaceID, "browser-main", "browser-slot-terminate-1", terminate); err != nil {
		t.Fatal(err)
	}
	if _, _, err := slots.Put(context.Background(), tenantID, actor, secondWorkspace.Operation.WorkspaceID, "browser-main", "browser-slot-put-2", request); err != nil {
		t.Fatalf("quota was not released after termination: %v", err)
	}
	for table, want := range map[string]int{"outbox": 5, "workspace_events": 5, "product_operations": 5, "security_audit": 5} {
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.`+table+` WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s count=%d want=%d", table, count, want)
		}
	}
	var messageType string
	if err := pool.QueryRow(context.Background(), `SELECT message_type FROM sandbox_runtime_product.outbox
WHERE tenant_id=$1 AND operation_id=$2`, tenantID, operation.ID).Scan(&messageType); err != nil || messageType != "slot.reconcile" {
		t.Fatalf("outbox message=%q err=%v", messageType, err)
	}
}

func TestIntegrationBrowserSlotConcurrentQuotaAndIdempotency(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-browser-slot-races"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 5*time.Second)
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowBrowserSlot{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "browser-slot-race-owner"}
	first, err := application.CreateWorkspace(context.Background(), tenantID, actor, "slot-race-workspace-1", integrationCreateWorkspaceRequest("slot race one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := application.CreateWorkspace(context.Background(), tenantID, actor, "slot-race-workspace-2", integrationCreateWorkspaceRequest("slot race two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas
    (tenant_id,max_workspaces,max_sessions,max_active_transfers,max_browser_slots,updated_at)
VALUES($1,100,1000,100,1,clock_timestamp())`, tenantID); err != nil {
		t.Fatal(err)
	}
	request := product.PutSlotRequest{ExpectedWorkspaceVersion: 1, Kind: "browser", ProfileID: product.BrowserSlotProfile,
		RequiredCapabilities: []product.CapabilityRequirement{{CapabilityID: product.BrowserCapabilityID, Version: product.BrowserCapabilityVersion, ProfileID: product.BrowserCapabilityProfile}}, DesiredState: "ready"}

	type result struct {
		operation product.Operation
		replay    bool
		err       error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			operation, replay, err := slots.Put(context.Background(), tenantID, actor, first.Operation.WorkspaceID, "browser-main", "slot-idempotency-race", request)
			results <- result{operation: operation, replay: replay, err: err}
		}()
	}
	close(start)
	firstResult, secondResult := <-results, <-results
	if firstResult.err != nil || secondResult.err != nil || firstResult.operation.ID != secondResult.operation.ID || firstResult.replay == secondResult.replay {
		t.Fatalf("idempotency race first=%#v second=%#v", firstResult, secondResult)
	}

	terminate := request
	terminate.ExpectedWorkspaceVersion = 2
	terminate.DesiredState = "terminated"
	if _, _, err := slots.Put(context.Background(), tenantID, actor, first.Operation.WorkspaceID, "browser-main", "slot-idempotency-race-terminate", terminate); err != nil {
		t.Fatal(err)
	}
	third, err := application.CreateWorkspace(context.Background(), tenantID, actor, "slot-race-workspace-3", integrationCreateWorkspaceRequest("slot race three"))
	if err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	results = make(chan result, 2)
	for index, workspaceID := range []string{second.Operation.WorkspaceID, third.Operation.WorkspaceID} {
		index, workspaceID := index, workspaceID
		go func() {
			<-start
			operation, replay, err := slots.Put(context.Background(), tenantID, actor, workspaceID, "browser-main", "slot-quota-race-"+string(rune('a'+index)), request)
			results <- result{operation: operation, replay: replay, err: err}
		}()
	}
	close(start)
	firstResult, secondResult = <-results, <-results
	successes, quotas := 0, 0
	for _, item := range []result{firstResult, secondResult} {
		switch {
		case item.err == nil:
			successes++
		case errors.Is(item.err, product.ErrQuotaExceeded):
			quotas++
		default:
			t.Fatalf("quota race unexpected result=%#v", item)
		}
	}
	if successes != 1 || quotas != 1 {
		t.Fatalf("quota race successes=%d quotas=%d first=%#v second=%#v", successes, quotas, firstResult, secondResult)
	}
}

func TestIntegrationCreateWorkspaceTransactionReplayAndConflict(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-kernel")
	store, err := New(pool, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	application, err := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-kernel"}
	request := integrationCreateWorkspaceRequest("kernel workspace")
	first, err := application.CreateWorkspace(context.Background(), "tenant-product-kernel", actor, "kernel-request-1", request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Replay || first.Operation.State != "accepted" || first.Operation.ReconciliationStatus != "pending" {
		t.Fatalf("first result = %#v", first)
	}
	workspace, err := application.GetWorkspace(context.Background(), "tenant-product-kernel", actor, first.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.ID != first.Operation.WorkspaceID || len(workspace.Slots) != 1 ||
		workspace.Slots[0].SlotKey != product.PrimarySlotKey || workspace.Owner != actor {
		t.Fatalf("workspace = %#v", workspace)
	}
	page, next, err := application.ListWorkspaces(context.Background(), "tenant-product-kernel", actor, "", 1)
	if err != nil || len(page) != 1 || page[0].ID != workspace.ID || next != "" {
		t.Fatalf("ListWorkspaces() = %#v, %q, %v", page, next, err)
	}
	otherPage, _, err := application.ListWorkspaces(context.Background(), "tenant-product-kernel", product.ActorRef{Type: product.ActorHuman, ID: "other-owner"}, "", 50)
	if err != nil || len(otherPage) != 0 {
		t.Fatalf("cross-owner ListWorkspaces() = %#v, %v", otherPage, err)
	}
	operation, err := application.GetOperation(context.Background(), "tenant-product-kernel", actor, first.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.ID != first.Operation.ID || operation.SubmittedBy != actor {
		t.Fatalf("operation = %#v", operation)
	}
	assertProductKernelCounts(t, pool, "tenant-product-kernel", 1)

	replay, err := application.CreateWorkspace(context.Background(), "tenant-product-kernel", actor, "kernel-request-1", request)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replay || replay.Operation.ID != first.Operation.ID || replay.Operation.WorkspaceID != first.Operation.WorkspaceID {
		t.Fatalf("replay = %#v; first = %#v", replay, first)
	}
	assertProductKernelCounts(t, pool, "tenant-product-kernel", 1)

	request.DisplayName = "different workspace"
	if _, err := application.CreateWorkspace(context.Background(), "tenant-product-kernel", actor, "kernel-request-1", request); !errors.Is(err, product.ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	assertProductKernelCounts(t, pool, "tenant-product-kernel", 1)
}

func TestIntegrationCreateWorkspaceConcurrentReplayHasOneAuthority(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-concurrent")
	store, _ := New(pool, 5*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorAgent, ID: "agent-product-concurrent"}
	request := integrationCreateWorkspaceRequest("concurrent workspace")

	const callers = 12
	start := make(chan struct{})
	results := make(chan product.CreateWorkspaceResult, callers)
	errorsChannel := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := application.CreateWorkspace(context.Background(), "tenant-product-concurrent", actor, "same-command", request)
			results <- result
			errorsChannel <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent CreateWorkspace() error = %v", err)
		}
	}
	var operationID string
	for result := range results {
		if operationID == "" {
			operationID = result.Operation.ID
		}
		if result.Operation.ID != operationID {
			t.Fatalf("operation ID = %q; want %q", result.Operation.ID, operationID)
		}
	}
	assertProductKernelCounts(t, pool, "tenant-product-concurrent", 1)
}

func TestIntegrationCreateWorkspaceRollbackLeavesNoPartialAuthority(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-rollback")
	store, _ := New(pool, 2*time.Second)
	command := product.CreateWorkspaceCommand{
		TenantID: "tenant-product-rollback",
		Actor:    product.ActorRef{Type: product.ActorService, ID: "service-product-rollback"},
		Method:   product.CreateWorkspaceMethod, Path: product.CreateWorkspacePath,
		IdempotencyKey: "rollback-command", WorkspaceID: "wrk_product_rollback",
		OperationID: "op_product_rollback", EventID: "evt_product_rollback", OutboxID: "out_product_rollback",
		DisplayName: "rollback", Lifetime: time.Hour,
		PrimarySlot: product.SlotSpec{
			SlotKey: product.PrimarySlotKey, Kind: "invalid", ProfileID: "coding-shell-v1", DesiredState: "ready",
			RequiredCapabilities: []product.CapabilityRequirement{{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"}},
		},
	}
	command.RequestDigest[0] = 1
	if _, err := store.CreateWorkspace(context.Background(), command); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("CreateWorkspace() error = %v", err)
	}
	assertProductKernelCounts(t, pool, "tenant-product-rollback", 0)
}

func TestIntegrationProductHTTPCreateAndReadUsesPostgresAuthority(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-http")
	store, err := New(pool, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	application, err := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	const token = "product-http-integration-token-00000001"
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{{
		Token: token,
		Principal: productapi.Principal{
			TenantID: "tenant-product-http",
			Actor:    product.ActorRef{Type: product.ActorHuman, ID: "actor-product-http"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := productapiv1.NewHandler(application, authenticator, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	body := `{"display_name":"HTTP workspace","lifetime_seconds":3600,"primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}}`
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/workspaces", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "http-create-1")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("POST status = %d", response.StatusCode)
	}
	var operation productapiv1.ProductOperation
	if err := json.NewDecoder(response.Body).Decode(&operation); err != nil {
		t.Fatal(err)
	}
	if operation.WorkspaceID == "" || operation.OperationID == "" {
		t.Fatalf("operation = %#v", operation)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/workspaces/"+operation.WorkspaceID, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", response.StatusCode)
	}
	var workspace productapiv1.Workspace
	if err := json.NewDecoder(response.Body).Decode(&workspace); err != nil {
		t.Fatal(err)
	}
	if workspace.WorkspaceID != operation.WorkspaceID || workspace.TenantID != "tenant-product-http" {
		t.Fatalf("workspace = %#v", workspace)
	}
}

func TestIntegrationOutboxLeaseDispatchEvidenceAndEventAreAtomic(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-outbox")
	store, _ := New(pool, 2*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-outbox"}
	created, err := application.CreateWorkspace(context.Background(), "tenant-product-outbox", actor, "outbox-create-1", integrationCreateWorkspaceRequest("outbox workspace"))
	if err != nil {
		t.Fatal(err)
	}
	leased, err := store.LeaseReconcileWork(context.Background(), "worker-product-1", 10*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].OperationID != created.Operation.ID || leased[0].AttemptID != leased[0].OutboxID {
		t.Fatalf("leased = %#v", leased)
	}
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: strings.Repeat("a", 40), SandboxID: "provider-sandbox-private-1",
		ProviderOperationID: "provider-operation-private-1", RequestDigest: "sha256:" + strings.Repeat("b", 64),
		State: "accepted", ObservedAt: time.Now().UTC()}
	if err := store.RecordDispatchEvidence(context.Background(), leased[0], evidence); err != nil {
		t.Fatal(err)
	}
	operation, err := application.GetOperation(context.Background(), "tenant-product-outbox", actor, created.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := application.GetWorkspace(context.Background(), "tenant-product-outbox", actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != "running" || operation.ReconciliationStatus != "reconciling" || workspace.ObservedState != "provisioning" ||
		len(workspace.Slots) != 1 || workspace.Slots[0].ObservedState != "provisioning" {
		t.Fatalf("operation=%#v workspace=%#v", operation, workspace)
	}
	var events, bindings, attempts, delivered int
	if err := pool.QueryRow(context.Background(), `SELECT
  (SELECT count(*) FROM sandbox_runtime_product.workspace_events WHERE tenant_id=$1),
  (SELECT count(*) FROM sandbox_runtime_product.provider_bindings WHERE tenant_id=$1),
  (SELECT count(*) FROM sandbox_runtime_product.product_operation_attempts WHERE tenant_id=$1),
  (SELECT count(*) FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND state='delivered')`, "tenant-product-outbox").Scan(&events, &bindings, &attempts, &delivered); err != nil {
		t.Fatal(err)
	}
	if events != 2 || bindings != 1 || attempts != 1 || delivered != 1 {
		t.Fatalf("events=%d bindings=%d attempts=%d delivered=%d", events, bindings, attempts, delivered)
	}
	observations, err := store.LeaseProviderObservations(context.Background(), "observer-product-1", 10*time.Second, 10)
	if err != nil || len(observations) != 1 {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
	terminal := evidence
	terminal.State = "succeeded"
	terminal.ObservedAt = time.Now().UTC()
	if err := store.RecordProviderObservation(context.Background(), observations[0], terminal, "evt-product-provider-ready-1"); err != nil {
		t.Fatal(err)
	}
	operation, err = application.GetOperation(context.Background(), "tenant-product-outbox", actor, created.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err = application.GetWorkspace(context.Background(), "tenant-product-outbox", actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if operation.State != "succeeded" || operation.ReconciliationStatus != "complete" || workspace.ObservedState != "active" || workspace.Slots[0].ObservedState != "ready" || workspace.Slots[0].ObservedGeneration != 1 {
		t.Fatalf("terminal operation=%#v workspace=%#v", operation, workspace)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.workspace_events WHERE tenant_id=$1`, "tenant-product-outbox").Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 3 {
		t.Fatalf("terminal events=%d", events)
	}
	again, err := store.LeaseReconcileWork(context.Background(), "worker-product-2", 10*time.Second, 10)
	if err != nil || len(again) != 0 {
		t.Fatalf("second lease=%#v err=%v", again, err)
	}
}

func TestIntegrationControlLeaseUsesDatabaseTimeFenceIdempotencyAndAudit(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-control")
	store, _ := New(pool, 2*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	controls, _ := product.NewControlService(store, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-control"}
	created, err := application.CreateWorkspace(context.Background(), "tenant-product-control", actor, "control-workspace", integrationCreateWorkspaceRequest("control workspace"))
	if err != nil {
		t.Fatal(err)
	}
	request := product.AcquireControlLeaseRequest{ExpectedWorkspaceVersion: 1, Scope: product.ControlScope{Type: "workspace", ID: created.Operation.WorkspaceID}, DurationSeconds: 30}
	lease, replay, err := controls.Acquire(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID, "control-acquire-1", request)
	if err != nil || replay || lease.Fence != 1 {
		t.Fatalf("lease=%#v replay=%v err=%v", lease, replay, err)
	}
	replayed, replay, err := controls.Acquire(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID, "control-acquire-1", request)
	if err != nil || !replay || replayed.ID != lease.ID {
		t.Fatalf("replayed=%#v replay=%v err=%v", replayed, replay, err)
	}
	workspace, err := application.GetWorkspace(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	conflictRequest := request
	conflictRequest.ExpectedWorkspaceVersion = workspace.Version
	if _, _, err := controls.Acquire(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID, "control-acquire-2", conflictRequest); !errors.Is(err, product.ErrControlConflict) {
		t.Fatalf("conflict err=%v", err)
	}
	renewed, _, err := controls.Renew(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID, lease.ID, "control-renew-1", product.RenewControlLeaseRequest{Fence: lease.Fence, DurationSeconds: 60})
	if err != nil || !renewed.ExpiresAt.After(lease.ExpiresAt) {
		t.Fatalf("renewed=%#v err=%v", renewed, err)
	}
	if _, _, err := controls.Renew(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID, lease.ID, "control-renew-stale", product.RenewControlLeaseRequest{Fence: lease.Fence + 1, DurationSeconds: 60}); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("stale err=%v", err)
	}
	if replay, err := controls.Release(context.Background(), "tenant-product-control", actor, created.Operation.WorkspaceID, lease.ID, "control-release-1", lease.Fence, "done"); err != nil || replay {
		t.Fatalf("release replay=%v err=%v", replay, err)
	}
	var auditCount, eventCount int
	if err := pool.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM sandbox_runtime_product.security_audit WHERE tenant_id=$1),(SELECT count(*) FROM sandbox_runtime_product.workspace_events WHERE tenant_id=$1)`, "tenant-product-control").Scan(&auditCount, &eventCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 4 || eventCount != 4 {
		t.Fatalf("audit=%d events=%d", auditCount, eventCount)
	}
}

func TestIntegrationWorkspaceQuotaSerializesConcurrentAcceptance(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-quota")
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas(tenant_id,max_workspaces,max_sessions,max_active_transfers,updated_at)VALUES($1,1,10,10,clock_timestamp())`, "tenant-product-quota"); err != nil {
		t.Fatal(err)
	}
	store, _ := New(pool, 5*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-quota"}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func(index int) {
			<-start
			_, err := application.CreateWorkspace(context.Background(), "tenant-product-quota", actor, "quota-"+string(rune('a'+index)), integrationCreateWorkspaceRequest("quota workspace"))
			results <- err
		}(index)
	}
	close(start)
	accepted, limited := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			accepted++
		} else if errors.Is(err, product.ErrQuotaExceeded) {
			limited++
		} else {
			t.Fatalf("unexpected err=%v", err)
		}
	}
	if accepted != 1 || limited != 1 {
		t.Fatalf("accepted=%d limited=%d", accepted, limited)
	}
}

func TestIntegrationTerminalSessionIntentDispatchAndCloseAreDurable(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-session")
	store, _ := New(pool, 2*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	sessions, _ := product.NewSessionService(store, allowTerminalSession{}, product.CryptoIDGenerator{})
	controls, _ := product.NewControlService(store, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-session"}
	created, err := application.CreateWorkspace(context.Background(), "tenant-product-session", actor, "session-workspace", integrationCreateWorkspaceRequest("session workspace"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE sandbox_runtime_product.workspaces SET observed_state='active' WHERE tenant_id=$1`,
		`UPDATE sandbox_runtime_product.workspace_slots SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1`,
		`INSERT INTO sandbox_runtime_product.product_operation_attempts(tenant_id,operation_id,attempt_id,workspace_id,slot_key,slot_generation,fencing_token,idempotency_key,request_digest,provider_revision_id,provider_operation_id,state,outcome,deadline_at,dispatched_at,observed_at,created_at,updated_at)
		SELECT tenant_id,operation_id,'bootstrap-attempt',workspace_id,'primary-code',1,1,'bootstrap','sha256:'||repeat('b',64),repeat('a',40),'bootstrap-provider-op','succeeded','known',clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp(),clock_timestamp(),clock_timestamp() FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1`,
		`INSERT INTO sandbox_runtime_product.provider_bindings(tenant_id,workspace_id,slot_key,slot_generation,binding_generation,provider_revision_id,runtime_profile_id,sandbox_id,create_operation_id,create_attempt_id,provider_operation_id,observed_state,current,last_observed_at,created_at,updated_at)
SELECT tenant_id,workspace_id,'primary-code',1,1,repeat('a',40),'coding-shell-v1','provider-sandbox-session',operation_id,'bootstrap-attempt','bootstrap-provider-op','ready',true,clock_timestamp(),clock_timestamp(),clock_timestamp() FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1`,
	} {
		if _, err := pool.Exec(context.Background(), statement, "tenant-product-session"); err != nil {
			t.Fatal(err)
		}
	}
	workspace, err := application.GetWorkspace(context.Background(), "tenant-product-session", actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := sessions.Create(context.Background(), "tenant-product-session", actor, created.Operation.WorkspaceID, "session-create-1", product.CreateSessionRequest{ExpectedWorkspaceVersion: workspace.Version, SlotKey: product.PrimarySlotKey, Kind: "terminal", ProtocolProfile: "product-terminal.v1", ExpiresInSeconds: 3600, RecordingPolicy: "metadata_only"})
	if err != nil {
		t.Fatal(err)
	}
	work, err := store.LeaseSessionWork(context.Background(), "session-worker-1", 10*time.Second, 10)
	if err != nil || len(work) != 1 || work[0].Action != "open" {
		t.Fatalf("work=%#v err=%v", work, err)
	}
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: strings.Repeat("a", 40), SandboxID: "provider-sandbox-session", ProviderOperationID: "provider-session-open", RequestDigest: "sha256:" + strings.Repeat("c", 64), State: "succeeded", ObservedAt: time.Now().UTC()}
	if err := store.RecordSessionDispatch(context.Background(), work[0], evidence); err != nil {
		t.Fatal(err)
	}
	session, err := sessions.Get(context.Background(), "tenant-product-session", actor, operation.SessionID)
	if err != nil || session.State != "provisioning" {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	observations, err := store.LeaseProviderObservations(context.Background(), "session-observer-1", 10*time.Second, 10)
	if err != nil || len(observations) != 1 {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
	evidence.HandoffReference = "ref:session:private-session-reference"
	evidence.ConnectionGeneration = 1
	evidence.HandoffExpiresAt = session.ExpiresAt
	if err := store.RecordProviderObservation(context.Background(), observations[0], evidence, "evt-session-ready"); err != nil {
		t.Fatal(err)
	}
	session, err = sessions.Get(context.Background(), "tenant-product-session", actor, operation.SessionID)
	if err != nil || session.State != "ready" {
		t.Fatalf("ready session=%#v err=%v", session, err)
	}
	workspace, err = application.GetWorkspace(context.Background(), "tenant-product-session", actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := controls.Acquire(context.Background(), "tenant-product-session", actor, workspace.ID, "session-control-1", product.AcquireControlLeaseRequest{ExpectedWorkspaceVersion: workspace.Version, Scope: product.ControlScope{Type: "session", ID: session.ID}, DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	grantRepository, err := NewGrantRepository(store, "test-key-v1", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := product.NewGrantService(grantRepository, product.CryptoIDGenerator{}, product.CryptoTicketGenerator{}, "wss://gateway.example.test/connect", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	connectionRequest := product.CreateConnectionRequest{ExpectedSessionVersion: session.Version, ProtocolProfile: session.ProtocolProfile, ControlLeaseID: control.ID, ControlFence: control.Fence}
	grant, replay, err := grants.Create(context.Background(), "tenant-product-session", actor, session.ID, "connection-grant-1", connectionRequest)
	if err != nil || replay || grant.Ticket == "" || grant.GatewayURI != "wss://gateway.example.test/connect" {
		t.Fatalf("grant=%#v replay=%v err=%v", grant, replay, err)
	}
	replayedGrant, replay, err := grants.Create(context.Background(), "tenant-product-session", actor, session.ID, "connection-grant-1", connectionRequest)
	if err != nil || !replay || replayedGrant.Ticket != grant.Ticket {
		t.Fatalf("replayed grant=%#v replay=%v err=%v", replayedGrant, replay, err)
	}
	var ciphertext []byte
	if err := pool.QueryRow(context.Background(), `SELECT ticket_ciphertext FROM sandbox_runtime_product.connection_grants WHERE tenant_id=$1 AND connection_id=$2`, "tenant-product-session", grant.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(grant.Ticket)) {
		t.Fatal("connection ticket stored in plaintext")
	}
	binding, err := grantRepository.ConsumeConnectionGrant(context.Background(), grant.Ticket)
	if err != nil || binding.HandoffReference != evidence.HandoffReference || binding.ControlFence != control.Fence {
		t.Fatalf("binding=%#v err=%v", binding, err)
	}
	if _, err := grantRepository.ConsumeConnectionGrant(context.Background(), grant.Ticket); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("ticket replay err=%v", err)
	}
	closeOperation, _, err := sessions.Close(context.Background(), "tenant-product-session", actor, session.ID, "session-close-1", product.CloseSessionRequest{ExpectedVersion: session.Version, Reason: "done"})
	if err != nil {
		t.Fatal(err)
	}
	work, err = store.LeaseSessionWork(context.Background(), "session-worker-2", 10*time.Second, 10)
	if err != nil || len(work) != 1 || work[0].Action != "close" {
		t.Fatalf("close work=%#v err=%v", work, err)
	}
	evidence.ProviderOperationID = "provider-session-close"
	if err := store.RecordSessionDispatch(context.Background(), work[0], evidence); err != nil {
		t.Fatal(err)
	}
	session, err = sessions.Get(context.Background(), "tenant-product-session", actor, session.ID)
	if err != nil || session.State != "closed" {
		t.Fatalf("closed session=%#v err=%v", session, err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), binding); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("closed session gateway authority err=%v", err)
	}
	final, err := application.GetOperation(context.Background(), "tenant-product-session", actor, closeOperation.ID)
	if err != nil || final.State != "succeeded" {
		t.Fatalf("final=%#v err=%v", final, err)
	}
}

func TestIntegrationBrowserSessionAuthorityIsDurableAndTerminalWorkerCannotConsumeIt(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-product-browser-session"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 2*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	sessions, _ := product.NewSessionService(store, allowBrowserSession{}, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-browser-session"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "browser-workspace", integrationCreateWorkspaceRequest("browser session workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.workspace_slots
    (tenant_id,workspace_id,slot_key,kind,profile_id,required_capabilities,desired_state,observed_state,generation,observed_generation,version,created_at,updated_at)
VALUES ($1,$2,'browser-main','browser','sandbox-runtime-browser-v1',
    '[{"capability_id":"sandbox.browser","version":"1.0.0","profile_id":"browser-v1"}]'::jsonb,
    'ready','ready',1,1,1,clock_timestamp(),clock_timestamp())`, tenantID, created.Operation.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	workspace, err := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	request := product.CreateSessionRequest{ExpectedWorkspaceVersion: workspace.Version, SlotKey: "browser-main", Kind: product.SessionKindBrowserLive, ProtocolProfile: product.SessionProfileBrowserLive, ExpiresInSeconds: 900, RecordingPolicy: "required"}
	operation, replay, err := sessions.Create(context.Background(), tenantID, actor, workspace.ID, "browser-session-create-1", request)
	if err != nil || replay || operation.SessionID == "" {
		t.Fatalf("operation=%#v replay=%v err=%v", operation, replay, err)
	}
	replayed, replay, err := sessions.Create(context.Background(), tenantID, actor, workspace.ID, "browser-session-create-1", request)
	if err != nil || !replay || replayed.ID != operation.ID {
		t.Fatalf("replayed=%#v replay=%v err=%v", replayed, replay, err)
	}
	conflictingRequest := request
	conflictingRequest.RecordingPolicy = "metadata_only"
	if _, _, err := sessions.Create(context.Background(), tenantID, actor, workspace.ID, "browser-session-create-1", conflictingRequest); !errors.Is(err, product.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict err=%v", err)
	}
	session, err := sessions.Get(context.Background(), tenantID, actor, operation.SessionID)
	if err != nil || session.Kind != product.SessionKindBrowserLive || session.ProtocolProfile != product.SessionProfileBrowserLive || session.State != product.SessionStateRequested {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	if _, err := sessions.Get(context.Background(), tenantID, product.ActorRef{Type: product.ActorHuman, ID: "other-owner"}, operation.SessionID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-actor read err=%v", err)
	}
	if _, err := sessions.Get(context.Background(), "other-tenant", actor, operation.SessionID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-tenant read err=%v", err)
	}
	var outboxType string
	if err := pool.QueryRow(context.Background(), `SELECT message_type FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND operation_id=$2`, tenantID, operation.ID).Scan(&outboxType); err != nil || outboxType != "browser_session.open" {
		t.Fatalf("outbox type=%q err=%v", outboxType, err)
	}
	if work, err := store.LeaseSessionWork(context.Background(), "terminal-worker", 10*time.Second, 10); err != nil || len(work) != 0 {
		t.Fatalf("terminal worker consumed browser work=%#v err=%v", work, err)
	}
	closeOperation, replay, err := sessions.Close(context.Background(), tenantID, actor, session.ID, "browser-session-close-1", product.CloseSessionRequest{ExpectedVersion: session.Version, Reason: "owner requested close"})
	if err != nil || replay || closeOperation.SessionID != session.ID {
		t.Fatalf("close=%#v replay=%v err=%v", closeOperation, replay, err)
	}
	session, err = sessions.Get(context.Background(), tenantID, actor, session.ID)
	if err != nil || session.State != product.SessionStateDraining {
		t.Fatalf("draining session=%#v err=%v", session, err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT message_type FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND operation_id=$2`, tenantID, closeOperation.ID).Scan(&outboxType); err != nil || outboxType != "browser_session.close" {
		t.Fatalf("close outbox type=%q err=%v", outboxType, err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.runtime_sessions
    (tenant_id,session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at)
VALUES ($1,'ses-invalid-browser-profile',$2,'browser-main',1,'human',$3,'browser_live','product-browser-automation.v1','requested',true,'disabled',1,clock_timestamp()+interval '5 minutes',clock_timestamp(),clock_timestamp())`, tenantID, workspace.ID, actor.ID); err == nil {
		t.Fatal("database accepted mismatched browser kind/profile")
	}
}

func TestIntegrationGuestBindingChallengeRotationAndRevocation(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-guest")
	store, _ := New(pool, 2*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	guests, _ := product.NewGuestService(store, product.CryptoIDGenerator{})
	authenticator, _ := productguest.NewAuthenticator(store)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-guest"}
	created, err := application.CreateWorkspace(context.Background(), "tenant-product-guest", actor, "guest-workspace", integrationCreateWorkspaceRequest("guest workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.workspace_slots SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1`, "tenant-product-guest"); err != nil {
		t.Fatal(err)
	}
	workspace, _ := application.GetWorkspace(context.Background(), "tenant-product-guest", actor, created.Operation.WorkspaceID)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	request := product.ProvisionGuestRequest{ExpectedWorkspaceVersion: workspace.Version, SlotKey: product.PrimarySlotKey, ProtocolVersion: guestagent.ProtocolVersion, Capabilities: []string{"guest.health", "files.list"}, PublicKey: publicKey, LifetimeSeconds: 600}
	binding, replay, err := guests.Provision(context.Background(), "tenant-product-guest", actor, workspace.ID, "guest-provision-1", request)
	if err != nil || replay || binding.BindingGeneration != 1 {
		t.Fatalf("binding=%#v replay=%v err=%v", binding, replay, err)
	}
	replayed, replay, err := guests.Provision(context.Background(), "tenant-product-guest", actor, workspace.ID, "guest-provision-1", request)
	if err != nil || !replay || replayed.GuestID != binding.GuestID {
		t.Fatalf("replayed=%#v replay=%v err=%v", replayed, replay, err)
	}
	authRequest := signedGuestAuth(t, binding, privateKey, "challenge-a")
	identity, err := authenticator.Authenticate(context.Background(), authRequest)
	if err != nil || identity.TenantID != "tenant-product-guest" || len(identity.Capabilities) != 2 {
		t.Fatalf("identity=%#v err=%v", identity, err)
	}
	if err := authenticator.CheckAuthority(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.Disconnected(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	workspace, _ = application.GetWorkspace(context.Background(), "tenant-product-guest", actor, workspace.ID)
	newPublicKey, newPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated, _, err := guests.Provision(context.Background(), "tenant-product-guest", actor, workspace.ID, "guest-provision-2", product.ProvisionGuestRequest{ExpectedWorkspaceVersion: workspace.Version, SlotKey: product.PrimarySlotKey, ProtocolVersion: guestagent.ProtocolVersion, Capabilities: []string{"guest.health", "files.list", "files.stat", "files.snapshot"}, PublicKey: newPublicKey, LifetimeSeconds: 600})
	if err != nil || rotated.BindingGeneration != 2 || rotated.GuestID == binding.GuestID {
		t.Fatalf("rotated=%#v err=%v", rotated, err)
	}
	if _, err := authenticator.Authenticate(context.Background(), signedGuestAuth(t, binding, privateKey, "challenge-old")); !errors.Is(err, guestagent.ErrUnauthorized) {
		t.Fatalf("old credential err=%v", err)
	}
	newIdentity, err := authenticator.Authenticate(context.Background(), signedGuestAuth(t, rotated, newPrivateKey, "challenge-new"))
	if err != nil {
		t.Fatal(err)
	}
	fileAuthority := product.FileAuthority{TenantID: newIdentity.TenantID, WorkspaceID: newIdentity.WorkspaceID, SlotKey: newIdentity.SlotKey, GuestID: newIdentity.GuestID, SlotGeneration: newIdentity.SlotGeneration, BindingGeneration: newIdentity.BindingGeneration}
	firstSnapshot := product.FileSnapshot{Authority: fileAuthority, Entries: []product.FileEntry{
		{Path: "src", Name: "src", Type: "directory", Mode: 0o755, ModifiedAt: time.Now().UTC(), Revision: "sha256:" + strings.Repeat("1", 64)},
		{Path: "src/a.txt", Name: "a.txt", Type: "file", Mode: 0o640, SizeBytes: 3, ModifiedAt: time.Now().UTC(), Revision: "sha256:" + strings.Repeat("2", 64)},
	}}
	changes, err := store.ApplyFileSnapshot(context.Background(), product.FileSnapshotCommand{TenantID: "tenant-product-guest", WorkspaceID: workspace.ID, SlotKey: product.PrimarySlotKey, Actor: actor, Snapshot: firstSnapshot})
	if err != nil || len(changes) != 2 || changes[0].Sequence != 1 {
		t.Fatalf("first changes=%#v err=%v", changes, err)
	}
	renamedSnapshot := firstSnapshot
	renamedSnapshot.Entries = append([]product.FileEntry(nil), firstSnapshot.Entries...)
	renamedSnapshot.Entries[1].Path = "src/b.txt"
	renamedSnapshot.Entries[1].Name = "b.txt"
	changes, err = store.ApplyFileSnapshot(context.Background(), product.FileSnapshotCommand{TenantID: "tenant-product-guest", WorkspaceID: workspace.ID, SlotKey: product.PrimarySlotKey, Actor: actor, Snapshot: renamedSnapshot})
	if err != nil || len(changes) != 1 || changes[0].Type != "rename" || changes[0].PreviousPath != "src/a.txt" || changes[0].Path != "src/b.txt" {
		t.Fatalf("rename changes=%#v err=%v", changes, err)
	}
	renamedSnapshot.Entries[1].Revision = "sha256:" + strings.Repeat("3", 64)
	changes, err = store.ApplyFileSnapshot(context.Background(), product.FileSnapshotCommand{TenantID: "tenant-product-guest", WorkspaceID: workspace.ID, SlotKey: product.PrimarySlotKey, Actor: actor, Snapshot: renamedSnapshot})
	if err != nil || len(changes) != 1 || changes[0].Type != "modify" {
		t.Fatalf("modify changes=%#v err=%v", changes, err)
	}
	page, err := store.ListFileChanges(context.Background(), "tenant-product-guest", actor, workspace.ID, product.PrimarySlotKey, 0, 10)
	if err != nil || len(page) != 4 || page[3].Sequence != 4 {
		t.Fatalf("change page=%#v err=%v", page, err)
	}
	if _, err := store.ListFileChanges(context.Background(), "tenant-other", actor, workspace.ID, product.PrimarySlotKey, 0, 10); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-tenant file changes err=%v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.file_changes(tenant_id,workspace_id,slot_key,sequence,path,change_type,revision,occurred_at) SELECT $1,$2,$3,value,'retained/'||value,'modify','sha256:'||repeat('4',64),clock_timestamp() FROM generate_series(5,1002) AS value`, "tenant-product-guest", workspace.ID, product.PrimarySlotKey); err != nil {
		t.Fatal(err)
	}
	changes, err = store.ApplyFileSnapshot(context.Background(), product.FileSnapshotCommand{TenantID: "tenant-product-guest", WorkspaceID: workspace.ID, SlotKey: product.PrimarySlotKey, Actor: actor, Snapshot: renamedSnapshot})
	if err != nil || len(changes) != 0 {
		t.Fatalf("retention refresh changes=%#v err=%v", changes, err)
	}
	if _, err := store.ListFileChanges(context.Background(), "tenant-product-guest", actor, workspace.ID, product.PrimarySlotKey, 1, 10); !errors.Is(err, product.ErrCursorExpired) {
		t.Fatalf("expired file cursor err=%v", err)
	}
	if err := store.RevokeGuest(context.Background(), "tenant-product-guest", rotated.GuestID, "removed"); err != nil {
		t.Fatal(err)
	}
	if err := authenticator.CheckAuthority(context.Background(), newIdentity); !errors.Is(err, guestagent.ErrUnauthorized) {
		t.Fatalf("revoked authority err=%v", err)
	}
	if _, err := store.ApplyFileSnapshot(context.Background(), product.FileSnapshotCommand{TenantID: "tenant-product-guest", WorkspaceID: workspace.ID, SlotKey: product.PrimarySlotKey, Actor: actor, Snapshot: renamedSnapshot}); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("stale file snapshot err=%v", err)
	}
}

func TestIntegrationResumableTransferDigestRevisionCASAndCleanup(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	cleanupProductTenant(t, pool, "tenant-product-transfer")
	store, _ := New(pool, 3*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	blobs, err := productbloblocal.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	transfers, _ := product.NewTransferService(store, blobs, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-transfer"}
	created, err := application.CreateWorkspace(context.Background(), "tenant-product-transfer", actor, "transfer-workspace", integrationCreateWorkspaceRequest("transfer workspace"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas(tenant_id,max_workspaces,max_sessions,max_active_transfers,updated_at)VALUES($1,10,10,1,clock_timestamp())`, "tenant-product-transfer"); err != nil {
		t.Fatal(err)
	}
	manifest := product.RevisionManifest{Entries: []product.RevisionManifestEntry{{Path: "README.md", Type: "file", Mode: 0o644, SizeBytes: 5, Digest: "sha256:" + strings.Repeat("a", 64)}, {Path: "src", Type: "directory", Mode: 0o755}}}
	document, _ := json.Marshal(manifest)
	digestBytes := sha256.Sum256(document)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	beginRequest := product.BeginUploadRequest{ExpectedWorkspaceVersion: 1, Digest: digest, SizeBytes: int64(len(document)), ExpiresInSeconds: 600}
	upload, replay, err := transfers.BeginUpload(context.Background(), "tenant-product-transfer", actor, created.Operation.WorkspaceID, "upload-manifest-1", beginRequest)
	if err != nil || replay || upload.State != "pending" {
		t.Fatalf("upload=%#v replay=%v err=%v", upload, replay, err)
	}
	workspace, _ := application.GetWorkspace(context.Background(), "tenant-product-transfer", actor, created.Operation.WorkspaceID)
	if _, _, err := transfers.BeginUpload(context.Background(), "tenant-product-transfer", actor, workspace.ID, "upload-over-quota", product.BeginUploadRequest{ExpectedWorkspaceVersion: workspace.Version, Digest: digest, SizeBytes: int64(len(document)), ExpiresInSeconds: 600}); !errors.Is(err, product.ErrQuotaExceeded) {
		t.Fatalf("quota err=%v", err)
	}
	half := len(document) / 2
	progress, err := transfers.Append(context.Background(), "tenant-product-transfer", actor, upload.ID, 0, document[:half])
	if err != nil || progress.CommittedBytes != int64(half) {
		t.Fatalf("progress=%#v err=%v", progress, err)
	}
	privateRecord, err := store.GetTransfer(context.Background(), "tenant-product-transfer", actor, upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blobs.Append(context.Background(), privateRecord.ObjectReference, int64(half), document[half:]); err != nil {
		t.Fatal(err)
	}
	resumed, err := transfers.Resume(context.Background(), "tenant-product-transfer", actor, upload.ID)
	if err != nil || resumed.CommittedBytes != int64(len(document)) {
		t.Fatalf("resumed=%#v err=%v", resumed, err)
	}
	completed, err := transfers.Complete(context.Background(), "tenant-product-transfer", actor, upload.ID)
	if err != nil || completed.State != "complete" || completed.Digest != digest {
		t.Fatalf("completed=%#v err=%v", completed, err)
	}
	replayedUpload, replay, err := transfers.BeginUpload(context.Background(), "tenant-product-transfer", actor, created.Operation.WorkspaceID, "upload-manifest-1", beginRequest)
	if err != nil || !replay || replayedUpload.ID != upload.ID || replayedUpload.State != "complete" {
		t.Fatalf("replayed upload=%#v replay=%v err=%v", replayedUpload, replay, err)
	}
	commitRequest := product.CommitRevisionRequest{ExpectedWorkspaceVersion: workspace.Version, UploadTransferID: upload.ID}
	revision, replay, err := transfers.CommitRevision(context.Background(), "tenant-product-transfer", actor, workspace.ID, "commit-revision-1", commitRequest)
	if err != nil || replay || revision.ParentRevisionID != "" || revision.FileCount != 1 || revision.SizeBytes != 5 {
		t.Fatalf("revision=%#v replay=%v err=%v", revision, replay, err)
	}
	replayedRevision, replay, err := transfers.CommitRevision(context.Background(), "tenant-product-transfer", actor, workspace.ID, "commit-revision-1", commitRequest)
	if err != nil || !replay || replayedRevision.ID != revision.ID {
		t.Fatalf("replayed revision=%#v replay=%v err=%v", replayedRevision, replay, err)
	}
	download, err := transfers.BeginRevisionDownload(context.Background(), "tenant-product-transfer", actor, workspace.ID, revision.ID)
	if err != nil || download.Direction != "download" {
		t.Fatalf("download=%#v err=%v", download, err)
	}
	read, eof, err := transfers.ReadDownload(context.Background(), "tenant-product-transfer", actor, download.ID, 0, product.MaxChunkBytes)
	if err != nil || !eof || !bytes.Equal(read, document) {
		t.Fatalf("download read=%q eof=%v err=%v", read, eof, err)
	}
	workspace, _ = application.GetWorkspace(context.Background(), "tenant-product-transfer", actor, workspace.ID)
	badDigest := "sha256:" + strings.Repeat("0", 64)
	bad, _, err := transfers.BeginUpload(context.Background(), "tenant-product-transfer", actor, workspace.ID, "upload-bad-digest", product.BeginUploadRequest{ExpectedWorkspaceVersion: workspace.Version, Digest: badDigest, SizeBytes: int64(len(document)), ExpiresInSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Append(context.Background(), "tenant-product-transfer", actor, bad.ID, 0, document); err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Complete(context.Background(), "tenant-product-transfer", actor, bad.ID); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("digest mismatch complete err=%v", err)
	}
	badRecord, _ := store.GetTransfer(context.Background(), "tenant-product-transfer", actor, bad.ID)
	if err := transfers.Cancel(context.Background(), "tenant-product-transfer", actor, bad.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := blobs.Inspect(context.Background(), badRecord.ObjectReference); err == nil {
		t.Fatal("cancelled staging object was not removed")
	}
	workspace, _ = application.GetWorkspace(context.Background(), "tenant-product-transfer", actor, workspace.ID)
	concurrentRequest := product.CommitRevisionRequest{ExpectedWorkspaceVersion: workspace.Version, ExpectedHeadRevisionID: revision.ID, UploadTransferID: upload.ID}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, key := range []string{"commit-race-a", "commit-race-b"} {
		key := key
		go func() {
			<-start
			_, _, err := transfers.CommitRevision(context.Background(), "tenant-product-transfer", actor, workspace.ID, key, concurrentRequest)
			results <- err
		}()
	}
	close(start)
	var success, conflicts int
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, product.ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent revision err=%v", err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("revision race success=%d conflicts=%d", success, conflicts)
	}
	workspace, _ = application.GetWorkspace(context.Background(), "tenant-product-transfer", actor, workspace.ID)
	abandonedDigestBytes := sha256.Sum256([]byte("abandoned"))
	abandonedDigest := "sha256:" + hex.EncodeToString(abandonedDigestBytes[:])
	abandoned, _, err := transfers.BeginUpload(context.Background(), "tenant-product-transfer", actor, workspace.ID, "upload-abandoned", product.BeginUploadRequest{ExpectedWorkspaceVersion: workspace.Version, Digest: abandonedDigest, SizeBytes: int64(len("abandoned")), ExpiresInSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	abandonedRecord, _ := store.GetTransfer(context.Background(), "tenant-product-transfer", actor, abandoned.ID)
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.blob_transfers SET created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE tenant_id=$1 AND transfer_id=$2`, "tenant-product-transfer", abandoned.ID); err != nil {
		t.Fatal(err)
	}
	cleaned, err := transfers.CleanupExpired(context.Background(), 10)
	if err != nil || cleaned != 1 {
		t.Fatalf("CleanupExpired()=%d, %v", cleaned, err)
	}
	expired, err := store.GetTransfer(context.Background(), "tenant-product-transfer", actor, abandoned.ID)
	if err != nil || expired.State != "expired" {
		t.Fatalf("expired transfer=%#v err=%v", expired, err)
	}
	if _, _, err := blobs.Inspect(context.Background(), abandonedRecord.ObjectReference); err == nil {
		t.Fatal("expired staging object was not removed")
	}
}

func TestIntegrationArtifactCatalogAndEncryptedRecordingLifecycle(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-product-catalog"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 3*time.Second)
	application, _ := product.NewApplication(store, allowPrimarySlot{}, product.CryptoIDGenerator{})
	actor := product.ActorRef{Type: product.ActorHuman, ID: "owner-product-catalog"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "catalog-workspace", integrationCreateWorkspaceRequest("catalog workspace"))
	if err != nil {
		t.Fatal(err)
	}

	blobRoot := t.TempDir()
	blobs, err := productbloblocal.New(blobRoot)
	if err != nil {
		t.Fatal(err)
	}
	transfers, _ := product.NewTransferService(store, blobs, product.CryptoIDGenerator{})
	payload := []byte("artifact body")
	payloadDigest := sha256.Sum256(payload)
	workspace, _ := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	upload, _, err := transfers.BeginUpload(context.Background(), tenantID, actor, workspace.ID, "artifact-upload", product.BeginUploadRequest{ExpectedWorkspaceVersion: workspace.Version, Digest: "sha256:" + hex.EncodeToString(payloadDigest[:]), SizeBytes: int64(len(payload)), ExpiresInSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Append(context.Background(), tenantID, actor, upload.ID, 0, payload); err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Complete(context.Background(), tenantID, actor, upload.ID); err != nil {
		t.Fatal(err)
	}
	workspace, _ = application.GetWorkspace(context.Background(), tenantID, actor, workspace.ID)
	catalog, _ := product.NewCatalogService(store, product.CryptoIDGenerator{})
	artifact, err := catalog.PublishArtifact(context.Background(), tenantID, actor, workspace.ID, product.PublishArtifactRequest{ExpectedWorkspaceVersion: workspace.Version, UploadTransferID: upload.ID, SlotKey: product.PrimarySlotKey, Name: "result.txt", MediaType: "text/plain"})
	if err != nil || artifact.Digest != upload.Digest || artifact.State != "available" {
		t.Fatalf("artifact=%#v err=%v", artifact, err)
	}
	artifactPage, err := catalog.ListArtifacts(context.Background(), tenantID, actor, workspace.ID, "", 50)
	if err != nil || len(artifactPage.Items) != 1 || artifactPage.Items[0].ID != artifact.ID {
		t.Fatalf("artifact page=%#v err=%v", artifactPage, err)
	}
	other := product.ActorRef{Type: product.ActorHuman, ID: "other-catalog-owner"}
	if _, err := catalog.GetArtifact(context.Background(), tenantID, other, artifact.ID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner artifact error=%v", err)
	}

	const sessionID = "ses_catalog_recording"
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.runtime_sessions(tenant_id,session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at) VALUES($1,$2,$3,'primary-code',1,$4,$5,'terminal','product-terminal.v1','active',true,'required',1,clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())`, tenantID, sessionID, workspace.ID, string(actor.Type), actor.ID); err != nil {
		t.Fatal(err)
	}
	recordingRoot := t.TempDir()
	content, err := productrecordinglocal.New(recordingRoot, bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	redactor, _ := product.NewPatternRedactor([]string{"SECRET-VALUE"})
	recordings, _ := product.NewRecordingService(store, content, redactor, product.CryptoIDGenerator{}, nil)
	const disabledSessionID = "ses_catalog_disabled"
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.runtime_sessions(tenant_id,session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at) VALUES($1,$2,$3,'primary-code',1,$4,$5,'terminal','product-terminal.v1','active',true,'disabled',1,clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())`, tenantID, disabledSessionID, workspace.ID, string(actor.Type), actor.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := recordings.Start(context.Background(), tenantID, actor, workspace.ID, product.StartRecordingRequest{SessionID: disabledSessionID, RecordingType: "terminal", ConsentReference: "consent_catalog_disabled", RetentionSeconds: 3600}); !errors.Is(err, product.ErrForbidden) {
		t.Fatalf("disabled recording policy error=%v", err)
	}
	recording, err := recordings.Start(context.Background(), tenantID, actor, workspace.ID, product.StartRecordingRequest{SessionID: sessionID, RecordingType: "terminal", ConsentReference: "consent_catalog_1", RetentionSeconds: 3600})
	if err != nil || recording.State != "recording" {
		t.Fatalf("recording=%#v err=%v", recording, err)
	}
	if _, err := recordings.Append(context.Background(), tenantID, actor, recording.ID, []byte("token=SECRET-VALUE\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := recordings.Append(context.Background(), tenantID, actor, recording.ID, []byte("done\n")); err != nil {
		t.Fatal(err)
	}
	recording, err = recordings.Finalize(context.Background(), tenantID, actor, recording.ID)
	if err != nil || recording.State != "available" || recording.Digest == "" || recording.SizeBytes == 0 {
		t.Fatalf("final recording=%#v err=%v", recording, err)
	}
	replay, err := recordings.Replay(context.Background(), tenantID, actor, recording.ID)
	if err != nil || len(replay) != 2 || strings.Contains(string(bytes.Join(replay, nil)), "SECRET-VALUE") || !strings.Contains(string(replay[0]), "[REDACTED]") {
		t.Fatalf("replay=%q err=%v", replay, err)
	}
	recordingPage, err := catalog.ListRecordings(context.Background(), tenantID, actor, workspace.ID, "", 50)
	if err != nil || len(recordingPage.Items) != 1 || recordingPage.Items[0].ID != recording.ID {
		t.Fatalf("recording page=%#v err=%v", recordingPage, err)
	}
	if _, err := catalog.GetRecording(context.Background(), tenantID, other, recording.ID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner recording error=%v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.recordings SET started_at=clock_timestamp()-interval '2 hours',retention_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND recording_id=$2`, tenantID, recording.ID); err != nil {
		t.Fatal(err)
	}
	cleaned, err := recordings.CleanupExpired(context.Background(), 10)
	if err != nil || cleaned != 1 {
		t.Fatalf("CleanupExpired()=%d,%v", cleaned, err)
	}
	deleted, err := catalog.GetRecording(context.Background(), tenantID, actor, recording.ID)
	if err != nil || deleted.State != "deleted" {
		t.Fatalf("deleted recording=%#v err=%v", deleted, err)
	}
	if _, err := recordings.Replay(context.Background(), tenantID, actor, recording.ID); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("deleted replay error=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(recordingRoot, "recordings"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("retained encrypted segments=%v err=%v", entries, err)
	}
}

func signedGuestAuth(t *testing.T, binding product.GuestBinding, privateKey ed25519.PrivateKey, label string) guestagent.AuthRequest {
	t.Helper()
	digest := sha256.Sum256([]byte(label))
	clientDigest := sha256.Sum256([]byte(label + "-client"))
	request := guestagent.AuthRequest{
		Challenge: guestagent.Challenge{Type: "challenge", Nonce: base64.RawURLEncoding.EncodeToString(digest[:]), ExpiresAt: time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano)},
		Hello:     guestagent.Hello{Type: "hello", GuestID: binding.GuestID, BindingGeneration: binding.BindingGeneration, ProtocolVersion: binding.ProtocolVersion, Capabilities: append([]string(nil), binding.Capabilities...), ClientNonce: base64.RawURLEncoding.EncodeToString(clientDigest[:])},
	}
	signing, err := request.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.Hello.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, signing))
	return request
}

func integrationProductPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connectionString := os.Getenv(productPostgresURLVariable)
	if connectionString == "" {
		t.Fatalf("%s is required for Product PostgreSQL integration tests", productPostgresURLVariable)
	}
	config, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 16
	config.MinConns = 0
	config.MinIdleConns = 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func applyProductMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ApplyMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("migration replay failed: %v", err)
	}
}

func cleanupProductTenant(t *testing.T, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, statement := range []string{
			`DELETE FROM sandbox_runtime_product.recording_segments WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.recordings WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.artifacts WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.blob_transfers WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.file_entries WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.file_changes WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspace_heads WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspace_revisions WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.guest_bindings WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.connection_grants WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.control_leases WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.control_lease_fences WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.provider_bindings WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.product_operation_attempts WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.security_audit WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.idempotency_records WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.outbox WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspace_events WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.product_operations WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspace_slots WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspaces WHERE tenant_id = $1`,
		} {
			_, _ = pool.Exec(ctx, statement, tenantID)
		}
	}
	cleanup()
	t.Cleanup(cleanup)
}

func assertProductKernelCounts(t *testing.T, pool *pgxpool.Pool, tenantID string, want int) {
	t.Helper()
	for _, table := range []string{"workspaces", "workspace_slots", "product_operations", "workspace_events", "outbox", "idempotency_records"} {
		var count int
		query := `SELECT count(*) FROM sandbox_runtime_product.` + table + ` WHERE tenant_id = $1`
		if err := pool.QueryRow(context.Background(), query, tenantID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s count = %d; want %d", table, count, want)
		}
	}
}

func integrationCreateWorkspaceRequest(displayName string) product.CreateWorkspaceRequest {
	return product.CreateWorkspaceRequest{
		DisplayName: displayName, LifetimeSeconds: 3600,
		PrimarySlot: product.SlotSpec{
			SlotKey: product.PrimarySlotKey, Kind: "code", ProfileID: "coding-shell-v1", DesiredState: "ready",
			RequiredCapabilities: []product.CapabilityRequirement{
				{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"},
				{CapabilityID: "sandbox.terminal", Version: "1.0.0", ProfileID: "terminal-v1"},
			},
		},
	}
}
