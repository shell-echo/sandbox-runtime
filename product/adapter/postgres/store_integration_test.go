//go:build integration

package productpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
)

const productPostgresURLVariable = "SANDBOX_RUNTIME_PRODUCT_POSTGRES_URL"

type allowPrimarySlot struct{}

func (allowPrimarySlot) AuthorizePrimarySlot(context.Context, product.SlotSpec) error { return nil }

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
			`DELETE FROM sandbox_runtime_product.file_changes WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspace_heads WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.workspace_revisions WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.guest_bindings WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.connection_grants WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.control_leases WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.control_lease_fences WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.provider_bindings WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.product_operation_attempts WHERE tenant_id = $1`,
			`DELETE FROM sandbox_runtime_product.security_audit WHERE tenant_id = $1`,
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
