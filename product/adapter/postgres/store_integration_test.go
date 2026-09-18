//go:build integration

package productpostgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/product"
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
