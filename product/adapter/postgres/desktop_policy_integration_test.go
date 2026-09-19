//go:build integration

package productpostgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestIntegrationDesktopPolicyPersistenceRevisionAndIsolation(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-policy"
	cleanupProductTenant(t, pool, tenantID)

	var migrationCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.schema_migrations WHERE version=11`).Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("Desktop policy migration count=%d err=%v", migrationCount, err)
	}
	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	service, err := product.NewDesktopPolicyService(store, ids)
	if err != nil {
		t.Fatal(err)
	}
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-policy-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-policy-workspace", integrationCreateWorkspaceRequest("Desktop policy"))
	if err != nil {
		t.Fatal(err)
	}
	session := prepareReadyDesktopGrantSession(t, store, application, slots, sessions, tenantID, actor, created.Operation.WorkspaceID, "desktop-policy-slot", "policy")
	binding := product.GatewayBinding{
		TenantID: tenantID, Actor: actor, WorkspaceID: created.Operation.WorkspaceID,
		SessionID: session.ID, SlotKey: "desktop-policy-slot", SlotGeneration: 1,
		ProtocolProfile: product.SessionProfileDesktop,
	}
	if _, err := store.CurrentDesktopPolicy(context.Background(), binding); !errors.Is(err, product.ErrForbidden) {
		t.Fatalf("missing policy err=%v", err)
	}

	policy := integrationDesktopPolicy(1)
	stored, replay, err := service.Put(context.Background(), tenantID, actor, binding.WorkspaceID, "desktop-policy-v1", 0, policy)
	if err != nil || replay || stored.Revision != 1 {
		t.Fatalf("stored=%#v replay=%t err=%v", stored, replay, err)
	}
	current, err := store.CurrentDesktopPolicy(context.Background(), binding)
	if err != nil || current.Revision != 1 || current.Clipboard.MaxBytes != 4096 {
		t.Fatalf("current=%#v err=%v", current, err)
	}
	if _, _, err := service.Put(context.Background(), tenantID, product.ActorRef{Type: product.ActorHuman, ID: "other-owner"}, binding.WorkspaceID, "desktop-policy-cross-owner", 1, integrationDesktopPolicy(2)); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner policy err=%v", err)
	}

	type result struct {
		policy product.DesktopPolicy
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wait sync.WaitGroup
	for _, key := range []string{"desktop-policy-v2-a", "desktop-policy-v2-b"} {
		key := key
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			updated, _, err := service.Put(context.Background(), tenantID, actor, binding.WorkspaceID, key, 1, integrationDesktopPolicy(2))
			results <- result{policy: updated, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for item := range results {
		switch {
		case item.err == nil && item.policy.Revision == 2:
			successes++
		case errors.Is(item.err, product.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected policy race result=%#v", item)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("policy race successes=%d conflicts=%d", successes, conflicts)
	}

	replayed, wasReplay, err := service.Put(context.Background(), tenantID, actor, binding.WorkspaceID, "desktop-policy-v1", 0, policy)
	if err != nil || !wasReplay || replayed.Revision != 1 {
		t.Fatalf("historical replay=%#v replay=%t err=%v", replayed, wasReplay, err)
	}
	conflicting := policy
	conflicting.Clipboard.MaxBytes = 1024
	if _, _, err := service.Put(context.Background(), tenantID, actor, binding.WorkspaceID, "desktop-policy-v1", 0, conflicting); !errors.Is(err, product.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict err=%v", err)
	}

	restarted, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	current, err = restarted.CurrentDesktopPolicy(context.Background(), binding)
	if err != nil || current.Revision != 2 {
		t.Fatalf("restart current=%#v err=%v", current, err)
	}
	var audits int
	var metadata string
	if err := pool.QueryRow(context.Background(), `SELECT count(*),COALESCE(string_agg(action||':'||resource_id||':'||reason_code,','),'')
FROM sandbox_runtime_product.security_audit WHERE tenant_id=$1 AND action='desktop_policy.update'`, tenantID).Scan(&audits, &metadata); err != nil {
		t.Fatal(err)
	}
	if audits != 2 || strings.Contains(metadata, "text/plain") || strings.Contains(metadata, "4096") {
		t.Fatalf("policy audits=%d metadata=%q", audits, metadata)
	}
}

func integrationDesktopPolicy(revision int64) product.DesktopPolicy {
	transfer := product.DesktopTransferPolicy{
		Enabled: true, MaxFiles: 4, MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20,
		AllowedMediaTypes: []string{"application/json", "text/plain"}, RequireActivation: true, RequireConsent: true,
	}
	return product.DesktopPolicy{
		Revision:  revision,
		Input:     product.DesktopInputPolicy{Keyboard: true, Pointer: true, Touch: true, RequireActivation: true},
		Clipboard: product.DesktopClipboardPolicy{Read: true, Write: true, MaxBytes: 4096, RequireActivation: true, RequireConsent: true},
		Upload:    transfer, Download: transfer,
	}
}
