//go:build integration

package productpostgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/product"
)

type allowDesktopSlot struct{}

func (allowDesktopSlot) AuthorizeSlot(context.Context, product.SlotSpec) error { return nil }

type allowDesktopSession struct{}

func (allowDesktopSession) AuthorizeSession(_ context.Context, kind, profile string) error {
	if kind == product.SessionKindDesktop && profile == product.SessionProfileDesktop {
		return nil
	}
	return product.ErrCapabilityUnsupported
}

func TestIntegrationDesktopAuthorityAtomicIsolationAndRestartReads(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-authority"
	cleanupProductTenant(t, pool, tenantID)

	var migrationCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.schema_migrations WHERE version=8`).Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("Desktop migration count=%d err=%v", migrationCount, err)
	}
	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-workspace", integrationCreateWorkspaceRequest("desktop authority"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.outbox SET state='delivered' WHERE tenant_id=$1 AND message_type='workspace.reconcile'`, tenantID); err != nil {
		t.Fatal(err)
	}

	putRequest := desktopSlotRequest(1)
	putOperation, replay, err := slots.Put(context.Background(), tenantID, actor, created.Operation.WorkspaceID, "desktop-main", "desktop-slot-create", putRequest)
	if err != nil || replay || putOperation.Type != "put_slot" {
		t.Fatalf("put=%#v replay=%v err=%v", putOperation, replay, err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.workspace_slots
SET observed_state='ready',observed_generation=generation
WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key='desktop-main'`, tenantID, created.Operation.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	workspace, err := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	if err != nil || workspace.Version != 2 {
		t.Fatalf("workspace=%#v err=%v", workspace, err)
	}
	sessionRequest := product.CreateSessionRequest{ExpectedWorkspaceVersion: workspace.Version, SlotKey: "desktop-main", Kind: product.SessionKindDesktop, ProtocolProfile: product.SessionProfileDesktop, ExpiresInSeconds: 900, RecordingPolicy: "metadata_only"}
	sessionOperation, replay, err := sessions.Create(context.Background(), tenantID, actor, workspace.ID, "desktop-session-create", sessionRequest)
	if err != nil || replay || sessionOperation.SessionID == "" {
		t.Fatalf("session operation=%#v replay=%v err=%v", sessionOperation, replay, err)
	}

	for _, lease := range []struct {
		name string
		call func() (int, error)
	}{
		{name: "terminal session", call: func() (int, error) {
			work, err := store.LeaseSessionWork(context.Background(), "terminal-worker", 10*time.Second, 10)
			return len(work), err
		}},
		{name: "browser session", call: func() (int, error) {
			work, err := store.LeaseBrowserSessionWork(context.Background(), "browser-session-worker", 10*time.Second, 10)
			return len(work), err
		}},
		{name: "browser slot", call: func() (int, error) {
			work, err := store.LeaseBrowserSlotWork(context.Background(), "browser-slot-worker", 10*time.Second, 10)
			return len(work), err
		}},
	} {
		count, err := lease.call()
		if err != nil || count != 0 {
			t.Fatalf("%s consumed Desktop work: count=%d err=%v", lease.name, count, err)
		}
	}

	var openType string
	if err := pool.QueryRow(context.Background(), `SELECT message_type FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND operation_id=$2`, tenantID, sessionOperation.ID).Scan(&openType); err != nil || openType != "desktop_session.open" {
		t.Fatalf("Desktop open outbox type=%q err=%v", openType, err)
	}
	for table, want := range map[string]int{"product_operations": 3, "workspace_events": 3, "outbox": 3, "security_audit": 3} {
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.`+table+` WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil || count != want {
			t.Fatalf("atomic %s count=%d want=%d err=%v", table, count, want, err)
		}
	}

	restartedStore, _ := New(pool, 5*time.Second)
	restartedSlots, _ := product.NewSlotService(restartedStore, allowDesktopSlot{}, ids)
	restartedSessions, _ := product.NewSessionService(restartedStore, allowDesktopSession{}, ids)
	storedSlot, err := restartedSlots.Get(context.Background(), tenantID, actor, workspace.ID, "desktop-main")
	if err != nil || storedSlot.Kind != product.DesktopSlotKind || storedSlot.ProfileID != product.DesktopSlotProfile || storedSlot.Generation != 1 {
		t.Fatalf("restarted slot=%#v err=%v", storedSlot, err)
	}
	storedSession, err := restartedSessions.Get(context.Background(), tenantID, actor, sessionOperation.SessionID)
	if err != nil || storedSession.Kind != product.SessionKindDesktop || storedSession.ProtocolProfile != product.SessionProfileDesktop || storedSession.State != product.SessionStateRequested {
		t.Fatalf("restarted session=%#v err=%v", storedSession, err)
	}
	replayed, replay, err := restartedSessions.Create(context.Background(), tenantID, actor, workspace.ID, "desktop-session-create", sessionRequest)
	if err != nil || !replay || replayed.ID != sessionOperation.ID {
		t.Fatalf("restart replay=%#v replay=%v err=%v", replayed, replay, err)
	}
	if _, err := restartedSessions.Get(context.Background(), "other-tenant", actor, sessionOperation.SessionID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-tenant Desktop session read err=%v", err)
	}
	if _, err := restartedSlots.Get(context.Background(), tenantID, product.ActorRef{Type: product.ActorHuman, ID: "other-owner"}, workspace.ID, "desktop-main"); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner Desktop slot read err=%v", err)
	}

	closeOperation, replay, err := restartedSessions.Close(context.Background(), tenantID, actor, sessionOperation.SessionID, "desktop-close", product.CloseSessionRequest{ExpectedVersion: storedSession.Version, Reason: "owner requested close"})
	if err != nil || replay || closeOperation.SessionID != sessionOperation.SessionID {
		t.Fatalf("Desktop close=%#v replay=%v err=%v", closeOperation, replay, err)
	}
	var closeType string
	if err := pool.QueryRow(context.Background(), `SELECT message_type FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND operation_id=$2`, tenantID, closeOperation.ID).Scan(&closeType); err != nil || closeType != "desktop_session.close" {
		t.Fatalf("Desktop close outbox type=%q err=%v", closeType, err)
	}
	closedCandidate, err := restartedSessions.Get(context.Background(), tenantID, actor, sessionOperation.SessionID)
	if err != nil || closedCandidate.State != product.SessionStateDraining || closedCandidate.Version != 2 {
		t.Fatalf("Desktop draining session=%#v err=%v", closedCandidate, err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.runtime_sessions SET state='closed' WHERE tenant_id=$1 AND session_id=$2`, tenantID, sessionOperation.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restartedSessions.Close(context.Background(), tenantID, actor, sessionOperation.SessionID, "desktop-close-after-terminal", product.CloseSessionRequest{ExpectedVersion: closedCandidate.Version, Reason: "must remain closed"}); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("absorbing Desktop close err=%v", err)
	}
	for table, want := range map[string]int{"product_operations": 4, "workspace_events": 4, "outbox": 4, "security_audit": 4} {
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.`+table+` WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil || count != want {
			t.Fatalf("failed close changed %s count=%d want=%d err=%v", table, count, want, err)
		}
	}

	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.runtime_sessions
    (tenant_id,session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at)
VALUES ($1,'ses-invalid-desktop-profile',$2,'desktop-main',1,'human',$3,'desktop','product-browser-live.v1','requested',true,'disabled',1,clock_timestamp()+interval '5 minutes',clock_timestamp(),clock_timestamp())`, tenantID, workspace.ID, actor.ID); err == nil {
		t.Fatal("database accepted mismatched Desktop session profile")
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.workspace_slots
    (tenant_id,workspace_id,slot_key,kind,profile_id,required_capabilities,desired_state,observed_state,generation,observed_generation,version,created_at,updated_at)
VALUES ($1,$2,'desktop-invalid','desktop','sandbox-runtime-browser-v1','[{"capability_id":"sandbox.browser","version":"1.0.0","profile_id":"browser-v1"}]'::jsonb,'ready','requested',1,0,1,clock_timestamp(),clock_timestamp())`, tenantID, workspace.ID); err == nil {
		t.Fatal("database accepted mismatched Desktop slot authority")
	}
}

func TestIntegrationDesktopExpectedVersionAndIdempotencyRaces(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-command-races"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 5*time.Second)
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-race-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-race-workspace", integrationCreateWorkspaceRequest("desktop races"))
	if err != nil {
		t.Fatal(err)
	}

	type slotResult struct {
		operation product.Operation
		replay    bool
		err       error
	}
	results := make(chan slotResult, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			operation, replay, err := slots.Put(context.Background(), tenantID, actor, created.Operation.WorkspaceID, "desktop-main", "desktop-idempotency-race", desktopSlotRequest(1))
			results <- slotResult{operation: operation, replay: replay, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.operation.ID != second.operation.ID || first.replay == second.replay {
		t.Fatalf("Desktop idempotency race first=%#v second=%#v", first, second)
	}

	results = make(chan slotResult, 2)
	start = make(chan struct{})
	for index, slotKey := range []string{"desktop-tools", "desktop-preview"} {
		index, slotKey := index, slotKey
		go func() {
			<-start
			operation, replay, err := slots.Put(context.Background(), tenantID, actor, created.Operation.WorkspaceID, slotKey, "desktop-version-race-"+string(rune('a'+index)), desktopSlotRequest(2))
			results <- slotResult{operation: operation, replay: replay, err: err}
		}()
	}
	close(start)
	first, second = <-results, <-results
	successes, conflicts := 0, 0
	for _, item := range []slotResult{first, second} {
		switch {
		case item.err == nil:
			successes++
		case errors.Is(item.err, product.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("Desktop version race unexpected=%#v", item)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("Desktop version race successes=%d conflicts=%d first=%#v second=%#v", successes, conflicts, first, second)
	}
}

func TestIntegrationDesktopSessionExpectedVersionAndIdempotencyRaces(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-session-command-races"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 5*time.Second)
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-session-race-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-session-race-workspace", integrationCreateWorkspaceRequest("desktop session races"))
	if err != nil {
		t.Fatal(err)
	}
	for index, slotKey := range []string{"desktop-main", "desktop-tools", "desktop-preview"} {
		if _, _, err := slots.Put(context.Background(), tenantID, actor, created.Operation.WorkspaceID, slotKey, "desktop-session-race-slot-"+string(rune('a'+index)), desktopSlotRequest(int64(index+1))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.workspace_slots
SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1 AND kind='desktop'`, tenantID); err != nil {
		t.Fatal(err)
	}

	type result struct {
		operation product.Operation
		replay    bool
		err       error
	}
	create := func(slotKey, key string, expected int64) result {
		operation, replay, err := sessions.Create(context.Background(), tenantID, actor, created.Operation.WorkspaceID, key, product.CreateSessionRequest{
			ExpectedWorkspaceVersion: expected, SlotKey: slotKey, Kind: product.SessionKindDesktop,
			ProtocolProfile: product.SessionProfileDesktop, ExpiresInSeconds: 900, RecordingPolicy: "disabled",
		})
		return result{operation: operation, replay: replay, err: err}
	}

	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			results <- create("desktop-main", "desktop-session-idempotency-race", 4)
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.operation.ID != second.operation.ID || first.replay == second.replay {
		t.Fatalf("Desktop session idempotency race first=%#v second=%#v", first, second)
	}

	results = make(chan result, 2)
	start = make(chan struct{})
	for index, slotKey := range []string{"desktop-tools", "desktop-preview"} {
		index, slotKey := index, slotKey
		go func() {
			<-start
			results <- create(slotKey, "desktop-session-version-race-"+string(rune('a'+index)), 5)
		}()
	}
	close(start)
	first, second = <-results, <-results
	successes, conflicts := 0, 0
	for _, item := range []result{first, second} {
		switch {
		case item.err == nil:
			successes++
		case errors.Is(item.err, product.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("Desktop session version race unexpected=%#v", item)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("Desktop session version race successes=%d conflicts=%d first=%#v second=%#v", successes, conflicts, first, second)
	}
}

func TestIntegrationDesktopSlotAndSessionQuotaRaces(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	testDesktopSlotQuotaRace(t, pool)
	testDesktopSessionQuotaRace(t, pool)
}

func testDesktopSlotQuotaRace(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	const tenantID = "tenant-desktop-slot-quota-race"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 5*time.Second)
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-slot-quota-owner"}
	firstWorkspace, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-slot-quota-workspace-1", integrationCreateWorkspaceRequest("desktop slot quota one"))
	if err != nil {
		t.Fatal(err)
	}
	secondWorkspace, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-slot-quota-workspace-2", integrationCreateWorkspaceRequest("desktop slot quota two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas
    (tenant_id,max_workspaces,max_sessions,max_active_transfers,max_desktop_slots,max_desktop_sessions,updated_at)
VALUES($1,100,1000,100,1,16,clock_timestamp())`, tenantID); err != nil {
		t.Fatal(err)
	}

	type result struct {
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for index, workspaceID := range []string{firstWorkspace.Operation.WorkspaceID, secondWorkspace.Operation.WorkspaceID} {
		index, workspaceID := index, workspaceID
		go func() {
			<-start
			_, _, err := slots.Put(context.Background(), tenantID, actor, workspaceID, "desktop-main", "desktop-slot-quota-"+string(rune('a'+index)), desktopSlotRequest(1))
			results <- result{err: err}
		}()
	}
	close(start)
	successes, quotas := 0, 0
	for range 2 {
		item := <-results
		switch {
		case item.err == nil:
			successes++
		case errors.Is(item.err, product.ErrQuotaExceeded):
			quotas++
		default:
			t.Fatalf("Desktop slot quota race unexpected err=%v", item.err)
		}
	}
	if successes != 1 || quotas != 1 {
		t.Fatalf("Desktop slot quota race successes=%d quotas=%d", successes, quotas)
	}
}

func testDesktopSessionQuotaRace(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	const tenantID = "tenant-desktop-session-quota-race"
	cleanupProductTenant(t, pool, tenantID)
	store, _ := New(pool, 5*time.Second)
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-session-quota-owner"}
	firstWorkspace, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-session-quota-workspace-1", integrationCreateWorkspaceRequest("desktop session quota one"))
	if err != nil {
		t.Fatal(err)
	}
	secondWorkspace, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-session-quota-workspace-2", integrationCreateWorkspaceRequest("desktop session quota two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas
    (tenant_id,max_workspaces,max_sessions,max_active_transfers,max_desktop_slots,max_desktop_sessions,updated_at)
VALUES($1,100,1000,100,2,1,clock_timestamp())`, tenantID); err != nil {
		t.Fatal(err)
	}
	for index, workspaceID := range []string{firstWorkspace.Operation.WorkspaceID, secondWorkspace.Operation.WorkspaceID} {
		if _, _, err := slots.Put(context.Background(), tenantID, actor, workspaceID, "desktop-main", "desktop-session-slot-"+string(rune('a'+index)), desktopSlotRequest(1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.workspace_slots
SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1 AND kind='desktop'`, tenantID); err != nil {
		t.Fatal(err)
	}

	type result struct {
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for index, workspaceID := range []string{firstWorkspace.Operation.WorkspaceID, secondWorkspace.Operation.WorkspaceID} {
		index, workspaceID := index, workspaceID
		go func() {
			<-start
			workspace, loadErr := application.GetWorkspace(context.Background(), tenantID, actor, workspaceID)
			if loadErr != nil {
				results <- result{err: loadErr}
				return
			}
			_, _, createErr := sessions.Create(context.Background(), tenantID, actor, workspaceID, "desktop-session-quota-"+string(rune('a'+index)), product.CreateSessionRequest{
				ExpectedWorkspaceVersion: workspace.Version, SlotKey: "desktop-main", Kind: product.SessionKindDesktop,
				ProtocolProfile: product.SessionProfileDesktop, ExpiresInSeconds: 900, RecordingPolicy: "disabled",
			})
			results <- result{err: createErr}
		}()
	}
	close(start)
	successes, quotas := 0, 0
	for range 2 {
		item := <-results
		switch {
		case item.err == nil:
			successes++
		case errors.Is(item.err, product.ErrQuotaExceeded):
			quotas++
		default:
			t.Fatalf("Desktop session quota race unexpected err=%v", item.err)
		}
	}
	if successes != 1 || quotas != 1 {
		t.Fatalf("Desktop session quota race successes=%d quotas=%d", successes, quotas)
	}
}

func desktopSlotRequest(expectedVersion int64) product.PutSlotRequest {
	return product.PutSlotRequest{
		ExpectedWorkspaceVersion: expectedVersion,
		Kind:                     product.DesktopSlotKind,
		ProfileID:                product.DesktopSlotProfile,
		RequiredCapabilities: []product.CapabilityRequirement{{
			CapabilityID: product.DesktopCapabilityID, Version: product.DesktopCapabilityVersion, ProfileID: product.DesktopCapabilityProfile,
		}},
		DesiredState: "ready",
	}
}
