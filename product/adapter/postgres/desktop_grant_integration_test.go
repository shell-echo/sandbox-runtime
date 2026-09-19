//go:build integration

package productpostgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
)

func TestIntegrationDesktopGrantAuthorityFencingQuotasAndRevocation(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	var recoveryMigrationCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sandbox_runtime_product.schema_migrations WHERE version=12`).Scan(&recoveryMigrationCount); err != nil || recoveryMigrationCount != 1 {
		t.Fatalf("Desktop recovery migration count=%d err=%v", recoveryMigrationCount, err)
	}
	const tenantID = "tenant-desktop-grants"
	cleanupProductTenant(t, pool, tenantID)

	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	controls, _ := product.NewControlService(store, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-grant-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-grant-workspace", integrationCreateWorkspaceRequest("desktop grants"))
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

	firstSession := prepareReadyDesktopGrantSession(t, store, application, slots, sessions, tenantID, actor, created.Operation.WorkspaceID, "desktop-grant-a", "a")
	secondSession := prepareReadyDesktopGrantSession(t, store, application, slots, sessions, tenantID, actor, created.Operation.WorkspaceID, "desktop-grant-b", "b")

	grantRepository, err := NewGrantRepository(store, "desktop-grant-key-v1", bytes.Repeat([]byte{0x7d}, 32))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := product.NewGrantService(grantRepository, ids, product.CryptoTicketGenerator{}, "wss://desktop-gateway.example.test/connect", 60*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	viewRequest := product.CreateConnectionRequest{ExpectedSessionVersion: firstSession.Version, ProtocolProfile: product.SessionProfileDesktop, AccessMode: product.GrantAccessView}
	viewGrant, replayed, err := grants.Create(context.Background(), tenantID, actor, firstSession.ID, "desktop-view-grant", viewRequest)
	if err != nil || replayed || viewGrant.AccessMode != product.GrantAccessView || viewGrant.ProtocolProfile != product.SessionProfileDesktop || viewGrant.GatewayURI != "wss://desktop-gateway.example.test/connect" {
		t.Fatalf("Desktop view grant=%#v replayed=%t err=%v", viewGrant, replayed, err)
	}
	replayedView, replayed, err := grants.Create(context.Background(), tenantID, actor, firstSession.ID, "desktop-view-grant", viewRequest)
	if err != nil || !replayed || replayedView.ID != viewGrant.ID || replayedView.Ticket != viewGrant.Ticket {
		t.Fatalf("Desktop view replay=%#v replayed=%t err=%v", replayedView, replayed, err)
	}
	if _, _, err := grants.Create(context.Background(), tenantID, product.ActorRef{Type: product.ActorHuman, ID: "other-desktop-owner"}, firstSession.ID, "desktop-cross-owner", viewRequest); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("Desktop cross-owner grant err=%v", err)
	}
	var ciphertext []byte
	if err := pool.QueryRow(context.Background(), `SELECT ticket_ciphertext FROM sandbox_runtime_product.connection_grants WHERE tenant_id=$1 AND connection_id=$2`, tenantID, viewGrant.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(viewGrant.Ticket)) {
		t.Fatal("Desktop connection ticket stored in plaintext")
	}
	viewBinding, err := grantRepository.ConsumeConnectionGrant(context.Background(), viewGrant.Ticket)
	if err != nil || viewBinding.AccessMode != product.GrantAccessView || viewBinding.ControlLeaseID != "" || viewBinding.ControlFence != 0 || !strings.HasPrefix(viewBinding.HandoffReference, "ref:desktop-session:") {
		t.Fatalf("Desktop view binding=%#v err=%v", viewBinding, err)
	}
	if _, err := grantRepository.ConsumeConnectionGrant(context.Background(), viewGrant.Ticket); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("Desktop ticket replay err=%v", err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), viewBinding); err != nil {
		t.Fatal(err)
	}
	tampered := viewBinding
	tampered.HandoffReference = "ref:desktop-session:substituted"
	if err := grantRepository.CheckGatewayAuthority(context.Background(), tampered); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("Desktop substituted handoff err=%v", err)
	}
	tampered = viewBinding
	tampered.ConnectionGeneration++
	if err := grantRepository.CheckGatewayAuthority(context.Background(), tampered); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("Desktop substituted generation err=%v", err)
	}
	if err := grantRepository.CloseGatewayConnection(context.Background(), viewBinding); err != nil {
		t.Fatal(err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), viewBinding); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("closed Desktop viewer authority err=%v", err)
	}

	workspace, _ := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	firstLease, _, err := controls.Acquire(context.Background(), tenantID, actor, workspace.ID, "desktop-control-a", product.AcquireControlLeaseRequest{
		ExpectedWorkspaceVersion: workspace.Version, Scope: product.ControlScope{Type: "session", ID: firstSession.ID}, DurationSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	controlRequest := product.CreateConnectionRequest{ExpectedSessionVersion: firstSession.Version, ProtocolProfile: product.SessionProfileDesktop, AccessMode: product.GrantAccessControl, ControlLeaseID: firstLease.ID, ControlFence: firstLease.Fence}
	controlGrant, _, err := grants.Create(context.Background(), tenantID, actor, firstSession.ID, "desktop-control-grant", controlRequest)
	if err != nil {
		t.Fatal(err)
	}
	controlBinding, err := grantRepository.ConsumeConnectionGrant(context.Background(), controlGrant.Ticket)
	if err != nil || controlBinding.ControlLeaseID != firstLease.ID || controlBinding.ControlFence != firstLease.Fence {
		t.Fatalf("Desktop control binding=%#v err=%v", controlBinding, err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), controlBinding); err != nil {
		t.Fatal(err)
	}
	if _, _, err := grants.Create(context.Background(), tenantID, actor, firstSession.ID, "desktop-second-controller", controlRequest); !errors.Is(err, product.ErrControlConflict) {
		t.Fatalf("second Desktop controller err=%v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.connection_grants
SET gateway_lease_expires_at=clock_timestamp()-interval '1 second'
WHERE tenant_id=$1 AND connection_id=$2`, tenantID, controlBinding.ConnectionID); err != nil {
		t.Fatal(err)
	}
	restartedGrantRepository, err := NewGrantRepository(store, "desktop-grant-key-v1", bytes.Repeat([]byte{0x7d}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedGrantRepository.CheckGatewayAuthority(context.Background(), controlBinding); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("crashed Desktop gateway lease remained authoritative: %v", err)
	}
	reconnectGrant, _, err := grants.Create(context.Background(), tenantID, actor, firstSession.ID, "desktop-control-reconnect", controlRequest)
	if err != nil || reconnectGrant.ID == controlGrant.ID || reconnectGrant.Ticket == controlGrant.Ticket {
		t.Fatalf("fresh Desktop reconnect grant=%#v err=%v", reconnectGrant, err)
	}
	reconnectBinding, err := restartedGrantRepository.ConsumeConnectionGrant(context.Background(), reconnectGrant.Ticket)
	if err != nil || reconnectBinding.ConnectionID != reconnectGrant.ID || reconnectBinding.HandoffReference != controlBinding.HandoffReference || reconnectBinding.ConnectionGeneration != controlBinding.ConnectionGeneration || reconnectBinding.SlotGeneration != controlBinding.SlotGeneration {
		t.Fatalf("fresh Desktop reconnect binding=%#v err=%v", reconnectBinding, err)
	}
	if err := restartedGrantRepository.CheckGatewayAuthority(context.Background(), reconnectBinding); err != nil {
		t.Fatal(err)
	}
	tamperedReconnect := reconnectBinding
	tamperedReconnect.SlotGeneration++
	if err := restartedGrantRepository.CheckGatewayAuthority(context.Background(), tamperedReconnect); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("reconnected Desktop generation substitution err=%v", err)
	}
	if err := restartedGrantRepository.CloseGatewayConnection(context.Background(), reconnectBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := controls.Release(context.Background(), tenantID, actor, workspace.ID, firstLease.ID, "desktop-control-release", firstLease.Fence, "controller_released"); err != nil {
		t.Fatal(err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), controlBinding); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("released Desktop controller authority err=%v", err)
	}
	workspace, _ = application.GetWorkspace(context.Background(), tenantID, actor, workspace.ID)
	replacementLease, _, err := controls.Acquire(context.Background(), tenantID, actor, workspace.ID, "desktop-control-a-replacement", product.AcquireControlLeaseRequest{
		ExpectedWorkspaceVersion: workspace.Version, Scope: product.ControlScope{Type: "session", ID: firstSession.ID}, DurationSeconds: 120,
	})
	if err != nil || replacementLease.Fence <= firstLease.Fence {
		t.Fatalf("replacement Desktop lease=%#v err=%v", replacementLease, err)
	}
	if _, _, err := grants.Create(context.Background(), tenantID, actor, firstSession.ID, "desktop-stale-controller", controlRequest); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("stale Desktop controller fence err=%v", err)
	}

	if _, err := pool.Exec(context.Background(), `INSERT INTO sandbox_runtime_product.tenant_quotas
    (tenant_id,max_workspaces,max_sessions,max_active_transfers,max_desktop_viewers,max_desktop_controllers,updated_at)
VALUES($1,100,1000,100,1,1,clock_timestamp())
ON CONFLICT(tenant_id) DO UPDATE SET max_desktop_viewers=1,max_desktop_controllers=1,updated_at=clock_timestamp()`, tenantID); err != nil {
		t.Fatal(err)
	}
	viewWinner := raceDesktopGrants(t, grants, tenantID, actor, []desktopGrantRaceInput{
		{session: firstSession, key: "desktop-view-quota-a", request: viewRequest},
		{session: firstSession, key: "desktop-view-quota-b", request: viewRequest},
	}, product.ErrQuotaExceeded)
	viewQuotaBinding, err := grantRepository.ConsumeConnectionGrant(context.Background(), viewWinner.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err := grantRepository.CloseGatewayConnection(context.Background(), viewQuotaBinding); err != nil {
		t.Fatal(err)
	}

	workspace, _ = application.GetWorkspace(context.Background(), tenantID, actor, workspace.ID)
	secondLease, _, err := controls.Acquire(context.Background(), tenantID, actor, workspace.ID, "desktop-control-b", product.AcquireControlLeaseRequest{
		ExpectedWorkspaceVersion: workspace.Version, Scope: product.ControlScope{Type: "session", ID: secondSession.ID}, DurationSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	controllerWinner := raceDesktopGrants(t, grants, tenantID, actor, []desktopGrantRaceInput{
		{session: firstSession, key: "desktop-controller-quota-a", request: product.CreateConnectionRequest{ExpectedSessionVersion: firstSession.Version, ProtocolProfile: product.SessionProfileDesktop, AccessMode: product.GrantAccessControl, ControlLeaseID: replacementLease.ID, ControlFence: replacementLease.Fence}},
		{session: secondSession, key: "desktop-controller-quota-b", request: product.CreateConnectionRequest{ExpectedSessionVersion: secondSession.Version, ProtocolProfile: product.SessionProfileDesktop, AccessMode: product.GrantAccessControl, ControlLeaseID: secondLease.ID, ControlFence: secondLease.Fence}},
	}, product.ErrQuotaExceeded)
	controllerBinding, err := grantRepository.ConsumeConnectionGrant(context.Background(), controllerWinner.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), controllerBinding); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE sandbox_runtime_product.control_leases
SET issued_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 second',updated_at=clock_timestamp()
WHERE tenant_id=$1 AND lease_id=$2`, tenantID, controllerBinding.ControlLeaseID); err != nil {
		t.Fatal(err)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), controllerBinding); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("database-expired Desktop controller authority err=%v", err)
	}

	var issueAudits int
	var auditMetadata string
	if err := pool.QueryRow(context.Background(), `SELECT count(*),COALESCE(string_agg(action||':'||resource_type||':'||resource_id||':'||outcome||':'||reason_code,','),'')
FROM sandbox_runtime_product.security_audit WHERE tenant_id=$1 AND action='connection_grant.issue'`, tenantID).Scan(&issueAudits, &auditMetadata); err != nil {
		t.Fatal(err)
	}
	if issueAudits != 5 || strings.Contains(auditMetadata, viewGrant.Ticket) || strings.Contains(auditMetadata, viewBinding.HandoffReference) {
		t.Fatalf("Desktop grant audit count=%d metadata=%q", issueAudits, auditMetadata)
	}
}

func TestIntegrationDesktopSlotReplacementRevokesConnectionsAndCleansHandoff(t *testing.T) {
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-replacement"
	cleanupProductTenant(t, pool, tenantID)
	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-replacement-owner"}
	created, err := application.CreateWorkspace(context.Background(), tenantID, actor, "desktop-replacement-workspace", integrationCreateWorkspaceRequest("desktop replacement"))
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
	ready := prepareReadyDesktopGrantSession(t, store, application, slots, sessions, tenantID, actor, created.Operation.WorkspaceID, "desktop-main", "replacement")
	grantRepository, _ := NewGrantRepository(store, "desktop-replacement-key-v1", bytes.Repeat([]byte{0x4d}, 32))
	grantService, _ := product.NewGrantService(grantRepository, ids, product.CryptoTicketGenerator{}, "wss://desktop-gateway.example.test/connect", 60*time.Second)
	grant, _, err := grantService.Create(context.Background(), tenantID, actor, ready.ID, "desktop-replacement-view", product.CreateConnectionRequest{
		ExpectedSessionVersion: ready.Version, ProtocolProfile: product.SessionProfileDesktop, AccessMode: product.GrantAccessView,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := grantRepository.ConsumeConnectionGrant(context.Background(), grant.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := application.GetWorkspace(context.Background(), tenantID, actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	replaceOperation, _, err := slots.Put(context.Background(), tenantID, actor, workspace.ID, "desktop-main", "desktop-slot-replace", desktopSlotRequest(workspace.Version))
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := store.LeaseDesktopLifecycleWork(context.Background(), "desktop-replacement-lifecycle", 10*time.Second, 10)
	if err != nil || len(lifecycle) != 1 || lifecycle[0].Action != "replace" || lifecycle[0].PreviousGeneration != 1 || lifecycle[0].SlotGeneration != 2 {
		t.Fatalf("Desktop replacement lifecycle=%#v err=%v", lifecycle, err)
	}
	now := time.Now().UTC()
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: strings.Repeat("d", 40), SandboxID: "provider-desktop-grant-replacement",
		ProviderOperationID: "provider-desktop-replace-terminate", RequestDigest: "sha256:" + strings.Repeat("c", 64), State: "accepted", ObservedAt: now}
	if err := store.RecordDispatchEvidence(context.Background(), lifecycle[0], evidence); err != nil {
		t.Fatal(err)
	}
	observations, err := store.LeaseDesktopProviderObservations(context.Background(), "desktop-replacement-observer", 10*time.Second, 10)
	if err != nil || len(observations) != 1 || observations[0].ProviderAction != "terminate" {
		t.Fatalf("Desktop replacement observations=%#v err=%v", observations, err)
	}
	evidence.State, evidence.ObservedAt = "succeeded", now.Add(time.Millisecond)
	if err := store.RecordProviderObservation(context.Background(), observations[0], evidence, "evt-desktop-replacement-terminated"); err != nil {
		t.Fatal(err)
	}
	var sessionState, grantState string
	var handoff *string
	if err := pool.QueryRow(context.Background(), `SELECT state,provider_handoff_reference FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2`, tenantID, ready.ID).Scan(&sessionState, &handoff); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT state FROM sandbox_runtime_product.connection_grants WHERE tenant_id=$1 AND connection_id=$2`, tenantID, grant.ID).Scan(&grantState); err != nil {
		t.Fatal(err)
	}
	if sessionState != "closed" || handoff != nil || grantState != "revoked" {
		t.Fatalf("replacement cleanup session=%q handoff=%v grant=%q", sessionState, handoff, grantState)
	}
	if err := grantRepository.CheckGatewayAuthority(context.Background(), binding); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("replaced Desktop binding remained authoritative: %v", err)
	}
	replacement, err := store.LeaseDesktopSlotWork(context.Background(), "desktop-replacement-provision", 10*time.Second, 10)
	if err != nil || len(replacement) != 1 || replacement[0].OperationID != replaceOperation.ID || replacement[0].SlotGeneration != 2 || replacement[0].PreviousGeneration != 1 {
		t.Fatalf("Desktop deterministic replacement=%#v err=%v", replacement, err)
	}
	if duplicate, err := store.LeaseDesktopSlotWork(context.Background(), "desktop-replacement-duplicate", 10*time.Second, 10); err != nil || len(duplicate) != 0 {
		t.Fatalf("duplicate Desktop replacement=%#v err=%v", duplicate, err)
	}
	evidence.ProviderOperationID, evidence.SandboxID, evidence.State, evidence.ObservedAt = "provider-desktop-replacement-create", "provider-desktop-replacement-new", "accepted", now.Add(2*time.Millisecond)
	if err := store.RecordDispatchEvidence(context.Background(), replacement[0], evidence); err != nil {
		t.Fatal(err)
	}
	observations, err = store.LeaseDesktopProviderObservations(context.Background(), "desktop-replacement-ready-observer", 10*time.Second, 10)
	if err != nil || len(observations) != 1 || observations[0].ProviderAction != "create" {
		t.Fatalf("Desktop replacement create observations=%#v err=%v", observations, err)
	}
	evidence.State, evidence.ObservedAt = "succeeded", now.Add(3*time.Millisecond)
	if err := store.RecordProviderObservation(context.Background(), observations[0], evidence, "evt-desktop-replacement-ready"); err != nil {
		t.Fatal(err)
	}
	var currentCount int
	var currentGeneration int64
	if err := pool.QueryRow(context.Background(), `SELECT count(*),COALESCE(max(slot_generation),0) FROM sandbox_runtime_product.provider_bindings WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key='desktop-main' AND current`, tenantID, workspace.ID).Scan(&currentCount, &currentGeneration); err != nil {
		t.Fatal(err)
	}
	if currentCount != 1 || currentGeneration != 2 {
		t.Fatalf("Desktop replacement current bindings=%d generation=%d", currentCount, currentGeneration)
	}
}

type desktopGrantRaceInput struct {
	session product.RuntimeSession
	key     string
	request product.CreateConnectionRequest
}

func raceDesktopGrants(t *testing.T, grants *product.GrantService, tenantID string, actor product.ActorRef, inputs []desktopGrantRaceInput, losingError error) product.ConnectionGrant {
	t.Helper()
	type result struct {
		grant product.ConnectionGrant
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, len(inputs))
	var wait sync.WaitGroup
	for _, input := range inputs {
		input := input
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			grant, _, err := grants.Create(context.Background(), tenantID, actor, input.session.ID, input.key, input.request)
			results <- result{grant: grant, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var winner product.ConnectionGrant
	successes, rejected := 0, 0
	for item := range results {
		switch {
		case item.err == nil:
			successes++
			winner = item.grant
		case errors.Is(item.err, losingError):
			rejected++
		default:
			t.Fatalf("Desktop grant race unexpected result=%#v", item)
		}
	}
	if successes != 1 || rejected != len(inputs)-1 {
		t.Fatalf("Desktop grant race successes=%d rejected=%d", successes, rejected)
	}
	return winner
}

func prepareReadyDesktopGrantSession(t *testing.T, store *Store, application *product.Application, slots *product.SlotService, sessions *product.SessionService, tenantID string, actor product.ActorRef, workspaceID, slotKey, suffix string) product.RuntimeSession {
	t.Helper()
	ctx := context.Background()
	workspace, err := application.GetWorkspace(ctx, tenantID, actor, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := slots.Put(ctx, tenantID, actor, workspaceID, slotKey, "desktop-grant-slot-"+suffix, desktopSlotRequest(workspace.Version)); err != nil {
		t.Fatal(err)
	}
	slotWork, err := store.LeaseDesktopSlotWork(ctx, "desktop-grant-slot-worker-"+suffix, 10*time.Second, 1)
	if err != nil || len(slotWork) != 1 || slotWork[0].SlotKey != slotKey {
		t.Fatalf("Desktop grant slot work=%#v err=%v", slotWork, err)
	}
	now := time.Now().UTC()
	evidence := product.ProviderOperationEvidence{
		ProviderRevisionID:  strings.Repeat("d", 40),
		SandboxID:           "provider-desktop-grant-" + suffix,
		ProviderOperationID: "provider-desktop-slot-" + suffix,
		RequestDigest:       "sha256:" + strings.Repeat("a", 64),
		State:               "accepted",
		ObservedAt:          now,
	}
	if err := store.RecordDispatchEvidence(ctx, slotWork[0], evidence); err != nil {
		t.Fatal(err)
	}
	observations, err := store.LeaseDesktopProviderObservations(ctx, "desktop-grant-slot-observer-"+suffix, 10*time.Second, 1)
	if err != nil || len(observations) != 1 {
		t.Fatalf("Desktop grant slot observations=%#v err=%v", observations, err)
	}
	evidence.State = "succeeded"
	evidence.ObservedAt = now.Add(time.Millisecond)
	if err := store.RecordProviderObservation(ctx, observations[0], evidence, "evt-desktop-grant-slot-"+suffix); err != nil {
		t.Fatal(err)
	}

	workspace, err = application.GetWorkspace(ctx, tenantID, actor, workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	operation, _, err := sessions.Create(ctx, tenantID, actor, workspaceID, "desktop-grant-session-"+suffix, product.CreateSessionRequest{
		ExpectedWorkspaceVersion: workspace.Version,
		SlotKey:                  slotKey,
		Kind:                     product.SessionKindDesktop,
		ProtocolProfile:          product.SessionProfileDesktop,
		ExpiresInSeconds:         1800,
		RecordingPolicy:          "metadata_only",
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionWork, err := store.LeaseDesktopSessionWork(ctx, "desktop-grant-session-worker-"+suffix, 10*time.Second, 1)
	if err != nil || len(sessionWork) != 1 || sessionWork[0].SessionID != operation.SessionID {
		t.Fatalf("Desktop grant session work=%#v err=%v", sessionWork, err)
	}
	evidence.ProviderOperationID = "provider-desktop-session-" + suffix
	evidence.RequestDigest = "sha256:" + strings.Repeat("b", 64)
	evidence.State = "accepted"
	evidence.ObservedAt = now.Add(2 * time.Millisecond)
	if err := store.RecordSessionDispatch(ctx, sessionWork[0], evidence); err != nil {
		t.Fatal(err)
	}
	observations, err = store.LeaseDesktopProviderObservations(ctx, "desktop-grant-session-observer-"+suffix, 10*time.Second, 1)
	if err != nil || len(observations) != 1 || observations[0].SessionID != operation.SessionID {
		t.Fatalf("Desktop grant session observations=%#v err=%v", observations, err)
	}
	evidence.State = "succeeded"
	evidence.HandoffReference = "ref:desktop-session:opaque-" + suffix
	evidence.ConnectionGeneration = 7
	evidence.HandoffExpiresAt = sessionWork[0].ExpiresAt
	evidence.ObservedAt = now.Add(3 * time.Millisecond)
	if err := store.RecordProviderObservation(ctx, observations[0], evidence, "evt-desktop-grant-session-"+suffix); err != nil {
		t.Fatal(err)
	}
	ready, err := sessions.Get(ctx, tenantID, actor, operation.SessionID)
	if err != nil || ready.State != product.SessionStateReady || ready.ProtocolProfile != product.SessionProfileDesktop {
		t.Fatalf("ready Desktop grant session=%#v err=%v", ready, err)
	}
	return ready
}
