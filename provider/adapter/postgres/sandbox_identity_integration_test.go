//go:build integration

package providerpostgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

func TestSandboxIdentitySeparateProviderPostgresPools(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_SANDBOX_IDENTITY_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_SANDBOX_IDENTITY_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	container := fmt.Sprintf("sr-identity-pg-%d-%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container,
		"-e", "POSTGRES_PASSWORD=identity-admin", "-e", "POSTGRES_DB=provider_browser",
		"-p", "127.0.0.1::5432", providerPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start identity PostgreSQL: %v: %.512s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := func(database string) string {
		return "postgres://postgres:identity-admin@127.0.0.1:" + port + "/" + database + "?sslmode=disable"
	}
	runtimeDSN := func(database, role string) string {
		return "postgres://" + role + ":identity-runtime@127.0.0.1:" + port + "/" + database + "?sslmode=disable"
	}
	waitForProviderPostgres(t, ctx, adminDSN("provider_browser"))
	admin, err := pgxpool.New(ctx, adminDSN("provider_browser"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	for _, statement := range []string{
		`CREATE DATABASE provider_desktop`,
		`CREATE ROLE browser_provider_runtime LOGIN PASSWORD 'identity-runtime'`,
		`CREATE ROLE desktop_provider_runtime LOGIN PASSWORD 'identity-runtime'`,
		`REVOKE CONNECT ON DATABASE provider_browser FROM PUBLIC`,
		`REVOKE CONNECT ON DATABASE provider_desktop FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE provider_browser TO browser_provider_runtime`,
		`GRANT CONNECT ON DATABASE provider_desktop TO desktop_provider_runtime`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("set up isolated Provider databases: %v", err)
		}
	}
	for _, boundary := range []struct{ database, role string }{
		{"provider_browser", "browser_provider_runtime"}, {"provider_desktop", "desktop_provider_runtime"},
	} {
		owner, err := pgxpool.New(ctx, adminDSN(boundary.database))
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyMigrations(ctx, owner); err != nil {
			owner.Close()
			t.Fatal(err)
		}
		for _, statement := range []string{
			"GRANT USAGE ON SCHEMA sandbox_runtime_provider TO " + boundary.role,
			"GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO " + boundary.role,
			"GRANT SELECT,UPDATE ON sandbox_runtime_provider.control_state TO " + boundary.role,
		} {
			if _, err := owner.Exec(ctx, statement); err != nil {
				owner.Close()
				t.Fatal(err)
			}
		}
		owner.Close()
	}
	for _, crossed := range []struct{ database, role string }{
		{"provider_desktop", "browser_provider_runtime"}, {"provider_browser", "desktop_provider_runtime"},
	} {
		pool, err := pgxpool.New(ctx, runtimeDSN(crossed.database, crossed.role))
		if err == nil {
			pingCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			err = pool.Ping(pingCtx)
			stop()
			pool.Close()
		}
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "42501" {
			t.Fatalf("%s cross-connect to %s did not fail with database permission denial: %v", crossed.role, crossed.database, err)
		}
	}
	browserPool, err := pgxpool.New(ctx, runtimeDSN("provider_browser", "browser_provider_runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer browserPool.Close()
	secondBrowserPool, err := pgxpool.New(ctx, runtimeDSN("provider_browser", "browser_provider_runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer secondBrowserPool.Close()
	desktopPool, err := pgxpool.New(ctx, runtimeDSN("provider_desktop", "desktop_provider_runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer desktopPool.Close()
	for _, owner := range []struct {
		pool     *pgxpool.Pool
		database string
		role     string
	}{{browserPool, "provider_browser", "browser_provider_runtime"},
		{secondBrowserPool, "provider_browser", "browser_provider_runtime"},
		{desktopPool, "provider_desktop", "desktop_provider_runtime"}} {
		pool := owner.pool
		if err := VerifySchemaCompatibility(ctx, pool); err != nil {
			t.Fatal(err)
		}
		if err := VerifyRuntimeRole(ctx, pool, owner.role); err != nil {
			t.Fatalf("real PostgreSQL runtime role %s: %v", owner.role, err)
		}
		connection, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyBoundRuntimeConnection(ctx, connection.Conn(), owner.database, owner.role); err != nil {
			connection.Release()
			t.Fatalf("bound runtime connection %s: %v", owner.role, err)
		}
		if err := VerifyBoundRuntimeConnection(ctx, connection.Conn(), "wrong_database", owner.role); err == nil {
			connection.Release()
			t.Fatal("wrong database accepted on a live connection")
		}
		connection.Release()
	}
	browserPlan := integrationIdentityPlan("browser")
	desktopPlan := integrationIdentityPlan("desktop")
	browserStore, _ := New(browserPool, 10*time.Second)
	secondBrowserStore, _ := New(secondBrowserPool, 10*time.Second)
	desktopStore, _ := New(desktopPool, 10*time.Second)
	first, err := NewSandboxIdentityRepository(ctx, browserStore, browserPlan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSandboxIdentityRepository(ctx, secondBrowserStore, browserPlan)
	if err != nil {
		t.Fatal(err)
	}
	desktopRepo, err := NewSandboxIdentityRepository(ctx, desktopStore, desktopPlan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSandboxIdentityRepository(ctx, browserStore, desktopPlan); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-owner PostgreSQL constructor = %v", err)
	}
	if _, err := first.Reserve(ctx, identityClaim("sandbox-before-init"), identitySpecs(browserPlan)); !errors.Is(err, sandboxidentity.ErrUninitialized) {
		t.Fatalf("uninitialized reservation = %v", err)
	}
	cleanCheck := func(context.Context, sandboxidentity.Plan) error { return nil } // Disposable DB; no workload resources have been created.
	if err := first.Initialize(ctx, cleanCheck); err != nil {
		t.Fatal(err)
	}
	if err := second.Initialize(ctx, cleanCheck); !errors.Is(err, sandboxidentity.ErrConflict) {
		t.Fatalf("active authority was reinitialized: %v", err)
	}
	if err := desktopRepo.Initialize(ctx, cleanCheck); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := make([]sandboxidentity.Reservation, 0, 2)
	for index := range 16 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			repo := first
			if index%2 == 1 {
				repo = second
			}
			claim := identityClaim(fmt.Sprintf("sandbox-%d", index))
			reserved, err := repo.Reserve(ctx, claim, identitySpecs(browserPlan))
			if err != nil && !errors.Is(err, sandboxidentity.ErrExhausted) {
				t.Errorf("concurrent reserve: %v", err)
			}
			if err == nil {
				mu.Lock()
				accepted = append(accepted, reserved)
				mu.Unlock()
			}
		}(index)
	}
	wg.Wait()
	if len(accepted) != 2 || accepted[0].Slot.ID == accepted[1].Slot.ID {
		t.Fatalf("two-process-pool reservations = %+v", accepted)
	}
	unknown, err := first.BeginCreate(ctx, accepted[0])
	if err != nil || unknown.Status != sandboxidentity.Creating {
		t.Fatalf("unknown create state = %+v, %v", unknown, err)
	}
	if _, err := second.BeginCleanup(ctx, unknown); !errors.Is(err, sandboxidentity.ErrInProgress) {
		t.Fatalf("unknown create freed = %v", err)
	}
	creating, err := first.BeginCreate(ctx, accepted[1])
	if err != nil {
		t.Fatal(err)
	}
	active, err := first.CompleteCreate(ctx, creating)
	if err != nil {
		t.Fatal(err)
	}
	cleaning, err := second.BeginCleanup(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.CompleteCleanup(ctx, cleaning, func(context.Context, sandboxidentity.Reservation) error { return errors.New("Docker absence unknown") }); err == nil {
		t.Fatal("uncertain cleanup released a slot")
	}
	started := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		completed <- second.CompleteCleanup(ctx, cleaning, func(context.Context, sandboxidentity.Reservation) error {
			close(started)
			<-release
			return nil // Test-only exact-absence fixture; no workload container was created.
		})
	}()
	<-started
	readCtx, stopRead := context.WithTimeout(ctx, time.Second)
	if _, err := first.Reservations(readCtx); err != nil {
		t.Fatalf("external cleanup held global Provider row lock: %v", err)
	}
	stopRead()
	if _, err := first.Reserve(ctx, identityClaim("sandbox-during-cleaning"), identitySpecs(browserPlan)); !errors.Is(err, sandboxidentity.ErrExhausted) {
		t.Fatalf("concurrent Reserve reused Cleaning or Creating UID: %v", err)
	}
	if _, err := first.BeginCreate(ctx, active); !errors.Is(err, sandboxidentity.ErrConflict) {
		t.Fatalf("stale BeginCreate crossed Cleaning CAS: %v", err)
	}
	close(release)
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	reused, err := first.Reserve(ctx, identityClaim("sandbox-after-cleaning"), identitySpecs(browserPlan))
	if err != nil || reused.Slot != cleaning.Slot {
		t.Fatalf("freed exact UID was not reusable after CompleteCleanup: %+v, %v", reused, err)
	}
	reusedCleaning, err := first.BeginCleanup(ctx, reused)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CompleteCleanup(ctx, reusedCleaning, func(context.Context, sandboxidentity.Reservation) error {
		return nil // Test-only reservation; no Docker allocation was dispatched.
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := desktopRepo.Reserve(ctx, identityClaim("desktop-1"), identitySpecs(desktopPlan)); err != nil {
		t.Fatalf("Desktop owner pool = %v", err)
	}
	changed := browserPlan
	changed.ProfileDigest = identityDigest("9")
	drifted, err := NewSandboxIdentityRepository(ctx, browserStore, changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := drifted.Reservations(ctx); !errors.Is(err, sandboxidentity.ErrUninitialized) {
		t.Fatalf("plan drift = %v", err)
	}
	if output, err := exec.CommandContext(ctx, "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("restart identity PostgreSQL: %v: %.512s", err, output)
	}
	portOutput, err = exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err = net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	waitForProviderPostgres(t, ctx, adminDSN("provider_browser"))
	restartedBrowserPool, err := pgxpool.New(ctx, runtimeDSN("provider_browser", "browser_provider_runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer restartedBrowserPool.Close()
	restartedDesktopPool, err := pgxpool.New(ctx, runtimeDSN("provider_desktop", "desktop_provider_runtime"))
	if err != nil {
		t.Fatal(err)
	}
	defer restartedDesktopPool.Close()
	restartedBrowserStore, _ := New(restartedBrowserPool, 10*time.Second)
	restartedDesktopStore, _ := New(restartedDesktopPool, 10*time.Second)
	restartedBrowser, err := NewSandboxIdentityRepository(ctx, restartedBrowserStore, browserPlan)
	if err != nil {
		t.Fatal(err)
	}
	restartedDesktop, err := NewSandboxIdentityRepository(ctx, restartedDesktopStore, desktopPlan)
	if err != nil {
		t.Fatal(err)
	}
	if retained, err := restartedBrowser.Reservations(ctx); err != nil || len(retained) != 1 || retained[0] != unknown {
		t.Fatalf("unknown Browser slot after PostgreSQL restart = %+v, %v", retained, err)
	}
	if retained, err := restartedDesktop.Reservations(ctx); err != nil || len(retained) != 1 || retained[0].Status != sandboxidentity.Reserved {
		t.Fatalf("Desktop slot after PostgreSQL restart = %+v, %v", retained, err)
	} else {
		// This old test-owned reservation never had a dispatch permit.
		cleaning, cleanupErr := restartedDesktop.BeginCleanup(ctx, retained[0])
		if cleanupErr != nil {
			t.Fatal(cleanupErr)
		}
		if cleanupErr := restartedDesktop.CompleteCleanup(ctx, cleaning,
			func(context.Context, sandboxidentity.Reservation) error { return nil }); cleanupErr != nil {
			t.Fatal(cleanupErr)
		}
	}
	// The Desktop production ledger binds its original Open claim, not the
	// Close operation, to the one finite UID. The absence callback here is a
	// test fixture; this is a real PostgreSQL CAS gate, not a Docker gate.
	boundDesktop, err := NewDesktopBoundIdentityRepository(ctx, restartedDesktopStore, desktopPlan)
	if err != nil {
		t.Fatal(err)
	}
	desktopSessions, err := NewDesktopRepository(restartedDesktopStore)
	if err != nil {
		t.Fatal(err)
	}
	desktopNow := time.Now().UTC()
	desktopAuthority := desktop.SandboxAuthority{SandboxID: "desktop-bound-1", ProviderRevisionID: "desktop-revision-1",
		Ready: true, Generation: 1, LeaseExpiresAt: desktopNow.Add(5 * time.Minute), FencingToken: 1,
		CapabilityProfileID: desktop.CapabilityProfileID, NetworkPolicyReference: "desktop-policy-1"}
	if err := desktopSessions.SynchronizeSandboxAuthority(ctx, desktopAuthority); err != nil {
		t.Fatal(err)
	}
	desktopOpen := desktop.OpenRequest{SandboxID: desktopAuthority.SandboxID,
		ProviderRevisionID: desktopAuthority.ProviderRevisionID, OperationID: "desktop-bound-open",
		AttemptID: "desktop-bound-attempt", FencingToken: 1, IdempotencyKey: "desktop-bound-key",
		RequestDigest: identityDigest("7"), Deadline: desktopNow.Add(4 * time.Minute), ExpectedGeneration: 1,
		DesktopSessionID: "desktop-bound-session", CapabilityProfileID: desktop.CapabilityProfileID,
		ExpiresAt: desktopNow.Add(4 * time.Minute)}
	desktopOpenReservation, err := desktopSessions.ReserveOpen(ctx, desktopOpen, desktopNow)
	if err != nil {
		t.Fatal(err)
	}
	desktopRunning, err := desktop.Transition(desktopOpenReservation.Record, desktop.StatusRunning,
		desktopNow.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopSessions.UpdateOpenAt(ctx, desktopRunning, desktop.StatusAccepted, desktopRunning.ObservedAt); err != nil {
		t.Fatal(err)
	}
	desktopAllocation := desktop.Allocation{Request: desktop.AllocationRequest{
		SandboxID: desktopOpen.SandboxID, DesktopSessionID: desktopOpen.DesktopSessionID,
		OperationID: desktopOpen.OperationID, AttemptID: desktopOpen.AttemptID,
		FencingToken: desktopOpen.FencingToken, ExpectedGeneration: desktopOpen.ExpectedGeneration,
		RequestDigest: desktopOpen.RequestDigest, NetworkPolicyReference: desktopAuthority.NetworkPolicyReference,
		ExpiresAt: desktopOpen.ExpiresAt}, AllocatedAt: desktopOpenReservation.Record.AcceptedAt}
	desktopTicket, err := boundDesktop.ReserveAuthorized(ctx, desktopAllocation, identitySpecs(desktopPlan))
	if err != nil || desktopTicket.Status != sandboxidentity.Reserved {
		t.Fatalf("Desktop authorized slot = %+v, %v", desktopTicket, err)
	}
	creatingDesktop, err := boundDesktop.BeginCreateAuthorized(ctx, desktopAllocation, desktopTicket)
	if err != nil || creatingDesktop.Status != sandboxidentity.Creating {
		t.Fatalf("Desktop first dispatch permit = %+v, %v", creatingDesktop, err)
	}
	activeDesktop, err := boundDesktop.CompleteCreate(ctx, creatingDesktop)
	if err != nil || activeDesktop.Status != sandboxidentity.Active {
		t.Fatalf("Desktop known create completion = %+v, %v", activeDesktop, err)
	}
	desktopReceipt := desktop.AllocationReceipt{Reference: "ref:desktop/00000000000000000000000000000001",
		SandboxID: desktopOpen.SandboxID, DesktopSessionID: desktopOpen.DesktopSessionID,
		OperationID: desktopOpen.OperationID, AttemptID: desktopOpen.AttemptID,
		FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1,
		AllocatedAt: desktopAllocation.AllocatedAt, ExpiresAt: desktopOpen.ExpiresAt}
	attachedDesktop, err := desktopSessions.AttachAllocation(ctx, desktopReceipt)
	if err != nil {
		t.Fatal(err)
	}
	desktopSucceeded, err := desktop.Transition(attachedDesktop.Record, desktop.StatusSucceeded,
		desktopNow.Add(2*time.Second), &desktop.EndpointEvidence{
			InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := desktopSessions.UpdateOpenAt(ctx, desktopSucceeded, desktop.StatusRunning, desktopSucceeded.ObservedAt); err != nil {
		t.Fatal(err)
	}
	desktopClose := desktop.CloseRequest{SandboxID: desktopOpen.SandboxID,
		ProviderRevisionID: desktopOpen.ProviderRevisionID, OperationID: "desktop-bound-close",
		AttemptID: "desktop-bound-close-attempt", FencingToken: 1, IdempotencyKey: "desktop-bound-close-key",
		RequestDigest: identityDigest("8"), Deadline: desktopNow.Add(4 * time.Minute), ExpectedGeneration: 1,
		DesktopSessionID: desktopOpen.DesktopSessionID, ConnectionGeneration: 1, Reason: "caller_complete"}
	desktopCloseReservation, err := desktopSessions.ReserveClose(ctx, desktopClose, desktopNow.Add(3*time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	if desktopCloseReservation.Record.SourceOpenOperationID != desktopOpen.OperationID {
		t.Fatal("Desktop Close did not retain source Open authority")
	}
	cleaningDesktop, err := boundDesktop.BeginCleanupAuthorized(ctx, desktopReceipt, activeDesktop, desktopClose.OperationID)
	if err != nil || cleaningDesktop.Status != sandboxidentity.Cleaning {
		t.Fatalf("Desktop source-Open cleanup fence = %+v, %v", cleaningDesktop, err)
	}
	if err := boundDesktop.CompleteCleanupAuthorized(ctx, cleaningDesktop,
		func(context.Context, sandboxidentity.Reservation) error {
			return errors.New("Desktop exact absence unknown")
		}); err == nil {
		t.Fatal("Desktop UID released without exact absence")
	}
	if err := boundDesktop.CompleteCleanupAuthorized(ctx, cleaningDesktop,
		func(context.Context, sandboxidentity.Reservation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if proof, err := boundDesktop.CompletedRetirement(ctx, desktopReceipt); err != nil || proof != cleaningDesktop {
		t.Fatalf("Desktop released source-Open proof = %+v, %v", proof, err)
	}
	if replay, err := boundDesktop.ReserveAuthorized(ctx, desktopAllocation, identitySpecs(desktopPlan)); err == nil {
		t.Fatalf("retired Desktop Open claim replayed: %+v", replay)
	}
	if remaining, err := restartedDesktop.Reservations(ctx); err != nil || len(remaining) != 0 {
		t.Fatalf("Desktop slot not released: %+v, %v", remaining, err)
	}
	if retry, err := restartedBrowser.Reserve(ctx, unknown.Claim, identitySpecs(browserPlan)); err != nil || retry != unknown {
		t.Fatalf("restart retry changed unknown slot = %+v, %v", retry, err)
	}
	admin, err = pgxpool.New(ctx, adminDSN("provider_browser"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `UPDATE sandbox_runtime_provider.control_state
SET documents=documents-'sandbox_identity_browser_state' WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	if _, err := restartedBrowser.Reservations(ctx); !errors.Is(err, sandboxidentity.ErrUninitialized) {
		t.Fatalf("missing initialized state became empty = %v", err)
	}
}

func integrationIdentityPlan(role string) sandboxidentity.Plan {
	plan := sandboxidentity.Plan{ProfileDigest: identityDigest("a"), OwnerPrincipalDigest: identityDigest("b"),
		TemplateDigest: identityDigest("c"), ServiceName: "postgres", ServiceIdentityDigest: identityDigest("f")}
	if role == "browser" {
		plan.Capacity = 2
		plan.OwnerDeployment, plan.Template, plan.ControllerID = "provider-browser-runtime", "browser-sandbox-runtime", "browser-controller-1"
		plan.Namespace, plan.TrustEdgeID, plan.MaterialBindingID = "browser-production", "provider-browser-postgres", "browser-provider-runtime-dsn"
		plan.EgressPolicyID, plan.BrokerDeployment = "provider-browser-egress", "egress-broker-provider-browser"
		plan.BrokerRoleEdgeID, plan.BrokerExternalEdgeID = "egress-role-provider-browser", "egress-provider-browser-postgres"
		plan.DatabaseName, plan.RuntimeRole = "provider_browser", "browser_provider_runtime"
		plan.Slots = []sandboxidentity.Slot{
			{ID: "browser-0000", WorkloadUID: 41000, WorkloadGID: 51000, GatewayUID: 43000, GatewayGID: 53000},
			{ID: "browser-0001", WorkloadUID: 41001, WorkloadGID: 51001, GatewayUID: 43001, GatewayGID: 53001},
		}
	} else {
		plan.Capacity = 1
		plan.OwnerDeployment, plan.Template, plan.ControllerID = "provider-desktop-runtime", "desktop-sandbox-runtime", "desktop-controller-1"
		plan.Namespace, plan.TrustEdgeID, plan.MaterialBindingID = "desktop-production", "provider-desktop-postgres", "desktop-provider-runtime-dsn"
		plan.EgressPolicyID, plan.BrokerDeployment = "provider-desktop-egress", "egress-broker-provider-desktop"
		plan.BrokerRoleEdgeID, plan.BrokerExternalEdgeID = "egress-role-provider-desktop", "egress-provider-desktop-postgres"
		plan.DatabaseName, plan.RuntimeRole = "provider_desktop", "desktop_provider_runtime"
		plan.Slots = []sandboxidentity.Slot{{ID: "desktop-0000", WorkloadUID: 42000, WorkloadGID: 52000, GatewayUID: 44000, GatewayGID: 54000}}
	}
	return plan
}

func identityDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func identityClaim(sandbox string) sandboxidentity.Claim {
	return sandboxidentity.Claim{SandboxID: sandbox, SessionID: sandbox + "-session", OperationID: sandbox + "-operation",
		AttemptID: "attempt-1", RequestDigest: identityDigest("d"), Generation: 1, Fence: 1}
}

func identitySpecs(plan sandboxidentity.Plan) map[string]string {
	result := make(map[string]string, len(plan.Slots))
	for _, slot := range plan.Slots {
		result[slot.ID] = identityDigest("e")
	}
	return result
}
