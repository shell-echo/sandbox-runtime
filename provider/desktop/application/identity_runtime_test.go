package application

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

type desktopIdentityLedgerFixture struct {
	mu           sync.Mutex
	plan         sandboxidentity.Plan
	state        sandboxidentity.State
	failComplete bool
}

func (f *desktopIdentityLedgerFixture) Plan() sandboxidentity.Plan { return f.plan }
func (f *desktopIdentityLedgerFixture) Reservations(context.Context) ([]sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sandboxidentity.Reservation(nil), f.state.Reservations...), nil
}
func (f *desktopIdentityLedgerFixture) ReserveAuthorized(_ context.Context, allocation desktop.Allocation,
	specs map[string]string) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state.Reserve(f.plan, desktopAllocationClaim(allocation), specs)
}
func (f *desktopIdentityLedgerFixture) BeginCreateAuthorized(_ context.Context, _ desktop.Allocation,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state.BeginCreate(f.plan, ticket)
}
func (f *desktopIdentityLedgerFixture) CompleteCreate(_ context.Context,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failComplete {
		return sandboxidentity.Reservation{}, errors.New("PG CompleteCreate unavailable")
	}
	return f.state.CompleteCreate(f.plan, ticket)
}
func (f *desktopIdentityLedgerFixture) BeginCleanupAuthorized(context.Context, desktop.AllocationReceipt,
	sandboxidentity.Reservation, string) (sandboxidentity.Reservation, error) {
	return sandboxidentity.Reservation{}, sandboxidentity.ErrInProgress
}
func (f *desktopIdentityLedgerFixture) CompleteCleanupAuthorized(context.Context, sandboxidentity.Reservation,
	func(context.Context, sandboxidentity.Reservation) error) error {
	return sandboxidentity.ErrInProgress
}
func (f *desktopIdentityLedgerFixture) CompletedRetirement(context.Context,
	desktop.AllocationReceipt) (sandboxidentity.Reservation, error) {
	return sandboxidentity.Reservation{}, sandboxidentity.ErrConflict
}
func (f *desktopIdentityLedgerFixture) RetireUnallocated(context.Context, desktop.Record) error {
	return sandboxidentity.ErrInProgress
}

type desktopBoundRuntimeFixture struct {
	authority     sandboxidentity.RuntimeAuthority
	ledger        *desktopIdentityLedgerFixture
	receipt       desktop.AllocationReceipt
	mu            sync.Mutex
	creates       int
	recovers      int
	completed     bool
	allocationErr error
}

func (f *desktopBoundRuntimeFixture) RuntimeAuthority() sandboxidentity.RuntimeAuthority {
	return f.authority
}
func (f *desktopBoundRuntimeFixture) Ready(context.Context) error { return nil }
func (f *desktopBoundRuntimeFixture) DesiredSpecDigests(desktop.Allocation) (map[string]string, error) {
	return map[string]string{f.authority.Slots[0].ID: desktopIdentityDigest("c")}, nil
}
func (f *desktopBoundRuntimeFixture) AllocateBound(_ context.Context, _ desktop.Allocation,
	ticket sandboxidentity.Reservation) (desktop.AllocationReceipt, error) {
	f.ledger.mu.Lock()
	creating := len(f.ledger.state.Reservations) == 1 && f.ledger.state.Reservations[0].Status == sandboxidentity.Creating
	f.ledger.mu.Unlock()
	if !creating || ticket.Status != sandboxidentity.Creating {
		return desktop.AllocationReceipt{}, errors.New("Docker called before PG BeginCreate")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.allocationErr != nil {
		return desktop.AllocationReceipt{}, f.allocationErr
	}
	f.completed = true
	return f.receipt, nil
}
func (f *desktopBoundRuntimeFixture) CompletedBound(_ context.Context, _ desktop.Allocation,
	ticket sandboxidentity.Reservation) (desktop.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.completed || ticket.Status != sandboxidentity.Creating {
		return desktop.AllocationReceipt{}, desktop.ErrAllocationUnknown
	}
	return f.receipt, nil
}
func (f *desktopBoundRuntimeFixture) RecoverBound(_ context.Context, _ desktop.Allocation,
	ticket sandboxidentity.Reservation) (desktop.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ticket.Status != sandboxidentity.Active {
		return desktop.AllocationReceipt{}, desktop.ErrAllocationUnknown
	}
	f.recovers++
	return f.receipt, nil
}
func (f *desktopBoundRuntimeFixture) CompletedTerminalBound(context.Context, desktop.Record,
	sandboxidentity.Reservation) (desktop.AllocationReceipt, error) {
	return desktop.AllocationReceipt{}, desktop.ErrAllocationUnknown
}
func (f *desktopBoundRuntimeFixture) ObserveBound(context.Context, desktop.Allocation,
	desktop.AllocationReceipt, sandboxidentity.Reservation) (desktop.AllocationObservation, error) {
	return desktop.AllocationObservation{}, desktop.ErrAllocationUnknown
}
func (f *desktopBoundRuntimeFixture) AttachBound(context.Context, desktop.AllocationReceipt,
	sandboxidentity.Reservation) (desktop.Attachment, error) {
	return desktop.Attachment{}, desktop.ErrAllocationUnknown
}
func (f *desktopBoundRuntimeFixture) CleanupBound(context.Context, desktop.AllocationReceipt,
	sandboxidentity.Reservation) error {
	return desktop.ErrAllocationUnknown
}
func (f *desktopBoundRuntimeFixture) ConfirmAbsentBound(context.Context, desktop.AllocationReceipt,
	sandboxidentity.Reservation) error {
	return desktop.ErrAllocationUnknown
}
func (f *desktopBoundRuntimeFixture) FinalizeCleanupBound(context.Context, desktop.AllocationReceipt,
	sandboxidentity.Reservation) error {
	return desktop.ErrAllocationUnknown
}

func desktopIdentityDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func newDesktopIdentityFixture(t *testing.T) (*DesktopIdentityRuntime,
	*desktopIdentityLedgerFixture, *desktopBoundRuntimeFixture, desktop.Allocation) {
	t.Helper()
	plan := sandboxidentity.Plan{ProfileDigest: desktopIdentityDigest("a"), OwnerDeployment: "provider-desktop-runtime",
		OwnerPrincipalDigest: desktopIdentityDigest("b"), Namespace: "desktop-test", ServiceName: "postgres",
		ServiceIdentityDigest: desktopIdentityDigest("d"), TrustEdgeID: "provider-desktop-postgres",
		EgressPolicyID: "desktop-egress", BrokerDeployment: "broker-desktop",
		BrokerRoleEdgeID: "broker-role-desktop", BrokerExternalEdgeID: "broker-external-desktop",
		MaterialBindingID: "desktop-runtime-dsn", DatabaseName: "provider_desktop",
		RuntimeRole: "desktop_runtime", ControllerID: "controller-1", Template: "desktop-sandbox-runtime",
		TemplateDigest: desktopIdentityDigest("e"), Capacity: 1,
		Slots: []sandboxidentity.Slot{{ID: "desktop-0000", WorkloadUID: 20000, WorkloadGID: 30000,
			GatewayUID: 20001, GatewayGID: 30001}}}
	state, err := sandboxidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := plan.ProjectRuntimeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)
	allocation := desktop.Allocation{Request: desktop.AllocationRequest{SandboxID: "sandbox-1",
		DesktopSessionID: "session-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 1, ExpectedGeneration: 1, RequestDigest: desktopIdentityDigest("f"),
		NetworkPolicyReference: "desktop-egress", ExpiresAt: now.Add(5 * time.Minute)}, AllocatedAt: now}
	receipt := desktop.AllocationReceipt{Reference: "ref:desktop/" + strings.Repeat("a", 32),
		SandboxID: allocation.Request.SandboxID, DesktopSessionID: allocation.Request.DesktopSessionID,
		OperationID: allocation.Request.OperationID, AttemptID: allocation.Request.AttemptID,
		FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1,
		AllocatedAt: now, ExpiresAt: allocation.Request.ExpiresAt}
	ledger := &desktopIdentityLedgerFixture{plan: plan, state: state}
	backend := &desktopBoundRuntimeFixture{authority: authority, ledger: ledger, receipt: receipt}
	runtime, err := NewDesktopIdentityRuntime(ledger, backend, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return runtime, ledger, backend, allocation
}

func TestDesktopIdentityKnownFinishedCreatingRecoversWithoutRedispatch(t *testing.T) {
	runtime, ledger, backend, allocation := newDesktopIdentityFixture(t)
	ledger.failComplete = true
	if _, err := runtime.Allocate(t.Context(), allocation); !errors.Is(err, desktop.ErrAllocationUnknown) {
		t.Fatalf("lost CompleteCreate = %v", err)
	}
	if backend.creates != 1 || ledger.state.Reservations[0].Status != sandboxidentity.Creating {
		t.Fatalf("first dispatch/PG status = %d/%s", backend.creates, ledger.state.Reservations[0].Status)
	}
	ledger.failComplete = false
	receipt, err := runtime.Allocate(t.Context(), allocation)
	if err != nil || receipt != backend.receipt || backend.creates != 1 ||
		ledger.state.Reservations[0].Status != sandboxidentity.Active {
		t.Fatalf("read-only recovery = %+v, %v, creates %d", receipt, err, backend.creates)
	}
	if _, err := runtime.Allocate(t.Context(), allocation); err != nil || backend.creates != 1 || backend.recovers != 1 {
		t.Fatalf("Active retry redispatched: %v, %d/%d", err, backend.creates, backend.recovers)
	}
}

func TestDesktopIdentityUnknownCreatingRetainsSlotAndNeverRedispatches(t *testing.T) {
	runtime, ledger, backend, allocation := newDesktopIdentityFixture(t)
	backend.allocationErr = desktop.ErrAllocationUnknown
	if _, err := runtime.Allocate(t.Context(), allocation); !errors.Is(err, desktop.ErrAllocationUnknown) {
		t.Fatalf("first unknown = %v", err)
	}
	backend.allocationErr = nil
	if _, err := runtime.Allocate(t.Context(), allocation); !errors.Is(err, desktop.ErrAllocationUnknown) {
		t.Fatalf("unproved Creating retry = %v", err)
	}
	if backend.creates != 1 || len(ledger.state.Reservations) != 1 ||
		ledger.state.Reservations[0].Status != sandboxidentity.Creating {
		t.Fatalf("unknown Creating was reused: %d, %+v", backend.creates, ledger.state.Reservations)
	}
}
