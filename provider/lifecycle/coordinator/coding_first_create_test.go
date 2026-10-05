package coordinator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/memory"
)

type testCodingBoundRepository struct {
	repository.Repository
	mu     sync.Mutex
	clock  Clock
	digest string
	begins int
}

func (r *testCodingBoundRepository) BeginCodingFirstCreate(ctx context.Context, operationID string) (
	codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	operation, err := r.Repository.GetOperation(ctx, operationID)
	if err != nil || operation.State != lifecycle.OperationAccepted || operation.CancelRequested ||
		!operation.Deadline.After(r.clock.Now()) {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	sandbox, err := r.Repository.GetSandbox(ctx, operation.SandboxID)
	if err != nil || sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	allocationID, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID, sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	now := r.clock.Now()
	provisioning, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedProvisioning, sandbox.Generation, now)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	running, err := lifecycle.BeginOperation(operation, now)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if err := r.Repository.UpdateSandbox(ctx, provisioning, sandbox.Generation, operation.FencingToken); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if err := r.Repository.UpdateOperation(ctx, running); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if _, err := r.Repository.AppendEvent(ctx, lifecycle.Event{ID: "event-coding-first-permit", SandboxID: sandbox.ID,
		OperationID: operation.ID, Generation: sandbox.Generation, FencingToken: operation.FencingToken,
		Kind: "provisioning", OccurredAt: now}); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	r.begins++
	return codingidentity.Reservation{PlanDigest: "sha256:" + strings.Repeat("a", 64),
		Slot: codingidentity.Slot{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
			InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
		Claim: codingidentity.Claim{TenantDigest: tenantDigest, SandboxID: sandbox.ID,
			AllocationID: allocationID, OperationID: operation.ID, AttemptID: operation.AttemptID,
			RequestDigest: r.digest, Generation: sandbox.Generation, Fence: operation.FencingToken},
		SpecDigest: "sha256:" + strings.Repeat("b", 64), Status: codingidentity.Creating}, running, provisioning, nil
}

type testCodingDispatchDriver struct {
	mu             sync.Mutex
	legacyCreates  int
	legacyInspects int
	dispatches     int
	dispatchErr    error
}

// Simulate a different coordinator winning the PG transaction after this
// coordinator read Accepted, then receiving the conflict from its own permit.
type testCodingConflictAfterWinner struct{ *testCodingBoundRepository }

func (r *testCodingConflictAfterWinner) BeginCodingFirstCreate(ctx context.Context, operationID string) (
	codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error,
) {
	if _, _, _, err := r.testCodingBoundRepository.BeginCodingFirstCreate(ctx, operationID); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
}

func (d *testCodingDispatchDriver) Create(context.Context, lifecycle.Sandbox) error {
	d.mu.Lock()
	d.legacyCreates++
	d.mu.Unlock()
	return errors.New("legacy Docker Create must never be used")
}

func (d *testCodingDispatchDriver) Inspect(context.Context, string) (RuntimeObservation, error) {
	d.mu.Lock()
	d.legacyInspects++
	d.mu.Unlock()
	return RuntimeObservation{State: RuntimeReady}, nil
}

func (d *testCodingDispatchDriver) DispatchCodingCreate(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox,
	ticket codingidentity.Reservation) error {
	if ctx.Err() != nil || operation.ID != ticket.Claim.OperationID ||
		sandbox.ID != ticket.Claim.SandboxID || ticket.Status != codingidentity.Creating {
		return codingidentity.ErrConflict
	}
	d.mu.Lock()
	d.dispatches++
	err := d.dispatchErr
	d.mu.Unlock()
	return err
}

func newTestCodingCoordinator(t *testing.T, dispatchErr error) (*Coordinator, *testCodingBoundRepository, *testCodingDispatchDriver, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	base := memory.NewRepository()
	t.Cleanup(func() { _ = base.Close() })
	digest := validRequest(clock.Now()).RequestDigest
	bound := &testCodingBoundRepository{Repository: base, clock: clock, digest: digest}
	driver := &testCodingDispatchDriver{dispatchErr: dispatchErr}
	c, err := NewWithCodingFirstCreate(bound, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	return c, bound, driver, clock
}

func codingRequest(now time.Time) lifecycle.CreateRequest {
	request := validRequest(now)
	request.Spec.RuntimeProfile = "sandbox-runtime-coding-shell-v1"
	request.Spec.Network = lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}
	return request
}

func TestCodingFirstPermitCoordinatorDoesNotUseLegacyCreateOrClaimReady(t *testing.T) {
	c, bound, driver, clock := newTestCodingCoordinator(t, nil)
	request := codingRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := c.ReconcileOperation(context.Background(), request.OperationID)
	if err != nil || !result.Dispatched || result.Operation.State != lifecycle.OperationRunning ||
		result.Sandbox.ObservedState != lifecycle.ObservedProvisioning {
		t.Fatalf("ticket dispatch was treated as ready or failed: %#v, %v", result, err)
	}
	if _, err := c.ReconcileOperation(context.Background(), request.OperationID); !errors.Is(err, ErrUnknownRuntime) {
		t.Fatalf("running create used legacy inspect: %v", err)
	}
	restarted, err := NewWithCodingFirstCreate(bound, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ReconcileOperation(context.Background(), request.OperationID); !errors.Is(err, ErrUnknownRuntime) {
		t.Fatalf("restart inferred ready without receipt: %v", err)
	}
	if bound.begins != 1 || driver.dispatches != 1 || driver.legacyCreates != 0 || driver.legacyInspects != 0 {
		t.Fatalf("first-permit/replay counts: bound=%d dispatch=%d legacy-create=%d legacy-inspect=%d",
			bound.begins, driver.dispatches, driver.legacyCreates, driver.legacyInspects)
	}
}

func TestCodingUnknownAndExpiredNeverRedispatch(t *testing.T) {
	c, bound, driver, clock := newTestCodingCoordinator(t, ErrUnknownRuntime)
	request := codingRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(context.Background(), request.OperationID); err == nil {
		t.Fatal("unknown dispatch was reported complete")
	}
	unknown, err := bound.GetOperation(context.Background(), request.OperationID)
	if err != nil || unknown.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("unknown operation = %#v, %v", unknown, err)
	}
	if _, err := c.ReconcileOperation(context.Background(), request.OperationID); !errors.Is(err, ErrUnknownRuntime) {
		t.Fatalf("unknown operation reentered dispatch: %v", err)
	}
	if bound.begins != 1 || driver.dispatches != 1 || driver.legacyCreates != 0 || driver.legacyInspects != 0 {
		t.Fatal("unknown operation released or redispatched")
	}
	other, otherBound, otherDriver, otherClock := newTestCodingCoordinator(t, nil)
	expired := codingRequest(otherClock.Now())
	if _, err := other.AcceptCreate(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	otherClock.mu.Lock()
	otherClock.now = expired.Deadline.Add(time.Second)
	otherClock.mu.Unlock()
	if _, err := other.ReconcileOperation(context.Background(), expired.OperationID); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("expired first permit did not fail closed: %v", err)
	}
	if otherBound.begins != 0 || otherDriver.dispatches != 0 {
		t.Fatal("expired create gained first permit or dispatch")
	}
}

func TestCodingExplicitCapabilityPairRequired(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	base := memory.NewRepository()
	t.Cleanup(func() { _ = base.Close() })
	bound := &testCodingBoundRepository{Repository: base, clock: clock}
	if _, err := NewWithCodingFirstCreate(bound, &testDriver{}, clock); !errors.Is(err, ErrInvalidCoordinator) {
		t.Fatalf("missing ticket-only dispatcher accepted: %v", err)
	}
}

func TestCodingPermitConflictReturnsCurrentDurableWinnerWithoutDispatch(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	base := memory.NewRepository()
	t.Cleanup(func() { _ = base.Close() })
	request := codingRequest(clock.Now())
	bound := &testCodingBoundRepository{Repository: base, clock: clock, digest: request.RequestDigest}
	repo := &testCodingConflictAfterWinner{testCodingBoundRepository: bound}
	driver := &testCodingDispatchDriver{}
	c, err := NewWithCodingFirstCreate(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := c.ReconcileOperation(context.Background(), request.OperationID)
	if !errors.Is(err, codingidentity.ErrConflict) || result.Dispatched ||
		result.Operation.State != lifecycle.OperationRunning || result.Sandbox.ObservedState != lifecycle.ObservedProvisioning {
		t.Fatalf("conflict reported stale Accepted state or dispatched: %#v, %v", result, err)
	}
	if bound.begins != 1 || driver.dispatches != 0 || driver.legacyCreates != 0 || driver.legacyInspects != 0 {
		t.Fatal("conflict path used a second permit or physical driver")
	}
}
