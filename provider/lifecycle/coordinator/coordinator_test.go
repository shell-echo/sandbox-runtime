package coordinator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/memory"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

type testDriver struct {
	mu         sync.Mutex
	creates    int
	inspect    RuntimeObservation
	createErr  error
	inspectErr error
}

type controlDriver struct {
	mu          sync.Mutex
	states      map[string]RuntimeState
	removeCalls int
	removeErr   error
}

func newControlDriver() *controlDriver { return &controlDriver{states: make(map[string]RuntimeState)} }

func (d *controlDriver) Create(ctx context.Context, sandbox lifecycle.Sandbox) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	d.states[sandbox.ID] = RuntimeReady
	d.mu.Unlock()
	return nil
}

func (d *controlDriver) Inspect(ctx context.Context, id string) (RuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeObservation{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.states[id]
	if !ok {
		return RuntimeObservation{State: RuntimeAbsent}, nil
	}
	return RuntimeObservation{State: state}, nil
}

func (d *controlDriver) Suspend(ctx context.Context, id string) error {
	return d.transition(ctx, id, RuntimeReady, RuntimeSuspended)
}

func (d *controlDriver) Resume(ctx context.Context, id string) error {
	return d.transition(ctx, id, RuntimeSuspended, RuntimeReady)
}

func (d *controlDriver) transition(ctx context.Context, id string, from, to RuntimeState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.states[id] != from {
		return errors.New("unexpected runtime state")
	}
	d.states[id] = to
	return nil
}

func (d *controlDriver) Remove(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.removeCalls++
	delete(d.states, id)
	return d.removeErr
}

func (d *testDriver) Create(ctx context.Context, _ lifecycle.Sandbox) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.creates++
	return d.createErr
}

func (d *testDriver) Inspect(ctx context.Context, _ string) (RuntimeObservation, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeObservation{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inspectErr != nil {
		return RuntimeObservation{}, d.inspectErr
	}
	return d.inspect, nil
}

type staleSandboxRepository struct{ repository.Repository }

func (r staleSandboxRepository) UpdateSandbox(context.Context, lifecycle.Sandbox, uint64, uint64) error {
	return lifecycle.ErrGenerationConflict
}

func validRequest(now time.Time) lifecycle.CreateRequest {
	return lifecycle.CreateRequest{
		OperationID:    "operation-create-1",
		AttemptID:      "attempt-1",
		FencingToken:   1,
		IdempotencyKey: "create-1",
		RequestDigest:  "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:       now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID:          "sandbox-1",
			TenantID:           "tenant-1",
			WorkOrderID:        "work-1",
			WorkspaceID:        "workspace-1",
			ProviderRevisionID: "revision-1",
			RuntimeProfile:     "profile-1",
			SandboxSlotKey:     "primary",
			LeaseExpiresAt:     now.Add(time.Hour),
		},
	}
}

func newCoordinator(t *testing.T, driver *testDriver) (*Coordinator, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	repo := memory.NewRepository()
	coordinator, err := New(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return coordinator, clock
}

func TestAcceptCreateIsDurableAndIdempotent(t *testing.T) {
	driver := &testDriver{}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	first, err := c.AcceptCreate(context.Background(), request)
	if err != nil || first.Replayed || first.Operation.State != lifecycle.OperationAccepted {
		t.Fatalf("first accept = %#v, %v", first, err)
	}
	second, err := c.AcceptCreate(context.Background(), request)
	if err != nil || !second.Replayed || second.Operation.ID != first.Operation.ID {
		t.Fatalf("replay = %#v, %v", second, err)
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 0 {
		t.Fatalf("AcceptCreate dispatched %d backend calls", creates)
	}
}

func TestLifecycleControlMutationsAndEventsReconcileExactRuntime(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	repo := memory.NewRepository()
	driver := newControlDriver()
	c, err := New(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	create := validRequest(now)
	if _, err := c.AcceptCreate(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(context.Background(), create.OperationID); err != nil {
		t.Fatal(err)
	}

	suspend := lifecycle.DesiredStateRequest{MutationRequest: mutationRequest(now, "suspend", 2, 1), DesiredState: lifecycle.DesiredSuspended}
	accepted, err := c.AcceptDesiredState(context.Background(), create.Spec.SandboxID, suspend)
	if err != nil || accepted.Sandbox.Generation != 2 {
		t.Fatalf("AcceptDesiredState() = %#v, %v", accepted, err)
	}
	result, err := c.ReconcileOperation(context.Background(), suspend.OperationID)
	if err != nil || result.Sandbox.ObservedState != lifecycle.ObservedSuspended || result.Operation.State != lifecycle.OperationSucceeded {
		t.Fatalf("suspend reconcile = %#v, %v", result, err)
	}

	resume := lifecycle.DesiredStateRequest{MutationRequest: mutationRequest(now, "resume", 3, 2), DesiredState: lifecycle.DesiredReady}
	if _, err := c.AcceptDesiredState(context.Background(), create.Spec.SandboxID, resume); err != nil {
		t.Fatal(err)
	}
	result, err = c.ReconcileOperation(context.Background(), resume.OperationID)
	if err != nil || result.Sandbox.ObservedState != lifecycle.ObservedReady || result.Sandbox.Generation != 3 {
		t.Fatalf("resume reconcile = %#v, %v", result, err)
	}

	lease := lifecycle.LeaseRequest{MutationRequest: mutationRequest(now, "lease", 4, 3), ExtendSeconds: 60}
	leaseResult, err := c.AcceptLease(context.Background(), create.Spec.SandboxID, lease, 7200)
	if err != nil || leaseResult.Sandbox.Generation != 3 || !leaseResult.Sandbox.LeaseExpiresAt.Equal(create.Spec.LeaseExpiresAt.Add(time.Minute)) {
		t.Fatalf("lease accept = %#v, %v", leaseResult, err)
	}
	if _, err := c.ReconcileOperation(context.Background(), lease.OperationID); err != nil {
		t.Fatal(err)
	}

	terminate := lifecycle.TerminateRequest{MutationRequest: mutationRequest(now, "terminate", 5, 3), Reason: "complete"}
	if _, err := c.AcceptTerminate(context.Background(), create.Spec.SandboxID, terminate); err != nil {
		t.Fatal(err)
	}
	result, err = c.ReconcileOperation(context.Background(), terminate.OperationID)
	if err != nil || result.Sandbox.ObservedState != lifecycle.ObservedTerminated || result.Operation.State != lifecycle.OperationSucceeded {
		t.Fatalf("terminate reconcile = %#v, %v", result, err)
	}
	page, err := c.ReadEvents(context.Background(), create.Spec.SandboxID, 0)
	if err != nil || len(page.Events) < 9 || page.NextSequence != page.LatestSequence {
		t.Fatalf("event page = %#v, %v", page, err)
	}
	for index, event := range page.Events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("event sequence at %d = %d", index, event.Sequence)
		}
	}
}

func TestTerminationOutcomeUnknownReconcilesByObservationWithoutRedispatch(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	repo := memory.NewRepository()
	driver := newControlDriver()
	c, err := New(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	create := validRequest(now)
	if _, err := c.AcceptCreate(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(context.Background(), create.OperationID); err != nil {
		t.Fatal(err)
	}
	driver.removeErr = ErrUnknownRuntime
	terminate := lifecycle.TerminateRequest{MutationRequest: mutationRequest(now, "terminate-unknown", 2, 1), Reason: "complete"}
	if _, err := c.AcceptTerminate(context.Background(), create.Spec.SandboxID, terminate); err != nil {
		t.Fatal(err)
	}
	first, err := c.ReconcileOperation(context.Background(), terminate.OperationID)
	if err == nil || first.Operation.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("first reconcile = %#v, %v", first, err)
	}
	driver.removeErr = nil
	second, err := c.ReconcileOperation(context.Background(), terminate.OperationID)
	if err != nil || second.Operation.State != lifecycle.OperationOutcomeUnknown || second.Sandbox.ObservedState != lifecycle.ObservedTerminated {
		t.Fatalf("second reconcile = %#v, %v", second, err)
	}
	driver.mu.Lock()
	removeCalls := driver.removeCalls
	driver.mu.Unlock()
	if removeCalls != 1 {
		t.Fatalf("unknown termination was redispatched %d times", removeCalls)
	}
	before, err := c.ReadEvents(context.Background(), create.Spec.SandboxID, 0)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := c.ReconcilePending(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("observed unknown remained pending: %#v, %v", pending, err)
	}
	after, err := c.ReadEvents(context.Background(), create.Spec.SandboxID, 0)
	if err != nil || len(after.Events) != len(before.Events) {
		t.Fatalf("observed unknown appended duplicate events: before=%d after=%d err=%v", len(before.Events), len(after.Events), err)
	}
}

func TestExpiredLeaseCreatesDurableTerminationAndCleansRuntime(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	repo := memory.NewRepository()
	driver := newControlDriver()
	c, err := New(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	create := validRequest(now)
	create.Spec.LeaseExpiresAt = now.Add(time.Minute)
	if _, err := c.AcceptCreate(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(context.Background(), create.OperationID); err != nil {
		t.Fatal(err)
	}
	clock.mu.Lock()
	clock.now = now.Add(2 * time.Minute)
	clock.mu.Unlock()
	results, err := c.ProcessExpiredLeases(context.Background())
	if err != nil || len(results) != 1 || results[0].Operation.Type != lifecycle.OperationTerminate || results[0].Operation.State != lifecycle.OperationSucceeded || results[0].Sandbox.ObservedState != lifecycle.ObservedTerminated {
		t.Fatalf("ProcessExpiredLeases() = %#v, %v", results, err)
	}
	page, err := c.ReadEvents(context.Background(), create.Spec.SandboxID, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range page.Events {
		found = found || event.Kind == "lease-expired"
	}
	if !found {
		t.Fatalf("lease-expired event missing: %#v", page.Events)
	}
}

func TestExpiredLeaseCleansAfterEarlierTerminationFailedBeforeDispatch(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	repo := memory.NewRepository()
	driver := newControlDriver()
	c, err := New(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	create := validRequest(now)
	create.Spec.LeaseExpiresAt = now.Add(time.Minute)
	if _, err := c.AcceptCreate(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(context.Background(), create.OperationID); err != nil {
		t.Fatal(err)
	}
	terminate := lifecycle.TerminateRequest{MutationRequest: mutationRequest(now, "terminate-expiring", 2, 1), Reason: "complete"}
	terminate.Deadline = now.Add(time.Second)
	if _, err := c.AcceptTerminate(context.Background(), create.Spec.SandboxID, terminate); err != nil {
		t.Fatal(err)
	}
	clock.mu.Lock()
	clock.now = now.Add(2 * time.Minute)
	clock.mu.Unlock()
	failed, err := c.ReconcileOperation(context.Background(), terminate.OperationID)
	if err == nil || failed.Operation.State != lifecycle.OperationFailed {
		t.Fatalf("expired explicit termination = %#v, %v", failed, err)
	}
	results, err := c.ProcessExpiredLeases(context.Background())
	if err != nil || len(results) != 1 || results[0].Operation.State != lifecycle.OperationSucceeded || results[0].Sandbox.ObservedState != lifecycle.ObservedTerminated {
		t.Fatalf("expiry cleanup after failed termination = %#v, %v", results, err)
	}
}

func mutationRequest(now time.Time, suffix string, fencing, generation uint64) lifecycle.MutationRequest {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return lifecycle.MutationRequest{
		OperationID: "operation-" + suffix, AttemptID: "attempt-" + suffix, FencingToken: fencing,
		IdempotencyKey: "key-" + suffix, RequestDigest: digest, Deadline: now.Add(10 * time.Minute), ExpectedGeneration: generation,
	}
}

func TestReconcileCreateAndRecordEvent(t *testing.T) {
	driver := &testDriver{}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	results, err := c.ReconcilePending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Operation.State != lifecycle.OperationSucceeded || results[0].Sandbox.ObservedState != lifecycle.ObservedReady || !results[0].Dispatched {
		t.Fatalf("results = %#v", results)
	}
	events, err := c.repository.ListEvents(context.Background(), request.Spec.SandboxID, 0, 10)
	if err != nil || len(events) != 2 || events[0].Kind != "provisioning" || events[1].Kind != "ready" {
		t.Fatalf("events = %#v, %v", events, err)
	}
	results, err = c.ReconcilePending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("terminal operation reconciled again: %#v", results)
	}
}

func TestCreateUnknownOutcomeIsNotRetriedBlindlyAndReconcilesByInspection(t *testing.T) {
	driver := &testDriver{createErr: ErrUnknownRuntime}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	results, err := c.ReconcilePending(context.Background())
	if err == nil || len(results) != 1 || results[0].Operation.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("unknown result = %#v, %v", results, err)
	}
	driver.mu.Lock()
	driver.inspect = RuntimeObservation{State: RuntimeReady}
	driver.mu.Unlock()
	result, err := c.ReconcileOperation(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation.State != lifecycle.OperationOutcomeUnknown || result.Sandbox.ObservedState != lifecycle.ObservedReady {
		t.Fatalf("reconciled result = %#v", result)
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 1 {
		t.Fatalf("unknown operation was retried %d times", creates)
	}
}

func TestKnownFailureAndDeadlineDoNotDispatch(t *testing.T) {
	driver := &testDriver{createErr: errors.New("backend unavailable")}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	request.Deadline = clock.Now().Add(time.Second)
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	clock.mu.Lock()
	clock.now = clock.now.Add(2 * time.Second)
	clock.mu.Unlock()
	results, err := c.ReconcilePending(context.Background())
	if err == nil || len(results) != 1 || results[0].Operation.State != lifecycle.OperationFailed {
		t.Fatalf("deadline result = %#v, %v", results, err)
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 0 {
		t.Fatalf("expired operation dispatched %d times", creates)
	}
}

func TestCanceledContextDoesNotDispatch(t *testing.T) {
	driver := &testDriver{}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ReconcileOperation(ctx, request.OperationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconcile = %v", err)
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 0 {
		t.Fatalf("canceled reconcile dispatched %d calls", creates)
	}
}

func TestStaleGenerationPreventsDriverDispatch(t *testing.T) {
	driver := &testDriver{}
	clock := &testClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	base := memory.NewRepository()
	t.Cleanup(func() { _ = base.Close() })
	c, err := New(staleSandboxRepository{Repository: base}, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReconcileOperation(context.Background(), request.OperationID); !errors.Is(err, lifecycle.ErrGenerationConflict) {
		t.Fatalf("stale reconcile = %v", err)
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 0 {
		t.Fatalf("stale generation dispatched %d calls", creates)
	}
}

func TestRestartedRunningOperationIsReconciledWithoutDuplicateCreate(t *testing.T) {
	driver := &testDriver{inspect: RuntimeObservation{State: RuntimeReady}}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	operation, err := c.repository.GetOperation(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := c.repository.GetSandbox(context.Background(), request.Spec.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	provisioning, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedProvisioning, sandbox.Generation, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.repository.UpdateSandbox(context.Background(), provisioning, sandbox.Generation, operation.FencingToken); err != nil {
		t.Fatal(err)
	}
	running, err := lifecycle.BeginOperation(operation, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.repository.UpdateOperation(context.Background(), running); err != nil {
		t.Fatal(err)
	}
	result, err := c.ReconcileOperation(context.Background(), request.OperationID)
	if err != nil || result.Operation.State != lifecycle.OperationSucceeded || result.Sandbox.ObservedState != lifecycle.ObservedReady || result.Dispatched {
		t.Fatalf("restart result = %#v, %v", result, err)
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 0 {
		t.Fatalf("restart reconciliation dispatched %d duplicate creates", creates)
	}
}

func TestConcurrentReconcileSerializesDispatch(t *testing.T) {
	driver := &testDriver{}
	c, clock := newCoordinator(t, driver)
	request := validRequest(clock.Now())
	if _, err := c.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	const workers = 16
	errorsCh := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.ReconcileOperation(context.Background(), request.OperationID)
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	driver.mu.Lock()
	creates := driver.creates
	driver.mu.Unlock()
	if creates != 1 {
		t.Fatalf("concurrent reconcile dispatched %d creates", creates)
	}
}
