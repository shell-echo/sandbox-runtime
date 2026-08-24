package coordinator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository/memory"
)

var coordinatorTestTime = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

type testExecutor struct {
	mu        sync.Mutex
	calls     int
	reference providerexec.ExecutionReference
	err       error
}

func (e *testExecutor) Start(_ context.Context, _ providerexec.Invocation) (providerexec.ExecutionReference, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return e.reference, e.err
}

func (e *testExecutor) Calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

type testCanceler struct {
	mu     sync.Mutex
	calls  int
	err    error
	attach providerexec.ExecutionAttachment
}

type attachFailRepository struct {
	repository.Repository
	err error
}

func (r attachFailRepository) AttachExecution(context.Context, providerexec.ExecutionAttachment) (providerexec.ExecutionReservation, error) {
	return providerexec.ExecutionReservation{}, r.err
}

func (c *testCanceler) Cancel(_ context.Context, attachment providerexec.ExecutionAttachment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.attach = attachment
	return c.err
}

func coordinatorRequest() providerexec.Request {
	return providerexec.Request{
		SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 1, ExpectedGeneration: 1, IdempotencyKey: "exec-key-1",
		RequestDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:      time.Now().UTC().Add(time.Hour), Command: []string{"true"},
		WorkingDirectory: "/workspace", ResultRetention: time.Hour,
	}
}

func coordinatorCancellation() providerexec.CancellationIntent {
	return providerexec.CancellationIntent{
		SandboxID: "sandbox-1", OperationID: "cancel-1", AttemptID: "cancel-attempt-1", FencingToken: 2,
		ExpectedGeneration: 1, IdempotencyKey: "cancel-key-1",
		RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Deadline:      time.Now().UTC().Add(time.Hour), TargetOperationID: "operation-1", TargetAttemptID: "attempt-1",
		Reason: providerexec.CancellationCallerRequested,
	}
}

func newCoordinator(t *testing.T, executor providerexec.Executor, canceler Canceler) (*Coordinator, *memory.Repository) {
	t.Helper()
	repo := memory.NewRepository()
	c, err := New(repo, executor, ClockFunc(func() time.Time { return coordinatorTestTime }), canceler)
	if err != nil {
		t.Fatal(err)
	}
	return c, repo
}

func TestStartPersistsBeforeDispatchAndNeverRedispatchesReplay(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	c, repo := newCoordinator(t, executor, nil)
	request := coordinatorRequest()
	first, err := c.Start(context.Background(), request)
	if err != nil || first.Replayed || !first.Execution.Attached {
		t.Fatalf("first start = %#v, %v", first, err)
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.Calls())
	}
	second, err := c.Start(context.Background(), request)
	if err != nil || !second.Replayed || !second.Execution.Attached {
		t.Fatalf("replayed start = %#v, %v", second, err)
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls after replay = %d, want 1", executor.Calls())
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStartDoesNotDispatchWhenReservationFails(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	c, repo := newCoordinator(t, executor, nil)
	request := coordinatorRequest()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	// A closed repository proves the executor is never called before durable
	// reservation: the call fails at the reservation boundary.
	if _, err := c.Start(context.Background(), request); !errors.Is(err, repository.ErrClosed) {
		t.Fatalf("closed reservation error = %v", err)
	}
	if executor.Calls() != 0 {
		t.Fatalf("executor calls on failed reservation = %d", executor.Calls())
	}
}

func TestStartDoesNotRedispatchAfterAttachFailure(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	base := memory.NewRepository()
	repo := attachFailRepository{Repository: base, err: errors.New("attach failed")}
	c, err := New(repo, executor, ClockFunc(func() time.Time { return coordinatorTestTime }), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := coordinatorRequest()
	if _, err := c.Start(context.Background(), request); err == nil {
		t.Fatal("first start unexpectedly succeeded")
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls = %d, want 1", executor.Calls())
	}
	// The repository's durable reservation is visible even though attachment
	// failed; a replay must not invoke the executor a second time.
	second, err := c.Start(context.Background(), request)
	if err != nil || !second.Replayed {
		t.Fatalf("replayed start = %#v, %v", second, err)
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls after attach replay = %d, want 1", executor.Calls())
	}
}

func TestStartMapsExecutorContextFailureToUnknownAndDoesNotRedispatch(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1", err: context.DeadlineExceeded}
	c, _ := newCoordinator(t, executor, nil)
	request := coordinatorRequest()
	reservation, err := c.Start(context.Background(), request)
	if !errors.Is(err, providerexec.ErrDispatchUnknown) || reservation.Replayed || reservation.Execution.Attached {
		t.Fatalf("unknown start = %#v, %v", reservation, err)
	}
	if _, err := c.Start(context.Background(), request); err != nil {
		t.Fatalf("replayed unknown start error = %v", err)
	}
	if executor.Calls() != 1 {
		t.Fatalf("executor calls after unknown replay = %d, want 1", executor.Calls())
	}
}

func TestStartKnownExecutorFailureLeavesDurablePendingReservation(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1", err: errors.New("backend unavailable")}
	c, repo := newCoordinator(t, executor, nil)
	request := coordinatorRequest()
	if _, err := c.Start(context.Background(), request); err == nil {
		t.Fatal("known executor failure unexpectedly succeeded")
	}
	record, err := repo.GetExecution(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Attached || record.Result != nil {
		t.Fatalf("known executor failure record = %#v, want unattached pending", record)
	}
}

func TestCancelRecordsCancelledOnlyAfterCancelerConfirmation(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	canceler := &testCanceler{}
	c, repo := newCoordinator(t, executor, canceler)
	request := coordinatorRequest()
	if _, err := c.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := c.Cancel(context.Background(), coordinatorCancellation())
	if err != nil || result.Status != CancellationConfirmed {
		t.Fatalf("cancel = %#v, %v", result, err)
	}
	if canceler.calls != 1 || canceler.attach.Dispatch.ExecutionReference != "ref:exec/receipt-1" {
		t.Fatalf("canceler call = %d attachment = %#v", canceler.calls, canceler.attach)
	}
	retained, err := repo.GetResult(context.Background(), request.OperationID, coordinatorTestTime)
	if err != nil || retained.Status != providerexec.ResultCancelled {
		t.Fatalf("cancelled result = %#v, %v", retained, err)
	}
}

func TestCancelWithoutCancelerRemainsPending(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	c, _ := newCoordinator(t, executor, nil)
	if _, err := c.Start(context.Background(), coordinatorRequest()); err != nil {
		t.Fatal(err)
	}
	result, err := c.Cancel(context.Background(), coordinatorCancellation())
	if err != nil || result.Status != CancellationPending {
		t.Fatalf("pending cancel = %#v, %v", result, err)
	}
}

func TestCancelReplayDoesNotRepeatCanceler(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	canceler := &testCanceler{}
	c, _ := newCoordinator(t, executor, canceler)
	if _, err := c.Start(context.Background(), coordinatorRequest()); err != nil {
		t.Fatal(err)
	}
	intent := coordinatorCancellation()
	first, err := c.Cancel(context.Background(), intent)
	if err != nil || first.Status != CancellationConfirmed {
		t.Fatalf("first cancel = %#v, %v", first, err)
	}
	second, err := c.Cancel(context.Background(), intent)
	if err != nil || second.Status != CancellationConfirmed {
		t.Fatalf("replayed cancel = %#v, %v", second, err)
	}
	if canceler.calls != 1 {
		t.Fatalf("canceler calls = %d, want 1", canceler.calls)
	}
}

func TestCancelDoesNotOverwriteExistingResult(t *testing.T) {
	executor := &testExecutor{reference: "ref:exec/receipt-1"}
	canceler := &testCanceler{}
	c, repo := newCoordinator(t, executor, canceler)
	request := coordinatorRequest()
	if _, err := c.Start(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	completed, err := providerexec.NewResult(request, coordinatorTestTime, coordinatorTestTime.Add(time.Second), providerexec.ResultOutcome{Status: providerexec.ResultCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.StoreResult(context.Background(), completed); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Cancel(context.Background(), coordinatorCancellation()); !errors.Is(err, repository.ErrAlreadyExists) {
		t.Fatalf("cancel after completion error = %v", err)
	}
	if canceler.calls != 0 {
		t.Fatalf("canceler calls after completed result = %d, want 0", canceler.calls)
	}
}
