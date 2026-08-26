package application

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/coordinator"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository/memory"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
)

type verticalRuntime struct {
	mu           sync.Mutex
	startCalls   int
	cancelCalls  int
	supportCalls int
	observeCalls int
	startErr     error
	supportErr   error
	reference    providerexec.ExecutionReference
	observation  providerexec.Observation
	observeErr   error
}

func (r *verticalRuntime) CheckSupport(_ context.Context, _ providerexec.Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.supportCalls++
	return r.supportErr
}

func (r *verticalRuntime) Start(_ context.Context, _ providerexec.Invocation) (providerexec.ExecutionReference, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.startCalls++
	return r.reference, r.startErr
}

func (r *verticalRuntime) Observe(_ context.Context, _ providerexec.Request) (providerexec.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observeCalls++
	return r.observation, r.observeErr
}

func (r *verticalRuntime) Cancel(_ context.Context, _ providerexec.ExecutionAttachment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancelCalls++
	return nil
}

type verticalSandboxReader struct {
	sandbox lifecycle.Sandbox
	err     error
}

func (r verticalSandboxReader) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	return r.sandbox, r.err
}

func verticalSandbox(now time.Time) lifecycle.Sandbox {
	return lifecycle.Sandbox{
		ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
		ProviderRevisionID: "provider-revision-1", RuntimeProfile: "sandbox-runtime-coding-shell-v1", SandboxSlotKey: "slot-1",
		DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady, Generation: 1, ObservedGeneration: 1,
		LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
}

func verticalRequest(now time.Time) providerexec.Request {
	return providerexec.Request{
		SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 1, ExpectedGeneration: 1, IdempotencyKey: "exec-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      now.Add(time.Minute), Command: []string{"true"}, WorkingDirectory: "/workspace", ResultRetention: time.Hour,
	}
}

func verticalCancellation(now time.Time) providerexec.CancellationIntent {
	return providerexec.CancellationIntent{
		SandboxID: "sandbox-1", OperationID: "cancel-1", AttemptID: "cancel-attempt-1", FencingToken: 2,
		ExpectedGeneration: 1, IdempotencyKey: "cancel-key-1",
		RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Deadline:      now.Add(time.Minute), TargetOperationID: "operation-1", TargetAttemptID: "attempt-1",
		Reason: providerexec.CancellationCallerRequested,
	}
}

func newVerticalForTest(t *testing.T, runtime *verticalRuntime, now time.Time) (*Vertical, *memory.Repository) {
	t.Helper()
	repo := memory.NewRepository()
	execCoordinator, err := coordinator.NewWithObserver(repo, runtime, runtime, coordinator.ClockFunc(func() time.Time { return now }), runtime)
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewVertical(execCoordinator, verticalSandboxReader{sandbox: verticalSandbox(now)}, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return application, repo
}

func TestVerticalAcceptsBeforeDispatchAndReconcilesApplicationExit(t *testing.T) {
	now := time.Now().UTC()
	exitCode := 9
	runtime := &verticalRuntime{
		reference: "ref:exec/runtime-one",
		observation: providerexec.Observation{
			ExecutionReference: "ref:exec/runtime-one", Status: providerexec.ResultCompleted,
			StartedAt: now, CompletedAt: now.Add(time.Second), ExitCode: &exitCode,
		},
	}
	application, repo := newVerticalForTest(t, runtime, now)
	request := verticalRequest(now)
	accepted, err := application.AcceptExec(context.Background(), request)
	if err != nil || accepted.Status != provideroperation.StatusRunning || runtime.startCalls != 1 {
		t.Fatalf("AcceptExec = %#v, %v start_calls=%d", accepted, err, runtime.startCalls)
	}
	replayed, err := application.AcceptExec(context.Background(), request)
	if err != nil || replayed.Status != provideroperation.StatusSucceeded || runtime.startCalls != 1 {
		t.Fatalf("replayed AcceptExec = %#v, %v start_calls=%d", replayed, err, runtime.startCalls)
	}
	result, err := application.GetResult(context.Background(), request.OperationID)
	if err != nil || result.Status != providerexec.ResultCompleted || result.ExitCode == nil || *result.ExitCode != 9 {
		t.Fatalf("GetResult = %#v, %v", result, err)
	}
	record, err := repo.GetExecution(context.Background(), request.OperationID)
	if err != nil || record.Result == nil || record.Result.Status != providerexec.ResultCompleted {
		t.Fatalf("durable record = %#v, %v", record, err)
	}
}

func TestVerticalRecordsKnownAndUnknownDispatchFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		dispatchErr error
		wantStatus  provideroperation.Status
		wantResult  providerexec.ResultStatus
	}{
		{name: "known provider failure", dispatchErr: errors.New("backend unavailable"), wantStatus: provideroperation.StatusFailed, wantResult: providerexec.ResultFailed},
		{name: "unknown dispatch", dispatchErr: providerexec.ErrDispatchUnknown, wantStatus: provideroperation.StatusOutcomeUnknown, wantResult: providerexec.ResultOutcomeUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			runtime := &verticalRuntime{reference: "ref:exec/runtime-one", startErr: test.dispatchErr}
			application, _ := newVerticalForTest(t, runtime, now)
			view, err := application.AcceptExec(context.Background(), verticalRequest(now))
			if err != nil || view.Status != test.wantStatus {
				t.Fatalf("AcceptExec = %#v, %v", view, err)
			}
			result, err := application.GetResult(context.Background(), "operation-1")
			if err != nil || result.Status != test.wantResult || result.Error == nil {
				t.Fatalf("GetResult = %#v, %v", result, err)
			}
		})
	}
}

func TestVerticalRejectsGenerationBeforeDurableExecDispatch(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{reference: "ref:exec/runtime-one"}
	repo := memory.NewRepository()
	execCoordinator, err := coordinator.NewWithObserver(repo, runtime, runtime, coordinator.ClockFunc(func() time.Time { return now }), runtime)
	if err != nil {
		t.Fatal(err)
	}
	sandbox := verticalSandbox(now)
	sandbox.Generation = 2
	sandbox.ObservedGeneration = 2
	application, err := NewVertical(execCoordinator, verticalSandboxReader{sandbox: sandbox}, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := application.AcceptExec(context.Background(), verticalRequest(now)); !errors.Is(err, lifecycle.ErrGenerationConflict) {
		t.Fatalf("AcceptExec error = %v", err)
	}
	if runtime.startCalls != 0 {
		t.Fatalf("runtime start calls = %d", runtime.startCalls)
	}
	if _, err := repo.GetExecution(context.Background(), "operation-1"); err == nil {
		t.Fatal("generation conflict reserved an execution")
	}
}

func TestVerticalRejectsUnsupportedRequestBeforeDurableAcceptance(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{reference: "ref:exec/runtime-one", supportErr: providerexec.ErrUnsupportedRequest}
	repo := memory.NewRepository()
	execCoordinator, err := coordinator.NewWithObserver(repo, runtime, runtime, coordinator.ClockFunc(func() time.Time { return now }), runtime)
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewVerticalWithSupport(execCoordinator, verticalSandboxReader{sandbox: verticalSandbox(now)}, runtime, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	request := verticalRequest(now)
	request.Environment = map[string]string{"HOME": "envref:grant/home"}
	if _, err := application.AcceptExec(context.Background(), request); !errors.Is(err, providerexec.ErrUnsupportedRequest) {
		t.Fatalf("AcceptExec error = %v", err)
	}
	if runtime.supportCalls != 1 || runtime.startCalls != 0 {
		t.Fatalf("support calls = %d, start calls = %d", runtime.supportCalls, runtime.startCalls)
	}
	if _, err := repo.GetExecution(context.Background(), request.OperationID); err == nil {
		t.Fatal("unsupported request was durably accepted")
	}
}

func TestVerticalExecReplayDoesNotDependOnCurrentSandboxReadiness(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{
		reference:   "ref:exec/runtime-one",
		observation: providerexec.Observation{ExecutionReference: "ref:exec/runtime-one", Running: true, StartedAt: now},
	}
	reader := &verticalSandboxReader{sandbox: verticalSandbox(now)}
	repo := memory.NewRepository()
	execCoordinator, err := coordinator.NewWithObserver(repo, runtime, runtime, coordinator.ClockFunc(func() time.Time { return now }), runtime)
	if err != nil {
		t.Fatal(err)
	}
	application, err := NewVertical(execCoordinator, reader, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	request := verticalRequest(now)
	if _, err := application.AcceptExec(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	reader.err = errors.New("sandbox authority unavailable after acceptance")
	replayed, err := application.AcceptExec(context.Background(), request)
	if err != nil || replayed.Status != provideroperation.StatusRunning || runtime.startCalls != 1 {
		t.Fatalf("replayed AcceptExec = %#v, %v; start calls = %d", replayed, err, runtime.startCalls)
	}
}

func TestVerticalCancellationIsDurableAndConfirmed(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{
		reference:   "ref:exec/runtime-one",
		observation: providerexec.Observation{ExecutionReference: "ref:exec/runtime-one", Running: true, StartedAt: now},
	}
	application, _ := newVerticalForTest(t, runtime, now)
	if _, err := application.AcceptExec(context.Background(), verticalRequest(now)); err != nil {
		t.Fatal(err)
	}
	intent := verticalCancellation(now)
	view, err := application.AcceptCancellation(context.Background(), intent)
	if err != nil || view.Type != provideroperation.TypeCancelExec || view.Status != provideroperation.StatusSucceeded || runtime.cancelCalls != 1 {
		t.Fatalf("AcceptCancellation = %#v, %v cancel_calls=%d", view, err, runtime.cancelCalls)
	}
	replayed, err := application.AcceptCancellation(context.Background(), intent)
	if err != nil || replayed.Status != provideroperation.StatusSucceeded || runtime.cancelCalls != 1 {
		t.Fatalf("cancellation replay = %#v, %v cancel_calls=%d", replayed, err, runtime.cancelCalls)
	}
	result, err := application.GetResult(context.Background(), "operation-1")
	if err != nil || result.Status != providerexec.ResultCancelled {
		t.Fatalf("cancelled result = %#v, %v", result, err)
	}
}

func TestVerticalCancellationPersistsUnknownWhenRuntimeIdentityIsMissing(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{reference: "ref:exec/runtime-one", observeErr: providerexec.ErrExecutionNotFound}
	application, repo := newVerticalForTest(t, runtime, now)
	request := verticalRequest(now)
	if _, err := application.AcceptExec(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	intent := verticalCancellation(now)
	if _, err := application.AcceptCancellation(context.Background(), intent); !errors.Is(err, repository.ErrAlreadyExists) {
		t.Fatalf("AcceptCancellation error = %v, want ErrAlreadyExists", err)
	}
	if runtime.cancelCalls != 0 {
		t.Fatalf("runtime cancel calls = %d, want 0", runtime.cancelCalls)
	}
	if _, err := repo.GetCancellation(context.Background(), intent.OperationID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cancellation reservation error = %v, want ErrNotFound", err)
	}
	record, err := repo.GetExecution(context.Background(), request.OperationID)
	if err != nil || record.Terminal == nil || record.Terminal.Status != providerexec.ResultOutcomeUnknown {
		t.Fatalf("durable target = %#v, %v", record, err)
	}
}

func TestVerticalRejectsInvalidCancellationBeforeReconciliation(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{reference: "ref:exec/runtime-one"}
	application, repo := newVerticalForTest(t, runtime, now)
	request := verticalRequest(now)
	if _, err := application.AcceptExec(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	intent := verticalCancellation(now)
	intent.Deadline = now
	if _, err := application.AcceptCancellation(context.Background(), intent); !errors.Is(err, providerexec.ErrInvalidCancellation) {
		t.Fatalf("AcceptCancellation error = %v, want ErrInvalidCancellation", err)
	}
	if runtime.observeCalls != 0 || runtime.cancelCalls != 0 {
		t.Fatalf("runtime observe calls = %d, cancel calls = %d", runtime.observeCalls, runtime.cancelCalls)
	}
	if _, err := repo.GetCancellation(context.Background(), intent.OperationID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cancellation reservation error = %v, want ErrNotFound", err)
	}
}

func TestVerticalOperationReadPersistsUnknownWhenRuntimeIdentityIsMissing(t *testing.T) {
	now := time.Now().UTC()
	runtime := &verticalRuntime{reference: "ref:exec/runtime-one", observeErr: providerexec.ErrExecutionNotFound}
	application, repo := newVerticalForTest(t, runtime, now)
	request := verticalRequest(now)
	if _, err := application.AcceptExec(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	view, err := application.ReadOperation(context.Background(), request.OperationID)
	if err != nil || view.Status != provideroperation.StatusOutcomeUnknown {
		t.Fatalf("ReadOperation = %#v, %v", view, err)
	}
	record, err := repo.GetExecution(context.Background(), request.OperationID)
	if err != nil || record.Result == nil || record.Result.Status != providerexec.ResultOutcomeUnknown {
		t.Fatalf("durable unknown record = %#v, %v", record, err)
	}
}

func TestVerticalDemandReadsPreserveOperationTruthAfterResultExpiry(t *testing.T) {
	for _, test := range []struct {
		name string
		read func(*Vertical, providerexec.Request) (provideroperation.View, error)
	}{
		{name: "operation read", read: func(application *Vertical, request providerexec.Request) (provideroperation.View, error) {
			return application.ReadOperation(context.Background(), request.OperationID)
		}},
		{name: "exec replay", read: func(application *Vertical, request providerexec.Request) (provideroperation.View, error) {
			return application.AcceptExec(context.Background(), request)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			current := now
			exitCode := 0
			runtime := &verticalRuntime{
				reference:   "ref:exec/runtime-one",
				observation: providerexec.Observation{ExecutionReference: "ref:exec/runtime-one", Status: providerexec.ResultCompleted, StartedAt: now, CompletedAt: now.Add(time.Second), ExitCode: &exitCode},
			}
			repo := memory.NewRepository()
			clock := ClockFunc(func() time.Time { return current })
			execCoordinator, err := coordinator.NewWithObserver(repo, runtime, runtime, coordinator.ClockFunc(func() time.Time { return current }), runtime)
			if err != nil {
				t.Fatal(err)
			}
			application, err := NewVertical(execCoordinator, verticalSandboxReader{sandbox: verticalSandbox(now)}, clock)
			if err != nil {
				t.Fatal(err)
			}
			request := verticalRequest(now)
			request.ResultRetention = time.Second
			if _, err := application.AcceptExec(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if _, err := application.AcceptExec(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			current = now.Add(2 * time.Second)
			view, err := test.read(application, request)
			if err != nil || view.Status != provideroperation.StatusSucceeded || runtime.startCalls != 1 {
				t.Fatalf("demand read = %#v, %v; start calls = %d", view, err, runtime.startCalls)
			}
			record, err := repo.GetExecution(context.Background(), request.OperationID)
			if err != nil || !record.ResultExpired || record.Result != nil || record.Terminal == nil || record.Terminal.Status != providerexec.ResultCompleted {
				t.Fatalf("expired operation record = %#v, %v", record, err)
			}
		})
	}
}
