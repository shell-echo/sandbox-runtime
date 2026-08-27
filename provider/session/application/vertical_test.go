package application

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionfile "github.com/shell-echo/sandbox-runtime/provider/session/repository/file"
	sessionmemory "github.com/shell-echo/sandbox-runtime/provider/session/repository/memory"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

type verticalClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *verticalClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *verticalClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type sessionSandboxReader struct {
	mu      sync.Mutex
	sandbox lifecycle.Sandbox
	err     error
}

func (r *sessionSandboxReader) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sandbox, r.err
}

func (r *sessionSandboxReader) Update(update func(*lifecycle.Sandbox)) {
	r.mu.Lock()
	update(&r.sandbox)
	r.mu.Unlock()
}

type sessionRuntime struct {
	mu                     sync.Mutex
	clock                  *verticalClock
	receipts               map[string]terminal.Receipt
	allocateCalls          int
	allocationStarts       int
	observeCalls           int
	cleanupCalls           int
	allocationErr          error
	allocationErrAfterOnce error
	observationState       terminal.ObservationState
	observationErr         error
	cleanupErr             error
}

func newSessionRuntime(clock *verticalClock) *sessionRuntime {
	return &sessionRuntime{clock: clock, receipts: make(map[string]terminal.Receipt), observationState: terminal.ObservationRunning}
}

func (r *sessionRuntime) Allocate(_ context.Context, allocation terminal.Allocation) (terminal.Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allocateCalls++
	if r.allocationErr != nil {
		return terminal.Receipt{}, r.allocationErr
	}
	if receipt, ok := r.receipts[allocation.Request.OperationID]; ok {
		return receipt, nil
	}
	r.allocationStarts++
	receipt := terminal.Receipt{
		Reference: terminal.Reference(fmt.Sprintf("ref:terminal/%032x", r.allocationStarts)),
		SandboxID: allocation.Request.SandboxID, RuntimeSessionID: allocation.Request.RuntimeSessionID,
		OperationID: allocation.Request.OperationID, AttemptID: allocation.Request.AttemptID,
		FencingToken: allocation.Request.FencingToken, ExpectedGeneration: allocation.Request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: allocation.AllocatedAt.UTC(), ExpiresAt: allocation.Request.ExpiresAt.UTC(),
	}
	r.receipts[allocation.Request.OperationID] = receipt
	if r.allocationErrAfterOnce != nil {
		err := r.allocationErrAfterOnce
		r.allocationErrAfterOnce = nil
		return terminal.Receipt{}, err
	}
	return receipt, nil
}

func (r *sessionRuntime) Observe(_ context.Context, receipt terminal.Receipt) (terminal.Observation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observeCalls++
	if r.observationErr != nil {
		return terminal.Observation{}, r.observationErr
	}
	return terminal.Observation{Receipt: receipt, State: r.observationState, ObservedAt: r.clock.Now().UTC()}, nil
}

func (r *sessionRuntime) Attach(context.Context, terminal.Receipt) (terminal.Stream, error) {
	return nil, terminal.ErrTerminalUnsupported
}

func (r *sessionRuntime) Cleanup(context.Context, terminal.Receipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanupCalls++
	return r.cleanupErr
}

func (r *sessionRuntime) counts() (allocate, starts, observe, cleanup int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allocateCalls, r.allocationStarts, r.observeCalls, r.cleanupCalls
}

type failAttachAuthority struct {
	session.CoordinationAuthority
	mu       sync.Mutex
	failNext bool
}

func (a *failAttachAuthority) AttachAllocation(ctx context.Context, receipt session.AllocationReceipt) (session.Reservation, error) {
	a.mu.Lock()
	if a.failNext {
		a.failNext = false
		a.mu.Unlock()
		return session.Reservation{}, session.ErrDurability
	}
	a.mu.Unlock()
	return a.CoordinationAuthority.AttachAllocation(ctx, receipt)
}

func verticalProfile() TerminalProfile {
	return TerminalProfile{
		RuntimeProfileID: "sandbox-runtime-coding-shell-v1", CapabilityProfileID: "terminal-v1", WorkingDirectory: "/workspace",
	}
}

func verticalSandbox(now time.Time) lifecycle.Sandbox {
	return lifecycle.Sandbox{
		ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
		ProviderRevisionID: "provider-revision-1", RuntimeProfile: "sandbox-runtime-coding-shell-v1", SandboxSlotKey: "primary-code",
		DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady,
		Generation: 1, ObservedGeneration: 1, LeaseExpiresAt: now.Add(time.Hour),
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
}

func newVerticalTest(t *testing.T, authority session.CoordinationAuthority, runtime terminal.Runtime, reader SandboxReader, clock Clock) *Vertical {
	t.Helper()
	vertical, err := NewVertical(authority, runtime, reader, verticalProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	return vertical
}

func TestVerticalOpenAllocatesAfterDurableAcceptanceAndReplaysWithoutReplacement(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	repository := sessionmemory.NewRepository()
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	vertical := newVerticalTest(t, repository, runtime, reader, clock)
	request := validApplicationRequest()

	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != session.StatusRunning {
		t.Fatalf("Open() = %#v, %v", operation, err)
	}
	stored, err := repository.GetOpenAt(context.Background(), request.OperationID, now)
	if err != nil || stored.Allocation == nil || stored.Allocation.Receipt.Reference == "" || stored.Handoff != nil {
		t.Fatalf("stored operation = %#v, %v", stored, err)
	}
	clock.Set(now.Add(time.Second))
	replay, err := vertical.Open(context.Background(), request)
	if err != nil || replay.Status != session.StatusRunning {
		t.Fatalf("Open replay = %#v, %v", replay, err)
	}
	allocate, starts, observe, _ := runtime.counts()
	if allocate != 1 || starts != 1 || observe != 1 {
		t.Fatalf("runtime calls allocate=%d starts=%d observe=%d", allocate, starts, observe)
	}
}

func TestVerticalRecoveryReattachesLostDurableReceiptWithoutDuplicateAllocation(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	repository := sessionmemory.NewRepository()
	authority := &failAttachAuthority{CoordinationAuthority: repository, failNext: true}
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	vertical := newVerticalTest(t, authority, runtime, reader, clock)
	request := validApplicationRequest()

	if _, err := vertical.Open(context.Background(), request); !errors.Is(err, terminal.ErrAllocationUnknown) {
		t.Fatalf("Open() = %v", err)
	}
	accepted, err := repository.GetOpenAt(context.Background(), request.OperationID, now)
	if err != nil || accepted.Status != session.StatusAccepted || accepted.Allocation != nil {
		t.Fatalf("accepted after lost attachment = %#v, %v", accepted, err)
	}
	clock.Set(now.Add(time.Second))
	recovered, err := vertical.Recover(context.Background())
	if err != nil || len(recovered) != 1 || recovered[0].Status != session.StatusRunning {
		t.Fatalf("Recover() = %#v, %v", recovered, err)
	}
	allocate, starts, _, _ := runtime.counts()
	if allocate != 2 || starts != 1 {
		t.Fatalf("runtime calls allocate=%d starts=%d", allocate, starts)
	}
}

func TestVerticalUncertainAllocationIsTerminalAndNeverRedispatched(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	repository := sessionmemory.NewRepository()
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	runtime.allocationErrAfterOnce = terminal.ErrAllocationUnknown
	vertical := newVerticalTest(t, repository, runtime, reader, clock)
	request := validApplicationRequest()

	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != session.StatusOutcomeUnknown {
		t.Fatalf("Open() = %#v, %v", operation, err)
	}
	clock.Set(now.Add(time.Second))
	replay, err := vertical.Open(context.Background(), request)
	if err != nil || replay.Status != session.StatusOutcomeUnknown {
		t.Fatalf("Open replay = %#v, %v", replay, err)
	}
	allocate, starts, _, _ := runtime.counts()
	if allocate != 1 || starts != 1 {
		t.Fatalf("uncertain allocation was repeated: allocate=%d starts=%d", allocate, starts)
	}
}

func TestVerticalObservationAndExpiryMatrices(t *testing.T) {
	for _, test := range []struct {
		name        string
		state       terminal.ObservationState
		observeErr  error
		want        session.Status
		wantCleanup int
	}{
		{name: "running", state: terminal.ObservationRunning, want: session.StatusRunning},
		{name: "absent", state: terminal.ObservationAbsent, want: session.StatusFailed, wantCleanup: 1},
		{name: "expired", state: terminal.ObservationExpired, want: session.StatusFailed, wantCleanup: 1},
		{name: "unknown", state: terminal.ObservationOutcomeUnknown, want: session.StatusOutcomeUnknown},
		{name: "observer error", observeErr: errors.New("backend unavailable"), want: session.StatusOutcomeUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := applicationTestTime
			clock := &verticalClock{now: now}
			repository := sessionmemory.NewRepository()
			reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
			runtime := newSessionRuntime(clock)
			vertical := newVerticalTest(t, repository, runtime, reader, clock)
			request := validApplicationRequest()
			if _, err := vertical.Open(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			runtime.observationState = test.state
			runtime.observationErr = test.observeErr
			clock.Set(now.Add(time.Second))
			operation, err := vertical.Reconcile(context.Background(), request.OperationID)
			if err != nil || operation.Status != test.want {
				t.Fatalf("Reconcile() = %#v, %v", operation, err)
			}
			_, starts, observe, cleanup := runtime.counts()
			if starts != 1 || observe != 1 || cleanup != test.wantCleanup {
				t.Fatalf("runtime calls starts=%d observe=%d cleanup=%d", starts, observe, cleanup)
			}
		})
	}

	t.Run("session expiry", func(t *testing.T) {
		now := applicationTestTime
		clock := &verticalClock{now: now}
		repository := sessionmemory.NewRepository()
		reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
		runtime := newSessionRuntime(clock)
		vertical := newVerticalTest(t, repository, runtime, reader, clock)
		request := validApplicationRequest()
		if _, err := vertical.Open(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		clock.Set(request.ExpiresAt)
		operation, err := vertical.Reconcile(context.Background(), request.OperationID)
		if err != nil || operation.Status != session.StatusFailed {
			t.Fatalf("expired Reconcile() = %#v, %v", operation, err)
		}
		_, starts, observe, cleanup := runtime.counts()
		if starts != 1 || observe != 0 || cleanup != 1 {
			t.Fatalf("expiry calls starts=%d observe=%d cleanup=%d", starts, observe, cleanup)
		}
	})
}

func TestVerticalRecoveryRetriesIdentityBoundTerminalCleanup(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	repository := sessionmemory.NewRepository()
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	vertical := newVerticalTest(t, repository, runtime, reader, clock)
	request := validApplicationRequest()
	if _, err := vertical.Open(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	runtime.observationState = terminal.ObservationExpired
	runtime.cleanupErr = errors.New("cleanup unavailable")
	clock.Set(now.Add(time.Second))
	if _, err := vertical.Reconcile(context.Background(), request.OperationID); err == nil {
		t.Fatal("Reconcile() succeeded despite cleanup failure")
	}
	stored, err := repository.GetOpenAt(context.Background(), request.OperationID, clock.Now())
	if err != nil || stored.Status != session.StatusFailed || stored.Allocation == nil || stored.Allocation.State != session.AllocationExpired {
		t.Fatalf("stored terminal cleanup evidence = %#v, %v", stored, err)
	}
	runtime.cleanupErr = nil
	if recovered, err := vertical.Recover(context.Background()); err != nil || len(recovered) != 0 {
		t.Fatalf("Recover() = %#v, %v", recovered, err)
	}
	_, _, _, cleanup := runtime.counts()
	if cleanup != 2 {
		t.Fatalf("cleanup attempts = %d", cleanup)
	}
}

func TestVerticalSynchronizesLifecycleAuthorityBeforeAllocationAndCompletion(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	repository := sessionmemory.NewRepository()
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	vertical := newVerticalTest(t, repository, runtime, reader, clock)
	request := validApplicationRequest()

	wrongGeneration := request
	wrongGeneration.OperationID, wrongGeneration.AttemptID, wrongGeneration.RuntimeSessionID, wrongGeneration.IdempotencyKey = "operation-wrong", "attempt-wrong", "session-wrong", "key-wrong"
	wrongGeneration.RequestDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	wrongGeneration.ExpectedGeneration = 2
	if _, err := vertical.Open(context.Background(), wrongGeneration); !errors.Is(err, session.ErrGenerationConflict) {
		t.Fatalf("wrong generation = %v", err)
	}
	if allocate, _, _, _ := runtime.counts(); allocate != 0 {
		t.Fatalf("allocation before lifecycle admission = %d", allocate)
	}

	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != session.StatusRunning {
		t.Fatalf("Open() = %#v, %v", operation, err)
	}
	reader.Update(func(sandbox *lifecycle.Sandbox) {
		sandbox.ObservedState = lifecycle.ObservedFailed
		sandbox.UpdatedAt = now.Add(time.Second)
	})
	clock.Set(now.Add(time.Second))
	if _, err := vertical.CommitHandoff(context.Background(), request.OperationID, session.EndpointEvidence{
		InternalEndpointReference: "ref:session:opaque-vertical", ConnectionGeneration: 1,
	}); !errors.Is(err, session.ErrSandboxNotReady) {
		t.Fatalf("CommitHandoff with invalid lifecycle = %v", err)
	}
	stored, err := repository.GetOpenAt(context.Background(), request.OperationID, clock.Now())
	if err != nil || stored.Status != session.StatusRunning || stored.Handoff != nil {
		t.Fatalf("stored after rejected completion = %#v, %v", stored, err)
	}
	reader.Update(func(sandbox *lifecycle.Sandbox) {
		sandbox.ObservedState = lifecycle.ObservedReady
		sandbox.UpdatedAt = now.Add(2 * time.Second)
	})
	clock.Set(now.Add(2 * time.Second))
	committed, err := vertical.CommitHandoff(context.Background(), request.OperationID, session.EndpointEvidence{
		InternalEndpointReference: "ref:session:opaque-vertical", ConnectionGeneration: 1,
	})
	if err != nil || committed.Status != session.StatusSucceeded {
		t.Fatalf("CommitHandoff() = %#v, %v", committed, err)
	}
	handoff, err := vertical.GetHandoff(context.Background(), request.OperationID)
	if err != nil || handoff.InternalEndpointReference != "ref:session:opaque-vertical" {
		t.Fatalf("GetHandoff() = %#v, %v", handoff, err)
	}
}

func TestVerticalRejectsStaleSessionFenceBeforeAllocation(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	repository := sessionmemory.NewRepository()
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	vertical := newVerticalTest(t, repository, runtime, reader, clock)

	newer := validApplicationRequest()
	newer.FencingToken = 2
	if _, err := vertical.Open(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	stale := newer
	stale.OperationID, stale.AttemptID, stale.RuntimeSessionID, stale.IdempotencyKey = "operation-stale", "attempt-stale", "session-stale", "key-stale"
	stale.FencingToken = 1
	stale.RequestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := vertical.Open(context.Background(), stale); !errors.Is(err, session.ErrStaleFencingToken) {
		t.Fatalf("stale Open() = %v", err)
	}
	allocate, starts, _, _ := runtime.counts()
	if allocate != 1 || starts != 1 {
		t.Fatalf("stale fence reached runtime: allocate=%d starts=%d", allocate, starts)
	}
}

func TestVerticalFileRepositoryRestartReconcilesExistingReceipt(t *testing.T) {
	now := applicationTestTime
	clock := &verticalClock{now: now}
	path := filepath.Join(t.TempDir(), "session.json")
	repository, err := sessionfile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	reader := &sessionSandboxReader{sandbox: verticalSandbox(now)}
	runtime := newSessionRuntime(clock)
	vertical := newVerticalTest(t, repository, runtime, reader, clock)
	request := validApplicationRequest()
	if _, err := vertical.Open(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	repository, err = sessionfile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	clock.Set(now.Add(time.Second))
	restarted := newVerticalTest(t, repository, runtime, reader, clock)
	recovered, err := restarted.Recover(context.Background())
	if err != nil || len(recovered) != 1 || recovered[0].Status != session.StatusRunning {
		t.Fatalf("Recover after restart = %#v, %v", recovered, err)
	}
	allocate, starts, observe, _ := runtime.counts()
	if allocate != 1 || starts != 1 || observe != 1 {
		t.Fatalf("restart calls allocate=%d starts=%d observe=%d", allocate, starts, observe)
	}
}

func TestNewVerticalRejectsIncompleteDependenciesAndProfile(t *testing.T) {
	clock := &verticalClock{now: applicationTestTime}
	repository := sessionmemory.NewRepository()
	reader := &sessionSandboxReader{sandbox: verticalSandbox(applicationTestTime)}
	runtime := newSessionRuntime(clock)
	profile := verticalProfile()
	for name, build := range map[string]func() (*Vertical, error){
		"authority": func() (*Vertical, error) { return NewVertical(nil, runtime, reader, profile, clock) },
		"runtime":   func() (*Vertical, error) { return NewVertical(repository, nil, reader, profile, clock) },
		"reader":    func() (*Vertical, error) { return NewVertical(repository, runtime, nil, profile, clock) },
		"clock":     func() (*Vertical, error) { return NewVertical(repository, runtime, reader, profile, nil) },
		"profile": func() (*Vertical, error) {
			invalid := profile
			invalid.WorkingDirectory = "/tmp"
			return NewVertical(repository, runtime, reader, invalid, clock)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !errors.Is(err, ErrInvalidApplication) {
				t.Fatalf("NewVertical() = %v", err)
			}
		})
	}
}

var _ terminal.Runtime = (*sessionRuntime)(nil)
var _ session.CoordinationAuthority = (*failAttachAuthority)(nil)
