package application

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/repository"
	"github.com/shell-echo/sandbox-runtime/provider/browser/repository/file"
	"github.com/shell-echo/sandbox-runtime/provider/browser/repository/memory"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *testClock) Set(now time.Time) { c.mu.Lock(); c.now = now; c.mu.Unlock() }

type sandboxReader struct {
	sandbox lifecycle.Sandbox
	err     error
}

func (r sandboxReader) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	return r.sandbox, r.err
}

type runtimeSpy struct {
	mu                                      sync.Mutex
	receipts                                map[string]browser.AllocationReceipt
	allocations, starts, observes, cleanups int
	nextState                               browser.AllocationState
	allocationErr, observeErr, cleanupErr   error
}

func newRuntimeSpy() *runtimeSpy {
	return &runtimeSpy{receipts: make(map[string]browser.AllocationReceipt), nextState: browser.AllocationRunning}
}
func (r *runtimeSpy) Allocate(_ context.Context, allocation browser.Allocation) (browser.AllocationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allocations++
	if r.allocationErr != nil {
		return browser.AllocationReceipt{}, r.allocationErr
	}
	if receipt, ok := r.receipts[allocation.Request.OperationID]; ok {
		return receipt, nil
	}
	r.starts++
	receipt := browser.AllocationReceipt{Reference: fmt.Sprintf("ref:browser/%032x", r.starts), SandboxID: allocation.Request.SandboxID, BrowserSessionID: allocation.Request.BrowserSessionID, OperationID: allocation.Request.OperationID, AttemptID: allocation.Request.AttemptID, FencingToken: allocation.Request.FencingToken, ExpectedGeneration: allocation.Request.ExpectedGeneration, ConnectionGeneration: 1, AllocatedAt: allocation.AllocatedAt.UTC(), ExpiresAt: allocation.Request.ExpiresAt.UTC()}
	r.receipts[allocation.Request.OperationID] = receipt
	return receipt, nil
}
func (r *runtimeSpy) Observe(_ context.Context, receipt browser.AllocationReceipt) (browser.AllocationObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observes++
	if r.observeErr != nil {
		return browser.AllocationObservation{}, r.observeErr
	}
	return browser.AllocationObservation{Receipt: receipt, State: r.nextState, ObservedAt: receipt.AllocatedAt.Add(time.Second).UTC()}, nil
}
func (r *runtimeSpy) Attach(context.Context, browser.AllocationReceipt) (browser.Stream, error) {
	return nil, browser.ErrBrowserUnsupported
}
func (r *runtimeSpy) Cleanup(context.Context, browser.AllocationReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanups++
	return r.cleanupErr
}
func (r *runtimeSpy) counts() (int, int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allocations, r.starts, r.observes, r.cleanups
}

type registrarSpy struct {
	calls    int
	evidence browser.EndpointEvidence
	err      error
}

func (r *registrarSpy) RegisterHandoff(context.Context, browser.Record) (browser.EndpointEvidence, error) {
	r.calls++
	return r.evidence, r.err
}

func browserSandbox(now time.Time) lifecycle.Sandbox {
	return lifecycle.Sandbox{ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1", RuntimeProfile: "sandbox-runtime-browser-v1", SandboxSlotKey: "primary-browser", DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady, Generation: 1, ObservedGeneration: 1, LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Minute), UpdatedAt: now}
}
func browserRequest(now time.Time) browser.OpenRequest {
	return browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: now.Add(10 * time.Minute), ExpectedGeneration: 1, BrowserSessionID: "browser-session-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(5 * time.Minute)}
}
func browserProfile() BrowserProfile {
	return BrowserProfile{RuntimeProfileID: "sandbox-runtime-browser-v1", CapabilityProfileID: browser.CapabilityProfileID}
}

func TestVerticalOpenReplaysWithoutDuplicateAllocation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	authority := memory.NewRepository()
	runtime := newRuntimeSpy()
	vertical, err := NewVertical(authority, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest(now)
	first, err := vertical.Open(context.Background(), request)
	if err != nil || first.Status != browser.StatusRunning {
		t.Fatalf("first = %#v, %v", first, err)
	}
	clock.Set(now.Add(time.Second))
	replay, err := vertical.Open(context.Background(), request)
	if err != nil || replay.Status != browser.StatusRunning {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	allocations, starts, observes, _ := runtime.counts()
	if allocations != 1 || starts != 1 || observes != 1 {
		t.Fatalf("runtime calls allocations=%d starts=%d observes=%d", allocations, starts, observes)
	}
}

func TestVerticalHandoffCommitAndRecovery(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	authority := memory.NewRepository()
	runtime := newRuntimeSpy()
	registrar := &registrarSpy{evidence: browser.EndpointEvidence{InternalEndpointReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1}}
	vertical, err := NewVerticalWithHandoffRegistrar(authority, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), registrar, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest(now)
	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != browser.StatusSucceeded || registrar.calls != 1 {
		t.Fatalf("open = %#v, %v calls=%d", operation, err, registrar.calls)
	}
	handoff, err := vertical.GetHandoff(context.Background(), request.OperationID)
	if err != nil || handoff.InternalEndpointReference != registrar.evidence.InternalEndpointReference {
		t.Fatalf("handoff = %#v, %v", handoff, err)
	}
	if replay, err := vertical.Open(context.Background(), request); err != nil || replay.Status != browser.StatusSucceeded || registrar.calls != 1 {
		t.Fatalf("replay = %#v, %v calls=%d", replay, err, registrar.calls)
	}
}

func TestVerticalUnknownOutcomeIsTerminalAndExpiryCleans(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	authority := memory.NewRepository()
	runtime := newRuntimeSpy()
	runtime.allocationErr = errors.New("lost response")
	vertical, err := NewVertical(authority, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest(now)
	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != browser.StatusOutcomeUnknown {
		t.Fatalf("unknown open = %#v, %v", operation, err)
	}
	runtime.allocationErr = nil
	replay, err := vertical.Open(context.Background(), request)
	if err != nil || replay.Status != browser.StatusOutcomeUnknown {
		t.Fatalf("unknown replay = %#v, %v", replay, err)
	}
	_, starts, _, _ := runtime.counts()
	if starts != 0 {
		t.Fatalf("unknown operation allocated %d resources", starts)
	}
}

func TestVerticalFileRepositoryRecoversAndCancelCleans(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	path := filepath.Join(t.TempDir(), "browser-sessions.json")
	authority, err := file.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	runtime := newRuntimeSpy()
	vertical, err := NewVertical(authority, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest(now)
	if _, err := vertical.Open(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := file.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := NewVertical(restarted, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := recovered.Recover(context.Background())
	if err != nil || len(operations) != 1 || operations[0].Status != browser.StatusRunning {
		t.Fatalf("recover = %#v, %v", operations, err)
	}
	_, starts, observes, _ := runtime.counts()
	if starts != 1 || observes != 1 {
		t.Fatalf("recovery runtime starts=%d observes=%d", starts, observes)
	}
	if _, err := recovered.Cancel(context.Background(), request.OperationID); err != nil {
		t.Fatal(err)
	}
	_, _, _, cleanups := runtime.counts()
	if cleanups != 1 {
		t.Fatalf("cleanup calls = %d", cleanups)
	}
	_ = restarted.Close()
}

func TestVerticalCancelCleanupFailurePersistsUnknownOutcome(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	authority := memory.NewRepository()
	runtime := newRuntimeSpy()
	vertical, err := NewVertical(authority, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest(now)
	if _, err := vertical.Open(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	runtime.cleanupErr = errors.New("cleanup outcome unavailable")
	operation, err := vertical.Cancel(context.Background(), request.OperationID)
	if err == nil || operation.Status != browser.StatusOutcomeUnknown {
		t.Fatalf("cancel = %#v, %v", operation, err)
	}
	persisted, err := vertical.GetOperation(context.Background(), request.OperationID)
	if err != nil || persisted.Status != browser.StatusOutcomeUnknown {
		t.Fatalf("persisted = %#v, %v", persisted, err)
	}
}

func TestVerticalExpiryCleansAllocation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	authority := memory.NewRepository()
	runtime := newRuntimeSpy()
	vertical, err := NewVertical(authority, runtime, sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
	if err != nil {
		t.Fatal(err)
	}
	request := browserRequest(now)
	if _, err := vertical.Open(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	clock.Set(request.ExpiresAt.Add(time.Second))
	operation, err := vertical.Reconcile(context.Background(), request.OperationID)
	if err != nil || operation.Status != browser.StatusFailed {
		t.Fatalf("expired = %#v, %v", operation, err)
	}
	_, _, _, cleanups := runtime.counts()
	if cleanups != 1 {
		t.Fatalf("cleanup calls = %d", cleanups)
	}
}

func TestRepositoryInterfaceCompile(t *testing.T) {
	var _ browser.CoordinationAuthority = repository.Repository(nil)
	_ = fmt.Sprint
}
