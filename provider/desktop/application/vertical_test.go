package application

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopfile "github.com/shell-echo/sandbox-runtime/provider/desktop/repository/file"
	desktopmemory "github.com/shell-echo/sandbox-runtime/provider/desktop/repository/memory"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type desktopClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *desktopClock) Now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *desktopClock) Set(now time.Time) { c.mu.Lock(); c.now = now; c.mu.Unlock() }

type desktopSandboxReader struct{ sandbox lifecycle.Sandbox }

func (r desktopSandboxReader) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	return r.sandbox, nil
}

type desktopRuntimeSpy struct {
	mu                sync.Mutex
	receipts          map[string]desktop.AllocationReceipt
	nextState         desktop.AllocationState
	allocateErr       error
	allocateThenError bool
	cleanupErr        error
	cleanupThenError  bool
	cancelAllocate    context.CancelFunc
	allocates         int
	observes          int
	cleanups          int
	cleanupEffects    int
	lastCleanup       desktop.AllocationReceipt
	trace             *effectTrace
}

type effectTrace struct {
	mu     sync.Mutex
	events []string
}

func (t *effectTrace) add(event string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, event)
}

func (t *effectTrace) snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.events...)
}

func newDesktopRuntimeSpy() *desktopRuntimeSpy {
	return &desktopRuntimeSpy{receipts: make(map[string]desktop.AllocationReceipt), nextState: desktop.AllocationRunning}
}

func (r *desktopRuntimeSpy) Allocate(ctx context.Context, allocation desktop.Allocation) (desktop.AllocationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allocates++
	if r.cancelAllocate != nil {
		r.cancelAllocate()
		return desktop.AllocationReceipt{}, ctx.Err()
	}
	if allocation.Request.NetworkPolicyReference != "desktop-egress-policy-1" {
		return desktop.AllocationReceipt{}, desktop.ErrDesktopUnsupported
	}
	if existing, ok := r.receipts[allocation.Request.OperationID]; ok {
		return existing, nil
	}
	receipt := desktop.AllocationReceipt{
		Reference: fmt.Sprintf("ref:desktop/%032x", len(r.receipts)+1), SandboxID: allocation.Request.SandboxID,
		DesktopSessionID: allocation.Request.DesktopSessionID, OperationID: allocation.Request.OperationID,
		AttemptID: allocation.Request.AttemptID, FencingToken: allocation.Request.FencingToken,
		ExpectedGeneration: allocation.Request.ExpectedGeneration, ConnectionGeneration: 1,
		AllocatedAt: allocation.AllocatedAt.UTC(), ExpiresAt: allocation.Request.ExpiresAt.UTC(),
	}
	if r.allocateThenError {
		r.receipts[allocation.Request.OperationID] = receipt
		return desktop.AllocationReceipt{}, r.allocateErr
	}
	if r.allocateErr != nil {
		return desktop.AllocationReceipt{}, r.allocateErr
	}
	r.receipts[allocation.Request.OperationID] = receipt
	return receipt, nil
}

func (r *desktopRuntimeSpy) Observe(_ context.Context, allocation desktop.Allocation) (desktop.AllocationObservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observes++
	r.trace.add("observe")
	state := r.nextState
	receipt, exists := r.receipts[allocation.Request.OperationID]
	if !exists && state == desktop.AllocationRunning {
		state = desktop.AllocationAbsent
	}
	observation := desktop.AllocationObservation{Request: allocation.Request, State: state, ObservedAt: allocation.AllocatedAt.Add(10 * time.Second)}
	if state == desktop.AllocationRunning {
		copy := receipt
		observation.Receipt = &copy
	}
	return observation, nil
}

func (r *desktopRuntimeSpy) Cleanup(_ context.Context, receipt desktop.AllocationReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanups++
	r.trace.add("cleanup")
	r.lastCleanup = receipt
	if r.cleanupThenError {
		if _, exists := r.receipts[receipt.OperationID]; exists {
			r.cleanupEffects++
		}
		delete(r.receipts, receipt.OperationID)
		return r.cleanupErr
	}
	if r.cleanupErr != nil {
		return r.cleanupErr
	}
	if _, exists := r.receipts[receipt.OperationID]; exists {
		r.cleanupEffects++
		delete(r.receipts, receipt.OperationID)
	}
	r.nextState = desktop.AllocationAbsent
	return nil
}

func (r *desktopRuntimeSpy) counts() (int, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.allocates, r.observes, r.cleanups
}

func (r *desktopRuntimeSpy) cleanupEffectCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleanupEffects
}

type desktopRegistrar struct {
	mu    sync.Mutex
	calls int
}

func (r *desktopRegistrar) RegisterHandoff(_ context.Context, record desktop.Record) (desktop.EndpointEvidence, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return desktop.EndpointEvidence{InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: record.Allocation.Receipt.ConnectionGeneration}, nil
}

type desktopRevoker struct {
	mu       sync.Mutex
	revoked  map[string]bool
	revokes  int
	effects  int
	observes int
	err      error
	trace    *effectTrace
}

func newDesktopRevoker() *desktopRevoker { return &desktopRevoker{revoked: make(map[string]bool)} }

func (r *desktopRevoker) RevokeHandoff(_ context.Context, record desktop.Record, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokes++
	r.trace.add("revoke")
	if r.err != nil {
		return r.err
	}
	if !r.revoked[record.Request.OperationID] {
		r.effects++
	}
	r.revoked[record.Request.OperationID] = true
	return nil
}

type closeBarrierAuthority struct {
	desktop.CoordinationAuthority
	expected desktop.Status
	target   desktop.Status
	entered  chan struct{}
	release  chan struct{}
}

func (a *closeBarrierAuthority) UpdateClose(ctx context.Context, record desktop.CloseRecord, expected desktop.Status, source desktop.Record) error {
	if expected == a.expected && record.Status == a.target {
		a.entered <- struct{}{}
		select {
		case <-a.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return a.CoordinationAuthority.UpdateClose(ctx, record, expected, source)
}

func (a *closeBarrierAuthority) GetOpenAt(ctx context.Context, operationID string, now time.Time) (desktop.Record, error) {
	return a.CoordinationAuthority.(interface {
		GetOpenAt(context.Context, string, time.Time) (desktop.Record, error)
	}).GetOpenAt(ctx, operationID, now)
}

func (a *closeBarrierAuthority) UpdateOpenAt(ctx context.Context, record desktop.Record, expected desktop.Status, now time.Time) error {
	return a.CoordinationAuthority.(interface {
		UpdateOpenAt(context.Context, desktop.Record, desktop.Status, time.Time) error
	}).UpdateOpenAt(ctx, record, expected, now)
}

func (r *desktopRevoker) ObserveHandoffRevoked(_ context.Context, record desktop.Record) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observes++
	return r.revoked[record.Request.OperationID], nil
}

func desktopSandbox(now time.Time) lifecycle.Sandbox {
	return lifecycle.Sandbox{
		ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
		ProviderRevisionID: "revision-1", RuntimeProfile: lifecycle.DesktopRuntimeProfile,
		Network:        lifecycle.NetworkPolicy{Mode: lifecycle.NetworkRestricted, PolicyReference: "desktop-egress-policy-1", EgressGatewayRequired: true},
		SandboxSlotKey: "desktop-primary", DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady,
		Generation: 1, ObservedGeneration: 1, LeaseExpiresAt: now.Add(2 * time.Hour),
		CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
}

func desktopOpenRequest(now time.Time) desktop.OpenRequest {
	return desktop.OpenRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "open-operation-1",
		AttemptID: "open-attempt-1", FencingToken: 3, IdempotencyKey: "desktop-open-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      now.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1",
		CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute),
	}
}

func desktopCloseRequest(now time.Time) desktop.CloseRequest {
	return desktop.CloseRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "close-operation-1",
		AttemptID: "close-attempt-1", FencingToken: 4, IdempotencyKey: "desktop-close-1",
		RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Deadline:      now.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1",
		ConnectionGeneration: 1, Reason: "caller_complete",
	}
}

func desktopProfile() DesktopProfile {
	return DesktopProfile{RuntimeProfileID: lifecycle.DesktopRuntimeProfile, CapabilityProfileID: desktop.CapabilityProfileID}
}

func newDesktopVertical(t *testing.T, now time.Time, runtime *desktopRuntimeSpy, registrar *desktopRegistrar, revoker *desktopRevoker) (*Vertical, *desktopClock, *desktopmemory.Repository) {
	t.Helper()
	clock := &desktopClock{now: now}
	authority := desktopmemory.NewRepository()
	vertical, err := NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), registrar, revoker, clock)
	if err != nil {
		t.Fatal(err)
	}
	return vertical, clock, authority
}

func TestVerticalOpenReplayAndOpaqueHandoff(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	registrar := &desktopRegistrar{}
	vertical, _, _ := newDesktopVertical(t, now, runtime, registrar, newDesktopRevoker())
	request := desktopOpenRequest(now)
	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != desktop.StatusSucceeded || operation.Type != OperationOpenDesktopSession {
		t.Fatalf("open = %#v, %v", operation, err)
	}
	replay, err := vertical.Open(context.Background(), request)
	if err != nil || replay.Status != desktop.StatusSucceeded {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	allocates, _, _ := runtime.counts()
	if allocates != 1 || registrar.calls != 1 {
		t.Fatalf("effects allocates=%d registrar=%d", allocates, registrar.calls)
	}
	handoff, err := vertical.GetHandoff(context.Background(), request.OperationID)
	if err != nil || handoff.Protocol != desktop.ProtocolWebRTC || handoff.MediaProfileID != desktop.MediaProfileID ||
		handoff.ControlProfileID != desktop.ControlProfileID || handoff.InternalEndpointReference != "ref:desktop-session:opaque-1" {
		t.Fatalf("handoff = %#v, %v", handoff, err)
	}
}

func TestVerticalUnknownOpenReconcilesByObservationWithoutRedispatch(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	runtime.allocateErr = errors.New("runtime response lost")
	runtime.allocateThenError = true
	vertical, _, _ := newDesktopVertical(t, now, runtime, &desktopRegistrar{}, newDesktopRevoker())
	request := desktopOpenRequest(now)
	unknown, err := vertical.Open(context.Background(), request)
	if err != nil || unknown.Status != desktop.StatusOutcomeUnknown {
		t.Fatalf("unknown open = %#v, %v", unknown, err)
	}
	runtime.allocateErr = nil
	runtime.allocateThenError = false
	reconciled, err := vertical.Reconcile(context.Background(), request.OperationID)
	if err != nil || reconciled.Status != desktop.StatusSucceeded {
		t.Fatalf("reconcile = %#v, %v", reconciled, err)
	}
	allocates, observes, _ := runtime.counts()
	if allocates != 1 || observes != 1 {
		t.Fatalf("unknown replay effects allocates=%d observes=%d", allocates, observes)
	}
}

func TestVerticalCancellationBeforeAndDuringEffect(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	vertical, _, authority := newDesktopVertical(t, now, runtime, &desktopRegistrar{}, newDesktopRevoker())
	preCancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := vertical.Open(preCancelled, desktopOpenRequest(now)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled open = %v", err)
	}
	if records, err := authority.ListOpen(context.Background()); err != nil || len(records) != 0 {
		t.Fatalf("pre-cancelled records = %#v, %v", records, err)
	}
	during, duringCancel := context.WithCancel(context.Background())
	runtime.cancelAllocate = duringCancel
	operation, err := vertical.Open(during, desktopOpenRequest(now))
	if err != nil || operation.Status != desktop.StatusOutcomeUnknown {
		t.Fatalf("during-effect cancellation = %#v, %v", operation, err)
	}
	records, err := authority.ListOpen(context.Background())
	if err != nil || len(records) != 1 || records[0].Status != desktop.StatusOutcomeUnknown {
		t.Fatalf("persisted cancellation = %#v, %v", records, err)
	}
}

func TestVerticalCloseRevokesCleansAndConfirmsAbsence(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	revoker := newDesktopRevoker()
	trace := &effectTrace{}
	runtime.trace = trace
	revoker.trace = trace
	vertical, clock, authority := newDesktopVertical(t, now, runtime, &desktopRegistrar{}, revoker)
	if _, err := vertical.Open(context.Background(), desktopOpenRequest(now)); err != nil {
		t.Fatal(err)
	}
	clock.Set(now.Add(time.Minute))
	operation, err := vertical.CloseDesktopSession(context.Background(), desktopCloseRequest(now.Add(time.Minute)))
	if err != nil || operation.Status != desktop.StatusSucceeded || operation.Type != OperationCloseDesktopSession {
		t.Fatalf("close = %#v, %v", operation, err)
	}
	_, observes, cleanups := runtime.counts()
	if revoker.revokes != 1 || observes != 1 || cleanups != 1 || runtime.lastCleanup.OperationID != "open-operation-1" {
		t.Fatalf("close effects revokes=%d observes=%d cleanups=%d receipt=%#v", revoker.revokes, observes, cleanups, runtime.lastCleanup)
	}
	wantTrace := []string{"revoke", "cleanup", "observe"}
	if got := trace.snapshot(); fmt.Sprint(got) != fmt.Sprint(wantTrace) {
		t.Fatalf("close effect order = %v, want %v", got, wantTrace)
	}
	if _, err := vertical.GetHandoff(context.Background(), "open-operation-1"); !errors.Is(err, desktop.ErrHandoffRevoked) {
		t.Fatalf("revoked handoff = %v", err)
	}
	records, err := authority.ListOpen(context.Background())
	if err != nil || len(records) != 1 || records[0].SessionState() != desktop.SessionClosed {
		t.Fatalf("source state = %#v, %v", records, err)
	}
}

func TestCloseCASConvergenceRequiresExactImmutableAttempt(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	record := closeRecordFixture(t, now)
	mutations := map[string]func(*desktop.CloseRecord){
		"request digest": func(value *desktop.CloseRecord) { value.Request.RequestDigest = "sha256:" + strings.Repeat("c", 64) },
		"receipt": func(value *desktop.CloseRecord) {
			value.Receipt.Reference = "ref:desktop/00000000000000000000000000000002"
		},
		"source":     func(value *desktop.CloseRecord) { value.SourceOpenOperationID = "open-operation-2" },
		"session":    func(value *desktop.CloseRecord) { value.Request.DesktopSessionID = "desktop-session-2" },
		"generation": func(value *desktop.CloseRecord) { value.Request.ExpectedGeneration++ },
		"operation":  func(value *desktop.CloseRecord) { value.Request.OperationID = "close-operation-2" },
		"fence":      func(value *desktop.CloseRecord) { value.Request.FencingToken++ },
	}
	if !sameCloseAttempt(record, record.Clone()) {
		t.Fatal("exact close attempt did not match itself")
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := record.Clone()
			mutate(&changed)
			if sameCloseAttempt(record, changed) {
				t.Fatal("different immutable close attempt converged")
			}
		})
	}
}

func TestCloseCASConvergenceAcceptsOnlyMonotonicSameBranchState(t *testing.T) {
	tests := []struct {
		name                string
		expected, attempted desktop.Status
		persisted           desktop.Status
		want                bool
	}{
		{"accepted unchanged", desktop.StatusAccepted, desktop.StatusRunning, desktop.StatusAccepted, true},
		{"accepted to running", desktop.StatusAccepted, desktop.StatusRunning, desktop.StatusRunning, true},
		{"accepted to unknown", desktop.StatusAccepted, desktop.StatusRunning, desktop.StatusOutcomeUnknown, true},
		{"accepted to succeeded", desktop.StatusAccepted, desktop.StatusRunning, desktop.StatusSucceeded, true},
		{"running unchanged", desktop.StatusRunning, desktop.StatusOutcomeUnknown, desktop.StatusRunning, true},
		{"running to unknown", desktop.StatusRunning, desktop.StatusOutcomeUnknown, desktop.StatusOutcomeUnknown, true},
		{"unknown to succeeded", desktop.StatusOutcomeUnknown, desktop.StatusSucceeded, desktop.StatusSucceeded, true},
		{"terminal outcome mismatch", desktop.StatusRunning, desktop.StatusSucceeded, desktop.StatusOutcomeUnknown, false},
		{"terminal failure mismatch", desktop.StatusRunning, desktop.StatusFailed, desktop.StatusSucceeded, false},
		{"illegal regression", desktop.StatusRunning, desktop.StatusOutcomeUnknown, desktop.StatusAccepted, false},
		{"illegal terminal branch", desktop.StatusAccepted, desktop.StatusRunning, desktop.StatusFailed, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := closeStatusConverges(test.expected, test.attempted, test.persisted); got != test.want {
				t.Fatalf("closeStatusConverges() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestVerticalConcurrentCloseAndRecoverConvergeAfterAcceptedCAS(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	revoker := newDesktopRevoker()
	base := desktopmemory.NewRepository()
	authority := &closeBarrierAuthority{
		CoordinationAuthority: base, expected: desktop.StatusAccepted, target: desktop.StatusRunning,
		entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	clock := &desktopClock{now: now}
	vertical, err := NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), &desktopRegistrar{}, revoker, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vertical.Open(context.Background(), desktopOpenRequest(now)); err != nil {
		t.Fatal(err)
	}
	clock.Set(now.Add(time.Minute))
	type closeResult struct {
		operations []Operation
		operation  Operation
		err        error
	}
	results := make(chan closeResult, 2)
	go func() {
		operation, closeErr := vertical.CloseDesktopSession(context.Background(), desktopCloseRequest(now.Add(time.Minute)))
		results <- closeResult{operation: operation, err: closeErr}
	}()
	select {
	case <-authority.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not reach accepted CAS barrier")
	}
	go func() {
		operations, recoverErr := vertical.Recover(context.Background())
		results <- closeResult{operations: operations, err: recoverErr}
	}()
	select {
	case <-authority.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Recover did not reach accepted CAS barrier")
	}
	close(authority.release)
	statuses := make([]desktop.Status, 0, 2)
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("concurrent close/recover = %v", result.err)
			}
			if len(result.operations) != 0 {
				statuses = append(statuses, result.operations[0].Status)
			} else {
				statuses = append(statuses, result.operation.Status)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent close/recover did not finish")
		}
	}
	terminal := 0
	for _, status := range statuses {
		if status == desktop.StatusSucceeded {
			terminal++
		} else if status != desktop.StatusRunning {
			t.Fatalf("unexpected converged status %q", status)
		}
	}
	if terminal != 1 {
		t.Fatalf("terminal owners=%d statuses=%v", terminal, statuses)
	}
	_, observes, cleanups := runtime.counts()
	if cleanups != 1 || runtime.cleanupEffectCount() != 1 || observes != 1 || revoker.revokes != 1 || revoker.effects != 1 {
		t.Fatalf("effects revoke=%d/%d cleanup=%d/%d observe=%d", revoker.revokes, revoker.effects, cleanups, runtime.cleanupEffectCount(), observes)
	}
}

func TestVerticalConcurrentRunningCloseConvergesAtTerminalCAS(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	revoker := newDesktopRevoker()
	base := desktopmemory.NewRepository()
	clock := &desktopClock{now: now}
	setup, err := NewVerticalWithHandoffLifecycle(base, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), &desktopRegistrar{}, revoker, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Open(context.Background(), desktopOpenRequest(now)); err != nil {
		t.Fatal(err)
	}
	request := desktopCloseRequest(now.Add(time.Minute))
	clock.Set(now.Add(time.Minute))
	if err := setup.synchronizeCloseAuthority(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	reservation, err := base.ReserveClose(context.Background(), request, now.Add(time.Minute), false)
	if err != nil {
		t.Fatal(err)
	}
	running, err := desktop.TransitionClose(reservation.Record, desktop.StatusRunning, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	source, err := setup.retainedOpen(context.Background(), running.SourceOpenOperationID)
	if err != nil || base.UpdateClose(context.Background(), running, desktop.StatusAccepted, source) != nil {
		t.Fatalf("prepare running close: %v", err)
	}
	authority := &closeBarrierAuthority{
		CoordinationAuthority: base, expected: desktop.StatusRunning, target: desktop.StatusSucceeded,
		entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	vertical, err := NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), &desktopRegistrar{}, revoker, clock)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for range 2 {
		go func() {
			operation, reconcileErr := vertical.Reconcile(context.Background(), request.OperationID)
			if reconcileErr == nil && operation.Status != desktop.StatusSucceeded {
				reconcileErr = fmt.Errorf("status=%s", operation.Status)
			}
			results <- reconcileErr
		}()
	}
	for range 2 {
		select {
		case <-authority.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("reconciler did not reach terminal CAS barrier")
		}
	}
	close(authority.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("terminal reconciliation = %v", err)
		}
	}
	if runtime.cleanupEffectCount() != 1 || revoker.effects != 1 {
		t.Fatalf("idempotent effects cleanup=%d revoke=%d", runtime.cleanupEffectCount(), revoker.effects)
	}
}

func TestVerticalConcurrentCloseAndRecoverPreserveOutcomeUnknown(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	runtime.cleanupErr = errors.New("cleanup outcome is unknown")
	revoker := newDesktopRevoker()
	base := desktopmemory.NewRepository()
	authority := &closeBarrierAuthority{
		CoordinationAuthority: base, expected: desktop.StatusAccepted, target: desktop.StatusRunning,
		entered: make(chan struct{}, 2), release: make(chan struct{}),
	}
	clock := &desktopClock{now: now}
	vertical, err := NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), &desktopRegistrar{}, revoker, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vertical.Open(context.Background(), desktopOpenRequest(now)); err != nil {
		t.Fatal(err)
	}
	clock.Set(now.Add(time.Minute))
	results := make(chan Operation, 2)
	errorsSeen := make(chan error, 2)
	go func() {
		operation, closeErr := vertical.CloseDesktopSession(context.Background(), desktopCloseRequest(now.Add(time.Minute)))
		results <- operation
		errorsSeen <- closeErr
	}()
	select {
	case <-authority.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not reach accepted CAS barrier")
	}
	go func() {
		operations, recoverErr := vertical.Recover(context.Background())
		if len(operations) == 0 {
			results <- Operation{}
		} else {
			results <- operations[0]
		}
		errorsSeen <- recoverErr
	}()
	select {
	case <-authority.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Recover did not reach accepted CAS barrier")
	}
	close(authority.release)
	unknown := 0
	for range 2 {
		if err := <-errorsSeen; err != nil {
			t.Fatalf("concurrent unknown close/recover = %v", err)
		}
		status := (<-results).Status
		if status == desktop.StatusOutcomeUnknown {
			unknown++
		} else if status != desktop.StatusRunning {
			t.Fatalf("unexpected unknown convergence status %q", status)
		}
	}
	if unknown != 1 {
		t.Fatalf("outcome-unknown owners=%d", unknown)
	}
	_, observes, cleanups := runtime.counts()
	if cleanups != 1 || runtime.cleanupEffectCount() != 0 || observes != 0 || revoker.revokes != 1 || revoker.effects != 1 {
		t.Fatalf("unknown effects revoke=%d/%d cleanup=%d/%d observe=%d", revoker.revokes, revoker.effects, cleanups, runtime.cleanupEffectCount(), observes)
	}
}

func closeRecordFixture(t *testing.T, now time.Time) desktop.CloseRecord {
	t.Helper()
	authority := desktopmemory.NewRepository()
	if err := authority.SynchronizeSandboxAuthority(context.Background(), desktop.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(2 * time.Hour), FencingToken: 3, CapabilityProfileID: desktop.CapabilityProfileID,
		NetworkPolicyReference: "desktop-egress-policy-1",
	}); err != nil {
		t.Fatal(err)
	}
	runtime := newDesktopRuntimeSpy()
	vertical, err := NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), &desktopRegistrar{}, newDesktopRevoker(), &desktopClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vertical.Open(context.Background(), desktopOpenRequest(now)); err != nil {
		t.Fatal(err)
	}
	request := desktopCloseRequest(now.Add(time.Minute))
	if err := authority.SynchronizeSandboxAuthority(context.Background(), desktop.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(2 * time.Hour), FencingToken: request.FencingToken, CapabilityProfileID: desktop.CapabilityProfileID,
		NetworkPolicyReference: "desktop-egress-policy-1",
	}); err != nil {
		t.Fatal(err)
	}
	reservation, err := authority.ReserveClose(context.Background(), request, now.Add(time.Minute), false)
	if err != nil {
		t.Fatal(err)
	}
	return reservation.Record
}

func TestVerticalUnknownCloseObservesWithoutRepeatingEffects(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	revoker := newDesktopRevoker()
	vertical, clock, authority := newDesktopVertical(t, now, runtime, &desktopRegistrar{}, revoker)
	if _, err := vertical.Open(context.Background(), desktopOpenRequest(now)); err != nil {
		t.Fatal(err)
	}
	clock.Set(now.Add(time.Minute))
	runtime.cleanupErr = errors.New("cleanup response lost")
	runtime.cleanupThenError = true
	unknown, err := vertical.CloseDesktopSession(context.Background(), desktopCloseRequest(now.Add(time.Minute)))
	if err != nil || unknown.Status != desktop.StatusOutcomeUnknown {
		t.Fatalf("unknown close = %#v, %v", unknown, err)
	}
	runtime.cleanupErr = nil
	runtime.cleanupThenError = false
	reconciled, err := vertical.Reconcile(context.Background(), unknown.OperationID)
	if err != nil || reconciled.Status != desktop.StatusSucceeded {
		t.Fatalf("reconciled close = %#v, %v", reconciled, err)
	}
	_, _, cleanups := runtime.counts()
	if revoker.revokes != 1 || cleanups != 1 || revoker.observes != 1 {
		t.Fatalf("unknown close repeated effects revokes=%d cleanups=%d observe-revoked=%d", revoker.revokes, cleanups, revoker.observes)
	}
	records, err := authority.ListOpen(context.Background())
	if err != nil || records[0].SessionState() != desktop.SessionClosed {
		t.Fatalf("resolved source = %#v, %v", records, err)
	}
}

func TestVerticalFileRestartReconcilesOpenAndCloseBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	clock := &desktopClock{now: now}
	runtime := newDesktopRuntimeSpy()
	runtime.allocateErr = errors.New("open response lost")
	runtime.allocateThenError = true
	registrar := &desktopRegistrar{}
	revoker := newDesktopRevoker()
	path := filepath.Join(t.TempDir(), "desktop-authority.json")
	authority, err := desktopfile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	vertical, err := NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), registrar, revoker, clock)
	if err != nil {
		t.Fatal(err)
	}
	if operation, err := vertical.Open(context.Background(), desktopOpenRequest(now)); err != nil || operation.Status != desktop.StatusOutcomeUnknown {
		t.Fatalf("unknown before restart = %#v, %v", operation, err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err = desktopfile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	runtime.allocateErr = nil
	runtime.allocateThenError = false
	vertical, _ = NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), registrar, revoker, clock)
	if operations, err := vertical.Recover(context.Background()); err != nil || len(operations) != 1 || operations[0].Status != desktop.StatusSucceeded {
		t.Fatalf("open restart recover = %#v, %v", operations, err)
	}
	clock.Set(now.Add(time.Minute))
	runtime.cleanupErr = errors.New("close response lost")
	runtime.cleanupThenError = true
	if operation, err := vertical.CloseDesktopSession(context.Background(), desktopCloseRequest(now.Add(time.Minute))); err != nil || operation.Status != desktop.StatusOutcomeUnknown {
		t.Fatalf("unknown close before restart = %#v, %v", operation, err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err = desktopfile.NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	runtime.cleanupErr = nil
	runtime.cleanupThenError = false
	vertical, _ = NewVerticalWithHandoffLifecycle(authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), registrar, revoker, clock)
	operations, err := vertical.Recover(context.Background())
	if err != nil || len(operations) != 1 || operations[0].Type != OperationCloseDesktopSession || operations[0].Status != desktop.StatusSucceeded {
		t.Fatalf("close restart recover = %#v, %v", operations, err)
	}
	allocates, _, cleanups := runtime.counts()
	if allocates != 1 || cleanups != 1 {
		t.Fatalf("restart repeated effects allocates=%d cleanups=%d", allocates, cleanups)
	}
	_ = authority.Close()
}

func TestVerticalRestartBoundaryMatrix(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name            string
		prepare         func(*testing.T, *desktopfile.Repository, *desktopRuntimeSpy, desktop.OpenRequest)
		wantStatus      desktop.Status
		wantAllocations int
	}{
		{
			name: "accepted commit before dispatch",
			prepare: func(t *testing.T, repository *desktopfile.Repository, _ *desktopRuntimeSpy, request desktop.OpenRequest) {
				if _, err := repository.ReserveOpen(context.Background(), request, now); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: desktop.StatusSucceeded, wantAllocations: 1,
		},
		{
			name: "opening commit before effect",
			prepare: func(t *testing.T, repository *desktopfile.Repository, _ *desktopRuntimeSpy, request desktop.OpenRequest) {
				reservation, err := repository.ReserveOpen(context.Background(), request, now)
				if err != nil {
					t.Fatal(err)
				}
				opening, err := desktop.Transition(reservation.Record, desktop.StatusRunning, now, nil)
				if err != nil || repository.UpdateOpenAt(context.Background(), opening, desktop.StatusAccepted, now) != nil {
					t.Fatalf("prepare opening = %#v, %v", opening, err)
				}
			},
			wantStatus: desktop.StatusFailed, wantAllocations: 0,
		},
		{
			name: "effect before receipt commit",
			prepare: func(t *testing.T, repository *desktopfile.Repository, runtime *desktopRuntimeSpy, request desktop.OpenRequest) {
				reservation, err := repository.ReserveOpen(context.Background(), request, now)
				if err != nil {
					t.Fatal(err)
				}
				opening, _ := desktop.Transition(reservation.Record, desktop.StatusRunning, now, nil)
				if err := repository.UpdateOpenAt(context.Background(), opening, desktop.StatusAccepted, now); err != nil {
					t.Fatal(err)
				}
				allocation := desktop.Allocation{Request: desktop.AllocationRequest{
					SandboxID: request.SandboxID, DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID,
					AttemptID: request.AttemptID, FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
					RequestDigest: request.RequestDigest, NetworkPolicyReference: "desktop-egress-policy-1", ExpiresAt: request.ExpiresAt,
				}, AllocatedAt: now}
				if _, err := runtime.Allocate(context.Background(), allocation); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: desktop.StatusSucceeded, wantAllocations: 1,
		},
		{
			name: "receipt commit before handoff",
			prepare: func(t *testing.T, repository *desktopfile.Repository, runtime *desktopRuntimeSpy, request desktop.OpenRequest) {
				reservation, err := repository.ReserveOpen(context.Background(), request, now)
				if err != nil {
					t.Fatal(err)
				}
				opening, _ := desktop.Transition(reservation.Record, desktop.StatusRunning, now, nil)
				if err := repository.UpdateOpenAt(context.Background(), opening, desktop.StatusAccepted, now); err != nil {
					t.Fatal(err)
				}
				allocation := desktop.Allocation{Request: desktop.AllocationRequest{
					SandboxID: request.SandboxID, DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID,
					AttemptID: request.AttemptID, FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
					RequestDigest: request.RequestDigest, NetworkPolicyReference: "desktop-egress-policy-1", ExpiresAt: request.ExpiresAt,
				}, AllocatedAt: now}
				receipt, err := runtime.Allocate(context.Background(), allocation)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := repository.AttachAllocation(context.Background(), receipt); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: desktop.StatusSucceeded, wantAllocations: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "desktop-boundary.json")
			repository, err := desktopfile.NewRepository(path)
			if err != nil {
				t.Fatal(err)
			}
			authority := desktop.SandboxAuthority{
				SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
				LeaseExpiresAt: now.Add(2 * time.Hour), FencingToken: 3, CapabilityProfileID: desktop.CapabilityProfileID,
				NetworkPolicyReference: "desktop-egress-policy-1",
			}
			if err := repository.SynchronizeSandboxAuthority(context.Background(), authority); err != nil {
				t.Fatal(err)
			}
			runtime := newDesktopRuntimeSpy()
			request := desktopOpenRequest(now)
			test.prepare(t, repository, runtime, request)
			if err := repository.Close(); err != nil {
				t.Fatal(err)
			}
			repository, err = desktopfile.NewRepository(path)
			if err != nil {
				t.Fatal(err)
			}
			clock := &desktopClock{now: now}
			vertical, err := NewVerticalWithHandoffLifecycle(repository, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), &desktopRegistrar{}, newDesktopRevoker(), clock)
			if err != nil {
				t.Fatal(err)
			}
			operations, err := vertical.Recover(context.Background())
			if err != nil || len(operations) != 1 || operations[0].Status != test.wantStatus {
				t.Fatalf("recover = %#v, %v", operations, err)
			}
			allocations, _, _ := runtime.counts()
			if allocations != test.wantAllocations {
				t.Fatalf("allocations = %d, want %d", allocations, test.wantAllocations)
			}
			_ = repository.Close()
		})
	}
}

func TestVerticalExpiryUsesClosePath(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	runtime := newDesktopRuntimeSpy()
	revoker := newDesktopRevoker()
	vertical, clock, authority := newDesktopVertical(t, now, runtime, &desktopRegistrar{}, revoker)
	request := desktopOpenRequest(now)
	if _, err := vertical.Open(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	clock.Set(request.ExpiresAt.Add(time.Second))
	if operation, err := vertical.GetOperation(context.Background(), request.OperationID); err != nil || operation.Status != desktop.StatusSucceeded {
		t.Fatalf("expired operation retention = %#v, %v", operation, err)
	}
	if _, err := vertical.GetHandoff(context.Background(), request.OperationID); !errors.Is(err, desktop.ErrHandoffExpired) {
		t.Fatalf("expired handoff = %v", err)
	}
	if _, err := vertical.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := authority.ListOpen(context.Background())
	if err != nil || records[0].SessionState() != desktop.SessionExpired || revoker.revokes != 1 {
		t.Fatalf("expiry = %#v revokes=%d, %v", records, revoker.revokes, err)
	}
}
