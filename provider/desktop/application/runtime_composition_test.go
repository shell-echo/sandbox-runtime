package application

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
	referencememory "github.com/shell-echo/sandbox-runtime/provider/desktop/reference/repository/memory"
	desktopmemory "github.com/shell-echo/sandbox-runtime/provider/desktop/repository/memory"
	desktopusage "github.com/shell-echo/sandbox-runtime/provider/desktop/usage"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
)

type compositionRuntime struct {
	*desktopRuntimeSpy
	clock    *desktopClock
	attaches int
}

func (r *compositionRuntime) Attach(_ context.Context, receipt desktop.AllocationReceipt) (desktop.Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	retained, ok := r.receipts[receipt.OperationID]
	if !ok {
		return desktop.Attachment{}, desktop.ErrDesktopNotFound
	}
	if retained != receipt {
		return desktop.Attachment{}, desktop.ErrDesktopConflict
	}
	r.attaches++
	return desktop.Attachment{
		DesktopSessionID: receipt.DesktopSessionID, ConnectionGeneration: receipt.ConnectionGeneration,
		MediaProfileID: desktop.MediaProfileID, ControlProfileID: desktop.ControlProfileID,
		DisplayReference: "ref:desktop-display:primary", Width: 1280, Height: 720, Depth: 24,
		PrivateInputModes: []string{"keyboard", "pointer"}, AttachedAt: r.clock.Now(),
	}, nil
}

type tracingReferenceStore struct {
	reference.Store
	trace *effectTrace
}

func (s tracingReferenceStore) Revoke(ctx context.Context, value string, revokedAt time.Time) error {
	s.trace.add("revoke")
	return s.Store.Revoke(ctx, value, revokedAt)
}

func TestRuntimeReferenceCloseAndUsageComposition(t *testing.T) {
	now := time.Date(2026, 9, 19, 11, 0, 0, 0, time.UTC)
	clock := &desktopClock{now: now}
	trace := &effectTrace{}
	baseRuntime := newDesktopRuntimeSpy()
	baseRuntime.trace = trace
	runtime := &compositionRuntime{desktopRuntimeSpy: baseRuntime, clock: clock}
	authority := desktopmemory.NewRepository()
	store := tracingReferenceStore{Store: referencememory.NewRegistry(), trace: trace}
	registrar, err := reference.NewRegistrar(store, clock, func() (string, error) {
		return "ref:desktop-session:11111111111111111111111111111111", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	vertical, err := NewVerticalWithHandoffLifecycle(
		authority, runtime, desktopSandboxReader{sandbox: desktopSandbox(now)}, desktopProfile(), registrar, registrar, clock,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := desktopOpenRequest(now)
	operation, err := vertical.Open(context.Background(), request)
	if err != nil || operation.Status != desktop.StatusSucceeded {
		t.Fatalf("open = %#v, %v", operation, err)
	}
	handoff, err := vertical.GetHandoff(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := reference.NewResolver(store, authority, runtime, clock)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolver.Resolve(context.Background(), handoff.InternalEndpointReference)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		attachment, attachErr := endpoint.Attach(context.Background())
		if attachErr != nil || attachment.ConnectionGeneration != handoff.ConnectionGeneration {
			t.Fatalf("attach %d = %#v, %v", attempt, attachment, attachErr)
		}
	}
	if runtime.attaches != 2 {
		t.Fatalf("fresh attach count = %d", runtime.attaches)
	}
	trace.mu.Lock()
	trace.events = nil
	trace.mu.Unlock()
	clock.Set(now.Add(time.Minute))
	closeOperation, err := vertical.CloseDesktopSession(context.Background(), desktopCloseRequest(clock.Now()))
	if err != nil || closeOperation.Status != desktop.StatusSucceeded {
		t.Fatalf("close = %#v, %v", closeOperation, err)
	}
	if got, want := fmt.Sprint(trace.snapshot()), fmt.Sprint([]string{"revoke", "cleanup", "observe"}); got != want {
		t.Fatalf("close order = %s, want %s", got, want)
	}
	if _, err := resolver.Resolve(context.Background(), handoff.InternalEndpointReference); !errors.Is(err, reference.ErrRevoked) {
		t.Fatalf("resolve after revoke = %v", err)
	}
	source, err := authority.GetOpen(context.Background(), request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := desktopusage.BuildEvidence(source, clock.Now(), clock.Now().Add(time.Hour))
	if err != nil || evidence.ReconciliationStatus != providerusage.ReconciliationComplete ||
		evidence.Entries[0].Meter != providerusage.MeterDesktopSession || !evidence.ObservedAt.Equal(*source.RevokedAt) {
		t.Fatalf("duration evidence = %#v, %v", evidence, err)
	}
}
