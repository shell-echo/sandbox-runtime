package reference_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/reference/repository/memory"
)

type refClock struct{ now time.Time }

func (c refClock) Now() time.Time { return c.now }

type refAttacher struct{ calls int }

func (a *refAttacher) Attach(_ context.Context, receipt desktop.AllocationReceipt) (desktop.Attachment, error) {
	a.calls++
	return desktop.Attachment{
		DesktopSessionID: receipt.DesktopSessionID, ConnectionGeneration: receipt.ConnectionGeneration,
		MediaProfileID: desktop.MediaProfileID, ControlProfileID: desktop.ControlProfileID,
		DisplayReference: "ref:desktop-display:primary", Width: 1280, Height: 720, Depth: 24,
		PrivateInputModes: []string{"keyboard", "pointer"}, AttachedAt: receipt.AllocatedAt.Add(time.Second),
	}, nil
}

func runningRecord(t *testing.T, now time.Time) (desktop.Record, desktop.AllocationReceipt) {
	t.Helper()
	request := desktop.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1", CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute)}
	record, err := desktop.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt := desktop.AllocationReceipt{Reference: "ref:desktop/11111111111111111111111111111111", SandboxID: request.SandboxID, DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(time.Second), ExpiresAt: request.ExpiresAt}
	record, err = desktop.AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	return record, receipt
}

func succeededRecord(t *testing.T, running desktop.Record, reference string, now time.Time) desktop.Record {
	t.Helper()
	record, err := desktop.Transition(running, desktop.StatusSucceeded, now, &desktop.EndpointEvidence{InternalEndpointReference: reference, ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestRegistrarResolverRequiresCommittedHandoffAndRechecksOnAttach(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	running, _ := runningRecord(t, now)
	registry := memory.NewRegistry()
	registrar, err := reference.NewRegistrar(registry, refClock{now: now.Add(2 * time.Second)}, func() (string, error) { return "ref:desktop-session:11111111111111111111111111111111", nil })
	if err != nil {
		t.Fatal(err)
	}
	registration, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	pendingResolver, err := reference.NewResolver(registry, authorityReader{record: running}, &refAttacher{}, refClock{now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pendingResolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("uncommitted resolve = %v", err)
	}
	committed := succeededRecord(t, running, registration.Record.Reference, now.Add(3*time.Second))
	reader := authorityReader{record: committed}
	attacher := &refAttacher{}
	resolver, err := reference.NewResolver(registry, reader, attacher, refClock{now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolver.Resolve(context.Background(), registration.Record.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.DesktopSessionID != "desktop-session-1" {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if _, err := endpoint.Attach(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attacher.calls != 1 {
		t.Fatalf("attach calls = %d", attacher.calls)
	}
	if err := registry.Revoke(context.Background(), registration.Record.Reference, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Attach(context.Background()); !errors.Is(err, reference.ErrRevoked) {
		t.Fatalf("attach after revoke = %v", err)
	}
	if attacher.calls != 1 {
		t.Fatalf("attach calls after revoke = %d", attacher.calls)
	}
}

type authorityReader struct{ record desktop.Record }

func (r authorityReader) GetOpen(context.Context, string) (desktop.Record, error) {
	return r.record.Clone(), nil
}

func TestRegistrarReplayAndRevocationFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	running, _ := runningRecord(t, now)
	registry := memory.NewRegistry()
	registrar, err := reference.NewRegistrar(registry, refClock{now: now.Add(time.Second)}, func() (string, error) { return "ref:desktop-session:22222222222222222222222222222222", nil })
	if err != nil {
		t.Fatal(err)
	}
	first, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registrar.Register(context.Background(), running)
	if err != nil || second.Record.Reference != first.Record.Reference {
		t.Fatalf("replay = %#v, %v", second, err)
	}
	if err := registry.Revoke(context.Background(), first.Record.Reference, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	resolver, err := reference.NewResolver(registry, authorityReader{record: succeededRecord(t, running, first.Record.Reference, now.Add(2*time.Second))}, &refAttacher{}, refClock{now: now.Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), first.Record.Reference); !errors.Is(err, reference.ErrRevoked) {
		t.Fatalf("revoked resolve = %v", err)
	}
}
