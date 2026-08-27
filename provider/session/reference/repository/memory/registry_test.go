package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
)

func memoryRecord(t *testing.T) reference.Record {
	t.Helper()
	now := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	request := session.OpenRequest{
		SandboxID: "sandbox-reference-memory", ProviderRevisionID: "provider-revision-reference-memory",
		OperationID: "operation-reference-memory", AttemptID: "attempt-reference-memory", FencingToken: 1,
		IdempotencyKey: "reference-memory-key", RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Deadline: now.Add(30 * time.Minute), ExpectedGeneration: 1,
		RuntimeSessionID: "session-reference-memory", RuntimeType: session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1", ExpiresAt: now.Add(10 * time.Minute),
	}
	running, err := session.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	running, err = session.AttachAllocation(running, session.AllocationReceipt{
		Reference: "ref:terminal/33333333333333333333333333333333", SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: now, ExpiresAt: request.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := reference.NewRecord("ref:session:dddddddddddddddddddddddddddddddd", running, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestRegistryHonorsCloseContextAndIdempotentRevocation(t *testing.T) {
	registry := NewRegistry()
	record := memoryRecord(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := registry.Create(ctx, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create(cancelled) error = %v", err)
	}
	if err := registry.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke(context.Background(), record.Reference, record.CreatedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Revoke(context.Background(), record.Reference, record.CreatedAt.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := registry.Get(context.Background(), record.Reference)
	if err != nil || got.RevokedAt == nil || !got.RevokedAt.Equal(record.CreatedAt.Add(time.Second)) {
		t.Fatalf("revoked record = %#v, %v", got, err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Get(context.Background(), record.Reference); !errors.Is(err, reference.ErrClosed) {
		t.Fatalf("Get(closed) error = %v", err)
	}
}
