package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

var repositoryTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func repositoryEvidence() usage.Evidence {
	return usage.Evidence{
		EvidenceID: "usage-evidence-1", SandboxID: "sandbox-1", OperationID: "exec-operation-1", AttemptID: "exec-attempt-1", FencingToken: 2,
		Entries:              []usage.Entry{{EntryID: "entry-wall", SandboxID: "sandbox-1", OperationID: "exec-operation-1", Meter: usage.MeterWallTime, Quantity: 1250, Unit: "milliseconds", MeterSource: usage.SourceRuntime, EvidenceReference: "ref:usage/wall", OccurredAt: repositoryTestNow}},
		ReconciliationStatus: usage.ReconciliationComplete, ObservedAt: repositoryTestNow, RetainedUntil: repositoryTestNow.Add(time.Hour), EvidenceDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}
}

func newRepository(t *testing.T) *Repository {
	t.Helper()
	repository, err := NewRepository(ClockFunc(func() time.Time { return repositoryTestNow }))
	if err != nil {
		t.Fatal(err)
	}
	return repository
}

func TestPutGetAndIdempotentReplay(t *testing.T) {
	repository := newRepository(t)
	evidence := repositoryEvidence()
	if err := repository.Put(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	if err := repository.Put(context.Background(), evidence); err != nil {
		t.Fatalf("same evidence replay error = %v", err)
	}
	read, err := repository.Get(context.Background(), evidence.EvidenceID)
	if err != nil || read.EvidenceDigest != evidence.EvidenceDigest {
		t.Fatalf("Get() = %#v, %v", read, err)
	}
	read.Entries[0].Quantity = 999
	again, err := repository.Get(context.Background(), evidence.EvidenceID)
	if err != nil || again.Entries[0].Quantity == 999 {
		t.Fatalf("Get() did not return an immutable snapshot: %#v, %v", again, err)
	}
	byOperation, err := repository.GetEvidence(context.Background(), evidence.OperationID, repositoryTestNow)
	if err != nil || byOperation.EvidenceID != evidence.EvidenceID {
		t.Fatalf("GetEvidence() = %#v, %v", byOperation, err)
	}
	byOperation.Entries[0].Quantity = 777
	again, _ = repository.GetEvidence(context.Background(), evidence.OperationID, repositoryTestNow)
	if again.Entries[0].Quantity == 777 {
		t.Fatalf("operation lookup did not return immutable snapshot: %#v", again)
	}
}

func TestPutConflictsAndExpiry(t *testing.T) {
	repository := newRepository(t)
	evidence := repositoryEvidence()
	if err := repository.Put(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	conflict := evidence
	conflict.EvidenceDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if err := repository.Put(context.Background(), conflict); err != ErrConflict {
		t.Fatalf("conflict error = %v, want %v", err, ErrConflict)
	}
	operationConflict := evidence
	operationConflict.EvidenceID = "usage-evidence-2"
	if err := repository.Put(context.Background(), operationConflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("operation conflict error = %v", err)
	}
	correlationConflict := evidence
	correlationConflict.EvidenceID = "usage-evidence-3"
	correlationConflict.AttemptID = "exec-attempt-2"
	if err := repository.Put(context.Background(), correlationConflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("correlation conflict error = %v", err)
	}
	repository.clock = ClockFunc(func() time.Time { return evidence.RetainedUntil })
	if _, err := repository.Get(context.Background(), evidence.EvidenceID); err != usage.ErrEvidenceExpired {
		t.Fatalf("expired Get() error = %v", err)
	}
	if _, err := repository.GetEvidence(context.Background(), evidence.OperationID, evidence.RetainedUntil); !errors.Is(err, usage.ErrEvidenceExpired) {
		t.Fatalf("expired GetEvidence() error = %v", err)
	}
	if _, err := repository.GetEvidence(context.Background(), "missing-operation", repositoryTestNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing GetEvidence() error = %v", err)
	}
}

func TestCloseRejectsAccess(t *testing.T) {
	repository := newRepository(t)
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	if err := repository.Put(context.Background(), repositoryEvidence()); err != ErrClosed {
		t.Fatalf("Put after close error = %v, want %v", err, ErrClosed)
	}
}
