package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

var usageFileTime = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

func TestRepositoryRestartRetainsEvidenceAndExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "usage.json")
	repository, err := NewRepository(path, ClockFunc(func() time.Time { return usageFileTime }))
	if err != nil {
		t.Fatal(err)
	}
	evidence := fileEvidence()
	if err := repository.Put(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(path, ClockFunc(func() time.Time { return usageFileTime })); err == nil {
		t.Fatal("second controller opened usage repository")
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}
	repository, err = NewRepository(path, ClockFunc(func() time.Time { return usageFileTime }))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	read, err := repository.GetEvidence(context.Background(), evidence.OperationID, usageFileTime)
	if err != nil || read.EvidenceID != evidence.EvidenceID {
		t.Fatalf("restarted GetEvidence() = %#v, %v", read, err)
	}
	if _, err := repository.GetEvidence(context.Background(), evidence.OperationID, evidence.RetainedUntil); !errors.Is(err, usage.ErrEvidenceExpired) {
		t.Fatalf("expired evidence error = %v", err)
	}
}

func TestRepositoryRejectsConflictsCorruptionAndCanceledWrite(t *testing.T) {
	repository, err := NewRepository(filepath.Join(t.TempDir(), "usage.json"), ClockFunc(func() time.Time { return usageFileTime }))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	evidence := fileEvidence()
	if err := repository.Put(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	conflict := evidence
	conflict.EvidenceDigest = "sha256:" + strings.Repeat("e", 64)
	if err := repository.Put(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Put() error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	second := evidence
	second.EvidenceID = "usage-evidence-2"
	second.OperationID = "exec-operation-2"
	second.Entries[0].OperationID = second.OperationID
	if err := repository.Put(canceled, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Put() error = %v", err)
	}

	corruptPath := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(corruptPath, []byte(`{"version":1,"evidence":[],"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(corruptPath, ClockFunc(func() time.Time { return usageFileTime })); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt NewRepository() error = %v", err)
	}
}

func fileEvidence() usage.Evidence {
	return usage.Evidence{
		EvidenceID: "usage-evidence-1", SandboxID: "sandbox-1", OperationID: "exec-operation-1", AttemptID: "attempt-1", FencingToken: 2,
		Entries:              []usage.Entry{{EntryID: "entry-1", SandboxID: "sandbox-1", OperationID: "exec-operation-1", Meter: usage.MeterExecCount, Quantity: 1, Unit: "count", MeterSource: usage.SourceReconciled, EvidenceReference: "ref:usage/count-1", OccurredAt: usageFileTime}},
		ReconciliationStatus: usage.ReconciliationPartial, ObservedAt: usageFileTime, RetainedUntil: usageFileTime.Add(time.Hour), EvidenceDigest: "sha256:" + strings.Repeat("d", 64),
	}
}
