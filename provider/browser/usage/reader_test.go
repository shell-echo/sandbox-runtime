package usage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
	usagememory "github.com/shell-echo/sandbox-runtime/provider/usage/memory"
)

type sessionLister struct {
	records []browser.Record
	err     error
}

func (l sessionLister) ListOpen(context.Context) ([]browser.Record, error) {
	result := make([]browser.Record, len(l.records))
	for index := range l.records {
		result[index] = l.records[index].Clone()
	}
	return result, l.err
}

func TestReaderProjectsPartialThenPersistsCompleteExpiryEvidence(t *testing.T) {
	started := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	record := usageRecord(t, started)
	storeNow := started.Add(10 * time.Second)
	store, err := usagememory.NewRepository(usagememory.ClockFunc(func() time.Time { return storeNow }))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewReader(sessionLister{records: []browser.Record{record}}, store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := reader.GetEvidence(context.Background(), record.Request.OperationID, storeNow)
	if err != nil || partial.ReconciliationStatus != providerusage.ReconciliationPartial || partial.Entries[0].Quantity != 8_000 {
		t.Fatalf("partial evidence = %#v, %v", partial, err)
	}
	if _, err := store.GetEvidence(context.Background(), record.Request.OperationID, storeNow); !errors.Is(err, providerusage.ErrEvidenceNotFound) {
		t.Fatalf("partial evidence was persisted: %v", err)
	}
	storeNow = record.Request.ExpiresAt
	complete, err := reader.GetEvidence(context.Background(), record.Request.OperationID, storeNow)
	if err != nil || complete.ReconciliationStatus != providerusage.ReconciliationComplete {
		t.Fatalf("complete evidence = %#v, %v", complete, err)
	}
	storeNow = storeNow.Add(time.Minute)
	replayed, err := reader.GetEvidence(context.Background(), record.Request.OperationID, storeNow)
	if err != nil || replayed.EvidenceDigest != complete.EvidenceDigest {
		t.Fatalf("persisted evidence = %#v, %v", replayed, err)
	}
}

func TestReaderPreservesMissingUnavailableAndExpiredStates(t *testing.T) {
	started := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	record := usageRecord(t, started)
	storeNow := started
	store, _ := usagememory.NewRepository(usagememory.ClockFunc(func() time.Time { return storeNow }))
	reader, _ := NewReader(sessionLister{}, store, time.Hour)
	if _, err := reader.GetEvidence(context.Background(), "operation-missing", storeNow); !errors.Is(err, providerusage.ErrEvidenceNotFound) {
		t.Fatalf("missing = %v", err)
	}
	pending := record.Clone()
	pending.Status = browser.StatusRunning
	pending.Handoff = nil
	reader, _ = NewReader(sessionLister{records: []browser.Record{pending}}, store, time.Hour)
	if _, err := reader.GetEvidence(context.Background(), pending.Request.OperationID, storeNow); !errors.Is(err, providerusage.ErrEvidenceUnavailable) {
		t.Fatalf("pending = %v", err)
	}
	reader, _ = NewReader(sessionLister{records: []browser.Record{record}}, store, time.Hour)
	storeNow = record.Request.ExpiresAt.Add(time.Hour)
	if _, err := reader.GetEvidence(context.Background(), record.Request.OperationID, storeNow); !errors.Is(err, providerusage.ErrEvidenceExpired) {
		t.Fatalf("expired = %v", err)
	}
	if _, err := reader.GetEvidence(nil, record.Request.OperationID, storeNow); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context = %v", err)
	}
}
