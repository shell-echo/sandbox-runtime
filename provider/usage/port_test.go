package usage

import (
	"context"
	"errors"
	"testing"
	"time"
)

type evidenceReaderFunc func(context.Context, string, time.Time) (Evidence, error)

func (f evidenceReaderFunc) GetEvidence(ctx context.Context, operationID string, now time.Time) (Evidence, error) {
	return f(ctx, operationID, now)
}

func TestAggregatorSelectsOneUsageFamily(t *testing.T) {
	now := usageTestNow
	evidence := validUsageEvidence()
	aggregator, err := NewAggregator(
		evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) { return Evidence{}, ErrEvidenceNotFound }),
		evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) { return evidence, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := aggregator.GetEvidence(context.Background(), evidence.OperationID, now)
	if err != nil || got.EvidenceID != evidence.EvidenceID {
		t.Fatalf("GetEvidence = %#v, %v", got, err)
	}
}

func TestAggregatorFailsClosedOnDuplicateAndUnavailable(t *testing.T) {
	now := usageTestNow
	evidence := validUsageEvidence()
	found := evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) { return evidence, nil })
	aggregator, _ := NewAggregator(found, found)
	if _, err := aggregator.GetEvidence(context.Background(), evidence.OperationID, now); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("duplicate authority = %v", err)
	}
	aggregator, _ = NewAggregator(
		evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) { return Evidence{}, ErrEvidenceUnavailable }),
		found,
	)
	if _, err := aggregator.GetEvidence(context.Background(), evidence.OperationID, now); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("unavailable family = %v", err)
	}
}

func TestAggregatorPreservesMissAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	missing := evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) { return Evidence{}, ErrEvidenceNotFound })
	aggregator, _ := NewAggregator(missing, missing)
	if _, err := aggregator.GetEvidence(context.Background(), "operation-missing", now); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("missing = %v", err)
	}
	expired := evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) { return Evidence{}, ErrEvidenceExpired })
	aggregator, _ = NewAggregator(missing, expired)
	if _, err := aggregator.GetEvidence(context.Background(), "operation-expired", now); !errors.Is(err, ErrEvidenceExpired) {
		t.Fatalf("expired = %v", err)
	}
	found := evidenceReaderFunc(func(context.Context, string, time.Time) (Evidence, error) {
		evidence := validUsageEvidence()
		return evidence, nil
	})
	for _, readers := range [][]EvidenceReader{{found, expired}, {expired, found}, {expired, expired}} {
		aggregator, _ = NewAggregator(readers...)
		if _, err := aggregator.GetEvidence(context.Background(), validUsageEvidence().OperationID, now); !errors.Is(err, ErrEvidenceUnavailable) {
			t.Fatalf("ambiguous expired authority = %v", err)
		}
	}
	if _, err := aggregator.GetEvidence(nil, "operation-expired", now); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context = %v", err)
	}
}
