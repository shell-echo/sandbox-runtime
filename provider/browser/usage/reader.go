package usage

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
)

type SessionLister interface {
	ListOpen(context.Context) ([]browser.Record, error)
}

// Reader derives Browser duration evidence from the durable session record.
// Ongoing evidence is a point-in-time partial projection; complete expiry
// evidence is persisted once and then served immutably through the shared
// Provider usage store.
type Reader struct {
	sessions    SessionLister
	store       providerusage.Store
	retainedFor time.Duration
}

func NewReader(sessions SessionLister, store providerusage.Store, retainedFor time.Duration) (*Reader, error) {
	if sessions == nil || store == nil || retainedFor <= 0 {
		return nil, ErrUnavailable
	}
	return &Reader{sessions: sessions, store: store, retainedFor: retainedFor}, nil
}

func (r *Reader) GetEvidence(ctx context.Context, operationID string, now time.Time) (providerusage.Evidence, error) {
	if ctx == nil {
		return providerusage.Evidence{}, context.Canceled
	}
	if r == nil || r.sessions == nil || r.store == nil || operationID == "" || now.IsZero() {
		return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
	}
	now = now.UTC()
	evidence, err := r.store.GetEvidence(ctx, operationID, now)
	if err == nil || errors.Is(err, providerusage.ErrEvidenceExpired) {
		return evidence, err
	}
	if !errors.Is(err, providerusage.ErrEvidenceNotFound) {
		return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
	}
	records, err := r.sessions.ListOpen(ctx)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return providerusage.Evidence{}, contextErr
		}
		return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
	}
	var record *browser.Record
	for index := range records {
		if records[index].Request.OperationID == operationID {
			if record != nil {
				return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
			}
			copyRecord := records[index].Clone()
			record = &copyRecord
		}
	}
	if record == nil {
		return providerusage.Evidence{}, providerusage.ErrEvidenceNotFound
	}
	if record.Status != browser.StatusSucceeded || record.Handoff == nil {
		return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
	}
	retainedUntil := record.Request.ExpiresAt.UTC().Add(r.retainedFor)
	if !now.Before(retainedUntil) {
		return providerusage.Evidence{}, providerusage.ErrEvidenceExpired
	}
	evidence, err = BuildEvidence(*record, now, retainedUntil)
	if err != nil {
		return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
	}
	if evidence.ReconciliationStatus == providerusage.ReconciliationComplete {
		if err := r.store.Put(ctx, evidence); err != nil {
			return providerusage.Evidence{}, providerusage.ErrEvidenceUnavailable
		}
	}
	return evidence, nil
}

var _ providerusage.EvidenceReader = (*Reader)(nil)
