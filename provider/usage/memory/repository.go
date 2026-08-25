// Package memory provides a concurrency-safe usage evidence repository for
// tests and single-process development. It is not a billing ledger or a
// multi-controller implementation.
package memory

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

var (
	ErrNotFound = errors.New("usage evidence not found")
	ErrConflict = errors.New("usage evidence conflict")
	ErrClosed   = errors.New("usage evidence repository is closed")
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Repository struct {
	mu             sync.RWMutex
	clock          Clock
	values         map[string]usage.Evidence
	operationIndex map[string]string
	closed         bool
}

func NewRepository(clock Clock) (*Repository, error) {
	if clock == nil {
		return nil, errors.New("usage memory repository clock is required")
	}
	return &Repository{clock: clock, values: make(map[string]usage.Evidence), operationIndex: make(map[string]string)}, nil
}

func (r *Repository) Put(ctx context.Context, evidence usage.Evidence) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if err := evidence.Validate(r.clock.Now().UTC()); err != nil {
		return err
	}
	if previous, ok := r.values[evidence.EvidenceID]; ok {
		if reflect.DeepEqual(previous, evidence) {
			return nil
		}
		return ErrConflict
	}
	if evidenceID, ok := r.operationIndex[evidence.OperationID]; ok {
		previous, exists := r.values[evidenceID]
		if !exists || previous.SandboxID != evidence.SandboxID || previous.AttemptID != evidence.AttemptID || previous.FencingToken != evidence.FencingToken || !reflect.DeepEqual(previous, evidence) {
			return ErrConflict
		}
		return nil
	}
	r.values[evidence.EvidenceID] = evidence.Clone()
	r.operationIndex[evidence.OperationID] = evidence.EvidenceID
	return nil
}

func (r *Repository) GetByOperation(ctx context.Context, operationID string) (usage.Evidence, error) {
	return r.GetEvidence(ctx, operationID, r.clock.Now().UTC())
}

func (r *Repository) GetEvidence(ctx context.Context, operationID string, now time.Time) (usage.Evidence, error) {
	if err := contextError(ctx); err != nil {
		return usage.Evidence{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return usage.Evidence{}, ErrClosed
	}
	evidenceID, ok := r.operationIndex[operationID]
	if !ok {
		return usage.Evidence{}, ErrNotFound
	}
	evidence, ok := r.values[evidenceID]
	if !ok || evidence.OperationID != operationID {
		return usage.Evidence{}, ErrConflict
	}
	if now.IsZero() || !now.UTC().Before(evidence.RetainedUntil) {
		return usage.Evidence{}, usage.ErrEvidenceExpired
	}
	return evidence.Clone(), nil
}

func (r *Repository) Get(ctx context.Context, evidenceID string) (usage.Evidence, error) {
	if err := contextError(ctx); err != nil {
		return usage.Evidence{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return usage.Evidence{}, ErrClosed
	}
	evidence, ok := r.values[evidenceID]
	if !ok {
		return usage.Evidence{}, ErrNotFound
	}
	if !r.clock.Now().UTC().Before(evidence.RetainedUntil) {
		return usage.Evidence{}, usage.ErrEvidenceExpired
	}
	return evidence.Clone(), nil
}

var _ usage.EvidenceReader = (*Repository)(nil)

func (r *Repository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
