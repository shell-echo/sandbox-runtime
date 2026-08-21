// Package memory provides a concurrency-safe exec repository for tests and
// single-process development. It is not a multi-controller implementation.
package memory

import (
	"context"
	"sync"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
)

type Repository struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRepository() *Repository { return &Repository{state: repository.NewState()} }

func (r *Repository) ReserveExecution(ctx context.Context, request providerexec.Request, dispatch providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.ExecutionReservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return providerexec.ExecutionReservation{}, err
	}
	return r.state.ReserveExecution(request, dispatch)
}

func (r *Repository) GetExecution(ctx context.Context, operationID string) (providerexec.ExecutionRecord, error) {
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.ExecutionRecord{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return providerexec.ExecutionRecord{}, repository.ErrClosed
	}
	return r.state.GetExecution(operationID)
}

func (r *Repository) ReserveCancellation(ctx context.Context, intent providerexec.CancellationIntent) (providerexec.CancellationReservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.CancellationReservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return providerexec.CancellationReservation{}, err
	}
	return r.state.ReserveCancellation(intent, time.Now().UTC())
}

func (r *Repository) StoreResult(ctx context.Context, result providerexec.Result) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return err
	}
	return r.state.StoreResult(result)
}

func (r *Repository) GetResult(ctx context.Context, operationID string, now time.Time) (providerexec.Result, error) {
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.Result{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return providerexec.Result{}, repository.ErrClosed
	}
	result, err, _ := r.state.ReadResult(operationID, now.UTC())
	return result, err
}

func (r *Repository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *Repository) checkOpen(ctx context.Context) error {
	if r.closed {
		return repository.ErrClosed
	}
	return repository.ContextError(ctx)
}

var _ repository.Repository = (*Repository)(nil)
