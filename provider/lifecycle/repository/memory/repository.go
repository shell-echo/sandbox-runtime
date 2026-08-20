// Package memory provides a concurrency-safe lifecycle repository for tests
// and single-process development.
package memory

import (
	"context"
	"sync"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type Repository struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRepository() *Repository {
	return &Repository{state: repository.NewState()}
}

func (r *Repository) ReserveCreate(ctx context.Context, key, digest string, sandbox lifecycle.Sandbox, operation lifecycle.Operation) (repository.CreateResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.CreateResult{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpenAndContext(ctx); err != nil {
		return repository.CreateResult{}, err
	}
	return r.state.ReserveCreate(key, digest, sandbox, operation)
}

func (r *Repository) GetSandbox(ctx context.Context, id string) (lifecycle.Sandbox, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Sandbox{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return lifecycle.Sandbox{}, repository.ErrClosed
	}
	return r.state.GetSandbox(id)
}

func (r *Repository) UpdateSandbox(ctx context.Context, sandbox lifecycle.Sandbox, expectedGeneration, fencingToken uint64) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpenAndContext(ctx); err != nil {
		return err
	}
	return r.state.UpdateSandbox(sandbox, expectedGeneration, fencingToken)
}

func (r *Repository) ListSandboxes(ctx context.Context) ([]lifecycle.Sandbox, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListSandboxes(), nil
}

func (r *Repository) GetOperation(ctx context.Context, id string) (lifecycle.Operation, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Operation{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return lifecycle.Operation{}, repository.ErrClosed
	}
	return r.state.GetOperation(id)
}

func (r *Repository) UpdateOperation(ctx context.Context, operation lifecycle.Operation) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpenAndContext(ctx); err != nil {
		return err
	}
	return r.state.UpdateOperation(operation)
}

func (r *Repository) ListOperations(ctx context.Context) ([]lifecycle.Operation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListOperations(), nil
}

func (r *Repository) GetLease(ctx context.Context, id string) (lifecycle.Lease, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Lease{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return lifecycle.Lease{}, repository.ErrClosed
	}
	return r.state.GetLease(id)
}

func (r *Repository) ReplaceLease(ctx context.Context, lease lifecycle.Lease, fencingToken uint64) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpenAndContext(ctx); err != nil {
		return err
	}
	return r.state.ReplaceLease(lease, fencingToken)
}

func (r *Repository) AppendEvent(ctx context.Context, event lifecycle.Event) (lifecycle.Event, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Event{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpenAndContext(ctx); err != nil {
		return lifecycle.Event{}, err
	}
	return r.state.AppendEvent(event)
}

func (r *Repository) ListEvents(ctx context.Context, sandboxID string, after uint64, limit int) ([]lifecycle.Event, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListEvents(sandboxID, after, limit)
}

func (r *Repository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

func (r *Repository) checkOpenAndContext(ctx context.Context) error {
	if r.closed {
		return repository.ErrClosed
	}
	return contextError(ctx)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ repository.Repository = (*Repository)(nil)
