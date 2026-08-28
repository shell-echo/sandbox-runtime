// Package memory provides a concurrency-safe artifact staging authority for
// tests and single-process development. It is not multi-controller storage.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/artifact/repository"
)

type Repository struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRepository() *Repository { return &Repository{state: repository.NewState()} }

func (r *Repository) ReserveStage(ctx context.Context, request artifact.Request, acceptedAt time.Time) (artifact.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.Reservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return artifact.Reservation{}, err
	}
	return r.state.ReserveStageAt(request, acceptedAt)
}

func (r *Repository) GetStage(ctx context.Context, operationID string) (artifact.Operation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.Operation{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return artifact.Operation{}, repository.ErrClosed
	}
	return r.state.GetStage(operationID)
}

func (r *Repository) ListStages(ctx context.Context) ([]artifact.Operation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListStages()
}

func (r *Repository) UpdateStage(ctx context.Context, operation artifact.Operation, expected artifact.OperationStatus) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return err
	}
	return r.state.UpdateStage(operation, expected)
}

func (r *Repository) GetEvidence(ctx context.Context, operationID string, now time.Time) (artifact.Evidence, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	evidence, err, _ := r.state.ReadEvidenceAt(operationID, now)
	return evidence, err
}

func (r *Repository) PutSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return err
	}
	return r.state.PutSandboxAuthority(authority)
}

func (r *Repository) ReplaceSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority, expectedGeneration, fencingToken int64) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return err
	}
	return r.state.ReplaceSandboxAuthority(authority, expectedGeneration, fencingToken)
}

func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (artifact.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return artifact.SandboxAuthority{}, repository.ErrClosed
	}
	return r.state.GetSandboxAuthority(sandboxID)
}

func (r *Repository) SynchronizeSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return repository.ErrClosed
	}
	return r.state.SynchronizeSandboxAuthority(authority)
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
