// Package memory provides a concurrency-safe terminal-session authority
// repository for tests and single-process development. It is not a
// multi-controller implementation.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/repository"
)

type Repository struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRepository() *Repository { return &Repository{state: repository.NewState()} }

func (r *Repository) ReserveOpen(ctx context.Context, request session.OpenRequest, acceptedAt time.Time) (session.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.Reservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return session.Reservation{}, err
	}
	return r.state.ReserveOpenAt(request, acceptedAt)
}

func (r *Repository) GetOpen(ctx context.Context, operationID string) (session.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return session.Record{}, repository.ErrClosed
	}
	return r.state.GetOpen(operationID)
}

func (r *Repository) GetOpenAt(ctx context.Context, operationID string, now time.Time) (session.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return session.Record{}, repository.ErrClosed
	}
	return r.state.GetOpenAt(operationID, now)
}

func (r *Repository) UpdateOpen(ctx context.Context, record session.Record, expectedStatus session.Status) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return err
	}
	return r.state.UpdateOpenAt(record, expectedStatus, time.Now().UTC())
}

func (r *Repository) UpdateOpenAt(ctx context.Context, record session.Record, expectedStatus session.Status, now time.Time) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkOpen(ctx); err != nil {
		return err
	}
	return r.state.UpdateOpenAt(record, expectedStatus, now)
}

func (r *Repository) PutSandboxAuthority(ctx context.Context, authority session.SandboxAuthority) error {
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

func (r *Repository) ReplaceSandboxAuthority(ctx context.Context, authority session.SandboxAuthority, expectedGeneration, fencingToken int64) error {
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

func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (session.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return session.SandboxAuthority{}, repository.ErrClosed
	}
	return r.state.GetSandboxAuthority(sandboxID)
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
