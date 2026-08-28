// Package memory provides a concurrency-safe, single-process reference
// registry for tests and development composition.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference/repository"
)

type Registry struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRegistry() *Registry { return &Registry{state: repository.NewState()} }

func (r *Registry) Create(ctx context.Context, record reference.Record) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return reference.ErrClosed
	}
	return r.state.Create(record)
}

func (r *Registry) Get(ctx context.Context, value string) (reference.Record, error) {
	if err := contextError(ctx); err != nil {
		return reference.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return reference.Record{}, reference.ErrClosed
	}
	return r.state.Get(value)
}

func (r *Registry) FindRunning(ctx context.Context, source session.Record) (reference.Record, error) {
	if err := contextError(ctx); err != nil {
		return reference.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return reference.Record{}, reference.ErrClosed
	}
	return r.state.FindRunning(source)
}

func (r *Registry) Revoke(ctx context.Context, value string, revokedAt time.Time) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return reference.ErrClosed
	}
	return r.state.Revoke(value, revokedAt)
}

func (r *Registry) Close() error {
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

var _ reference.Store = (*Registry)(nil)
