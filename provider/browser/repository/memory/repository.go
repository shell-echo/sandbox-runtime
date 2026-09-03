// Package memory provides a concurrency-safe browser-session authority for
// tests and single-process development. It is not multi-controller storage.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/repository"
)

type Repository struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRepository() *Repository { return &Repository{state: repository.NewState()} }

func (r *Repository) ReserveOpen(ctx context.Context, request browser.OpenRequest, acceptedAt time.Time) (browser.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.Reservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return browser.Reservation{}, repository.ErrClosed
	}
	return r.state.ReserveOpenAt(request, acceptedAt)
}
func (r *Repository) GetOpen(ctx context.Context, operationID string) (browser.Record, error) {
	return r.GetOpenAt(ctx, operationID, time.Now().UTC())
}
func (r *Repository) GetOpenAt(ctx context.Context, operationID string, now time.Time) (browser.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return browser.Record{}, repository.ErrClosed
	}
	return r.state.GetOpenAt(operationID, now)
}
func (r *Repository) ListOpen(ctx context.Context) ([]browser.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListOpen(), nil
}
func (r *Repository) AttachAllocation(ctx context.Context, receipt browser.AllocationReceipt) (browser.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.Reservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return browser.Reservation{}, repository.ErrClosed
	}
	return r.state.AttachAllocation(receipt)
}
func (r *Repository) ObserveAllocation(ctx context.Context, operationID string, observation browser.AllocationEvidence) (browser.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.Record{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return browser.Record{}, repository.ErrClosed
	}
	return r.state.ObserveAllocation(operationID, observation)
}
func (r *Repository) UpdateOpen(ctx context.Context, record browser.Record, expectedStatus browser.Status) error {
	return r.UpdateOpenAt(ctx, record, expectedStatus, time.Now().UTC())
}
func (r *Repository) UpdateOpenAt(ctx context.Context, record browser.Record, expectedStatus browser.Status, now time.Time) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return repository.ErrClosed
	}
	return r.state.UpdateOpenAt(record, expectedStatus, now)
}
func (r *Repository) SynchronizeSandboxAuthority(ctx context.Context, authority browser.SandboxAuthority) error {
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
func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (browser.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return browser.SandboxAuthority{}, repository.ErrClosed
	}
	return r.state.GetSandboxAuthority(sandboxID)
}
func (r *Repository) Close() error { r.mu.Lock(); defer r.mu.Unlock(); r.closed = true; return nil }

var _ browser.CoordinationAuthority = (*Repository)(nil)
