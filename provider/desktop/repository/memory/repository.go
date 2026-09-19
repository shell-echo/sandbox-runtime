// Package memory provides a concurrency-safe desktop-session authority for
// tests and single-process development. It is not multi-controller storage.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	"github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

type Repository struct {
	mu     sync.RWMutex
	state  repository.State
	closed bool
}

func NewRepository() *Repository { return &Repository{state: repository.NewState()} }

func (r *Repository) ReserveOpen(ctx context.Context, request desktop.OpenRequest, acceptedAt time.Time) (desktop.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.Reservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return desktop.Reservation{}, repository.ErrClosed
	}
	return r.state.ReserveOpenAt(request, acceptedAt)
}
func (r *Repository) GetOpen(ctx context.Context, operationID string) (desktop.Record, error) {
	return r.GetOpenAt(ctx, operationID, time.Now().UTC())
}
func (r *Repository) GetOpenAt(ctx context.Context, operationID string, now time.Time) (desktop.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return desktop.Record{}, repository.ErrClosed
	}
	return r.state.GetOpenAt(operationID, now)
}
func (r *Repository) ListOpen(ctx context.Context) ([]desktop.Record, error) {
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
func (r *Repository) AttachAllocation(ctx context.Context, receipt desktop.AllocationReceipt) (desktop.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.Reservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return desktop.Reservation{}, repository.ErrClosed
	}
	return r.state.AttachAllocation(receipt)
}
func (r *Repository) ObserveAllocation(ctx context.Context, operationID string, observation desktop.AllocationEvidence) (desktop.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.Record{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return desktop.Record{}, repository.ErrClosed
	}
	return r.state.ObserveAllocation(operationID, observation)
}
func (r *Repository) ReserveClose(ctx context.Context, request desktop.CloseRequest, acceptedAt time.Time, expiration bool) (desktop.CloseReservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.CloseReservation{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return desktop.CloseReservation{}, repository.ErrClosed
	}
	return r.state.ReserveCloseAt(request, acceptedAt, expiration)
}
func (r *Repository) GetClose(ctx context.Context, operationID string) (desktop.CloseRecord, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.CloseRecord{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return desktop.CloseRecord{}, repository.ErrClosed
	}
	return r.state.GetClose(operationID)
}
func (r *Repository) UpdateClose(ctx context.Context, record desktop.CloseRecord, expected desktop.Status, source desktop.Record) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return repository.ErrClosed
	}
	return r.state.UpdateClose(record, expected, source)
}
func (r *Repository) ResolveUnknownClose(ctx context.Context, operationID string, observedAt time.Time) (desktop.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.Record{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return desktop.Record{}, repository.ErrClosed
	}
	return r.state.ResolveUnknownClose(operationID, observedAt)
}
func (r *Repository) ListClose(ctx context.Context) ([]desktop.CloseRecord, error) {
	if err := repository.ContextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListClose(), nil
}
func (r *Repository) UpdateOpen(ctx context.Context, record desktop.Record, expectedStatus desktop.Status) error {
	return r.UpdateOpenAt(ctx, record, expectedStatus, time.Now().UTC())
}
func (r *Repository) UpdateOpenAt(ctx context.Context, record desktop.Record, expectedStatus desktop.Status, now time.Time) error {
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
func (r *Repository) SynchronizeSandboxAuthority(ctx context.Context, authority desktop.SandboxAuthority) error {
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
func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (desktop.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return desktop.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return desktop.SandboxAuthority{}, repository.ErrClosed
	}
	return r.state.GetSandboxAuthority(sandboxID)
}
func (r *Repository) Close() error { r.mu.Lock(); defer r.mu.Unlock(); r.closed = true; return nil }

var _ desktop.CoordinationAuthority = (*Repository)(nil)
