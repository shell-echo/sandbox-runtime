package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

const desktopDocument = "desktop_sessions"

type DesktopRepository struct{ store *Store }

func NewDesktopRepository(store *Store) (*DesktopRepository, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &DesktopRepository{store: store}, nil
}
func newDesktopState() desktoprepository.State { return desktoprepository.NewState() }
func importDesktopState(state *desktoprepository.State, document json.RawMessage) error {
	var snapshot desktoprepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportDesktopState(state desktoprepository.State) any { return state.Export() }
func (r *DesktopRepository) mutate(ctx context.Context, mutation func(*desktoprepository.State) error) error {
	return mutateState(ctx, r.store, desktopDocument, newDesktopState, importDesktopState, exportDesktopState, mutation)
}
func (r *DesktopRepository) read(ctx context.Context) (desktoprepository.State, error) {
	return readState(ctx, r.store, desktopDocument, newDesktopState, importDesktopState)
}
func (r *DesktopRepository) ReserveOpen(ctx context.Context, request desktop.OpenRequest, at time.Time) (desktop.Reservation, error) {
	var result desktop.Reservation
	err := r.mutate(ctx, func(state *desktoprepository.State) error {
		var err error
		result, err = state.ReserveOpenAt(request, at)
		return err
	})
	return result, err
}
func (r *DesktopRepository) GetOpen(ctx context.Context, id string) (desktop.Record, error) {
	return r.GetOpenAt(ctx, id, time.Now().UTC())
}
func (r *DesktopRepository) GetOpenAt(ctx context.Context, id string, now time.Time) (desktop.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return desktop.Record{}, err
	}
	return state.GetOpenAt(id, now)
}
func (r *DesktopRepository) ListOpen(ctx context.Context) ([]desktop.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListOpen(), nil
}
func (r *DesktopRepository) AttachAllocation(ctx context.Context, receipt desktop.AllocationReceipt) (desktop.Reservation, error) {
	var result desktop.Reservation
	err := r.mutate(ctx, func(state *desktoprepository.State) error {
		var err error
		result, err = state.AttachAllocation(receipt)
		return err
	})
	return result, err
}
func (r *DesktopRepository) ObserveAllocation(ctx context.Context, id string, observation desktop.AllocationEvidence) (desktop.Record, error) {
	var result desktop.Record
	err := r.mutate(ctx, func(state *desktoprepository.State) error {
		var err error
		result, err = state.ObserveAllocation(id, observation)
		return err
	})
	return result, err
}
func (r *DesktopRepository) ReserveClose(ctx context.Context, request desktop.CloseRequest, at time.Time, expiration bool) (desktop.CloseReservation, error) {
	var result desktop.CloseReservation
	err := r.mutate(ctx, func(state *desktoprepository.State) error {
		var err error
		result, err = state.ReserveCloseAt(request, at, expiration)
		return err
	})
	return result, err
}
func (r *DesktopRepository) GetClose(ctx context.Context, id string) (desktop.CloseRecord, error) {
	state, err := r.read(ctx)
	if err != nil {
		return desktop.CloseRecord{}, err
	}
	return state.GetClose(id)
}
func (r *DesktopRepository) ListClose(ctx context.Context) ([]desktop.CloseRecord, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListClose(), nil
}
func (r *DesktopRepository) UpdateClose(ctx context.Context, record desktop.CloseRecord, expected desktop.Status, source desktop.Record) error {
	return r.mutate(ctx, func(state *desktoprepository.State) error { return state.UpdateClose(record, expected, source) })
}
func (r *DesktopRepository) ResolveUnknownClose(ctx context.Context, id string, observedAt time.Time) (desktop.Record, error) {
	var result desktop.Record
	err := r.mutate(ctx, func(state *desktoprepository.State) error {
		var err error
		result, err = state.ResolveUnknownClose(id, observedAt)
		return err
	})
	return result, err
}
func (r *DesktopRepository) UpdateOpen(ctx context.Context, record desktop.Record, expected desktop.Status) error {
	return r.UpdateOpenAt(ctx, record, expected, time.Now().UTC())
}
func (r *DesktopRepository) UpdateOpenAt(ctx context.Context, record desktop.Record, expected desktop.Status, now time.Time) error {
	return r.mutate(ctx, func(state *desktoprepository.State) error { return state.UpdateOpenAt(record, expected, now) })
}
func (r *DesktopRepository) SynchronizeSandboxAuthority(ctx context.Context, authority desktop.SandboxAuthority) error {
	return r.mutate(ctx, func(state *desktoprepository.State) error { return state.SynchronizeSandboxAuthority(authority) })
}
func (r *DesktopRepository) GetSandboxAuthority(ctx context.Context, id string) (desktop.SandboxAuthority, error) {
	state, err := r.read(ctx)
	if err != nil {
		return desktop.SandboxAuthority{}, err
	}
	return state.GetSandboxAuthority(id)
}
func (r *DesktopRepository) Close() error { return nil }

var _ desktoprepository.Repository = (*DesktopRepository)(nil)
