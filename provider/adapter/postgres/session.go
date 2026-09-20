package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionrepository "github.com/shell-echo/sandbox-runtime/provider/session/repository"
)

const sessionDocument = "terminal_sessions"

type SessionRepository struct{ store *Store }

func NewSessionRepository(store *Store) (*SessionRepository, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &SessionRepository{store: store}, nil
}
func newSessionState() sessionrepository.State { return sessionrepository.NewState() }
func importSessionState(state *sessionrepository.State, document json.RawMessage) error {
	var snapshot sessionrepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportSessionState(state sessionrepository.State) any { return state.Export() }
func (r *SessionRepository) mutate(ctx context.Context, mutation func(*sessionrepository.State) error) error {
	return mutateState(ctx, r.store, sessionDocument, newSessionState, importSessionState, exportSessionState, mutation)
}
func (r *SessionRepository) read(ctx context.Context) (sessionrepository.State, error) {
	return readState(ctx, r.store, sessionDocument, newSessionState, importSessionState)
}
func (r *SessionRepository) ReserveOpen(ctx context.Context, request session.OpenRequest, at time.Time) (session.Reservation, error) {
	var result session.Reservation
	err := r.mutate(ctx, func(state *sessionrepository.State) error {
		var err error
		result, err = state.ReserveOpenAt(request, at)
		return err
	})
	return result, err
}
func (r *SessionRepository) GetOpen(ctx context.Context, id string) (session.Record, error) {
	return r.GetOpenAt(ctx, id, time.Now().UTC())
}
func (r *SessionRepository) GetOpenAt(ctx context.Context, id string, now time.Time) (session.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return session.Record{}, err
	}
	return state.GetOpenAt(id, now)
}
func (r *SessionRepository) ListOpen(ctx context.Context) ([]session.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListOpen(), nil
}
func (r *SessionRepository) AttachAllocation(ctx context.Context, receipt session.AllocationReceipt) (session.Reservation, error) {
	var result session.Reservation
	err := r.mutate(ctx, func(state *sessionrepository.State) error {
		var err error
		result, err = state.AttachAllocation(receipt)
		return err
	})
	return result, err
}
func (r *SessionRepository) ObserveAllocation(ctx context.Context, id string, observation session.AllocationEvidence) (session.Record, error) {
	var result session.Record
	err := r.mutate(ctx, func(state *sessionrepository.State) error {
		var err error
		result, err = state.ObserveAllocation(id, observation)
		return err
	})
	return result, err
}
func (r *SessionRepository) ReserveClose(ctx context.Context, request session.CloseRequest, at time.Time) (session.CloseReservation, error) {
	var result session.CloseReservation
	err := r.mutate(ctx, func(state *sessionrepository.State) error {
		var err error
		result, err = state.ReserveCloseAt(request, at)
		return err
	})
	return result, err
}
func (r *SessionRepository) GetClose(ctx context.Context, id string) (session.CloseRecord, error) {
	state, err := r.read(ctx)
	if err != nil {
		return session.CloseRecord{}, err
	}
	return state.GetClose(id)
}
func (r *SessionRepository) ListClose(ctx context.Context) ([]session.CloseRecord, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListClose(), nil
}
func (r *SessionRepository) UpdateClose(ctx context.Context, record session.CloseRecord, expected session.Status) error {
	return r.mutate(ctx, func(state *sessionrepository.State) error { return state.UpdateCloseAt(record, expected) })
}
func (r *SessionRepository) UpdateOpen(ctx context.Context, record session.Record, expected session.Status) error {
	return r.UpdateOpenAt(ctx, record, expected, time.Now().UTC())
}
func (r *SessionRepository) UpdateOpenAt(ctx context.Context, record session.Record, expected session.Status, now time.Time) error {
	return r.mutate(ctx, func(state *sessionrepository.State) error { return state.UpdateOpenAt(record, expected, now) })
}
func (r *SessionRepository) PutSandboxAuthority(ctx context.Context, authority session.SandboxAuthority) error {
	return r.mutate(ctx, func(state *sessionrepository.State) error { return state.PutSandboxAuthority(authority) })
}
func (r *SessionRepository) SynchronizeSandboxAuthority(ctx context.Context, authority session.SandboxAuthority) error {
	return r.mutate(ctx, func(state *sessionrepository.State) error { return state.SynchronizeSandboxAuthority(authority) })
}
func (r *SessionRepository) ReplaceSandboxAuthority(ctx context.Context, authority session.SandboxAuthority, expected, fence int64) error {
	return r.mutate(ctx, func(state *sessionrepository.State) error {
		return state.ReplaceSandboxAuthority(authority, expected, fence)
	})
}
func (r *SessionRepository) GetSandboxAuthority(ctx context.Context, id string) (session.SandboxAuthority, error) {
	state, err := r.read(ctx)
	if err != nil {
		return session.SandboxAuthority{}, err
	}
	return state.GetSandboxAuthority(id)
}
func (r *SessionRepository) Close() error { return nil }

var _ sessionrepository.Repository = (*SessionRepository)(nil)
