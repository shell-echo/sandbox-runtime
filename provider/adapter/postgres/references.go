package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
	desktopreferencerepository "github.com/shell-echo/sandbox-runtime/provider/desktop/reference/repository"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
	sessionreferencerepository "github.com/shell-echo/sandbox-runtime/provider/session/reference/repository"
)

type SessionReferenceStore struct{ store *Store }

func NewSessionReferenceStore(store *Store) (*SessionReferenceStore, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &SessionReferenceStore{store: store}, nil
}
func newSessionReferenceState() sessionreferencerepository.State {
	return sessionreferencerepository.NewState()
}
func importSessionReferenceState(state *sessionreferencerepository.State, document json.RawMessage) error {
	var snapshot sessionreferencerepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportSessionReferenceState(state sessionreferencerepository.State) any { return state.Export() }
func (r *SessionReferenceStore) mutate(ctx context.Context, mutation func(*sessionreferencerepository.State) error) error {
	return mutateState(ctx, r.store, "terminal_references", newSessionReferenceState, importSessionReferenceState, exportSessionReferenceState, mutation)
}
func (r *SessionReferenceStore) read(ctx context.Context) (sessionreferencerepository.State, error) {
	return readState(ctx, r.store, "terminal_references", newSessionReferenceState, importSessionReferenceState)
}
func (r *SessionReferenceStore) Create(ctx context.Context, record sessionreference.Record) error {
	return r.mutate(ctx, func(state *sessionreferencerepository.State) error { return state.Create(record) })
}
func (r *SessionReferenceStore) Get(ctx context.Context, value string) (sessionreference.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return sessionreference.Record{}, err
	}
	return state.Get(value)
}
func (r *SessionReferenceStore) FindRunning(ctx context.Context, source session.Record) (sessionreference.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return sessionreference.Record{}, err
	}
	return state.FindRunning(source)
}
func (r *SessionReferenceStore) Revoke(ctx context.Context, value string, at time.Time) error {
	return r.mutate(ctx, func(state *sessionreferencerepository.State) error { return state.Revoke(value, at) })
}

type DesktopReferenceStore struct{ store *Store }

func NewDesktopReferenceStore(store *Store) (*DesktopReferenceStore, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &DesktopReferenceStore{store: store}, nil
}
func newDesktopReferenceState() desktopreferencerepository.State {
	return desktopreferencerepository.NewState()
}
func importDesktopReferenceState(state *desktopreferencerepository.State, document json.RawMessage) error {
	var snapshot desktopreferencerepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportDesktopReferenceState(state desktopreferencerepository.State) any { return state.Export() }
func (r *DesktopReferenceStore) mutate(ctx context.Context, mutation func(*desktopreferencerepository.State) error) error {
	return mutateState(ctx, r.store, "desktop_references", newDesktopReferenceState, importDesktopReferenceState, exportDesktopReferenceState, mutation)
}
func (r *DesktopReferenceStore) read(ctx context.Context) (desktopreferencerepository.State, error) {
	return readState(ctx, r.store, "desktop_references", newDesktopReferenceState, importDesktopReferenceState)
}
func (r *DesktopReferenceStore) Create(ctx context.Context, record desktopreference.Record) error {
	return r.mutate(ctx, func(state *desktopreferencerepository.State) error { return state.Create(record) })
}
func (r *DesktopReferenceStore) Get(ctx context.Context, value string) (desktopreference.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return desktopreference.Record{}, err
	}
	return state.Get(value)
}
func (r *DesktopReferenceStore) FindRunning(ctx context.Context, source desktop.Record) (desktopreference.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return desktopreference.Record{}, err
	}
	return state.FindRunning(source)
}
func (r *DesktopReferenceStore) Revoke(ctx context.Context, value string, at time.Time) error {
	return r.mutate(ctx, func(state *desktopreferencerepository.State) error { return state.Revoke(value, at) })
}

var _ sessionreference.Store = (*SessionReferenceStore)(nil)
var _ desktopreference.Store = (*DesktopReferenceStore)(nil)
