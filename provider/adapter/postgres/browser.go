package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	browserreferencerepository "github.com/shell-echo/sandbox-runtime/provider/browser/reference/repository"
	browserrepository "github.com/shell-echo/sandbox-runtime/provider/browser/repository"
)

const (
	browserSessionsDocument   = "browser_sessions"
	browserReferencesDocument = "browser_references"
)

// BrowserRepository keeps Provider-local Browser session truth in the same
// transactional PostgreSQL authority as lifecycle and usage evidence.
type BrowserRepository struct{ store *Store }

func NewBrowserRepository(store *Store) (*BrowserRepository, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &BrowserRepository{store: store}, nil
}

func newBrowserState() browserrepository.State { return browserrepository.NewState() }
func importBrowserState(state *browserrepository.State, document json.RawMessage) error {
	var snapshot browserrepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportBrowserState(state browserrepository.State) any { return state.Export() }
func (r *BrowserRepository) mutate(ctx context.Context, mutation func(*browserrepository.State) error) error {
	return mutateState(ctx, r.store, browserSessionsDocument, newBrowserState, importBrowserState, exportBrowserState, mutation)
}
func (r *BrowserRepository) read(ctx context.Context) (browserrepository.State, error) {
	return readState(ctx, r.store, browserSessionsDocument, newBrowserState, importBrowserState)
}
func (r *BrowserRepository) ReserveOpen(ctx context.Context, request browser.OpenRequest, at time.Time) (browser.Reservation, error) {
	var result browser.Reservation
	err := r.mutate(ctx, func(state *browserrepository.State) error {
		var err error
		result, err = state.ReserveOpenAt(request, at)
		return err
	})
	return result, err
}
func (r *BrowserRepository) GetOpen(ctx context.Context, id string) (browser.Record, error) {
	return r.GetOpenAt(ctx, id, time.Now().UTC())
}
func (r *BrowserRepository) GetOpenAt(ctx context.Context, id string, now time.Time) (browser.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return browser.Record{}, err
	}
	return state.GetOpenAt(id, now)
}
func (r *BrowserRepository) ListOpen(ctx context.Context) ([]browser.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListOpen(), nil
}
func (r *BrowserRepository) AttachAllocation(ctx context.Context, receipt browser.AllocationReceipt) (browser.Reservation, error) {
	var result browser.Reservation
	err := r.mutate(ctx, func(state *browserrepository.State) error {
		var err error
		result, err = state.AttachAllocation(receipt)
		return err
	})
	return result, err
}
func (r *BrowserRepository) ObserveAllocation(ctx context.Context, id string, observation browser.AllocationEvidence) (browser.Record, error) {
	var result browser.Record
	err := r.mutate(ctx, func(state *browserrepository.State) error {
		var err error
		result, err = state.ObserveAllocation(id, observation)
		return err
	})
	return result, err
}
func (r *BrowserRepository) UpdateOpen(ctx context.Context, record browser.Record, expected browser.Status) error {
	return r.UpdateOpenAt(ctx, record, expected, time.Now().UTC())
}
func (r *BrowserRepository) UpdateOpenAt(ctx context.Context, record browser.Record, expected browser.Status, now time.Time) error {
	return r.mutate(ctx, func(state *browserrepository.State) error { return state.UpdateOpenAt(record, expected, now) })
}
func (r *BrowserRepository) SynchronizeSandboxAuthority(ctx context.Context, authority browser.SandboxAuthority) error {
	return r.mutate(ctx, func(state *browserrepository.State) error { return state.SynchronizeSandboxAuthority(authority) })
}
func (r *BrowserRepository) GetSandboxAuthority(ctx context.Context, id string) (browser.SandboxAuthority, error) {
	state, err := r.read(ctx)
	if err != nil {
		return browser.SandboxAuthority{}, err
	}
	return state.GetSandboxAuthority(id)
}
func (r *BrowserRepository) Close() error { return nil }

// BrowserReferenceStore keeps Browser handoff references under the same
// Provider-owned row lock, never in the Browser executor role process.
type BrowserReferenceStore struct{ store *Store }

func NewBrowserReferenceStore(store *Store) (*BrowserReferenceStore, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &BrowserReferenceStore{store: store}, nil
}
func newBrowserReferenceState() browserreferencerepository.State {
	return browserreferencerepository.NewState()
}
func importBrowserReferenceState(state *browserreferencerepository.State, document json.RawMessage) error {
	var snapshot browserreferencerepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportBrowserReferenceState(state browserreferencerepository.State) any { return state.Export() }
func (r *BrowserReferenceStore) mutate(ctx context.Context, mutation func(*browserreferencerepository.State) error) error {
	return mutateState(ctx, r.store, browserReferencesDocument, newBrowserReferenceState, importBrowserReferenceState, exportBrowserReferenceState, mutation)
}
func (r *BrowserReferenceStore) read(ctx context.Context) (browserreferencerepository.State, error) {
	return readState(ctx, r.store, browserReferencesDocument, newBrowserReferenceState, importBrowserReferenceState)
}
func (r *BrowserReferenceStore) Create(ctx context.Context, record reference.Record) error {
	return r.mutate(ctx, func(state *browserreferencerepository.State) error { return state.Create(record) })
}
func (r *BrowserReferenceStore) Get(ctx context.Context, value string) (reference.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return reference.Record{}, err
	}
	return state.Get(value)
}
func (r *BrowserReferenceStore) FindRunning(ctx context.Context, source browser.Record) (reference.Record, error) {
	state, err := r.read(ctx)
	if err != nil {
		return reference.Record{}, err
	}
	return state.FindRunning(source)
}
func (r *BrowserReferenceStore) Revoke(ctx context.Context, value string, at time.Time) error {
	return r.mutate(ctx, func(state *browserreferencerepository.State) error { return state.Revoke(value, at) })
}
func (r *BrowserReferenceStore) Bind(ctx context.Context, binding reference.Binding, at time.Time) error {
	if err := binding.Validate(at); err != nil {
		return err
	}
	if binding.Version != 2 {
		return reference.ErrInvalidRecord
	}
	return mutateStatePair(ctx, r.store,
		browserSessionsDocument, browserReferencesDocument,
		newBrowserState, importBrowserState, exportBrowserState,
		newBrowserReferenceState, importBrowserReferenceState, exportBrowserReferenceState,
		func(sessions *browserrepository.State, references *browserreferencerepository.State) error {
			record, err := references.Get(binding.Reference)
			if err != nil {
				return err
			}
			source, err := sessions.GetOpenAt(record.OperationID, at)
			if err != nil {
				return err
			}
			authority, err := sessions.GetSandboxAuthority(record.SandboxID)
			if err != nil {
				return err
			}
			return references.Bind(binding, source, authority, at)
		})
}

func (r *BrowserReferenceStore) ClaimExecutor(ctx context.Context, binding reference.Binding, requestID string,
	claim reference.ExecutorReplayClaim, at time.Time) error {
	if err := binding.Validate(at); err != nil {
		return err
	}
	if binding.Version != 2 {
		return reference.ErrInvalidRecord
	}
	return mutateStatePair(ctx, r.store,
		browserSessionsDocument, browserReferencesDocument,
		newBrowserState, importBrowserState, exportBrowserState,
		newBrowserReferenceState, importBrowserReferenceState, exportBrowserReferenceState,
		func(sessions *browserrepository.State, references *browserreferencerepository.State) error {
			record, err := references.Get(binding.Reference)
			if err != nil {
				return err
			}
			source, err := sessions.GetOpenAt(record.OperationID, at)
			if err != nil {
				return err
			}
			authority, err := sessions.GetSandboxAuthority(record.SandboxID)
			if err != nil {
				return err
			}
			return references.ClaimExecutor(binding, requestID, claim, source, authority, at)
		})
}

func (r *BrowserReferenceStore) BindConnection(ctx context.Context, open browserhandoffv2.OpenRequest, at time.Time) error {
	_, err := r.BindConnectionWithOwnership(ctx, open, at)
	return err
}

func (r *BrowserReferenceStore) BindConnectionWithOwnership(ctx context.Context, open browserhandoffv2.OpenRequest, at time.Time) (bool, error) {
	var created bool
	err := mutateStatePair(ctx, r.store,
		browserSessionsDocument, browserReferencesDocument,
		newBrowserState, importBrowserState, exportBrowserState,
		newBrowserReferenceState, importBrowserReferenceState, exportBrowserReferenceState,
		func(sessions *browserrepository.State, references *browserreferencerepository.State) error {
			record, err := references.Get(open.HandoffReference)
			if err != nil {
				return err
			}
			source, err := sessions.GetOpenAt(record.OperationID, at)
			if err != nil {
				return err
			}
			authority, err := sessions.GetSandboxAuthority(record.SandboxID)
			if err != nil {
				return err
			}
			var bindErr error
			created, bindErr = references.BindConnectionWithOwnership(open, source, authority, at)
			return bindErr
		})
	if err != nil {
		return false, err
	}
	return created, nil
}

func (r *BrowserReferenceStore) ReserveExecutor(ctx context.Context, open executorprotocol.Open, at time.Time) error {
	return r.mutateExecutorConnection(ctx, open, at, false)
}

func (r *BrowserReferenceStore) ClaimExecutorV2(ctx context.Context, open executorprotocol.Open, at time.Time) error {
	return r.mutateExecutorConnection(ctx, open, at, true)
}

func (r *BrowserReferenceStore) mutateExecutorConnection(ctx context.Context, open executorprotocol.Open, at time.Time, consume bool) error {
	return mutateStatePair(ctx, r.store,
		browserSessionsDocument, browserReferencesDocument,
		newBrowserState, importBrowserState, exportBrowserState,
		newBrowserReferenceState, importBrowserReferenceState, exportBrowserReferenceState,
		func(sessions *browserrepository.State, references *browserreferencerepository.State) error {
			record, err := references.Get(open.HandoffReference)
			if err != nil {
				return err
			}
			source, err := sessions.GetOpenAt(record.OperationID, at)
			if err != nil {
				return err
			}
			authority, err := sessions.GetSandboxAuthority(record.SandboxID)
			if err != nil {
				return err
			}
			if consume {
				return references.ClaimExecutorV2(open, source, authority, at)
			}
			return references.ReserveExecutor(open, source, authority, at)
		})
}

func (r *BrowserReferenceStore) CloseConnection(ctx context.Context, referenceValue, epoch, authorityDigest string) error {
	return r.mutate(ctx, func(state *browserreferencerepository.State) error {
		return state.CloseConnection(referenceValue, epoch, authorityDigest)
	})
}

var _ browserrepository.Repository = (*BrowserRepository)(nil)
var _ reference.Store = (*BrowserReferenceStore)(nil)
var _ reference.BindingStore = (*BrowserReferenceStore)(nil)
