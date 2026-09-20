package providerpostgres

import (
	"context"
	"encoding/json"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

const lifecycleDocument = "lifecycle"

type LifecycleRepository struct{ store *Store }

func NewLifecycleRepository(store *Store) (*LifecycleRepository, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &LifecycleRepository{store: store}, nil
}

func newLifecycleState() lifecyclerepository.State { return lifecyclerepository.NewState() }
func importLifecycleState(state *lifecyclerepository.State, document json.RawMessage) error {
	var snapshot lifecyclerepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportLifecycleState(state lifecyclerepository.State) any { return state.Export() }

func (r *LifecycleRepository) mutate(ctx context.Context, mutation func(*lifecyclerepository.State) error) error {
	return mutateState(ctx, r.store, lifecycleDocument, newLifecycleState, importLifecycleState, exportLifecycleState, mutation)
}
func (r *LifecycleRepository) read(ctx context.Context) (lifecyclerepository.State, error) {
	return readState(ctx, r.store, lifecycleDocument, newLifecycleState, importLifecycleState)
}

func (r *LifecycleRepository) ReserveCreate(ctx context.Context, key, digest string, sandbox lifecycle.Sandbox, operation lifecycle.Operation) (lifecyclerepository.CreateResult, error) {
	var result lifecyclerepository.CreateResult
	err := r.mutate(ctx, func(state *lifecyclerepository.State) error {
		var err error
		result, err = state.ReserveCreate(key, digest, sandbox, operation)
		return err
	})
	return result, err
}

func (r *LifecycleRepository) ReserveMutation(ctx context.Context, key, digest string, expected uint64, sandbox lifecycle.Sandbox, operation lifecycle.Operation, event lifecycle.Event) (lifecyclerepository.MutationResult, error) {
	var result lifecyclerepository.MutationResult
	err := r.mutate(ctx, func(state *lifecyclerepository.State) error {
		var err error
		result, err = state.ReserveMutation(key, digest, expected, sandbox, operation, event)
		return err
	})
	return result, err
}

func (r *LifecycleRepository) GetSandbox(ctx context.Context, id string) (lifecycle.Sandbox, error) {
	state, err := r.read(ctx)
	if err != nil {
		return lifecycle.Sandbox{}, err
	}
	return state.GetSandbox(id)
}
func (r *LifecycleRepository) ListSandboxes(ctx context.Context) ([]lifecycle.Sandbox, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListSandboxes(), nil
}
func (r *LifecycleRepository) UpdateSandbox(ctx context.Context, sandbox lifecycle.Sandbox, expected, fence uint64) error {
	return r.mutate(ctx, func(state *lifecyclerepository.State) error { return state.UpdateSandbox(sandbox, expected, fence) })
}
func (r *LifecycleRepository) GetOperation(ctx context.Context, id string) (lifecycle.Operation, error) {
	state, err := r.read(ctx)
	if err != nil {
		return lifecycle.Operation{}, err
	}
	return state.GetOperation(id)
}
func (r *LifecycleRepository) ListOperations(ctx context.Context) ([]lifecycle.Operation, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListOperations(), nil
}
func (r *LifecycleRepository) UpdateOperation(ctx context.Context, operation lifecycle.Operation) error {
	return r.mutate(ctx, func(state *lifecyclerepository.State) error { return state.UpdateOperation(operation) })
}
func (r *LifecycleRepository) GetLease(ctx context.Context, id string) (lifecycle.Lease, error) {
	state, err := r.read(ctx)
	if err != nil {
		return lifecycle.Lease{}, err
	}
	return state.GetLease(id)
}
func (r *LifecycleRepository) ReplaceLease(ctx context.Context, lease lifecycle.Lease, fence uint64) error {
	return r.mutate(ctx, func(state *lifecyclerepository.State) error { return state.ReplaceLease(lease, fence) })
}
func (r *LifecycleRepository) AppendEvent(ctx context.Context, event lifecycle.Event) (lifecycle.Event, error) {
	var result lifecycle.Event
	err := r.mutate(ctx, func(state *lifecyclerepository.State) error {
		var err error
		result, err = state.AppendEvent(event)
		return err
	})
	return result, err
}
func (r *LifecycleRepository) ListEvents(ctx context.Context, sandboxID string, after uint64, limit int) ([]lifecycle.Event, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListEvents(sandboxID, after, limit)
}
func (r *LifecycleRepository) ReadEvents(ctx context.Context, sandboxID string, after uint64, limit int) (lifecyclerepository.EventPage, error) {
	state, err := r.read(ctx)
	if err != nil {
		return lifecyclerepository.EventPage{}, err
	}
	return state.ReadEvents(sandboxID, after, limit)
}
func (r *LifecycleRepository) Close() error { return nil }

var _ lifecyclerepository.Repository = (*LifecycleRepository)(nil)
