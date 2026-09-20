package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	execrepository "github.com/shell-echo/sandbox-runtime/provider/exec/repository"
)

const execDocument = "exec"

type ExecRepository struct{ store *Store }

func NewExecRepository(store *Store) (*ExecRepository, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &ExecRepository{store: store}, nil
}
func newExecState() execrepository.State { return execrepository.NewState() }
func importExecState(state *execrepository.State, document json.RawMessage) error {
	var snapshot execrepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportExecState(state execrepository.State) any { return state.Export() }
func (r *ExecRepository) mutate(ctx context.Context, mutation func(*execrepository.State) error) error {
	return mutateState(ctx, r.store, execDocument, newExecState, importExecState, exportExecState, mutation)
}
func (r *ExecRepository) read(ctx context.Context) (execrepository.State, error) {
	return readState(ctx, r.store, execDocument, newExecState, importExecState)
}
func (r *ExecRepository) ReserveExecution(ctx context.Context, request providerexec.Request, dispatch ...providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	acceptedAt := time.Now().UTC()
	if len(dispatch) == 1 {
		acceptedAt = dispatch[0].AcceptedAt
	}
	return r.ReserveExecutionAt(ctx, request, acceptedAt, dispatch...)
}
func (r *ExecRepository) ReserveExecutionAt(ctx context.Context, request providerexec.Request, acceptedAt time.Time, dispatch ...providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	var result providerexec.ExecutionReservation
	err := r.mutate(ctx, func(state *execrepository.State) error {
		var err error
		result, err = state.ReserveExecutionAt(request, acceptedAt, dispatch...)
		return err
	})
	return result, err
}
func (r *ExecRepository) AttachExecution(ctx context.Context, attachment providerexec.ExecutionAttachment) (providerexec.ExecutionReservation, error) {
	var result providerexec.ExecutionReservation
	err := r.mutate(ctx, func(state *execrepository.State) error {
		var err error
		result, err = state.AttachExecution(attachment)
		return err
	})
	return result, err
}
func (r *ExecRepository) GetExecution(ctx context.Context, id string) (providerexec.ExecutionRecord, error) {
	state, err := r.read(ctx)
	if err != nil {
		return providerexec.ExecutionRecord{}, err
	}
	return state.GetExecution(id)
}
func (r *ExecRepository) ListExecutions(ctx context.Context) ([]providerexec.ExecutionRecord, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListExecutions(), nil
}
func (r *ExecRepository) ReserveCancellation(ctx context.Context, intent providerexec.CancellationIntent) (providerexec.CancellationReservation, error) {
	return r.ReserveCancellationAt(ctx, intent, time.Now().UTC())
}
func (r *ExecRepository) ReserveCancellationAt(ctx context.Context, intent providerexec.CancellationIntent, at time.Time) (providerexec.CancellationReservation, error) {
	var result providerexec.CancellationReservation
	err := r.mutate(ctx, func(state *execrepository.State) error {
		var err error
		result, err = state.ReserveCancellation(intent, at)
		return err
	})
	return result, err
}
func (r *ExecRepository) GetCancellation(ctx context.Context, id string) (providerexec.CancellationIntent, error) {
	state, err := r.read(ctx)
	if err != nil {
		return providerexec.CancellationIntent{}, err
	}
	return state.GetCancellation(id)
}
func (r *ExecRepository) GetCancellationReservation(ctx context.Context, id string) (providerexec.CancellationReservation, error) {
	state, err := r.read(ctx)
	if err != nil {
		return providerexec.CancellationReservation{}, err
	}
	return state.GetCancellationReservation(id)
}
func (r *ExecRepository) StoreResult(ctx context.Context, result providerexec.Result) error {
	return r.mutate(ctx, func(state *execrepository.State) error { return state.StoreResult(result) })
}
func (r *ExecRepository) GetResult(ctx context.Context, id string, now time.Time) (providerexec.Result, error) {
	state, err := r.read(ctx)
	if err != nil {
		return providerexec.Result{}, err
	}
	result, readErr, _ := state.ReadResult(id, now.UTC())
	return result, readErr
}
func (r *ExecRepository) Close() error { return nil }

var _ execrepository.Repository = (*ExecRepository)(nil)
