package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	artifactrepository "github.com/shell-echo/sandbox-runtime/provider/artifact/repository"
)

const artifactDocument = "artifacts"

type ArtifactRepository struct{ store *Store }

func NewArtifactRepository(store *Store) (*ArtifactRepository, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return &ArtifactRepository{store: store}, nil
}
func newArtifactState() artifactrepository.State { return artifactrepository.NewState() }
func importArtifactState(state *artifactrepository.State, document json.RawMessage) error {
	var snapshot artifactrepository.PersistedState
	if err := decodePersisted(&snapshot, document); err != nil {
		return err
	}
	return state.Import(snapshot)
}
func exportArtifactState(state artifactrepository.State) any { return state.Export() }
func (r *ArtifactRepository) mutate(ctx context.Context, mutation func(*artifactrepository.State) error) error {
	return mutateState(ctx, r.store, artifactDocument, newArtifactState, importArtifactState, exportArtifactState, mutation)
}
func (r *ArtifactRepository) read(ctx context.Context) (artifactrepository.State, error) {
	return readState(ctx, r.store, artifactDocument, newArtifactState, importArtifactState)
}
func (r *ArtifactRepository) ReserveStage(ctx context.Context, request artifact.Request, at time.Time) (artifact.Reservation, error) {
	var result artifact.Reservation
	err := r.mutate(ctx, func(state *artifactrepository.State) error {
		var err error
		result, err = state.ReserveStageAt(request, at)
		return err
	})
	return result, err
}
func (r *ArtifactRepository) GetStage(ctx context.Context, id string) (artifact.Operation, error) {
	state, err := r.read(ctx)
	if err != nil {
		return artifact.Operation{}, err
	}
	return state.GetStage(id)
}
func (r *ArtifactRepository) ListStages(ctx context.Context) ([]artifact.Operation, error) {
	state, err := r.read(ctx)
	if err != nil {
		return nil, err
	}
	return state.ListStages()
}
func (r *ArtifactRepository) UpdateStage(ctx context.Context, operation artifact.Operation, expected artifact.OperationStatus) error {
	return r.mutate(ctx, func(state *artifactrepository.State) error { return state.UpdateStage(operation, expected) })
}
func (r *ArtifactRepository) GetEvidence(ctx context.Context, id string, now time.Time) (artifact.Evidence, error) {
	state, err := r.read(ctx)
	if err != nil {
		return artifact.Evidence{}, err
	}
	evidence, readErr, _ := state.ReadEvidenceAt(id, now)
	return evidence, readErr
}
func (r *ArtifactRepository) PutSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority) error {
	return r.mutate(ctx, func(state *artifactrepository.State) error { return state.PutSandboxAuthority(authority) })
}
func (r *ArtifactRepository) ReplaceSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority, expected, fence int64) error {
	return r.mutate(ctx, func(state *artifactrepository.State) error {
		return state.ReplaceSandboxAuthority(authority, expected, fence)
	})
}
func (r *ArtifactRepository) SynchronizeSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority) error {
	return r.mutate(ctx, func(state *artifactrepository.State) error { return state.SynchronizeSandboxAuthority(authority) })
}
func (r *ArtifactRepository) GetSandboxAuthority(ctx context.Context, id string) (artifact.SandboxAuthority, error) {
	state, err := r.read(ctx)
	if err != nil {
		return artifact.SandboxAuthority{}, err
	}
	return state.GetSandboxAuthority(id)
}
func (r *ArtifactRepository) Close() error { return nil }

var _ artifactrepository.Repository = (*ArtifactRepository)(nil)
