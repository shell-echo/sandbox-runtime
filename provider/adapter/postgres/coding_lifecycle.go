package providerpostgres

import (
	"context"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

// CodingLifecycleRepository binds normal lifecycle reads and the first-create
// permit to the same Provider Store. It is an offline composition primitive;
// production v3 remains unavailable until the complete Profile v2 and
// restricted control/receipt path are composed and gated.
type CodingLifecycleRepository struct {
	*LifecycleRepository
	bound      *CodingBoundCreateRepository
	specBySlot map[string]string
}

func NewCodingLifecycleRepository(store *Store, plan codingidentity.Plan,
	specBySlot map[string]string) (*CodingLifecycleRepository, error) {
	if len(specBySlot) != codingidentity.LocalCandidateCapacity || plan.Capacity != codingidentity.LocalCandidateCapacity {
		return nil, codingidentity.ErrInvalidPlan
	}
	bound, err := NewCodingBoundCreateRepository(store, plan)
	if err != nil {
		return nil, err
	}
	lifecycleRepo, err := NewLifecycleRepository(store)
	if err != nil {
		return nil, err
	}
	frozen := make(map[string]string, len(specBySlot))
	for _, slot := range plan.Slots {
		spec, exists := specBySlot[slot.ID]
		if !exists || lifecycle.ValidateDigest(spec) != nil {
			return nil, codingidentity.ErrInvalidPlan
		}
		frozen[slot.ID] = spec
	}
	return &CodingLifecycleRepository{LifecycleRepository: lifecycleRepo, bound: bound, specBySlot: frozen}, nil
}

func NewCodingLifecycleRepositoryWithPolicy(store *Store, plan codingidentity.Plan,
	specBySlot map[string]string, controlPolicyDigest string) (*CodingLifecycleRepository, error) {
	repository, err := NewCodingLifecycleRepository(store, plan, specBySlot)
	if err != nil {
		return nil, err
	}
	bound, err := NewCodingBoundCreateRepositoryWithPolicy(store, plan, controlPolicyDigest)
	if err != nil {
		return nil, err
	}
	repository.bound = bound
	return repository, nil
}

func (r *CodingLifecycleRepository) InitializeCoding(ctx context.Context,
	confirmClean func(context.Context, codingidentity.Plan) error) error {
	if r == nil || r.bound == nil {
		return ErrUnavailable
	}
	return r.bound.Initialize(ctx, confirmClean)
}

func (r *CodingLifecycleRepository) InitializeCodingAtomicOriginal(ctx context.Context,
	confirmClean func(context.Context, codingidentity.Plan) error) error {
	if r == nil || r.bound == nil {
		return ErrUnavailable
	}
	return r.bound.InitializeAtomicOriginal(ctx, confirmClean)
}

func (r *CodingLifecycleRepository) BeginCodingFirstCreate(ctx context.Context, operationID string) (
	codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error,
) {
	if r == nil || r.bound == nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, ErrUnavailable
	}
	return r.bound.BeginFirstCreate(ctx, operationID, r.specBySlot)
}

func (r *CodingLifecycleRepository) BeginCodingFirstCreateWithAuthority(ctx context.Context,
	operationID string) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox,
	dockercontrol.CodingCreateAuthority, error) {
	if r == nil || r.bound == nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, ErrUnavailable
	}
	return r.bound.BeginFirstCreateWithAuthority(ctx, operationID, r.specBySlot)
}

var _ lifecyclerepository.Repository = (*CodingLifecycleRepository)(nil)
