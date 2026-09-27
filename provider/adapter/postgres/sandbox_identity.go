package providerpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
)

type identityMarker struct {
	Initialized bool   `json:"initialized"`
	PlanDigest  string `json:"plan_digest"`
}

// SandboxIdentityRepository manages only one Provider's statically disjoint
// slot pool. It reuses the existing Provider control_state transaction; no
// Docker operation runs while that global PostgreSQL row is locked. The
// constructor is not deployment authorization: composition must project the
// complete trusted profile and verify the exact owner/controller DB authority.
type SandboxIdentityRepository struct {
	store     *Store
	plan      sandboxidentity.Plan
	stateKey  string
	markerKey string
	digest    string
}

func NewSandboxIdentityRepository(ctx context.Context, store *Store, plan sandboxidentity.Plan) (*SandboxIdentityRepository, error) {
	if ctx == nil || store == nil || store.pool == nil {
		return nil, ErrUnavailable
	}
	digest, err := plan.Digest()
	if err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var database, role, sessionRole string
	if err := store.pool.QueryRow(operation, `SELECT current_database(),current_user,session_user`).Scan(&database, &role, &sessionRole); err != nil ||
		database != plan.DatabaseName || role != plan.RuntimeRole || sessionRole != plan.RuntimeRole {
		return nil, ErrUnavailable
	}
	plan.Slots = slices.Clone(plan.Slots)
	suffix := "browser"
	if plan.OwnerDeployment == "provider-desktop-runtime" {
		suffix = "desktop"
	}
	return &SandboxIdentityRepository{store: store, plan: plan, digest: digest,
		stateKey: "sandbox_identity_" + suffix + "_state", markerKey: "sandbox_identity_" + suffix + "_marker"}, nil
}

func importIdentityState(state *sandboxidentity.State, document json.RawMessage) error {
	var decoded sandboxidentity.State
	if decodePersisted(&decoded, document) != nil {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrCorrupt
	}
	*state = decoded
	return nil
}

func importIdentityMarker(marker *identityMarker, document json.RawMessage) error {
	var decoded identityMarker
	if decodePersisted(&decoded, document) != nil {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrCorrupt
	}
	*marker = decoded
	return nil
}

func (r *SandboxIdentityRepository) mutate(ctx context.Context, action func(*sandboxidentity.State) error) error {
	if r == nil || action == nil {
		return ErrUnavailable
	}
	return mutateStatePair(ctx, r.store,
		r.markerKey, r.stateKey,
		func() identityMarker { return identityMarker{} }, importIdentityMarker, func(marker identityMarker) any { return marker },
		func() sandboxidentity.State { return sandboxidentity.State{} }, importIdentityState, func(state sandboxidentity.State) any { return state },
		func(marker *identityMarker, state *sandboxidentity.State) error {
			if !marker.Initialized || marker.PlanDigest != r.digest || state.Validate(r.plan) != nil {
				return sandboxidentity.ErrUninitialized
			}
			return action(state)
		})
}

// Initialize is an explicit bootstrap operation, never an automatic missing-
// key fallback. confirmClean must establish that this is a new authority with
// no run-owned sandbox/gateway/network/session resources; it runs before the
// transaction and must not be a synthetic assertion in production.
func (r *SandboxIdentityRepository) Initialize(ctx context.Context, confirmClean func(context.Context, sandboxidentity.Plan) error) error {
	if r == nil || ctx == nil || confirmClean == nil {
		return ErrUnavailable
	}
	if err := confirmClean(ctx, r.plan); err != nil {
		return err
	}
	return mutateStatePair(ctx, r.store,
		r.markerKey, r.stateKey,
		func() identityMarker { return identityMarker{} }, importIdentityMarker, func(marker identityMarker) any { return marker },
		func() sandboxidentity.State { return sandboxidentity.State{} }, importIdentityState, func(state sandboxidentity.State) any { return state },
		func(marker *identityMarker, state *sandboxidentity.State) error {
			if marker.Initialized || state.Initialized {
				return sandboxidentity.ErrConflict
			}
			if *marker != (identityMarker{}) || state.Version != 0 || state.PlanDigest != "" || state.Reservations != nil {
				return sandboxidentity.ErrInvalidState
			}
			fresh, err := sandboxidentity.NewState(r.plan)
			if err != nil {
				return err
			}
			*marker = identityMarker{Initialized: true, PlanDigest: r.digest}
			*state = fresh
			return nil
		})
}

func (r *SandboxIdentityRepository) Reserve(ctx context.Context, claim sandboxidentity.Claim, specBySlot map[string]string) (sandboxidentity.Reservation, error) {
	var result sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State) error {
		var reserveErr error
		result, reserveErr = state.Reserve(r.plan, claim, specBySlot)
		return reserveErr
	})
	return result, err
}

func (r *SandboxIdentityRepository) BeginCreate(ctx context.Context, reservation sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	return r.transition(ctx, func(state *sandboxidentity.State) (sandboxidentity.Reservation, error) {
		return state.BeginCreate(r.plan, reservation)
	})
}

func (r *SandboxIdentityRepository) CompleteCreate(ctx context.Context, reservation sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	return r.transition(ctx, func(state *sandboxidentity.State) (sandboxidentity.Reservation, error) {
		return state.CompleteCreate(r.plan, reservation)
	})
}

func (r *SandboxIdentityRepository) BeginCleanup(ctx context.Context, reservation sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	return r.transition(ctx, func(state *sandboxidentity.State) (sandboxidentity.Reservation, error) {
		return state.BeginCleanup(r.plan, reservation)
	})
}

func (r *SandboxIdentityRepository) transition(ctx context.Context,
	action func(*sandboxidentity.State) (sandboxidentity.Reservation, error)) (sandboxidentity.Reservation, error) {
	var result sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State) error {
		var transitionErr error
		result, transitionErr = action(state)
		return transitionErr
	})
	return result, err
}

func (r *SandboxIdentityRepository) Reservations(ctx context.Context) ([]sandboxidentity.Reservation, error) {
	if r == nil {
		return nil, ErrUnavailable
	}
	marker, err := readState(ctx, r.store, r.markerKey, func() identityMarker { return identityMarker{} }, importIdentityMarker)
	if err != nil {
		return nil, err
	}
	state, err := readState(ctx, r.store, r.stateKey, func() sandboxidentity.State { return sandboxidentity.State{} }, importIdentityState)
	if err != nil {
		return nil, err
	}
	if !marker.Initialized || marker.PlanDigest != r.digest || state.Validate(r.plan) != nil {
		return nil, sandboxidentity.ErrUninitialized
	}
	return slices.Clone(state.Reservations), nil
}

// CompleteCleanup never performs Docker I/O under the global control_state
// row lock. The caller must supply a real, exact-resource absence checker.
// Cleaning state fences new creates while this checker runs; a stale ticket
// cannot release a slot reallocated by another process.
func (r *SandboxIdentityRepository) CompleteCleanup(ctx context.Context, ticket sandboxidentity.Reservation,
	confirmAbsent func(context.Context, sandboxidentity.Reservation) error) error {
	if r == nil || confirmAbsent == nil || ticket.Status != sandboxidentity.Cleaning {
		return sandboxidentity.ErrInvalidState
	}
	reservations, err := r.Reservations(ctx)
	if err != nil {
		return err
	}
	if !slices.Contains(reservations, ticket) {
		return sandboxidentity.ErrConflict
	}
	if err := confirmAbsent(ctx, ticket); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.mutate(ctx, func(state *sandboxidentity.State) error {
		return state.CompleteCleanup(r.plan, ticket)
	})
}

func (r *SandboxIdentityRepository) Plan() sandboxidentity.Plan {
	if r == nil {
		return sandboxidentity.Plan{}
	}
	plan := r.plan
	plan.Slots = slices.Clone(plan.Slots)
	return plan
}
