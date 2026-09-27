package providerpostgres

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

// DesktopBoundIdentityRepository is the Provider-owned finite UID authority.
// All first-dispatch and retirement decisions lock the existing Desktop
// session document with the slot pool; Close refers only to its source Open.
type DesktopBoundIdentityRepository struct {
	identity *SandboxIdentityRepository
}

func NewDesktopBoundIdentityRepository(ctx context.Context, store *Store,
	plan sandboxidentity.Plan) (*DesktopBoundIdentityRepository, error) {
	if plan.OwnerDeployment != "provider-desktop-runtime" {
		return nil, sandboxidentity.ErrInvalidPlan
	}
	identity, err := NewSandboxIdentityRepository(ctx, store, plan)
	if err != nil {
		return nil, err
	}
	return &DesktopBoundIdentityRepository{identity: identity}, nil
}

func (r *DesktopBoundIdentityRepository) Plan() sandboxidentity.Plan {
	if r == nil || r.identity == nil {
		return sandboxidentity.Plan{}
	}
	return r.identity.Plan()
}

func (r *DesktopBoundIdentityRepository) Initialize(ctx context.Context,
	confirmClean func(context.Context, sandboxidentity.Plan) error) error {
	if r == nil || r.identity == nil {
		return ErrUnavailable
	}
	return r.identity.Initialize(ctx, confirmClean)
}

func (r *DesktopBoundIdentityRepository) Reservations(ctx context.Context) ([]sandboxidentity.Reservation, error) {
	if r == nil || r.identity == nil {
		return nil, ErrUnavailable
	}
	return r.identity.Reservations(ctx)
}

func (r *DesktopBoundIdentityRepository) mutate(ctx context.Context,
	action func(*sandboxidentity.State, *desktoprepository.State) error) error {
	if r == nil || r.identity == nil || action == nil {
		return ErrUnavailable
	}
	owner := r.identity
	return mutateStateTriple(ctx, owner.store,
		owner.markerKey, owner.stateKey, desktopDocument,
		func() identityMarker { return identityMarker{} }, importIdentityMarker,
		func(marker identityMarker) any { return marker },
		func() sandboxidentity.State { return sandboxidentity.State{} }, importIdentityState,
		func(state sandboxidentity.State) any { return state },
		newDesktopState, importDesktopState, exportDesktopState,
		func(marker *identityMarker, state *sandboxidentity.State, sessions *desktoprepository.State) error {
			if !marker.Initialized || marker.PlanDigest != owner.digest || state.Validate(owner.plan) != nil {
				return sandboxidentity.ErrUninitialized
			}
			return action(state, sessions)
		})
}

func desktopAllocationClaim(allocation desktop.Allocation) sandboxidentity.Claim {
	request := allocation.Request
	return sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.DesktopSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		RequestDigest: request.RequestDigest, Generation: request.ExpectedGeneration,
		Fence: request.FencingToken}
}

func desktopClaimMatchesRecord(claim sandboxidentity.Claim, record desktop.Record) bool {
	request := record.Request
	return claim.SandboxID == request.SandboxID && claim.SessionID == request.DesktopSessionID &&
		claim.OperationID == request.OperationID && claim.AttemptID == request.AttemptID &&
		claim.RequestDigest == request.RequestDigest && claim.Generation == request.ExpectedGeneration &&
		claim.Fence == request.FencingToken
}

func (r *DesktopBoundIdentityRepository) ReserveAuthorized(ctx context.Context,
	allocation desktop.Allocation, specs map[string]string) (sandboxidentity.Reservation, error) {
	if allocation.Validate() != nil {
		return sandboxidentity.Reservation{}, desktop.ErrInvalidRequest
	}
	var ticket sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *desktoprepository.State) error {
		var reserveErr error
		ticket, reserveErr = state.Reserve(r.identity.plan, desktopAllocationClaim(allocation), specs)
		if reserveErr != nil {
			return reserveErr
		}
		now := time.Now().UTC()
		switch ticket.Status {
		case sandboxidentity.Reserved, sandboxidentity.Creating:
			return sessions.AuthorizeIdentityCreate(allocation, now)
		case sandboxidentity.Active:
			return sessions.AuthorizeIdentityRecovery(allocation, now)
		default:
			return sandboxidentity.ErrInProgress
		}
	})
	return ticket, err
}

func (r *DesktopBoundIdentityRepository) BeginCreateAuthorized(ctx context.Context,
	allocation desktop.Allocation, ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	if allocation.Validate() != nil || ticket.Claim != desktopAllocationClaim(allocation) {
		return sandboxidentity.Reservation{}, desktop.ErrInvalidRequest
	}
	var creating sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *desktoprepository.State) error {
		if err := sessions.AuthorizeIdentityCreate(allocation, time.Now().UTC()); err != nil {
			return err
		}
		var err error
		creating, err = state.BeginCreate(r.identity.plan, ticket)
		return err
	})
	return creating, err
}

func (r *DesktopBoundIdentityRepository) CompleteCreate(ctx context.Context,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	if ticket.Status != sandboxidentity.Creating {
		return sandboxidentity.Reservation{}, sandboxidentity.ErrInvalidState
	}
	var active sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *desktoprepository.State) error {
		record, ok := sessions.Sessions[ticket.Claim.OperationID]
		if !ok || record.Validate() != nil || !desktopClaimMatchesRecord(ticket.Claim, record) ||
			sessions.Retirements[ticket.Claim.OperationID].Ticket.Claim.OperationID != "" {
			return desktoprepository.ErrConflict
		}
		var err error
		active, err = state.CompleteCreate(r.identity.plan, ticket)
		return err
	})
	return active, err
}

// BeginCleanupAuthorized never takes the Close operation's claim as a new
// identity. It verifies the persisted Close's source Open and exact receipt.
// An empty closeOperationID is only for a terminal Open that never reached a
// normal Close operation.
func (r *DesktopBoundIdentityRepository) BeginCleanupAuthorized(ctx context.Context,
	receipt desktop.AllocationReceipt, ticket sandboxidentity.Reservation,
	closeOperationID string) (sandboxidentity.Reservation, error) {
	if receipt.Validate() != nil || ticket.Claim.OperationID != receipt.OperationID ||
		ticket.Claim.SessionID != receipt.DesktopSessionID || ticket.Claim.SandboxID != receipt.SandboxID ||
		ticket.Claim.AttemptID != receipt.AttemptID || ticket.Claim.Generation != receipt.ExpectedGeneration ||
		ticket.Claim.Fence != receipt.FencingToken {
		return sandboxidentity.Reservation{}, desktop.ErrDesktopConflict
	}
	var cleaning sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *desktoprepository.State) error {
		source, ok := sessions.Sessions[ticket.Claim.OperationID]
		if !ok || source.Validate() != nil || !desktopClaimMatchesRecord(ticket.Claim, source) {
			return desktoprepository.ErrConflict
		}
		if closeOperationID == "" {
			if source.Status != desktop.StatusFailed && source.Status != desktop.StatusCancelled &&
				source.Status != desktop.StatusOutcomeUnknown {
				return desktoprepository.ErrConflict
			}
		} else {
			close, exists := sessions.Closes[closeOperationID]
			if !exists || close.Validate() != nil || close.SourceOpenOperationID != source.Request.OperationID ||
				close.Receipt != receipt || source.Allocation == nil || source.Allocation.Receipt != receipt ||
				source.RevokedAt == nil {
				return desktoprepository.ErrConflict
			}
		}
		var err error
		cleaning, err = state.BeginCleanup(r.identity.plan, ticket)
		if err != nil {
			return err
		}
		return sessions.RetireIdentity(cleaning, receipt)
	})
	return cleaning, err
}

func (r *DesktopBoundIdentityRepository) CompleteCleanupAuthorized(ctx context.Context,
	ticket sandboxidentity.Reservation, confirmAbsent func(context.Context, sandboxidentity.Reservation) error) error {
	if r == nil || ticket.Status != sandboxidentity.Cleaning || confirmAbsent == nil {
		return sandboxidentity.ErrInvalidState
	}
	if err := confirmAbsent(ctx, ticket); err != nil {
		return err
	}
	return r.mutate(ctx, func(state *sandboxidentity.State, sessions *desktoprepository.State) error {
		if !sessions.IdentityRetired(ticket) {
			return desktoprepository.ErrConflict
		}
		if err := state.CompleteCleanup(r.identity.plan, ticket); err != nil {
			return err
		}
		return sessions.ReleaseIdentity(ticket)
	})
}

func (r *DesktopBoundIdentityRepository) CompletedRetirement(ctx context.Context,
	receipt desktop.AllocationReceipt) (sandboxidentity.Reservation, error) {
	if r == nil || r.identity == nil || ctx == nil || receipt.Validate() != nil {
		return sandboxidentity.Reservation{}, ErrUnavailable
	}
	sessions, err := readState(ctx, r.identity.store, desktopDocument, newDesktopState, importDesktopState)
	if err != nil {
		return sandboxidentity.Reservation{}, err
	}
	return sessions.CompletedIdentityRetirement(receipt)
}

// RetireUnallocated releases only a terminal Open still holding a Reserved
// ticket. This same row lock excludes BeginCreate's first-side-effect permit.
func (r *DesktopBoundIdentityRepository) RetireUnallocated(ctx context.Context, record desktop.Record) error {
	if record.Validate() != nil || record.Allocation != nil ||
		(record.Status != desktop.StatusFailed && record.Status != desktop.StatusCancelled) {
		return desktop.ErrInvalidRecord
	}
	claim := sandboxidentity.Claim{SandboxID: record.Request.SandboxID,
		SessionID: record.Request.DesktopSessionID, OperationID: record.Request.OperationID,
		AttemptID: record.Request.AttemptID, RequestDigest: record.Request.RequestDigest,
		Generation: record.Request.ExpectedGeneration, Fence: record.Request.FencingToken}
	return r.mutate(ctx, func(state *sandboxidentity.State, sessions *desktoprepository.State) error {
		stored, ok := sessions.Sessions[claim.OperationID]
		if !ok || stored.Validate() != nil || stored.Allocation != nil || stored.Status != record.Status ||
			!desktopClaimMatchesRecord(claim, stored) ||
			stored.Request.ProviderRevisionID != record.Request.ProviderRevisionID ||
			stored.Request.IdempotencyKey != record.Request.IdempotencyKey ||
			stored.Request.CapabilityProfileID != record.Request.CapabilityProfileID ||
			!stored.Request.Deadline.Equal(record.Request.Deadline) ||
			!stored.Request.ExpiresAt.Equal(record.Request.ExpiresAt) ||
			!stored.AcceptedAt.Equal(record.AcceptedAt) {
			return desktoprepository.ErrConflict
		}
		for _, ticket := range state.Reservations {
			if ticket.Claim.OperationID != claim.OperationID && ticket.Claim.SandboxID != claim.SandboxID {
				continue
			}
			if ticket.Claim != claim {
				return sandboxidentity.ErrConflict
			}
			if ticket.Status != sandboxidentity.Reserved {
				return sandboxidentity.ErrInProgress
			}
			cleaning, err := state.BeginCleanup(r.identity.plan, ticket)
			if err != nil {
				return err
			}
			if err := sessions.RetireIdentityNeverDispatched(cleaning); err != nil {
				return err
			}
			return state.CompleteCleanup(r.identity.plan, cleaning)
		}
		if retirement, exists := sessions.Retirements[claim.OperationID]; exists &&
			(retirement.Ticket.Claim != claim || !retirement.NeverDispatched || !retirement.Released) {
			return desktoprepository.ErrConflict
		}
		return nil
	})
}
