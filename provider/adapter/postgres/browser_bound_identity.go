package providerpostgres

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	browserrepository "github.com/shell-echo/sandbox-runtime/provider/browser/repository"
)

// BrowserBoundIdentityRepository is the Provider production slot port. Every
// first dispatch and retirement checks the existing Browser session authority
// in the same control_state transaction as the finite UID pool. The generic
// identity repository remains useful for isolated state-machine tests but is
// not a production Browser admission port.
type BrowserBoundIdentityRepository struct {
	identity *SandboxIdentityRepository
}

func NewBrowserBoundIdentityRepository(ctx context.Context, store *Store,
	plan sandboxidentity.Plan) (*BrowserBoundIdentityRepository, error) {
	if plan.OwnerDeployment != "provider-browser-runtime" {
		return nil, sandboxidentity.ErrInvalidPlan
	}
	identity, err := NewSandboxIdentityRepository(ctx, store, plan)
	if err != nil {
		return nil, err
	}
	return &BrowserBoundIdentityRepository{identity: identity}, nil
}

func (r *BrowserBoundIdentityRepository) Plan() sandboxidentity.Plan {
	if r == nil || r.identity == nil {
		return sandboxidentity.Plan{}
	}
	return r.identity.Plan()
}

func (r *BrowserBoundIdentityRepository) Initialize(ctx context.Context,
	confirmClean func(context.Context, sandboxidentity.Plan) error) error {
	if r == nil || r.identity == nil {
		return ErrUnavailable
	}
	return r.identity.Initialize(ctx, confirmClean)
}

func (r *BrowserBoundIdentityRepository) Reservations(ctx context.Context) ([]sandboxidentity.Reservation, error) {
	if r == nil || r.identity == nil {
		return nil, ErrUnavailable
	}
	return r.identity.Reservations(ctx)
}

func (r *BrowserBoundIdentityRepository) mutate(ctx context.Context,
	action func(*sandboxidentity.State, *browserrepository.State) error) error {
	if r == nil || r.identity == nil || action == nil {
		return ErrUnavailable
	}
	owner := r.identity
	return mutateStateTriple(ctx, owner.store,
		owner.markerKey, owner.stateKey, browserSessionsDocument,
		func() identityMarker { return identityMarker{} }, importIdentityMarker,
		func(marker identityMarker) any { return marker },
		func() sandboxidentity.State { return sandboxidentity.State{} }, importIdentityState,
		func(state sandboxidentity.State) any { return state },
		newBrowserState, importBrowserState, exportBrowserState,
		func(marker *identityMarker, state *sandboxidentity.State, sessions *browserrepository.State) error {
			if !marker.Initialized || marker.PlanDigest != owner.digest || state.Validate(owner.plan) != nil {
				return sandboxidentity.ErrUninitialized
			}
			return action(state, sessions)
		})
}

func allocationClaim(allocation browser.Allocation) sandboxidentity.Claim {
	request := allocation.Request
	return sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.BrowserSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID, RequestDigest: request.RequestDigest,
		Generation: request.ExpectedGeneration, Fence: request.FencingToken}
}

func (r *BrowserBoundIdentityRepository) ReserveAuthorized(ctx context.Context,
	allocation browser.Allocation, specs map[string]string) (sandboxidentity.Reservation, error) {
	if allocation.Validate() != nil {
		return sandboxidentity.Reservation{}, browser.ErrInvalidRequest
	}
	var ticket sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *browserrepository.State) error {
		var err error
		ticket, err = state.Reserve(r.identity.plan, allocationClaim(allocation), specs)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		switch ticket.Status {
		case sandboxidentity.Reserved:
			return sessions.AuthorizeIdentityCreate(allocation, now)
		case sandboxidentity.Creating:
			// Exact Creating can only read a finished-dispatch proof. The
			// coordinator never calls AllocateBound again for this ticket.
			return sessions.AuthorizeIdentityCreate(allocation, now)
		case sandboxidentity.Active:
			return sessions.AuthorizeIdentityRecovery(allocation, now)
		default:
			// Cleaning is never an admission or dispatch permit.
			// Leave all three documents untouched; the caller reports Unknown
			// while the same durable slot stays held for reconciliation.
			return sandboxidentity.ErrInProgress
		}
	})
	return ticket, err
}

func (r *BrowserBoundIdentityRepository) BeginCreateAuthorized(ctx context.Context,
	allocation browser.Allocation, ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	if allocation.Validate() != nil || ticket.Claim != allocationClaim(allocation) {
		return sandboxidentity.Reservation{}, browser.ErrInvalidRequest
	}
	var creating sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *browserrepository.State) error {
		if err := sessions.AuthorizeIdentityCreate(allocation, time.Now().UTC()); err != nil {
			return err
		}
		var err error
		creating, err = state.BeginCreate(r.identity.plan, ticket)
		return err
	})
	return creating, err
}

func (r *BrowserBoundIdentityRepository) CompleteCreate(ctx context.Context,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	if r == nil || r.identity == nil {
		return sandboxidentity.Reservation{}, ErrUnavailable
	}
	return r.identity.CompleteCreate(ctx, ticket)
}

func (r *BrowserBoundIdentityRepository) BeginCleanupAuthorized(ctx context.Context,
	receipt browser.AllocationReceipt, ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	if receipt.Validate() != nil || ticket.Claim.OperationID != receipt.OperationID ||
		ticket.Claim.SessionID != receipt.BrowserSessionID || ticket.Claim.SandboxID != receipt.SandboxID ||
		ticket.Claim.AttemptID != receipt.AttemptID || ticket.Claim.Generation != receipt.ExpectedGeneration ||
		ticket.Claim.Fence != receipt.FencingToken {
		return sandboxidentity.Reservation{}, browser.ErrBrowserConflict
	}
	var cleaning sandboxidentity.Reservation
	err := r.mutate(ctx, func(state *sandboxidentity.State, sessions *browserrepository.State) error {
		var err error
		cleaning, err = state.BeginCleanup(r.identity.plan, ticket)
		if err != nil {
			return err
		}
		return sessions.RetireIdentity(cleaning, receipt)
	})
	return cleaning, err
}

func (r *BrowserBoundIdentityRepository) CompleteCleanupAuthorized(ctx context.Context,
	ticket sandboxidentity.Reservation, confirmAbsent func(context.Context, sandboxidentity.Reservation) error) error {
	if r == nil || ticket.Status != sandboxidentity.Cleaning || confirmAbsent == nil {
		return sandboxidentity.ErrInvalidState
	}
	// The external absence check never runs under the Provider row lock.
	if err := confirmAbsent(ctx, ticket); err != nil {
		return err
	}
	return r.mutate(ctx, func(state *sandboxidentity.State, sessions *browserrepository.State) error {
		if !sessions.IdentityRetired(ticket) {
			return browserrepository.ErrConflict
		}
		if err := state.CompleteCleanup(r.identity.plan, ticket); err != nil {
			return err
		}
		return sessions.ReleaseIdentity(ticket)
	})
}

func (r *BrowserBoundIdentityRepository) CompletedRetirement(ctx context.Context,
	receipt browser.AllocationReceipt) (sandboxidentity.Reservation, error) {
	if r == nil || r.identity == nil || ctx == nil || receipt.Validate() != nil {
		return sandboxidentity.Reservation{}, ErrUnavailable
	}
	sessions, err := readState(ctx, r.identity.store, browserSessionsDocument,
		newBrowserState, importBrowserState)
	if err != nil {
		return sandboxidentity.Reservation{}, err
	}
	return sessions.CompletedIdentityRetirement(receipt)
}

func (r *BrowserBoundIdentityRepository) CompletedTerminalRetirement(ctx context.Context,
	record browser.Record) (sandboxidentity.Reservation, browser.AllocationReceipt, error) {
	if r == nil || r.identity == nil || ctx == nil || record.Validate() != nil || record.Allocation != nil ||
		(record.Status != browser.StatusFailed && record.Status != browser.StatusCancelled &&
			record.Status != browser.StatusOutcomeUnknown) {
		return sandboxidentity.Reservation{}, browser.AllocationReceipt{}, ErrUnavailable
	}
	sessions, err := readState(ctx, r.identity.store, browserSessionsDocument,
		newBrowserState, importBrowserState)
	if err != nil {
		return sandboxidentity.Reservation{}, browser.AllocationReceipt{}, err
	}
	return sessions.CompletedTerminalIdentityRetirement(record)
}

// RetireUnallocated releases only a terminal Browser session whose exact UID
// reservation is still Reserved. The row lock excludes a concurrent
// BeginCreateAuthorized, so no Docker side effect can have been permitted.
// Creating/Active/Cleaning are deliberately not inferred safe from a missing
// allocation receipt.
func (r *BrowserBoundIdentityRepository) RetireUnallocated(ctx context.Context, record browser.Record) error {
	if record.Validate() != nil || record.Allocation != nil ||
		(record.Status != browser.StatusFailed && record.Status != browser.StatusCancelled &&
			record.Status != browser.StatusOutcomeUnknown) {
		return browser.ErrInvalidRecord
	}
	claim := sandboxidentity.Claim{SandboxID: record.Request.SandboxID,
		SessionID: record.Request.BrowserSessionID, OperationID: record.Request.OperationID,
		AttemptID: record.Request.AttemptID, RequestDigest: record.Request.RequestDigest,
		Generation: record.Request.ExpectedGeneration, Fence: record.Request.FencingToken}
	return r.mutate(ctx, func(state *sandboxidentity.State, sessions *browserrepository.State) error {
		stored, ok := sessions.Sessions[claim.OperationID]
		if !ok || stored.Validate() != nil || stored.Allocation != nil || stored.Status != record.Status ||
			(stored.Status != browser.StatusFailed && stored.Status != browser.StatusCancelled &&
				stored.Status != browser.StatusOutcomeUnknown) ||
			stored.Request.ProviderRevisionID != record.Request.ProviderRevisionID ||
			stored.Request.IdempotencyKey != record.Request.IdempotencyKey ||
			stored.Request.CapabilityProfileID != record.Request.CapabilityProfileID ||
			!stored.Request.Deadline.Equal(record.Request.Deadline) ||
			!stored.Request.ExpiresAt.Equal(record.Request.ExpiresAt) ||
			!stored.AcceptedAt.Equal(record.AcceptedAt) ||
			claim.SandboxID != stored.Request.SandboxID || claim.SessionID != stored.Request.BrowserSessionID ||
			claim.AttemptID != stored.Request.AttemptID || claim.RequestDigest != stored.Request.RequestDigest ||
			claim.Generation != stored.Request.ExpectedGeneration || claim.Fence != stored.Request.FencingToken {
			return browserrepository.ErrConflict
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
		if retired, exists := sessions.Retirements[claim.OperationID]; exists &&
			(retired.Ticket.Claim != claim || !retired.NeverDispatched || !retired.Released) {
			return browserrepository.ErrConflict
		}
		return nil
	})
}
