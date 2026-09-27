package application

import (
	"context"
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

// DesktopIdentityLedger is the Provider-owned transactional authority. A
// driver never receives its PostgreSQL port or decides slot reuse.
type DesktopIdentityLedger interface {
	Plan() sandboxidentity.Plan
	Reservations(context.Context) ([]sandboxidentity.Reservation, error)
	ReserveAuthorized(context.Context, desktop.Allocation, map[string]string) (sandboxidentity.Reservation, error)
	BeginCreateAuthorized(context.Context, desktop.Allocation, sandboxidentity.Reservation) (sandboxidentity.Reservation, error)
	CompleteCreate(context.Context, sandboxidentity.Reservation) (sandboxidentity.Reservation, error)
	BeginCleanupAuthorized(context.Context, desktop.AllocationReceipt, sandboxidentity.Reservation, string) (sandboxidentity.Reservation, error)
	CompleteCleanupAuthorized(context.Context, sandboxidentity.Reservation,
		func(context.Context, sandboxidentity.Reservation) error) error
	CompletedRetirement(context.Context, desktop.AllocationReceipt) (sandboxidentity.Reservation, error)
	RetireUnallocated(context.Context, desktop.Record) error
}

// BoundDesktopRuntime is a focused capability interface: only the Provider
// coordinator can reach a first-dispatch method with the PG Creating ticket.
type BoundDesktopRuntime interface {
	RuntimeAuthority() sandboxidentity.RuntimeAuthority
	DesiredSpecDigests(desktop.Allocation) (map[string]string, error)
	AllocateBound(context.Context, desktop.Allocation, sandboxidentity.Reservation) (desktop.AllocationReceipt, error)
	CompletedBound(context.Context, desktop.Allocation, sandboxidentity.Reservation) (desktop.AllocationReceipt, error)
	CompletedTerminalBound(context.Context, desktop.Record, sandboxidentity.Reservation) (desktop.AllocationReceipt, error)
	RecoverBound(context.Context, desktop.Allocation, sandboxidentity.Reservation) (desktop.AllocationReceipt, error)
	ObserveBound(context.Context, desktop.Allocation, desktop.AllocationReceipt, sandboxidentity.Reservation) (desktop.AllocationObservation, error)
	AttachBound(context.Context, desktop.AllocationReceipt, sandboxidentity.Reservation) (desktop.Attachment, error)
	CleanupBound(context.Context, desktop.AllocationReceipt, sandboxidentity.Reservation) error
	ConfirmAbsentBound(context.Context, desktop.AllocationReceipt, sandboxidentity.Reservation) error
	FinalizeCleanupBound(context.Context, desktop.AllocationReceipt, sandboxidentity.Reservation) error
	Ready(context.Context) error
}

// DesktopIdentityRuntime is the Provider-private, slot-aware Desktop runtime.
// Its caller never receives a reusable first-dispatch permit.
type DesktopIdentityRuntime struct {
	ledger  DesktopIdentityLedger
	runtime BoundDesktopRuntime
	clock   Clock
}

func NewDesktopIdentityRuntime(ledger DesktopIdentityLedger, runtime BoundDesktopRuntime,
	clock Clock) (*DesktopIdentityRuntime, error) {
	if ledger == nil || runtime == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	authority, err := ledger.Plan().ProjectRuntimeAuthority()
	if err != nil || !sameDesktopRuntimeAuthority(authority, runtime.RuntimeAuthority()) {
		return nil, ErrInvalidApplication
	}
	return &DesktopIdentityRuntime{ledger: ledger, runtime: runtime, clock: clock}, nil
}

func sameDesktopRuntimeAuthority(a, b sandboxidentity.RuntimeAuthority) bool {
	return a.PlanDigest == b.PlanDigest && a.OwnerDeployment == b.OwnerDeployment &&
		a.Namespace == b.Namespace && a.ControllerID == b.ControllerID &&
		a.Template == b.Template && a.Capacity == b.Capacity && slices.Equal(a.Slots, b.Slots)
}

func (r *DesktopIdentityRuntime) Ready(ctx context.Context) error {
	if r == nil || r.ledger == nil || r.runtime == nil || ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	if _, err := r.ledger.Reservations(ctx); err != nil {
		return errors.Join(desktop.ErrAllocationUnknown, err)
	}
	return r.runtime.Ready(ctx)
}

func (r *DesktopIdentityRuntime) Allocate(ctx context.Context,
	allocation desktop.Allocation) (desktop.AllocationReceipt, error) {
	if r == nil || r.ledger == nil || r.runtime == nil || r.clock == nil || ctx == nil {
		return desktop.AllocationReceipt{}, ErrInvalidApplication
	}
	if err := ctx.Err(); err != nil {
		return desktop.AllocationReceipt{}, err
	}
	if err := allocation.Validate(); err != nil {
		return desktop.AllocationReceipt{}, err
	}
	now := r.clock.Now().UTC()
	if now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return desktop.AllocationReceipt{}, desktop.ErrDesktopExpired
	}
	specs, err := r.runtime.DesiredSpecDigests(allocation)
	if err != nil {
		return desktop.AllocationReceipt{}, desktop.ErrDesktopUnsupported
	}
	ticket, err := r.ledger.ReserveAuthorized(ctx, allocation, specs)
	if err != nil {
		switch {
		case errors.Is(err, sandboxidentity.ErrConflict):
			return desktop.AllocationReceipt{}, desktop.ErrDesktopConflict
		case errors.Is(err, sandboxidentity.ErrExhausted):
			return desktop.AllocationReceipt{}, desktop.ErrDesktopCapacity
		default:
			return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, err)
		}
	}
	claim := desktopAllocationClaim(allocation)
	if ticket.Claim != claim || ticket.SpecDigest != specs[ticket.Slot.ID] ||
		ticket.PlanDigest != r.runtime.RuntimeAuthority().PlanDigest {
		return desktop.AllocationReceipt{}, desktop.ErrAllocationUnknown
	}
	var receipt desktop.AllocationReceipt
	switch ticket.Status {
	case sandboxidentity.Reserved:
		if err := ctx.Err(); err != nil {
			return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, err)
		}
		creating, beginErr := r.ledger.BeginCreateAuthorized(ctx, allocation, ticket)
		if beginErr != nil || creating.Status != sandboxidentity.Creating || !creating.SameIdentity(ticket) {
			return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, beginErr)
		}
		if err := ctx.Err(); err != nil {
			return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, err)
		}
		receipt, err = r.runtime.AllocateBound(ctx, allocation, creating)
		if err != nil {
			return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, err)
		}
		ticket = creating
	case sandboxidentity.Creating:
		// Never replay Creating into AllocateBound. Unknown outcomes retain UID.
		receipt, err = r.runtime.CompletedBound(ctx, allocation, ticket)
		if err != nil {
			return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, err)
		}
	case sandboxidentity.Active:
		return r.runtime.RecoverBound(ctx, allocation, ticket)
	default:
		return desktop.AllocationReceipt{}, desktop.ErrAllocationUnknown
	}
	if receipt.Validate() != nil || !receipt.Matches(allocation.Request) ||
		!receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
		return desktop.AllocationReceipt{}, desktop.ErrAllocationUnknown
	}
	writeCtx, cancel := persistenceContext(ctx)
	active, err := r.ledger.CompleteCreate(writeCtx, ticket)
	cancel()
	if err != nil || active.Status != sandboxidentity.Active || !active.SameIdentity(ticket) {
		return desktop.AllocationReceipt{}, errors.Join(desktop.ErrAllocationUnknown, err)
	}
	return receipt, nil
}

func desktopAllocationClaim(allocation desktop.Allocation) sandboxidentity.Claim {
	request := allocation.Request
	return sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.DesktopSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		RequestDigest: request.RequestDigest, Generation: request.ExpectedGeneration,
		Fence: request.FencingToken}
}

func (r *DesktopIdentityRuntime) Observe(ctx context.Context,
	allocation desktop.Allocation) (desktop.AllocationObservation, error) {
	ticket, err := r.currentTicket(ctx, allocation.Request.SandboxID, allocation.Request.DesktopSessionID,
		allocation.Request.OperationID, allocation.Request.AttemptID, allocation.Request.ExpectedGeneration,
		allocation.Request.FencingToken)
	if err != nil || ticket.Status != sandboxidentity.Active || ticket.Claim != desktopAllocationClaim(allocation) {
		return desktop.AllocationObservation{}, errors.Join(desktop.ErrAllocationUnknown, err)
	}
	receipt, err := r.runtime.RecoverBound(ctx, allocation, ticket)
	if err != nil {
		return desktop.AllocationObservation{}, errors.Join(desktop.ErrAllocationUnknown, err)
	}
	return r.runtime.ObserveBound(ctx, allocation, receipt, ticket)
}

func (r *DesktopIdentityRuntime) Attach(ctx context.Context,
	receipt desktop.AllocationReceipt) (desktop.Attachment, error) {
	ticket, err := r.currentTicket(ctx, receipt.SandboxID, receipt.DesktopSessionID,
		receipt.OperationID, receipt.AttemptID, receipt.ExpectedGeneration, receipt.FencingToken)
	if err != nil || ticket.Status != sandboxidentity.Active {
		return desktop.Attachment{}, errors.Join(desktop.ErrAllocationUnknown, err)
	}
	return r.runtime.AttachBound(ctx, receipt, ticket)
}

func (r *DesktopIdentityRuntime) Cleanup(ctx context.Context, receipt desktop.AllocationReceipt) error {
	return r.cleanup(ctx, receipt, "")
}

func (r *DesktopIdentityRuntime) CleanupClose(ctx context.Context, record desktop.CloseRecord) error {
	if record.Validate() != nil {
		return desktop.ErrInvalidRecord
	}
	return r.cleanup(ctx, record.Receipt, record.Request.OperationID)
}

func (r *DesktopIdentityRuntime) cleanup(ctx context.Context,
	receipt desktop.AllocationReceipt, closeOperationID string) error {
	ticket, err := r.currentTicket(ctx, receipt.SandboxID, receipt.DesktopSessionID,
		receipt.OperationID, receipt.AttemptID, receipt.ExpectedGeneration, receipt.FencingToken)
	if err != nil {
		if errors.Is(err, sandboxidentity.ErrConflict) {
			if released, proofErr := r.ledger.CompletedRetirement(ctx, receipt); proofErr == nil {
				return r.runtime.FinalizeCleanupBound(ctx, receipt, released)
			}
		}
		return errors.Join(desktop.ErrAllocationUnknown, err)
	}
	switch ticket.Status {
	case sandboxidentity.Active:
		writeCtx, cancel := persistenceContext(ctx)
		cleaning, beginErr := r.ledger.BeginCleanupAuthorized(writeCtx, receipt, ticket, closeOperationID)
		cancel()
		if beginErr != nil || cleaning.Status != sandboxidentity.Cleaning || !cleaning.SameIdentity(ticket) {
			return errors.Join(desktop.ErrAllocationUnknown, beginErr)
		}
		ticket = cleaning
	case sandboxidentity.Cleaning:
		// The exact already-fenced cleanup can be retried.
	default:
		return desktop.ErrAllocationUnknown
	}
	if err := r.runtime.CleanupBound(ctx, receipt, ticket); err != nil {
		return errors.Join(desktop.ErrAllocationUnknown, err)
	}
	writeCtx, cancel := persistenceContext(ctx)
	err = r.ledger.CompleteCleanupAuthorized(writeCtx, ticket,
		func(checkCtx context.Context, checked sandboxidentity.Reservation) error {
			if checked != ticket {
				return sandboxidentity.ErrConflict
			}
			return r.runtime.ConfirmAbsentBound(checkCtx, receipt, checked)
		})
	cancel()
	if err != nil {
		return errors.Join(desktop.ErrAllocationUnknown, err)
	}
	return r.runtime.FinalizeCleanupBound(ctx, receipt, ticket)
}

func (r *DesktopIdentityRuntime) CompletedCloseRetirement(ctx context.Context,
	record desktop.CloseRecord) (bool, error) {
	if r == nil || record.Validate() != nil || record.SourceOpenOperationID != record.Receipt.OperationID ||
		record.Request.DesktopSessionID != record.Receipt.DesktopSessionID ||
		record.Request.ConnectionGeneration != record.Receipt.ConnectionGeneration {
		return false, ErrInvalidApplication
	}
	_, err := r.ledger.CompletedRetirement(ctx, record.Receipt)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (r *DesktopIdentityRuntime) RetireUnallocated(ctx context.Context, record desktop.Record) error {
	if r == nil || r.ledger == nil || r.runtime == nil || ctx == nil || record.Validate() != nil ||
		record.Allocation != nil || (record.Status != desktop.StatusFailed && record.Status != desktop.StatusCancelled) {
		return ErrInvalidApplication
	}
	writeCtx, cancel := persistenceContext(ctx)
	err := r.ledger.RetireUnallocated(writeCtx, record)
	cancel()
	if err == nil || !errors.Is(err, sandboxidentity.ErrInProgress) {
		return err
	}
	reservations, readErr := r.ledger.Reservations(ctx)
	if readErr != nil {
		return errors.Join(desktop.ErrAllocationUnknown, readErr)
	}
	for _, ticket := range reservations {
		if ticket.Claim.OperationID != record.Request.OperationID ||
			ticket.Claim.SandboxID != record.Request.SandboxID {
			continue
		}
		if ticket.Claim.SessionID != record.Request.DesktopSessionID ||
			ticket.Claim.AttemptID != record.Request.AttemptID ||
			ticket.Claim.RequestDigest != record.Request.RequestDigest ||
			ticket.Claim.Generation != record.Request.ExpectedGeneration ||
			ticket.Claim.Fence != record.Request.FencingToken ||
			ticket.PlanDigest != r.runtime.RuntimeAuthority().PlanDigest {
			return desktop.ErrAllocationUnknown
		}
		if ticket.Status != sandboxidentity.Creating && ticket.Status != sandboxidentity.Active &&
			ticket.Status != sandboxidentity.Cleaning {
			return desktop.ErrAllocationUnknown
		}
		receipt, proofErr := r.runtime.CompletedTerminalBound(ctx, record, ticket)
		if proofErr != nil {
			return errors.Join(desktop.ErrAllocationUnknown, proofErr)
		}
		if ticket.Status == sandboxidentity.Creating {
			writeCtx, cancel := persistenceContext(ctx)
			_, commitErr := r.ledger.CompleteCreate(writeCtx, ticket)
			cancel()
			if commitErr != nil {
				return errors.Join(desktop.ErrAllocationUnknown, commitErr)
			}
		}
		return r.Cleanup(ctx, receipt)
	}
	return desktop.ErrAllocationUnknown
}

func (r *DesktopIdentityRuntime) currentTicket(ctx context.Context,
	sandboxID, sessionID, operationID, attemptID string, generation, fence int64) (sandboxidentity.Reservation, error) {
	if r == nil || r.ledger == nil || r.runtime == nil || ctx == nil || ctx.Err() != nil {
		return sandboxidentity.Reservation{}, context.Canceled
	}
	reservations, err := r.ledger.Reservations(ctx)
	if err != nil {
		return sandboxidentity.Reservation{}, err
	}
	for _, ticket := range reservations {
		claim := ticket.Claim
		if claim.SandboxID == sandboxID && claim.SessionID == sessionID {
			if claim.OperationID != operationID || claim.AttemptID != attemptID ||
				claim.Generation != generation || claim.Fence != fence ||
				ticket.PlanDigest != r.runtime.RuntimeAuthority().PlanDigest {
				return sandboxidentity.Reservation{}, sandboxidentity.ErrConflict
			}
			return ticket, nil
		}
	}
	return sandboxidentity.Reservation{}, sandboxidentity.ErrConflict
}

var _ desktop.Runtime = (*DesktopIdentityRuntime)(nil)
