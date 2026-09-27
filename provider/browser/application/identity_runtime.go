package application

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

type BrowserIdentityLifecycleLedger interface {
	BrowserIdentityLedger
	Reservations(context.Context) ([]sandboxidentity.Reservation, error)
	BeginCleanupAuthorized(context.Context, browser.AllocationReceipt, sandboxidentity.Reservation) (sandboxidentity.Reservation, error)
	CompleteCleanupAuthorized(context.Context, sandboxidentity.Reservation,
		func(context.Context, sandboxidentity.Reservation) error) error
	CompletedRetirement(context.Context, browser.AllocationReceipt) (sandboxidentity.Reservation, error)
	CompletedTerminalRetirement(context.Context, browser.Record) (sandboxidentity.Reservation, browser.AllocationReceipt, error)
	RetireUnallocated(context.Context, browser.Record) error
}

type BoundBrowserRuntime interface {
	BoundBrowserCreator
	Ready(context.Context) error
	ObserveBound(context.Context, browser.AllocationReceipt, sandboxidentity.Reservation) (browser.AllocationObservation, error)
	AttachBound(context.Context, browser.AllocationReceipt, sandboxidentity.Reservation) (browser.Stream, error)
	CleanupBound(context.Context, browser.AllocationReceipt, sandboxidentity.Reservation) error
	ConfirmAbsentBound(context.Context, browser.AllocationReceipt, sandboxidentity.Reservation) error
	FinalizeCleanupBound(context.Context, browser.AllocationReceipt, sandboxidentity.Reservation) error
	CompletedTerminalBound(context.Context, browser.Record, sandboxidentity.Reservation) (browser.AllocationReceipt, error)
}

// BrowserIdentityRuntime is the Provider-private adapter passed to the
// Browser application and mux. It never exposes the raw bound driver or
// permits an Active ticket cached before a fresh repository read.
type BrowserIdentityRuntime struct {
	create  *BrowserIdentityCreateCoordinator
	ledger  BrowserIdentityLifecycleLedger
	runtime BoundBrowserRuntime
}

func NewBrowserIdentityRuntime(ledger BrowserIdentityLifecycleLedger, runtime BoundBrowserRuntime,
	clock Clock) (*BrowserIdentityRuntime, error) {
	if ledger == nil || runtime == nil {
		return nil, ErrInvalidApplication
	}
	create, err := NewBrowserIdentityCreateCoordinator(ledger, runtime, clock)
	if err != nil {
		return nil, err
	}
	return &BrowserIdentityRuntime{create: create, ledger: ledger, runtime: runtime}, nil
}

func (r *BrowserIdentityRuntime) Allocate(ctx context.Context,
	allocation browser.Allocation) (browser.AllocationReceipt, error) {
	if r == nil || r.create == nil {
		return browser.AllocationReceipt{}, ErrInvalidApplication
	}
	return r.create.Allocate(ctx, allocation)
}

func (r *BrowserIdentityRuntime) Ready(ctx context.Context) error {
	if r == nil || r.ledger == nil || r.runtime == nil {
		return ErrInvalidApplication
	}
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	if _, err := r.ledger.Reservations(ctx); err != nil {
		return errors.Join(browser.ErrAllocationUnknown, err)
	}
	return r.runtime.Ready(ctx)
}

func (r *BrowserIdentityRuntime) Observe(ctx context.Context,
	receipt browser.AllocationReceipt) (browser.AllocationObservation, error) {
	ticket, err := r.currentTicket(ctx, receipt)
	if err != nil || ticket.Status != sandboxidentity.Active {
		return browser.AllocationObservation{}, errors.Join(browser.ErrAllocationUnknown, err)
	}
	return r.runtime.ObserveBound(ctx, receipt, ticket)
}

func (r *BrowserIdentityRuntime) Attach(ctx context.Context,
	receipt browser.AllocationReceipt) (browser.Stream, error) {
	ticket, err := r.currentTicket(ctx, receipt)
	if err != nil || ticket.Status != sandboxidentity.Active {
		return nil, errors.Join(browser.ErrAllocationUnknown, err)
	}
	return r.runtime.AttachBound(ctx, receipt, ticket)
}

func (r *BrowserIdentityRuntime) Cleanup(ctx context.Context,
	receipt browser.AllocationReceipt) error {
	ticket, err := r.currentTicket(ctx, receipt)
	if err != nil {
		if errors.Is(err, sandboxidentity.ErrConflict) {
			// A lost CompleteCleanup response or failed local finalization may
			// leave only the durable Browser retirement. Absence of a slot by
			// itself is never proof of completion.
			released, proofErr := r.ledger.CompletedRetirement(ctx, receipt)
			if proofErr == nil && released.Status == sandboxidentity.Cleaning {
				return r.runtime.FinalizeCleanupBound(ctx, receipt, released)
			}
		}
		return errors.Join(browser.ErrAllocationUnknown, err)
	}
	switch ticket.Status {
	case sandboxidentity.Active:
		cleaning, err := r.ledger.BeginCleanupAuthorized(ctx, receipt, ticket)
		if err != nil || cleaning.Status != sandboxidentity.Cleaning || !cleaning.SameIdentity(ticket) {
			return errors.Join(browser.ErrAllocationUnknown, err)
		}
		ticket = cleaning
	case sandboxidentity.Cleaning:
		// Exact retry continues the same fenced cleanup.
	case sandboxidentity.Creating:
		// Unknown creation must be reconciled before cleanup may begin.
		return browser.ErrAllocationUnknown
	case sandboxidentity.Reserved:
		// No trusted runtime receipt exists yet. A separate admission/absence
		// reconciliation must retire this claim without fabricating one.
		return browser.ErrAllocationUnknown
	default:
		return browser.ErrAllocationUnknown
	}
	if err := r.runtime.CleanupBound(ctx, receipt, ticket); err != nil {
		return errors.Join(browser.ErrAllocationUnknown, err)
	}
	writeContext, cancel := persistenceContext(ctx)
	err = r.ledger.CompleteCleanupAuthorized(writeContext, ticket,
		func(checkContext context.Context, checked sandboxidentity.Reservation) error {
			if checked != ticket {
				return sandboxidentity.ErrConflict
			}
			return r.runtime.ConfirmAbsentBound(checkContext, receipt, checked)
		})
	cancel()
	if err != nil {
		return errors.Join(browser.ErrAllocationUnknown, err)
	}
	if err := r.runtime.FinalizeCleanupBound(ctx, receipt, ticket); err != nil {
		return errors.Join(browser.ErrAllocationUnknown, err)
	}
	return nil
}

func (r *BrowserIdentityRuntime) RetireUnallocated(ctx context.Context, record browser.Record) error {
	if r == nil || r.ledger == nil || ctx == nil || record.Validate() != nil || record.Allocation != nil ||
		(record.Status != browser.StatusFailed && record.Status != browser.StatusCancelled &&
			record.Status != browser.StatusOutcomeUnknown) {
		return ErrInvalidApplication
	}
	writeContext, cancel := persistenceContext(ctx)
	err := r.ledger.RetireUnallocated(writeContext, record)
	cancel()
	if err == nil {
		return nil
	}
	if !errors.Is(err, sandboxidentity.ErrInProgress) {
		// A committed cleanup with a lost response has no slot, but the
		// existing Browser retirement contains the Released proof and exact
		// receipt even if local finalization already removed its tombstone.
		if released, receipt, proofErr := r.ledger.CompletedTerminalRetirement(ctx, record); proofErr == nil {
			return r.runtime.FinalizeCleanupBound(ctx, receipt, released)
		}
		return err
	}
	// A terminal record may have lost AttachAllocation or its creation PG
	// commit after Docker finished. Only the exact durable finished-dispatch
	// proof may advance Creating to Active, then the ordinary fenced cleanup
	// path removes resources. No user access is restored.
	reservations, readErr := r.ledger.Reservations(ctx)
	if readErr != nil {
		return errors.Join(browser.ErrAllocationUnknown, readErr)
	}
	for _, ticket := range reservations {
		claim := ticket.Claim
		if claim.OperationID != record.Request.OperationID || claim.SandboxID != record.Request.SandboxID {
			continue
		}
		if claim.SessionID != record.Request.BrowserSessionID || claim.AttemptID != record.Request.AttemptID ||
			claim.RequestDigest != record.Request.RequestDigest || claim.Generation != record.Request.ExpectedGeneration ||
			claim.Fence != record.Request.FencingToken || ticket.PlanDigest != r.runtime.RuntimeAuthority().PlanDigest {
			return browser.ErrAllocationUnknown
		}
		if ticket.Status != sandboxidentity.Creating && ticket.Status != sandboxidentity.Active &&
			ticket.Status != sandboxidentity.Cleaning {
			return browser.ErrAllocationUnknown
		}
		receipt, proofErr := r.runtime.CompletedTerminalBound(ctx, record, ticket)
		if proofErr != nil {
			return errors.Join(browser.ErrAllocationUnknown, proofErr)
		}
		if ticket.Status == sandboxidentity.Creating {
			commitContext, stop := persistenceContext(ctx)
			_, commitErr := r.ledger.CompleteCreate(commitContext, ticket)
			stop()
			if commitErr != nil {
				return errors.Join(browser.ErrAllocationUnknown, commitErr)
			}
		}
		return r.Cleanup(ctx, receipt)
	}
	return browser.ErrAllocationUnknown
}

func (r *BrowserIdentityRuntime) currentTicket(ctx context.Context,
	receipt browser.AllocationReceipt) (sandboxidentity.Reservation, error) {
	if ctx == nil || ctx.Err() != nil {
		return sandboxidentity.Reservation{}, context.Canceled
	}
	if r == nil || r.ledger == nil || r.runtime == nil || receipt.Validate() != nil {
		return sandboxidentity.Reservation{}, ErrInvalidApplication
	}
	reservations, err := r.ledger.Reservations(ctx)
	if err != nil {
		return sandboxidentity.Reservation{}, err
	}
	for _, ticket := range reservations {
		claim := ticket.Claim
		if claim.SandboxID == receipt.SandboxID && claim.SessionID == receipt.BrowserSessionID {
			if claim.OperationID != receipt.OperationID || claim.AttemptID != receipt.AttemptID ||
				claim.Generation != receipt.ExpectedGeneration || claim.Fence != receipt.FencingToken ||
				ticket.PlanDigest != r.runtime.RuntimeAuthority().PlanDigest {
				return sandboxidentity.Reservation{}, sandboxidentity.ErrConflict
			}
			return ticket, nil
		}
	}
	return sandboxidentity.Reservation{}, sandboxidentity.ErrConflict
}

var _ browser.Runtime = (*BrowserIdentityRuntime)(nil)
