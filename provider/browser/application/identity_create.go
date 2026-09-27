package application

import (
	"context"
	"errors"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

// BrowserIdentityLedger is a Provider-owned transactional authority. Its
// implementation may use PostgreSQL, but no Docker operation runs under its
// row lock and the driver never receives this port.
type BrowserIdentityLedger interface {
	Plan() sandboxidentity.Plan
	ReserveAuthorized(context.Context, browser.Allocation, map[string]string) (sandboxidentity.Reservation, error)
	BeginCreateAuthorized(context.Context, browser.Allocation, sandboxidentity.Reservation) (sandboxidentity.Reservation, error)
	CompleteCreate(context.Context, sandboxidentity.Reservation) (sandboxidentity.Reservation, error)
}

// BoundBrowserCreator is the minimal slot-aware runtime port for creation.
// Active recovery is read-only: it may inspect exact owned resources, but
// cannot create, start or attach a relay.
type BoundBrowserCreator interface {
	RuntimeAuthority() sandboxidentity.RuntimeAuthority
	DesiredSpecDigests(browser.Allocation) (map[string]string, error)
	AllocateBound(context.Context, browser.Allocation, sandboxidentity.Reservation) (browser.AllocationReceipt, error)
	CompletedBound(context.Context, browser.Allocation, sandboxidentity.Reservation) (browser.AllocationReceipt, error)
	RecoverBound(context.Context, browser.Allocation, sandboxidentity.Reservation) (browser.AllocationReceipt, error)
}

// BrowserIdentityCreateCoordinator owns the Reserve/BeginCreate/CompleteCreate
// sequence. It is intentionally not a full browser.Runtime until bounded
// recovery, attach fencing and exact cleanup are composed as well.
type BrowserIdentityCreateCoordinator struct {
	ledger  BrowserIdentityLedger
	runtime BoundBrowserCreator
	clock   Clock
}

func NewBrowserIdentityCreateCoordinator(ledger BrowserIdentityLedger, runtime BoundBrowserCreator,
	clock Clock) (*BrowserIdentityCreateCoordinator, error) {
	if ledger == nil || runtime == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	authority, err := ledger.Plan().ProjectRuntimeAuthority()
	if err != nil || !sameRuntimeAuthority(authority, runtime.RuntimeAuthority()) {
		return nil, ErrInvalidApplication
	}
	return &BrowserIdentityCreateCoordinator{ledger: ledger, runtime: runtime, clock: clock}, nil
}

func sameRuntimeAuthority(a, b sandboxidentity.RuntimeAuthority) bool {
	return a.PlanDigest == b.PlanDigest && a.OwnerDeployment == b.OwnerDeployment &&
		a.Namespace == b.Namespace && a.ControllerID == b.ControllerID &&
		a.Template == b.Template && a.Capacity == b.Capacity && slices.Equal(a.Slots, b.Slots)
}

func (c *BrowserIdentityCreateCoordinator) Allocate(ctx context.Context,
	allocation browser.Allocation) (browser.AllocationReceipt, error) {
	if ctx == nil {
		return browser.AllocationReceipt{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return browser.AllocationReceipt{}, err
	}
	if c == nil || c.ledger == nil || c.runtime == nil || c.clock == nil {
		return browser.AllocationReceipt{}, ErrInvalidApplication
	}
	if err := allocation.Validate(); err != nil {
		return browser.AllocationReceipt{}, err
	}
	now := c.clock.Now().UTC()
	if now.IsZero() || !allocation.Request.ExpiresAt.After(now) {
		return browser.AllocationReceipt{}, browser.ErrBrowserExpired
	}
	specs, err := c.runtime.DesiredSpecDigests(allocation)
	if err != nil {
		return browser.AllocationReceipt{}, browser.ErrBrowserUnsupported
	}
	request := allocation.Request
	claim := sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.BrowserSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		RequestDigest: request.RequestDigest, Generation: request.ExpectedGeneration, Fence: request.FencingToken}
	ticket, err := c.ledger.ReserveAuthorized(ctx, allocation, specs)
	if err != nil {
		switch {
		case errors.Is(err, sandboxidentity.ErrConflict):
			return browser.AllocationReceipt{}, browser.ErrBrowserConflict
		case errors.Is(err, sandboxidentity.ErrExhausted):
			return browser.AllocationReceipt{}, browser.ErrBrowserUnsupported
		default:
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
	}
	if ticket.Claim != claim || ticket.SpecDigest != specs[ticket.Slot.ID] ||
		ticket.PlanDigest != c.runtime.RuntimeAuthority().PlanDigest {
		return browser.AllocationReceipt{}, browser.ErrAllocationUnknown
	}
	switch ticket.Status {
	case sandboxidentity.Reserved:
		if err := ctx.Err(); err != nil {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		creating, err := c.ledger.BeginCreateAuthorized(ctx, allocation, ticket)
		if err != nil || creating.Status != sandboxidentity.Creating || !creating.SameIdentity(ticket) {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		if err := ctx.Err(); err != nil {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		receipt, err := c.runtime.AllocateBound(ctx, allocation, creating)
		if err != nil || receipt.Validate() != nil || !receipt.Matches(request) ||
			!receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		writeContext, cancel := persistenceContext(ctx)
		active, err := c.ledger.CompleteCreate(writeContext, creating)
		cancel()
		if err != nil || active.Status != sandboxidentity.Active || !active.SameIdentity(creating) {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		return receipt, nil
	case sandboxidentity.Active:
		// A known Active retry inspects the exact existing resource. It never
		// invokes AllocateBound or consumes another UID.
		receipt, err := c.runtime.RecoverBound(ctx, allocation, ticket)
		if err != nil || receipt.Validate() != nil || !receipt.Matches(request) ||
			!receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		return receipt, nil
	case sandboxidentity.Creating:
		// Only a durable record written after the one permitted dispatch has
		// ended can complete this CAS. An unfinished/unknown Docker call remains
		// Creating and cannot be replayed into AllocateBound.
		receipt, proofErr := c.runtime.CompletedBound(ctx, allocation, ticket)
		if proofErr != nil || receipt.Validate() != nil || !receipt.Matches(request) ||
			!receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, proofErr)
		}
		writeContext, cancel := persistenceContext(ctx)
		active, err := c.ledger.CompleteCreate(writeContext, ticket)
		cancel()
		if err != nil || active.Status != sandboxidentity.Active || !active.SameIdentity(ticket) {
			return browser.AllocationReceipt{}, errors.Join(browser.ErrAllocationUnknown, err)
		}
		return receipt, nil
	case sandboxidentity.Cleaning:
		return browser.AllocationReceipt{}, browser.ErrAllocationUnknown
	default:
		return browser.AllocationReceipt{}, browser.ErrAllocationUnknown
	}
}
