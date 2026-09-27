package docker

import (
	"context"
	"errors"
	"os"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

// NewBound constructs the Phase 6 Browser runtime with a profile-projected
// finite slot set. The Provider application remains responsible for the
// durable reservation CAS; this driver receives no database authority.
func NewBound(ctx context.Context, options Options, provenance ProvenanceVerifier,
	network RestrictedNetwork, authority sandboxidentity.RuntimeAuthority) (*Driver, error) {
	if validateBoundAuthority(options, authority) != nil {
		return nil, ErrInvalidOptions
	}
	driver, err := New(ctx, options, provenance, network)
	if err != nil {
		return nil, err
	}
	driver.bind(authority)
	return driver, nil
}

func validateBoundAuthority(options Options, authority sandboxidentity.RuntimeAuthority) error {
	if authority.Validate() != nil || authority.OwnerDeployment != providerOwner ||
		authority.Template != "browser-sandbox-runtime" || authority.Namespace != options.Namespace ||
		authority.ControllerID != options.ControllerID || authority.Capacity != options.MaxSessionsPerController {
		return ErrInvalidOptions
	}
	return nil
}

func (d *Driver) bind(authority sandboxidentity.RuntimeAuthority) {
	authority.Slots = slices.Clone(authority.Slots)
	d.bound = &authority
}

func (d *Driver) RuntimeAuthority() sandboxidentity.RuntimeAuthority {
	if d == nil || d.bound == nil {
		return sandboxidentity.RuntimeAuthority{}
	}
	value := *d.bound
	value.Slots = slices.Clone(value.Slots)
	return value
}

// DesiredSpecDigests is pure: it calculates every trusted slot's desired
// runtime spec before the application calls the PostgreSQL Reserve CAS.
func (d *Driver) DesiredSpecDigests(allocation providerbrowser.Allocation) (map[string]string, error) {
	if d == nil || d.bound == nil || allocation.Validate() != nil {
		return nil, ErrInvalidOptions
	}
	result := make(map[string]string, len(d.bound.Slots))
	for _, slot := range d.bound.Slots {
		digest, err := d.specDigest(allocation, slot)
		if err != nil {
			return nil, err
		}
		result[slot.ID] = digest
	}
	return result, nil
}

// AllocateBound accepts only the Creating ticket returned by a successful
// BeginCreate CAS. It is not a replacement for the application's single-
// executor/recovery checks: an old Creating document must never be replayed
// into this method as a new permit.
func (d *Driver) AllocateBound(ctx context.Context, allocation providerbrowser.Allocation,
	ticket sandboxidentity.Reservation) (providerbrowser.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ticket.Status != sandboxidentity.Creating ||
		ticket.PlanDigest != d.bound.PlanDigest || !d.boundSlot(ticket.Slot) ||
		!claimMatchesAllocation(ticket.Claim, allocation) {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserUnsupported
	}
	digest, err := d.specDigest(allocation, ticket.Slot)
	if err != nil || ticket.SpecDigest != digest {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
	}
	receipt, err := d.allocate(ctx, allocation, ticket.Slot)
	if err != nil {
		return providerbrowser.AllocationReceipt{}, err
	}
	// d.allocate has returned: every network/Docker create/start/probe call
	// from this unique dispatch has reached a definite end. No further
	// create/start is permitted after this fsynced completion record.
	if err := d.persistBoundCompletion(allocation, ticket, receipt); err != nil {
		return providerbrowser.AllocationReceipt{}, errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	return receipt, nil
}

func (d *Driver) persistBoundCompletion(allocation providerbrowser.Allocation,
	ticket sandboxidentity.Reservation, receipt providerbrowser.AllocationReceipt) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.BrowserSessionID)
	if err != nil {
		return err
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != browserSlotStateVersion || !state.Ready || state.CleanupPending ||
		!state.matchesAllocation(allocation) || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest || state.CompletedBound != nil {
		return providerbrowser.ErrAllocationUnknown
	}
	state.CompletedBound = &boundCompletion{Ticket: ticket, Receipt: receipt}
	return persistBrowserState(path, state, d.options.NetworkPolicyReference)
}

// CompletedBound is read-only evidence for the unique finished dispatch. It
// cannot turn an unfinished/unknown Creating ticket into a new permit.
func (d *Driver) CompletedBound(ctx context.Context, allocation providerbrowser.Allocation,
	ticket sandboxidentity.Reservation) (providerbrowser.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ctx == nil || ctx.Err() != nil ||
		ticket.Status != sandboxidentity.Creating || ticket.PlanDigest != d.bound.PlanDigest ||
		!d.boundSlot(ticket.Slot) || !claimMatchesAllocation(ticket.Claim, allocation) {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	digest, err := d.specDigest(allocation, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.BrowserSessionID)
	if err != nil {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || state.CompletedBound == nil || state.CompletedBound.Ticket != ticket ||
		!state.matchesAllocation(allocation) || state.Network.Slot != ticket.Slot ||
		state.SpecDigest != ticket.SpecDigest || !state.Ready || state.CleanupPending {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operation, state)
	if err != nil || !found || info.id != state.BackendContainerID || !info.running || info.status != "running" ||
		d.network.Inspect(operation, state.Network) != nil {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	return state.CompletedBound.Receipt, nil
}

// CompletedTerminalBound supplies an exact receipt only for a terminal
// Browser session with no attached allocation and a fsynced completion of
// its unique dispatch. It does not require the container to remain running:
// the caller must fence and clean even an already-absent exact allocation.
func (d *Driver) CompletedTerminalBound(ctx context.Context, record providerbrowser.Record,
	ticket sandboxidentity.Reservation) (providerbrowser.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ctx == nil || ctx.Err() != nil || record.Validate() != nil ||
		record.Allocation != nil || ticket.PlanDigest != d.bound.PlanDigest || !d.boundSlot(ticket.Slot) ||
		(ticket.Status != sandboxidentity.Creating && ticket.Status != sandboxidentity.Active &&
			ticket.Status != sandboxidentity.Cleaning) {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(record.Request.SandboxID, record.Request.BrowserSessionID)
	if err != nil {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != browserSlotStateVersion || state.CompletedBound == nil ||
		!state.CompletedBound.Ticket.SameIdentity(ticket) || state.Network.Slot != ticket.Slot ||
		state.SpecDigest != ticket.SpecDigest || !state.Receipt.AllocatedAt.Equal(record.AcceptedAt) ||
		state.Request.SandboxID != record.Request.SandboxID ||
		state.Request.BrowserSessionID != record.Request.BrowserSessionID ||
		state.Request.OperationID != record.Request.OperationID ||
		state.Request.AttemptID != record.Request.AttemptID ||
		state.Request.RequestDigest != record.Request.RequestDigest ||
		state.Request.ExpectedGeneration != record.Request.ExpectedGeneration ||
		state.Request.FencingToken != record.Request.FencingToken ||
		!state.Request.ExpiresAt.Equal(record.Request.ExpiresAt) ||
		(state.Request.NetworkPolicyReference != d.options.NetworkPolicyReference) {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	if record.Status != providerbrowser.StatusFailed && record.Status != providerbrowser.StatusCancelled &&
		record.Status != providerbrowser.StatusOutcomeUnknown {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	allocation := providerbrowser.Allocation{Request: state.Request, AllocatedAt: record.AcceptedAt}
	digest, err := d.specDigest(allocation, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	return state.CompletedBound.Receipt, nil
}

// RecoverBound reuses a durable Active reservation without any create, start
// or relay exec. It accepts only exact local state and owned running Docker
// resources; any missing or ambiguous observation remains unresolved.
func (d *Driver) RecoverBound(ctx context.Context, allocation providerbrowser.Allocation,
	ticket sandboxidentity.Reservation) (providerbrowser.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ctx == nil || ctx.Err() != nil ||
		ticket.Status != sandboxidentity.Active || ticket.PlanDigest != d.bound.PlanDigest ||
		!d.boundSlot(ticket.Slot) || !claimMatchesAllocation(ticket.Claim, allocation) {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserUnsupported
	}
	digest, err := d.specDigest(allocation, ticket.Slot)
	if err != nil || ticket.SpecDigest != digest {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.BrowserSessionID)
	if err != nil {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrBrowserConflict
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != browserSlotStateVersion || !state.matchesAllocation(allocation) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest || !state.Ready || state.CleanupPending ||
		state.CompletedBound == nil || state.CompletedBound.Ticket.Claim != ticket.Claim ||
		state.CompletedBound.Ticket.PlanDigest != ticket.PlanDigest ||
		state.CompletedBound.Ticket.Slot != ticket.Slot || state.CompletedBound.Ticket.SpecDigest != ticket.SpecDigest {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operation, state)
	if err != nil || !found || info.id != state.BackendContainerID || !info.running || info.status != "running" ||
		d.network.Inspect(operation, state.Network) != nil {
		return providerbrowser.AllocationReceipt{}, providerbrowser.ErrAllocationUnknown
	}
	return state.Receipt, nil
}

func (d *Driver) boundSlot(slot sandboxidentity.Slot) bool {
	if slot.Validate() != nil {
		return false
	}
	for _, allowed := range d.bound.Slots {
		if slot.ID == allowed.ID {
			return slot == allowed
		}
	}
	return false
}

func claimMatchesAllocation(claim sandboxidentity.Claim, allocation providerbrowser.Allocation) bool {
	request := allocation.Request
	return allocation.Validate() == nil && claim.Validate() == nil &&
		claim.SandboxID == request.SandboxID && claim.SessionID == request.BrowserSessionID &&
		claim.OperationID == request.OperationID && claim.AttemptID == request.AttemptID &&
		claim.RequestDigest == request.RequestDigest && claim.Generation == request.ExpectedGeneration &&
		claim.Fence == request.FencingToken
}

// ObserveBound and AttachBound are reached only through the Provider
// coordinator after a current Active reservation and session authorization.
// They recheck the local runtime evidence before touching the container.
func (d *Driver) ObserveBound(ctx context.Context, receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation) (providerbrowser.AllocationObservation, error) {
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Active); err != nil {
		return providerbrowser.AllocationObservation{}, err
	}
	if ctx == nil || ctx.Err() != nil {
		return providerbrowser.AllocationObservation{}, context.Canceled
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.options.Clock.Now().UTC()
	observation := providerbrowser.AllocationObservation{Receipt: receipt, ObservedAt: now,
		State: providerbrowser.AllocationOutcomeUnknown}
	if now.IsZero() || now.Before(receipt.AllocatedAt) {
		return providerbrowser.AllocationObservation{}, providerbrowser.ErrAllocationUnknown
	}
	if !receipt.ExpiresAt.After(now) {
		observation.State = providerbrowser.AllocationExpired
		return observation, observation.Validate()
	}
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return providerbrowser.AllocationObservation{}, providerbrowser.ErrBrowserConflict
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || state.CleanupPending || !state.matchesReceipt(receipt) || state.Network.Slot != ticket.Slot {
		return observation, observation.Validate()
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operation, state)
	if err != nil || !found || info.id != state.BackendContainerID || !info.running || info.status != "running" ||
		d.network.Inspect(operation, state.Network) != nil {
		return observation, observation.Validate()
	}
	observation.State = providerbrowser.AllocationRunning
	return observation, observation.Validate()
}

func (d *Driver) AttachBound(ctx context.Context, receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation) (providerbrowser.Stream, error) {
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Active); err != nil {
		return nil, err
	}
	return d.attach(ctx, receipt)
}

func (d *Driver) validateBoundReceipt(receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation, status sandboxidentity.Status) error {
	if d == nil || d.bound == nil || receipt.Validate() != nil || ticket.Status != status ||
		ticket.PlanDigest != d.bound.PlanDigest || !d.boundSlot(ticket.Slot) {
		return providerbrowser.ErrBrowserUnsupported
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return providerbrowser.ErrBrowserConflict
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		return providerbrowser.ErrBrowserNotFound
	}
	if err != nil || state.Version != browserSlotStateVersion || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest ||
		state.CompletedBound == nil || !state.CompletedBound.Ticket.SameIdentity(ticket) ||
		(status == sandboxidentity.Active && state.CleanupPending) ||
		!claimMatchesAllocation(ticket.Claim, providerbrowser.Allocation{Request: state.Request, AllocatedAt: receipt.AllocatedAt}) {
		return providerbrowser.ErrBrowserConflict
	}
	digest, err := d.specDigest(providerbrowser.Allocation{Request: state.Request, AllocatedAt: receipt.AllocatedAt}, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerbrowser.ErrBrowserConflict
	}
	return nil
}

type networkAbsenceVerifier interface {
	Absent(context.Context, NetworkAttachment) error
}

// CleanupBound is called only after the application has entered Cleaning and
// stopped admitting new sessions. It persists a local attach fence before
// removing resources and retains the binding until independently confirmed
// absent and the PostgreSQL CompleteCleanup CAS has committed.
func (d *Driver) CleanupBound(ctx context.Context, receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Cleaning); err != nil {
		return err
	}
	if err := d.markBoundCleanupPending(receipt, ticket); err != nil {
		return err
	}
	return d.cleanup(ctx, receipt, true)
}

func (d *Driver) markBoundCleanupPending(receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return providerbrowser.ErrBrowserConflict
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != browserSlotStateVersion || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest {
		return providerbrowser.ErrBrowserConflict
	}
	if state.CleanupPending {
		return nil
	}
	state.CleanupPending = true
	if err := persistBrowserState(path, state, d.options.NetworkPolicyReference); err != nil {
		return providerbrowser.ErrAllocationUnknown
	}
	return nil
}

// ConfirmAbsentBound performs fresh independent Docker observations; it does
// not infer absence from CleanupBound's delete responses or a single 404.
func (d *Driver) ConfirmAbsentBound(ctx context.Context, receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Cleaning); err != nil {
		return err
	}
	network, ok := d.network.(networkAbsenceVerifier)
	if !ok {
		return providerbrowser.ErrAllocationUnknown
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return providerbrowser.ErrBrowserConflict
	}
	state, err := loadBrowserState(path, d.options.NetworkPolicyReference)
	if err != nil || !state.CleanupPending || !state.matchesReceipt(receipt) || state.Network.Slot != ticket.Slot {
		return providerbrowser.ErrAllocationUnknown
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	_, found, err := d.inspectOwned(operation, state)
	if err != nil {
		return errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	if found {
		return providerbrowser.ErrAllocationUnknown
	}
	if err := network.Absent(operation, state.Network); err != nil {
		return errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	return nil
}

// FinalizeCleanupBound removes only the local evidence after the application
// has committed CompleteCleanup. If this fails, the state remains as a
// recoverable tombstone and cannot authorize a new allocation.
func (d *Driver) FinalizeCleanupBound(ctx context.Context, receipt providerbrowser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	if err := d.ConfirmAbsentBound(ctx, receipt, ticket); err != nil {
		if !errors.Is(err, providerbrowser.ErrBrowserNotFound) {
			return err
		}
		// The caller must already have committed or independently recovered
		// the exact Released retirement in Provider PostgreSQL. A missing
		// local tombstone after that proof is an idempotent finalization retry.
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	directory, path, err := d.stateLocation(receipt.SandboxID, receipt.BrowserSessionID)
	if err != nil {
		return providerbrowser.ErrBrowserConflict
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	opened, err := os.Open(directory)
	if err != nil {
		return errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	if err := errors.Join(opened.Sync(), opened.Close()); err != nil {
		return errors.Join(providerbrowser.ErrAllocationUnknown, err)
	}
	return nil
}
