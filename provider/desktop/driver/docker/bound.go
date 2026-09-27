package docker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
)

// NewLocalCandidateBound is the non-release Desktop runtime constructor for
// a finite profile-projected UID set. Construction is not an execution permit:
// the legacy Allocate method is closed and only a future application-owned
// BeginCreate CAS may dispatch the exact selected slot.
func NewLocalCandidateBound(ctx context.Context, options Options, candidate desktopcandidate.Manifest,
	network RestrictedNetwork, candidatePath string,
	authority sandboxidentity.RuntimeAuthority) (*Driver, error) {
	var accounts desktopcandidate.AccountAllowlist
	if validateDesktopBoundAuthority(options, authority) != nil || candidate.ValidateCurrent() != nil ||
		json.Unmarshal([]byte(candidate.WorkloadAccounts), &accounts) != nil || accounts.Validate() != nil {
		return nil, ErrInvalidOptions
	}
	for _, slot := range authority.Slots {
		if !accounts.Supports(slot.WorkloadUID, slot.WorkloadGID) {
			return nil, ErrInvalidOptions
		}
	}
	driver, err := NewLocalCandidate(ctx, options, candidate, network, candidatePath)
	if err != nil {
		return nil, err
	}
	driver.bindDesktop(authority)
	return driver, nil
}

func validateDesktopBoundAuthority(options Options, authority sandboxidentity.RuntimeAuthority) error {
	if authority.Validate() != nil || authority.OwnerDeployment != "provider-desktop-runtime" ||
		authority.Template != "desktop-sandbox-runtime" || authority.Namespace != options.Namespace ||
		authority.ControllerID != options.ControllerID || authority.Capacity != options.MaxSessionsPerController {
		return ErrInvalidOptions
	}
	return nil
}

func (d *Driver) bindDesktop(authority sandboxidentity.RuntimeAuthority) {
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

// DesiredSpecDigests is pure and has no network or Docker side effects.
// Every slot binds a distinct numeric workload identity into the spec.
func (d *Driver) DesiredSpecDigests(allocation providerdesktop.Allocation) (map[string]string, error) {
	if d == nil || d.bound == nil || allocation.Validate() != nil {
		return nil, ErrInvalidOptions
	}
	result := make(map[string]string, len(d.bound.Slots))
	for _, slot := range d.bound.Slots {
		digest, err := d.specDigestForSlot(allocation, slot)
		if err != nil {
			return nil, err
		}
		result[slot.ID] = digest
	}
	return result, nil
}

// AllocateBound is only the first-dispatch entry point. The Provider
// coordinator must pass the Creating ticket returned by its BeginCreate CAS;
// a replayed persisted Creating ticket is not a new dispatch permit.
func (d *Driver) AllocateBound(ctx context.Context, allocation providerdesktop.Allocation,
	ticket sandboxidentity.Reservation) (providerdesktop.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ticket.Status != sandboxidentity.Creating ||
		ticket.PlanDigest != d.bound.PlanDigest || !d.boundSlot(ticket.Slot) ||
		!desktopClaimMatchesAllocation(ticket.Claim, allocation) {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopUnsupported
	}
	digest, err := d.specDigestForSlot(allocation, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
	}
	receipt, err := d.allocate(ctx, allocation, ticket.Slot)
	if err != nil {
		return providerdesktop.AllocationReceipt{}, err
	}
	// Every synchronous Docker/network/broker side effect of the unique
	// dispatch has ended before this exact completion proof is fsynced.
	if err := d.persistBoundCompletion(allocation, ticket, receipt); err != nil {
		return providerdesktop.AllocationReceipt{}, errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	return receipt, nil
}

func (d *Driver) persistBoundCompletion(allocation providerdesktop.Allocation,
	ticket sandboxidentity.Reservation, receipt providerdesktop.AllocationReceipt) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)
	if err != nil {
		return err
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != desktopSlotStateVersion || !state.Ready || state.CleanupPending ||
		!state.matchesAllocation(allocation) || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest || state.CompletedBound != nil {
		return providerdesktop.ErrAllocationUnknown
	}
	state.CompletedBound = &desktopBoundCompletion{Ticket: ticket, Receipt: receipt}
	return persistDesktopState(path, state, d.options.NetworkPolicyReference)
}

// CompletedBound is read-only recovery for one definitely finished dispatch.
// Ready state, an absent container, or a repeated Creating ticket alone is
// never sufficient to authorize a second Docker create.
func (d *Driver) CompletedBound(ctx context.Context, allocation providerdesktop.Allocation,
	ticket sandboxidentity.Reservation) (providerdesktop.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ctx == nil || ctx.Err() != nil ||
		ticket.Status != sandboxidentity.Creating || ticket.PlanDigest != d.bound.PlanDigest ||
		!d.boundSlot(ticket.Slot) || !desktopClaimMatchesAllocation(ticket.Claim, allocation) {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	digest, err := d.specDigestForSlot(allocation, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)
	if err != nil {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != desktopSlotStateVersion || state.CompletedBound == nil ||
		state.CompletedBound.Ticket != ticket || !state.matchesAllocation(allocation) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest ||
		!state.Ready || state.CleanupPending {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operation, state)
	if err != nil || !found || info.id != state.BackendContainerID || !info.running || info.status != "running" ||
		d.network.Inspect(operation, state.Network) != nil {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	return state.CompletedBound.Receipt, nil
}

// CompletedTerminalBound recovers the exact receipt of a finished dispatch
// whose terminal Open record never attached it. It deliberately does not
// infer resource absence; the caller must still fence and clean this claim.
func (d *Driver) CompletedTerminalBound(ctx context.Context, record providerdesktop.Record,
	ticket sandboxidentity.Reservation) (providerdesktop.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ctx == nil || ctx.Err() != nil || record.Validate() != nil ||
		record.Allocation != nil || ticket.PlanDigest != d.bound.PlanDigest || !d.boundSlot(ticket.Slot) ||
		(ticket.Status != sandboxidentity.Creating && ticket.Status != sandboxidentity.Active &&
			ticket.Status != sandboxidentity.Cleaning) ||
		(record.Status != providerdesktop.StatusFailed && record.Status != providerdesktop.StatusCancelled &&
			record.Status != providerdesktop.StatusOutcomeUnknown) {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(record.Request.SandboxID, record.Request.DesktopSessionID)
	if err != nil {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != desktopSlotStateVersion || state.CompletedBound == nil ||
		!state.CompletedBound.Ticket.SameIdentity(ticket) || state.Network.Slot != ticket.Slot ||
		state.SpecDigest != ticket.SpecDigest || !state.Receipt.AllocatedAt.Equal(record.AcceptedAt) ||
		state.Request.SandboxID != record.Request.SandboxID ||
		state.Request.DesktopSessionID != record.Request.DesktopSessionID ||
		state.Request.OperationID != record.Request.OperationID ||
		state.Request.AttemptID != record.Request.AttemptID ||
		state.Request.RequestDigest != record.Request.RequestDigest ||
		state.Request.ExpectedGeneration != record.Request.ExpectedGeneration ||
		state.Request.FencingToken != record.Request.FencingToken ||
		!state.Request.ExpiresAt.Equal(record.Request.ExpiresAt) ||
		state.Request.NetworkPolicyReference != d.options.NetworkPolicyReference {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	allocation := providerdesktop.Allocation{Request: state.Request, AllocatedAt: record.AcceptedAt}
	digest, err := d.specDigestForSlot(allocation, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	return state.CompletedBound.Receipt, nil
}

func (d *Driver) RecoverBound(ctx context.Context, allocation providerdesktop.Allocation,
	ticket sandboxidentity.Reservation) (providerdesktop.AllocationReceipt, error) {
	if d == nil || d.bound == nil || ctx == nil || ctx.Err() != nil ||
		ticket.Status != sandboxidentity.Active || ticket.PlanDigest != d.bound.PlanDigest ||
		!d.boundSlot(ticket.Slot) || !desktopClaimMatchesAllocation(ticket.Claim, allocation) {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopUnsupported
	}
	digest, err := d.specDigestForSlot(allocation, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)
	if err != nil {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrDesktopConflict
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != desktopSlotStateVersion || !state.matchesAllocation(allocation) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest || !state.Ready ||
		state.CleanupPending || state.CompletedBound == nil ||
		!state.CompletedBound.Ticket.SameIdentity(ticket) {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwned(operation, state)
	if err != nil || !found || info.id != state.BackendContainerID || !info.running || info.status != "running" ||
		d.network.Inspect(operation, state.Network) != nil {
		return providerdesktop.AllocationReceipt{}, providerdesktop.ErrAllocationUnknown
	}
	return state.Receipt, nil
}

func (d *Driver) boundSlot(slot sandboxidentity.Slot) bool {
	if d == nil || d.bound == nil || slot.Validate() != nil {
		return false
	}
	for _, allowed := range d.bound.Slots {
		if slot.ID == allowed.ID {
			return slot == allowed
		}
	}
	return false
}

func desktopClaimMatchesAllocation(claim sandboxidentity.Claim, allocation providerdesktop.Allocation) bool {
	request := allocation.Request
	return allocation.Validate() == nil && claim.Validate() == nil &&
		claim.SandboxID == request.SandboxID && claim.SessionID == request.DesktopSessionID &&
		claim.OperationID == request.OperationID && claim.AttemptID == request.AttemptID &&
		claim.RequestDigest == request.RequestDigest && claim.Generation == request.ExpectedGeneration &&
		claim.Fence == request.FencingToken
}

func (d *Driver) validateBoundReceipt(receipt providerdesktop.AllocationReceipt,
	ticket sandboxidentity.Reservation, status sandboxidentity.Status) error {
	if d == nil || d.bound == nil || receipt.Validate() != nil || ticket.Status != status ||
		ticket.PlanDigest != d.bound.PlanDigest || !d.boundSlot(ticket.Slot) {
		return providerdesktop.ErrDesktopUnsupported
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.DesktopSessionID)
	if err != nil {
		return providerdesktop.ErrDesktopConflict
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if errors.Is(err, os.ErrNotExist) {
		return providerdesktop.ErrDesktopNotFound
	}
	if err != nil || state.Version != desktopSlotStateVersion || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest ||
		state.CompletedBound == nil || !state.CompletedBound.Ticket.SameIdentity(ticket) ||
		(status == sandboxidentity.Active && state.CleanupPending) ||
		!desktopClaimMatchesAllocation(ticket.Claim,
			providerdesktop.Allocation{Request: state.Request, AllocatedAt: receipt.AllocatedAt}) {
		return providerdesktop.ErrDesktopConflict
	}
	digest, err := d.specDigestForSlot(providerdesktop.Allocation{Request: state.Request, AllocatedAt: receipt.AllocatedAt}, ticket.Slot)
	if err != nil || digest != ticket.SpecDigest {
		return providerdesktop.ErrDesktopConflict
	}
	return nil
}

func (d *Driver) ObserveBound(ctx context.Context, allocation providerdesktop.Allocation,
	receipt providerdesktop.AllocationReceipt, ticket sandboxidentity.Reservation) (providerdesktop.AllocationObservation, error) {
	if !receipt.Matches(allocation.Request) || !receipt.AllocatedAt.Equal(allocation.AllocatedAt) {
		return providerdesktop.AllocationObservation{}, providerdesktop.ErrDesktopConflict
	}
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Active); err != nil {
		return providerdesktop.AllocationObservation{}, err
	}
	return d.observe(ctx, allocation)
}

func (d *Driver) AttachBound(ctx context.Context, receipt providerdesktop.AllocationReceipt,
	ticket sandboxidentity.Reservation) (providerdesktop.Attachment, error) {
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Active); err != nil {
		return providerdesktop.Attachment{}, err
	}
	return d.attach(ctx, receipt)
}

type desktopNetworkAbsenceVerifier interface {
	Absent(context.Context, NetworkAttachment) error
}

// CleanupBound keeps the exact local evidence until independent absence and
// the Provider-owned PostgreSQL release CAS have both completed. The broker
// mux must first fence and drain all sessions admitted for this allocation.
func (d *Driver) CleanupBound(ctx context.Context, receipt providerdesktop.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Cleaning); err != nil {
		return err
	}
	if err := d.markBoundCleanupPending(receipt, ticket); err != nil {
		return err
	}
	d.mu.Lock()
	drainer := d.boundSessionDrainer
	d.mu.Unlock()
	if drainer == nil {
		return providerdesktop.ErrAllocationUnknown
	}
	if err := drainer.FenceAndDrain(ctx, receipt.SandboxID, receipt.DesktopSessionID); err != nil {
		return errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	return d.cleanup(ctx, receipt, true)
}

func (d *Driver) markBoundCleanupPending(receipt providerdesktop.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.DesktopSessionID)
	if err != nil {
		return providerdesktop.ErrDesktopConflict
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if err != nil || state.Version != desktopSlotStateVersion || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot || state.SpecDigest != ticket.SpecDigest ||
		state.CompletedBound == nil || !state.CompletedBound.Ticket.SameIdentity(ticket) {
		return providerdesktop.ErrDesktopConflict
	}
	if state.CleanupPending {
		return nil
	}
	state.CleanupPending = true
	if err := persistDesktopState(path, state, d.options.NetworkPolicyReference); err != nil {
		return errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	return nil
}

// ConfirmAbsentBound uses fresh Docker and network observations. Neither a
// successful remove call nor a single missing container releases the UID.
func (d *Driver) ConfirmAbsentBound(ctx context.Context, receipt providerdesktop.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	if err := d.validateBoundReceipt(receipt, ticket, sandboxidentity.Cleaning); err != nil {
		return err
	}
	network, ok := d.network.(desktopNetworkAbsenceVerifier)
	if !ok {
		return providerdesktop.ErrAllocationUnknown
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, path, err := d.stateLocation(receipt.SandboxID, receipt.DesktopSessionID)
	if err != nil {
		return providerdesktop.ErrDesktopConflict
	}
	state, err := loadDesktopState(path, d.options.NetworkPolicyReference)
	if err != nil || !state.CleanupPending || !state.matchesReceipt(receipt) ||
		state.Network.Slot != ticket.Slot {
		return providerdesktop.ErrAllocationUnknown
	}
	operation, cancel := d.operationContext(ctx)
	defer cancel()
	_, found, err := d.inspectOwned(operation, state)
	if err != nil || found {
		return providerdesktop.ErrAllocationUnknown
	}
	if err := network.Absent(operation, state.Network); err != nil {
		return providerdesktop.ErrAllocationUnknown
	}
	return nil
}

// FinalizeCleanupBound removes only the local tombstone after the PG
// CompleteCleanup CAS. A failed finalization leaves the slot already
// released, but never silently clears the evidence on an unknown result.
func (d *Driver) FinalizeCleanupBound(ctx context.Context, receipt providerdesktop.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	if err := d.ConfirmAbsentBound(ctx, receipt, ticket); err != nil {
		if errors.Is(err, providerdesktop.ErrDesktopNotFound) {
			// The caller must already have the exact Released retirement from PG.
			// A retry after successful local finalization is idempotent.
			return nil
		}
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	directory, path, err := d.stateLocation(receipt.SandboxID, receipt.DesktopSessionID)
	if err != nil {
		return providerdesktop.ErrDesktopConflict
	}
	if err := os.Remove(path); err != nil {
		return errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	opened, err := os.Open(directory)
	if err != nil {
		return errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	if err := errors.Join(opened.Sync(), opened.Close()); err != nil {
		return errors.Join(providerdesktop.ErrAllocationUnknown, err)
	}
	return nil
}
