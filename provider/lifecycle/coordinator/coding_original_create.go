package coordinator

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func (c *Coordinator) dispatchCodingOriginal(ctx context.Context,
	operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{Operation: operation, Sandbox: sandbox}, err
	}
	ticket, running, provisioning, authority, err :=
		c.codingAtomic.repository.BeginCodingFirstCreateWithAuthority(ctx, operation.ID)
	if err != nil {
		return c.readCurrentCodingCreate(ctx, operation.ID, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{Operation: running, Sandbox: provisioning}, err
	}
	if !codingOriginalTupleMatches(ticket, running, provisioning, operation, sandbox, authority) ||
		authority.Validate(time.Now().UTC()) != nil {
		return Result{Operation: running, Sandbox: provisioning}, ErrInvalidCoordinator
	}
	deadline := running.Deadline
	if authority.ExpiresAt.Before(deadline) {
		deadline = authority.ExpiresAt
	}
	dispatchCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := contextError(dispatchCtx); err != nil || authority.Validate(time.Now().UTC()) != nil {
		if err == nil {
			err = dockercontrol.ErrInvalidAuthority
		}
		return c.markUnknownWithDispatch(ctx, running, provisioning, "coding_original_expired", err, false)
	}
	if err := c.codingAtomic.dispatcher.DispatchCodingCreateAuthority(dispatchCtx, authority); err != nil {
		return c.markUnknownWithDispatch(ctx, running, provisioning, "coding_dispatch_unknown", err, true)
	}
	// A dispatched command is not a verified Completed receipt. Readback of a
	// committed first permit never calls this dispatcher again.
	return Result{Operation: running, Sandbox: provisioning, Dispatched: true}, nil
}

func codingOriginalTupleMatches(ticket codingidentity.Reservation, running lifecycle.Operation,
	provisioning lifecycle.Sandbox, accepted lifecycle.Operation,
	sandbox lifecycle.Sandbox, authority dockercontrol.CodingCreateAuthority) bool {
	claim := ticket.Claim
	return ticket.Status == codingidentity.Creating && claim.Validate() == nil &&
		claim.OperationID == accepted.ID && claim.AttemptID == accepted.AttemptID &&
		claim.SandboxID == sandbox.ID && claim.Generation == sandbox.Generation &&
		claim.Fence == accepted.FencingToken && running.Validate() == nil &&
		running.Type == lifecycle.OperationCreate && running.State == lifecycle.OperationRunning &&
		!running.CancelRequested && running.ID == accepted.ID &&
		running.AttemptID == claim.AttemptID && running.SandboxID == claim.SandboxID &&
		running.FencingToken == claim.Fence &&
		(running.RequestDigest == "" || running.RequestDigest == claim.RequestDigest) &&
		provisioning.Validate() == nil && provisioning.ObservedState == lifecycle.ObservedProvisioning &&
		provisioning.ID == sandbox.ID && provisioning.Generation == claim.Generation &&
		authority.PlanDigest == ticket.PlanDigest && authority.SpecDigest == ticket.SpecDigest &&
		authority.SlotID == ticket.Slot.ID && authority.TenantDigest == claim.TenantDigest &&
		authority.AllocationID == claim.AllocationID && authority.SandboxID == claim.SandboxID &&
		authority.OperationID == claim.OperationID && authority.AttemptID == claim.AttemptID &&
		authority.RequestDigest == claim.RequestDigest &&
		authority.CreationGeneration == claim.Generation && authority.Fence == claim.Fence &&
		authority.AuthorizedGeneration == provisioning.Generation &&
		authority.ProviderRevisionID == provisioning.ProviderRevisionID &&
		!authority.IssuedAt.Before(running.ObservedAt) &&
		authority.OperationDeadline.Equal(running.Deadline)
}
