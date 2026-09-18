package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

const eventPageSize = 100

const leaseExpiryOperationTimeout = 5 * time.Minute

// AcceptDesiredState durably records one suspend or resume intent before any
// driver call. Exact operation replays return the retained operation.
func (c *Coordinator) AcceptDesiredState(ctx context.Context, sandboxID string, request lifecycle.DesiredStateRequest) (repository.MutationResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.MutationResult{}, err
	}
	if replay, ok, err := c.mutationReplay(ctx, sandboxID, request.MutationRequest); ok || err != nil {
		return replay, err
	}
	now := c.clock.Now()
	sandbox, err := c.repository.GetSandbox(ctx, sandboxID)
	if err != nil {
		return repository.MutationResult{}, err
	}
	updated, operation, err := lifecycle.StartDesiredState(sandbox, request, now)
	if err != nil {
		return repository.MutationResult{}, err
	}
	event := acceptedEvent(operation, updated, request.RequestDigest, "desired-state-requested", now)
	return c.repository.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest, request.ExpectedGeneration, updated, operation, event)
}

// AcceptLease durably extends a lease and records its operation in the same
// repository transaction.
func (c *Coordinator) AcceptLease(ctx context.Context, sandboxID string, request lifecycle.LeaseRequest, maxLeaseSeconds int64) (repository.MutationResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.MutationResult{}, err
	}
	if replay, ok, err := c.mutationReplay(ctx, sandboxID, request.MutationRequest); ok || err != nil {
		return replay, err
	}
	now := c.clock.Now()
	sandbox, err := c.repository.GetSandbox(ctx, sandboxID)
	if err != nil {
		return repository.MutationResult{}, err
	}
	updated, _, operation, err := lifecycle.StartLeaseRenewal(sandbox, request, maxLeaseSeconds, now)
	if err != nil {
		return repository.MutationResult{}, err
	}
	event := acceptedEvent(operation, updated, request.RequestDigest, "lease-extended", now)
	return c.repository.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest, request.ExpectedGeneration, updated, operation, event)
}

// AcceptTerminate durably records irreversible termination intent before any
// runtime removal or Provider-owned storage cleanup.
func (c *Coordinator) AcceptTerminate(ctx context.Context, sandboxID string, request lifecycle.TerminateRequest) (repository.MutationResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.MutationResult{}, err
	}
	if replay, ok, err := c.mutationReplay(ctx, sandboxID, request.MutationRequest); ok || err != nil {
		return replay, err
	}
	now := c.clock.Now()
	sandbox, err := c.repository.GetSandbox(ctx, sandboxID)
	if err != nil {
		return repository.MutationResult{}, err
	}
	updated, operation, err := lifecycle.StartTerminate(sandbox, request, now)
	if err != nil {
		return repository.MutationResult{}, err
	}
	event := acceptedEvent(operation, updated, request.RequestDigest, "termination-requested", now)
	return c.repository.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest, request.ExpectedGeneration, updated, operation, event)
}

func (c *Coordinator) mutationReplay(ctx context.Context, sandboxID string, request lifecycle.MutationRequest) (repository.MutationResult, bool, error) {
	operation, err := c.repository.GetOperation(ctx, request.OperationID)
	if errors.Is(err, repository.ErrNotFound) {
		return repository.MutationResult{}, false, nil
	}
	if err != nil {
		return repository.MutationResult{}, false, err
	}
	if operation.SandboxID != sandboxID || operation.AttemptID != request.AttemptID || operation.FencingToken != request.FencingToken ||
		operation.IdempotencyKey != request.IdempotencyKey || operation.RequestDigest != request.RequestDigest {
		return repository.MutationResult{}, true, repository.ErrIdempotencyConflict
	}
	sandbox, err := c.repository.GetSandbox(ctx, sandboxID)
	if err != nil {
		return repository.MutationResult{}, true, err
	}
	return repository.MutationResult{Operation: operation, Sandbox: sandbox, Replayed: true}, true, nil
}

func (c *Coordinator) ReadEvents(ctx context.Context, sandboxID string, after uint64) (repository.EventPage, error) {
	if err := contextError(ctx); err != nil {
		return repository.EventPage{}, err
	}
	return c.repository.ReadEvents(ctx, sandboxID, after, eventPageSize)
}

// ProcessExpiredLeases converts each elapsed nonterminal lease into a durable
// termination attempt and runs that attempt through the same observation and
// cleanup path as an explicit termination. The derived identities are stable
// across restart, while the retained fencing token prevents expiry work from
// overwriting newer caller authority.
func (c *Coordinator) ProcessExpiredLeases(ctx context.Context) ([]Result, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	sandboxes, err := c.repository.ListSandboxes(ctx)
	if err != nil {
		return nil, err
	}
	operations, err := c.repository.ListOperations(ctx)
	if err != nil {
		return nil, err
	}
	pendingTermination := make(map[string]bool)
	for _, operation := range operations {
		if operation.Type == lifecycle.OperationTerminate && !terminalOperation(operation.State) {
			pendingTermination[operation.SandboxID] = true
		}
	}
	now := c.clock.Now()
	results := make([]Result, 0)
	for _, sandbox := range sandboxes {
		if now.Before(sandbox.LeaseExpiresAt) || sandbox.ObservedState == lifecycle.ObservedTerminated || sandbox.ObservedState == lifecycle.ObservedExpired {
			continue
		}
		if pendingTermination[sandbox.ID] {
			// ReconcilePending owns a retained explicit or prior expiry attempt.
			// Do not invent a second operation while that attempt may still have
			// taken effect.
			continue
		}
		lease, leaseErr := c.repository.GetLease(ctx, sandbox.ID)
		if leaseErr != nil {
			return results, leaseErr
		}
		request := leaseExpiryTerminateRequest(sandbox, lease, now)
		updated, operation, startErr := lifecycle.StartTerminate(sandbox, request, now)
		if startErr != nil {
			return results, startErr
		}
		event := acceptedEvent(operation, updated, request.RequestDigest, "lease-expired", now)
		reserved, reserveErr := c.repository.ReserveMutation(ctx, request.IdempotencyKey, request.RequestDigest, request.ExpectedGeneration, updated, operation, event)
		if reserveErr != nil {
			if errors.Is(reserveErr, lifecycle.ErrGenerationConflict) || errors.Is(reserveErr, lifecycle.ErrStaleFencingToken) {
				continue
			}
			return results, reserveErr
		}
		pendingTermination[sandbox.ID] = true
		result, reconcileErr := c.reconcileOperation(ctx, reserved.Operation.ID)
		if result.Operation.ID != "" {
			results = append(results, result)
		}
		if reconcileErr != nil {
			return results, reconcileErr
		}
	}
	return results, nil
}

func leaseExpiryTerminateRequest(sandbox lifecycle.Sandbox, lease lifecycle.Lease, now time.Time) lifecycle.TerminateRequest {
	seed := sandbox.ProviderRevisionID + "\x00" + sandbox.ID + "\x00" + fmt.Sprintf("%d", sandbox.Generation) + "\x00" + sandbox.LeaseExpiresAt.UTC().Format(time.RFC3339Nano)
	digest := sha256.Sum256([]byte(seed))
	id := fmt.Sprintf("lease-expiry-%x", digest[:16])
	requestDigest := sha256.Sum256([]byte("lease-expiry-request\x00" + seed))
	return lifecycle.TerminateRequest{
		MutationRequest: lifecycle.MutationRequest{
			OperationID: id, AttemptID: id, FencingToken: lease.FencingToken,
			IdempotencyKey: id, RequestDigest: fmt.Sprintf("sha256:%x", requestDigest[:]),
			Deadline: now.Add(leaseExpiryOperationTimeout), ExpectedGeneration: sandbox.Generation,
		},
		Reason: "lease_expired",
	}
}

func (c *Coordinator) reconcileLease(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	if operation.State == lifecycle.OperationOutcomeUnknown {
		return Result{Operation: operation, Sandbox: sandbox}, nil
	}
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	updated := operation
	var err error
	if updated.State == lifecycle.OperationAccepted {
		updated, err = lifecycle.BeginOperation(updated, c.clock.Now())
		if err != nil {
			return c.failBeforeDispatch(ctx, operation, sandbox, "deadline_expired", err)
		}
		if err := c.repository.UpdateOperation(writeCtx, updated); err != nil {
			return Result{}, err
		}
	}
	updated, err = lifecycle.SucceedOperation(updated, c.clock.Now())
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateOperation(writeCtx, updated); err != nil {
		return Result{}, err
	}
	if err := appendEvent(writeCtx, c.repository, updated, sandbox, "lease-renewal-succeeded", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updated, Sandbox: sandbox}, nil
}

func (c *Coordinator) reconcileDesiredState(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	target, intermediate, action, err := desiredRuntimeAction(c.driver, operation.Type)
	if err != nil {
		if operation.State == lifecycle.OperationOutcomeUnknown {
			return Result{Operation: operation, Sandbox: sandbox}, err
		}
		return c.markKnownFailure(ctx, operation, sandbox, "lifecycle_control_unsupported", err)
	}
	if operation.State == lifecycle.OperationAccepted {
		now := c.clock.Now()
		transitioning, transitionErr := lifecycle.ApplyObservedTransition(sandbox, intermediate, sandbox.Generation, now)
		if transitionErr != nil {
			return Result{}, transitionErr
		}
		if err := c.repository.UpdateSandbox(ctx, transitioning, sandbox.Generation, operation.FencingToken); err != nil {
			return Result{}, err
		}
		updated, beginErr := lifecycle.BeginOperation(operation, now)
		if beginErr != nil {
			return c.failBeforeDispatch(ctx, operation, transitioning, "deadline_expired", beginErr)
		}
		if err := c.repository.UpdateOperation(ctx, updated); err != nil {
			return Result{}, err
		}
		if err := appendEvent(ctx, c.repository, updated, transitioning, string(intermediate), now); err != nil {
			return Result{}, err
		}
		operation, sandbox = updated, transitioning
	}

	operationContext, cancel := c.operationContext(ctx, operation.Deadline)
	defer cancel()
	observation, inspectErr := c.driver.Inspect(operationContext, sandbox.ID)
	if inspectErr != nil {
		return c.markUnknown(ctx, operation, sandbox, "reconcile_inspect_unknown", inspectErr)
	}
	if observation.State == target {
		return c.markDesiredTarget(ctx, operation, sandbox, target, false)
	}
	if operation.State == lifecycle.OperationOutcomeUnknown {
		return Result{Operation: operation, Sandbox: sandbox}, nil
	}
	if err := action(operationContext, sandbox.ID); err != nil {
		if errors.Is(err, ErrUnknownRuntime) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return c.markUnknown(ctx, operation, sandbox, "lifecycle_control_unknown", err)
		}
		return c.markKnownFailure(ctx, operation, sandbox, "lifecycle_control_failed", err)
	}
	confirmed, inspectErr := c.driver.Inspect(operationContext, sandbox.ID)
	if inspectErr != nil || confirmed.State != target {
		return c.markUnknown(ctx, operation, sandbox, "lifecycle_confirmation_unknown", errors.Join(ErrUnknownRuntime, inspectErr))
	}
	return c.markDesiredTarget(ctx, operation, sandbox, target, true)
}

func desiredRuntimeAction(driver Driver, operationType lifecycle.OperationType) (RuntimeState, lifecycle.ObservedState, func(context.Context, string) error, error) {
	controller, ok := driver.(StateController)
	if !ok {
		return "", "", nil, ErrInvalidCoordinator
	}
	switch operationType {
	case lifecycle.OperationSuspend:
		return RuntimeSuspended, lifecycle.ObservedSuspending, controller.Suspend, nil
	case lifecycle.OperationResume:
		return RuntimeReady, lifecycle.ObservedResuming, controller.Resume, nil
	default:
		return "", "", nil, ErrInvalidCoordinator
	}
}

func (c *Coordinator) markDesiredTarget(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, target RuntimeState, dispatched bool) (Result, error) {
	observed := lifecycle.ObservedReady
	kind := "ready"
	if target == RuntimeSuspended {
		observed, kind = lifecycle.ObservedSuspended, "suspended"
	}
	if sandbox.ObservedState == observed && sandbox.ObservedGeneration == sandbox.Generation {
		return Result{Operation: operation, Sandbox: sandbox, Dispatched: dispatched}, nil
	}
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	updatedSandbox, err := lifecycle.ApplyObservedTransition(sandbox, observed, sandbox.Generation, c.clock.Now())
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateSandbox(writeCtx, updatedSandbox, sandbox.Generation, operation.FencingToken); err != nil {
		return Result{}, err
	}
	updatedOperation := operation
	if operation.State != lifecycle.OperationOutcomeUnknown {
		updatedOperation, err = lifecycle.SucceedOperation(operation, c.clock.Now())
		if err != nil {
			return Result{}, err
		}
		if err := c.repository.UpdateOperation(writeCtx, updatedOperation); err != nil {
			return Result{}, err
		}
	}
	if err := appendEvent(writeCtx, c.repository, updatedOperation, updatedSandbox, kind, c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updatedOperation, Sandbox: updatedSandbox, Dispatched: dispatched}, nil
}

func (c *Coordinator) reconcileTerminate(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	cleaner, ok := c.driver.(OrphanCleaner)
	if !ok {
		if operation.State == lifecycle.OperationOutcomeUnknown {
			return Result{Operation: operation, Sandbox: sandbox}, ErrInvalidCoordinator
		}
		return c.markKnownFailure(ctx, operation, sandbox, "termination_unsupported", ErrInvalidCoordinator)
	}
	if operation.State == lifecycle.OperationAccepted {
		now := c.clock.Now()
		terminating, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedTerminating, sandbox.Generation, now)
		if err != nil {
			return Result{}, err
		}
		if err := c.repository.UpdateSandbox(ctx, terminating, sandbox.Generation, operation.FencingToken); err != nil {
			return Result{}, err
		}
		updated, err := lifecycle.BeginOperation(operation, now)
		if err != nil {
			return c.failBeforeDispatch(ctx, operation, terminating, "deadline_expired", err)
		}
		if err := c.repository.UpdateOperation(ctx, updated); err != nil {
			return Result{}, err
		}
		if err := appendEvent(ctx, c.repository, updated, terminating, "terminating", now); err != nil {
			return Result{}, err
		}
		operation, sandbox = updated, terminating
	}
	operationContext, cancel := c.operationContext(ctx, operation.Deadline)
	defer cancel()
	observation, inspectErr := c.driver.Inspect(operationContext, sandbox.ID)
	if inspectErr != nil {
		return c.markUnknown(ctx, operation, sandbox, "termination_inspect_unknown", inspectErr)
	}
	if observation.State == RuntimeAbsent {
		return c.markTerminated(ctx, operation, sandbox, false)
	}
	if operation.State == lifecycle.OperationOutcomeUnknown {
		return Result{Operation: operation, Sandbox: sandbox}, nil
	}
	if err := cleaner.Remove(operationContext, sandbox.ID); err != nil {
		return c.markUnknown(ctx, operation, sandbox, "runtime_remove_unknown", err)
	}
	observation, err := c.driver.Inspect(operationContext, sandbox.ID)
	if err != nil || observation.State != RuntimeAbsent {
		return c.markUnknown(ctx, operation, sandbox, "termination_confirmation_unknown", errors.Join(ErrUnknownRuntime, err))
	}
	return c.markTerminated(ctx, operation, sandbox, true)
}

func (c *Coordinator) markTerminated(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, dispatched bool) (Result, error) {
	if sandbox.ObservedState == lifecycle.ObservedTerminated && sandbox.ObservedGeneration == sandbox.Generation {
		return Result{Operation: operation, Sandbox: sandbox, Dispatched: dispatched}, nil
	}
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	terminated, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedTerminated, sandbox.Generation, c.clock.Now())
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateSandbox(writeCtx, terminated, sandbox.Generation, operation.FencingToken); err != nil {
		return Result{}, err
	}
	updatedOperation := operation
	if operation.State != lifecycle.OperationOutcomeUnknown {
		updatedOperation, err = lifecycle.SucceedOperation(operation, c.clock.Now())
		if err != nil {
			return Result{}, err
		}
		if err := c.repository.UpdateOperation(writeCtx, updatedOperation); err != nil {
			return Result{}, err
		}
	}
	if err := appendEvent(writeCtx, c.repository, updatedOperation, terminated, "terminated", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updatedOperation, Sandbox: terminated, Dispatched: dispatched}, nil
}

func acceptedEvent(operation lifecycle.Operation, sandbox lifecycle.Sandbox, digest, kind string, now time.Time) lifecycle.Event {
	event := lifecycle.Event{
		SandboxID: sandbox.ID, OperationID: operation.ID, Generation: sandbox.Generation,
		FencingToken: operation.FencingToken, Kind: kind, DataDigest: digest, OccurredAt: now,
	}
	event.ID = eventID(operation.ID, kind)
	return event
}

func eventID(operationID, kind string) string {
	digest := operationEventDigest(operationID, kind)
	return "event-" + fmt.Sprintf("%x", digest[:])
}

func operationEventDigest(operationID, kind string) [sha256.Size]byte {
	return sha256.Sum256([]byte(operationID + "\x00" + kind))
}
