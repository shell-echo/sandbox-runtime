// Package coordinator executes provider-local lifecycle work after an
// operation has been durably accepted. It deliberately has no HTTP or
// aggregate operation-ledger dependencies.
package coordinator

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var (
	ErrInvalidCoordinator = errors.New("invalid lifecycle coordinator")
	ErrUnknownRuntime     = errors.New("runtime outcome is unknown")
)

const persistenceTimeout = 5 * time.Second

// RuntimeState is the bounded observation a provider driver may return. The
// coordinator does not expose backend-specific states or diagnostics.
type RuntimeState string

const (
	RuntimeAbsent       RuntimeState = "absent"
	RuntimeProvisioning RuntimeState = "provisioning"
	RuntimeReady        RuntimeState = "ready"
)

// RuntimeObservation is an authoritative point-in-time provider observation.
// A driver must return RuntimeAbsent only when it can establish that the
// provider resource does not exist.
type RuntimeObservation struct {
	State RuntimeState
}

// Driver is the provider-local runtime port. Create must make the requested
// sandbox ready or return an error; it must not return backend IDs or paths.
// Inspect is used after a restart or lost response to reconcile a pending
// operation. Orphan cleanup is an optional capability and is not called by
// this slice.
type Driver interface {
	Create(context.Context, lifecycle.Sandbox) error
	Inspect(context.Context, string) (RuntimeObservation, error)
}

// OrphanCleaner is intentionally separate from Driver until the orphan
// cleanup policy and its Contract projection have their own release gate.
type OrphanCleaner interface {
	Remove(context.Context, string) error
}

// Clock makes deadline and transition tests deterministic.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Result describes the latest provider-local state after reconciliation.
type Result struct {
	Operation  lifecycle.Operation
	Sandbox    lifecycle.Sandbox
	Dispatched bool
}

// Coordinator combines lifecycle transitions, repository atomic writes, and
// provider runtime observations. It is safe for concurrent callers when the
// supplied repository is safe for concurrent callers.
type Coordinator struct {
	mu         sync.Mutex
	repository repository.Repository
	driver     Driver
	clock      Clock
}

func New(repo repository.Repository, driver Driver, clock Clock) (*Coordinator, error) {
	if repo == nil || driver == nil || clock == nil {
		return nil, ErrInvalidCoordinator
	}
	return &Coordinator{repository: repo, driver: driver, clock: clock}, nil
}

// AcceptCreate validates and durably accepts a create request. No runtime
// dispatch occurs before this method returns successfully.
func (c *Coordinator) AcceptCreate(ctx context.Context, request lifecycle.CreateRequest) (repository.CreateResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.CreateResult{}, err
	}
	now := c.clock.Now()
	sandbox, operation, err := lifecycle.StartCreate(request, now)
	if err != nil {
		return repository.CreateResult{}, err
	}
	return c.repository.ReserveCreate(ctx, request.IdempotencyKey, request.RequestDigest, sandbox, operation)
}

// GetSandbox reads one provider-local sandbox record without dispatching
// reconciliation or runtime work.
func (c *Coordinator) GetSandbox(ctx context.Context, sandboxID string) (lifecycle.Sandbox, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Sandbox{}, err
	}
	return c.repository.GetSandbox(ctx, sandboxID)
}

// GetOperation reads one provider-local operation record without dispatching
// reconciliation or runtime work.
func (c *Coordinator) GetOperation(ctx context.Context, operationID string) (lifecycle.Operation, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Operation{}, err
	}
	return c.repository.GetOperation(ctx, operationID)
}

// ReconcilePending resumes every non-terminal create operation in stable ID
// order. A single failure is returned after earlier results are retained; the
// next call can safely retry because all writes and events are idempotent.
func (c *Coordinator) ReconcilePending(ctx context.Context) ([]Result, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	operations, err := c.repository.ListOperations(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(operations))
	for _, operation := range operations {
		if terminalOperation(operation.State) {
			continue
		}
		result, reconcileErr := c.ReconcileOperation(ctx, operation.ID)
		if reconcileErr != nil {
			if result.Operation.ID != "" {
				results = append(results, result)
			}
			return results, reconcileErr
		}
		results = append(results, result)
	}
	return results, nil
}

// ReconcileOperation advances one provider-local create operation. Running
// operations are inspected before retrying so a lost response cannot blindly
// dispatch duplicate backend work.
func (c *Coordinator) ReconcileOperation(ctx context.Context, operationID string) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileOperation(ctx, operationID)
}

func (c *Coordinator) reconcileOperation(ctx context.Context, operationID string) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	operation, err := c.repository.GetOperation(ctx, operationID)
	if err != nil {
		return Result{}, err
	}
	sandbox, err := c.repository.GetSandbox(ctx, operation.SandboxID)
	if err != nil {
		return Result{}, err
	}
	if terminalOperation(operation.State) {
		return Result{Operation: operation, Sandbox: sandbox}, nil
	}

	switch operation.State {
	case lifecycle.OperationAccepted:
		return c.dispatchCreate(ctx, operation, sandbox)
	case lifecycle.OperationRunning, lifecycle.OperationOutcomeUnknown:
		return c.reconcileRunning(ctx, operation, sandbox)
	default:
		return Result{}, fmt.Errorf("%w: unsupported operation state %q", ErrInvalidCoordinator, operation.State)
	}
}

func (c *Coordinator) dispatchCreate(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	now := c.clock.Now()
	if err := lifecycle.CheckDeadline(now, operation.Deadline); err != nil {
		return c.failBeforeDispatch(ctx, operation, sandbox, "deadline_expired", err)
	}
	if err := contextError(ctx); err != nil {
		return c.failBeforeDispatch(ctx, operation, sandbox, "cancelled_before_dispatch", err)
	}

	provisioning, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedProvisioning, sandbox.Generation, now)
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateSandbox(ctx, provisioning, sandbox.Generation, operation.FencingToken); err != nil {
		// The repository check happens before driver dispatch. A stale attempt
		// therefore cannot create or overwrite a newer generation.
		return Result{}, err
	}
	updatedOperation, err := lifecycle.BeginOperation(operation, now)
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateOperation(ctx, updatedOperation); err != nil {
		return Result{}, err
	}
	if err := appendEvent(ctx, c.repository, updatedOperation, provisioning, "provisioning", now); err != nil {
		return Result{}, err
	}

	operationContext, cancel := c.operationContext(ctx, operation.Deadline)
	defer cancel()
	if err := contextError(operationContext); err != nil {
		return c.markUnknownWithDispatch(ctx, updatedOperation, provisioning, "dispatch_deadline", err, false)
	}
	err = c.driver.Create(operationContext, provisioning)
	if err != nil {
		if errors.Is(err, ErrUnknownRuntime) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return c.markUnknown(ctx, updatedOperation, provisioning, "runtime_create_unknown", err)
		}
		return c.markKnownFailure(ctx, updatedOperation, provisioning, "runtime_create_failed", err)
	}
	return c.markReady(ctx, updatedOperation, provisioning, true)
}

func (c *Coordinator) reconcileRunning(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	operationContext, cancel := c.operationContext(ctx, operation.Deadline)
	defer cancel()
	if err := contextError(operationContext); err != nil {
		return c.markUnknown(ctx, operation, sandbox, "reconcile_deadline", err)
	}
	observation, err := c.driver.Inspect(operationContext, sandbox.ID)
	if err != nil {
		return c.markUnknown(ctx, operation, sandbox, "reconcile_inspect_unknown", err)
	}
	switch observation.State {
	case RuntimeReady:
		if operation.State == lifecycle.OperationOutcomeUnknown {
			return c.markSandboxReady(ctx, operation, sandbox)
		}
		return c.markReady(ctx, operation, sandbox, false)
	case RuntimeAbsent:
		if operation.State == lifecycle.OperationOutcomeUnknown {
			return Result{Operation: operation, Sandbox: sandbox}, nil
		}
		return c.markKnownFailure(ctx, operation, sandbox, "runtime_absent", errors.New("runtime is absent"))
	case RuntimeProvisioning:
		return Result{Operation: operation, Sandbox: sandbox}, nil
	default:
		return c.markUnknown(ctx, operation, sandbox, "invalid_runtime_observation", ErrUnknownRuntime)
	}
}

func (c *Coordinator) failBeforeDispatch(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, code string, cause error) (Result, error) {
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	failure := lifecycle.Failure{Code: code, Retryable: false, Outcome: lifecycle.FailureKnown}
	updatedOperation, err := lifecycle.FailOperation(operation, c.clock.Now(), failure)
	if err != nil {
		return Result{}, fmt.Errorf("mark %s: %w", code, err)
	}
	if err := c.repository.UpdateOperation(writeCtx, updatedOperation); err != nil {
		return Result{}, err
	}
	if err := appendEvent(writeCtx, c.repository, updatedOperation, sandbox, "failed", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updatedOperation, Sandbox: sandbox}, fmt.Errorf("%s: %w", code, cause)
}

func (c *Coordinator) markReady(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, dispatched bool) (Result, error) {
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	ready, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedReady, sandbox.Generation, c.clock.Now())
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateSandbox(writeCtx, ready, sandbox.Generation, operation.FencingToken); err != nil {
		return Result{}, err
	}
	updatedOperation, err := lifecycle.SucceedOperation(operation, c.clock.Now())
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateOperation(writeCtx, updatedOperation); err != nil {
		return Result{}, err
	}
	if err := appendEvent(writeCtx, c.repository, updatedOperation, ready, "ready", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updatedOperation, Sandbox: ready, Dispatched: dispatched}, nil
}

func (c *Coordinator) markSandboxReady(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	ready, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedReady, sandbox.Generation, c.clock.Now())
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateSandbox(writeCtx, ready, sandbox.Generation, operation.FencingToken); err != nil {
		return Result{}, err
	}
	if err := appendEvent(writeCtx, c.repository, operation, ready, "reconciled-ready", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: operation, Sandbox: ready}, nil
}

func (c *Coordinator) markKnownFailure(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, code string, cause error) (Result, error) {
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	failedSandbox, transitionErr := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedFailed, sandbox.Generation, c.clock.Now())
	if transitionErr == nil {
		if err := c.repository.UpdateSandbox(writeCtx, failedSandbox, sandbox.Generation, operation.FencingToken); err != nil {
			return Result{}, err
		}
	} else if !errors.Is(transitionErr, lifecycle.ErrInvalidTransition) {
		return Result{}, transitionErr
	} else {
		failedSandbox = sandbox
	}
	failure := lifecycle.Failure{Code: code, Retryable: true, Outcome: lifecycle.FailureKnown}
	updatedOperation, err := lifecycle.FailOperation(operation, c.clock.Now(), failure)
	if err != nil {
		return Result{}, err
	}
	if err := c.repository.UpdateOperation(writeCtx, updatedOperation); err != nil {
		return Result{}, err
	}
	if err := appendEvent(writeCtx, c.repository, updatedOperation, failedSandbox, "failed", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updatedOperation, Sandbox: failedSandbox, Dispatched: true}, fmt.Errorf("%s: %w", code, cause)
}

func (c *Coordinator) markUnknown(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, code string, cause error) (Result, error) {
	return c.markUnknownWithDispatch(ctx, operation, sandbox, code, cause, true)
}

func (c *Coordinator) markUnknownWithDispatch(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox, code string, cause error, dispatched bool) (Result, error) {
	writeCtx, cancel := c.persistenceContext(ctx)
	defer cancel()
	failure := lifecycle.Failure{Code: code, Retryable: true, Outcome: lifecycle.FailureUnknown}
	updatedOperation, err := lifecycle.MarkOutcomeUnknown(operation, c.clock.Now(), failure)
	if err != nil {
		if errors.Is(err, lifecycle.ErrTerminalOperation) {
			return Result{Operation: operation, Sandbox: sandbox}, nil
		}
		return Result{}, err
	}
	if err := c.repository.UpdateOperation(writeCtx, updatedOperation); err != nil {
		return Result{}, err
	}
	if err := appendEvent(writeCtx, c.repository, updatedOperation, sandbox, "outcome-unknown", c.clock.Now()); err != nil {
		return Result{}, err
	}
	return Result{Operation: updatedOperation, Sandbox: sandbox, Dispatched: dispatched}, fmt.Errorf("%s: %w", code, cause)
}

func appendEvent(ctx context.Context, repo repository.Repository, operation lifecycle.Operation, sandbox lifecycle.Sandbox, kind string, now time.Time) error {
	digest := sha256.Sum256([]byte(operation.ID + "\x00" + string(operation.State) + "\x00" + kind))
	event := lifecycle.Event{
		ID: "event-" + fmt.Sprintf("%x", digest[:]), SandboxID: sandbox.ID,
		OperationID: operation.ID, Generation: sandbox.Generation,
		FencingToken: operation.FencingToken, Kind: kind, OccurredAt: now,
	}
	_, err := repo.AppendEvent(ctx, event)
	return err
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func (c *Coordinator) operationContext(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	remaining := deadline.Sub(c.clock.Now())
	if remaining < 0 {
		remaining = 0
	}
	return context.WithTimeout(parent, remaining)
}

func (c *Coordinator) persistenceContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(parent), persistenceTimeout)
}

func terminalOperation(state lifecycle.OperationState) bool {
	switch state {
	case lifecycle.OperationSucceeded, lifecycle.OperationFailed,
		lifecycle.OperationCancelled:
		return true
	default:
		return false
	}
}
