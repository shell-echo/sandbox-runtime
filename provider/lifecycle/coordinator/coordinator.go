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

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var (
	ErrInvalidCoordinator = errors.New("invalid lifecycle coordinator")
	ErrUnknownRuntime     = errors.New("runtime outcome is unknown")
)

const persistenceTimeout = 5 * time.Second
const codingConflictReadbackTimeout = time.Second

// RuntimeState is the bounded observation a provider driver may return. The
// coordinator does not expose backend-specific states or diagnostics.
type RuntimeState string

const (
	RuntimeAbsent       RuntimeState = "absent"
	RuntimeProvisioning RuntimeState = "provisioning"
	RuntimeReady        RuntimeState = "ready"
	RuntimeSuspended    RuntimeState = "suspended"
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

// CodingFirstCreateRepository is a focused, same-Store lifecycle capability.
// Its first permit must atomically move the accepted Provider operation and
// finite allocation reservation to Running/Creating. It is not a second
// business-history ledger or a generic Driver expansion.
type CodingFirstCreateRepository interface {
	repository.Repository
	BeginCodingFirstCreate(context.Context, string) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error)
}

// CodingCreateDispatcher cannot be satisfied by the legacy daemon-facing
// Driver.Create method. A nil result means only that the ticket-bound command
// was accepted for dispatch, never that physical readiness was proven.
type CodingCreateDispatcher interface {
	DispatchCodingCreate(context.Context, lifecycle.Operation, lifecycle.Sandbox, codingidentity.Reservation) error
}

// CodingOriginalCreateRepository is the v3-only first-permit capability. It
// returns the exact original authority persisted by the same PG transaction,
// never a ticket from which a later caller may re-sign an effect.
type CodingOriginalCreateRepository interface {
	repository.Repository
	BeginCodingFirstCreateWithAuthority(context.Context, string) (codingidentity.Reservation,
		lifecycle.Operation, lifecycle.Sandbox, dockercontrol.CodingCreateAuthority, error)
}

type CodingAuthorityCreateDispatcher interface {
	DispatchCodingCreateAuthority(context.Context, dockercontrol.CodingCreateAuthority) error
}

// OrphanCleaner is a focused optional lifecycle capability. Composition must
// not advertise lifecycle control unless the selected driver implements it.
type OrphanCleaner interface {
	Remove(context.Context, string) error
}

// StateController is an optional lifecycle capability. Composition must not
// advertise lifecycle control unless the selected driver implements it.
type StateController interface {
	Suspend(context.Context, string) error
	Resume(context.Context, string) error
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
	mu           sync.Mutex
	repository   repository.Repository
	driver       Driver
	clock        Clock
	coding       *codingFirstCreateBoundary
	codingAtomic *codingOriginalCreateBoundary
}

type codingFirstCreateBoundary struct {
	repository CodingFirstCreateRepository
	dispatcher CodingCreateDispatcher
}

type codingOriginalCreateBoundary struct {
	repository CodingOriginalCreateRepository
	dispatcher CodingAuthorityCreateDispatcher
}

func New(repo repository.Repository, driver Driver, clock Clock) (*Coordinator, error) {
	if repo == nil || driver == nil || clock == nil {
		return nil, ErrInvalidCoordinator
	}
	return &Coordinator{repository: repo, driver: driver, clock: clock}, nil
}

// NewWithCodingFirstCreate is the explicit opt-in for the Profile-v2 coding
// path. It never falls back to Driver.Create and does not claim that the
// not-yet-composed control receipt/recovery path is production ready.
func NewWithCodingFirstCreate(repo CodingFirstCreateRepository, driver Driver, clock Clock) (*Coordinator, error) {
	service, err := New(repo, driver, clock)
	if err != nil {
		return nil, err
	}
	dispatcher, ok := driver.(CodingCreateDispatcher)
	if !ok {
		return nil, ErrInvalidCoordinator
	}
	service.coding = &codingFirstCreateBoundary{repository: repo, dispatcher: dispatcher}
	return service, nil
}

// NewWithCodingOriginalAuthority is the only v3 candidate composition. A
// legacy-only dispatcher cannot satisfy it and no fallback is attempted.
func NewWithCodingOriginalAuthority(repo CodingOriginalCreateRepository,
	driver Driver, clock Clock) (*Coordinator, error) {
	service, err := New(repo, driver, clock)
	if err != nil {
		return nil, err
	}
	dispatcher, ok := driver.(CodingAuthorityCreateDispatcher)
	if !ok {
		return nil, ErrInvalidCoordinator
	}
	service.codingAtomic = &codingOriginalCreateBoundary{repository: repo, dispatcher: dispatcher}
	return service, nil
}

// AcceptCreate validates and durably accepts a create request. No runtime
// dispatch occurs before this method returns successfully.
func (c *Coordinator) AcceptCreate(ctx context.Context, request lifecycle.CreateRequest) (repository.CreateResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.CreateResult{}, err
	}
	if (c.coding != nil || c.codingAtomic != nil) && (request.Spec.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		request.Spec.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone})) {
		return repository.CreateResult{}, ErrInvalidCoordinator
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
		if operation.State == lifecycle.OperationOutcomeUnknown {
			sandbox, sandboxErr := c.repository.GetSandbox(ctx, operation.SandboxID)
			if sandboxErr != nil {
				return results, sandboxErr
			}
			if unknownOutcomeObserved(operation.Type, sandbox) {
				continue
			}
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

func unknownOutcomeObserved(operationType lifecycle.OperationType, sandbox lifecycle.Sandbox) bool {
	if sandbox.ObservedGeneration != sandbox.Generation {
		return false
	}
	switch operationType {
	case lifecycle.OperationCreate, lifecycle.OperationResume:
		return sandbox.ObservedState == lifecycle.ObservedReady
	case lifecycle.OperationSuspend:
		return sandbox.ObservedState == lifecycle.ObservedSuspended
	case lifecycle.OperationTerminate:
		return sandbox.ObservedState == lifecycle.ObservedTerminated
	default:
		return false
	}
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
	if c.codingAtomic != nil && operation.Type != lifecycle.OperationCreate {
		// The v3 Control/typed-PG lifecycle path is distinct from the old
		// Driver Inspect/Remove/Suspend/Resume shortcuts. Until that path is
		// composed, retain the accepted operation without physical work or a
		// fabricated terminal result, even if the supplied driver happens to
		// implement every legacy optional capability.
		return Result{Operation: operation, Sandbox: sandbox}, ErrUnknownRuntime
	}

	switch operation.Type {
	case lifecycle.OperationCreate:
		switch operation.State {
		case lifecycle.OperationAccepted:
			return c.dispatchCreate(ctx, operation, sandbox)
		case lifecycle.OperationRunning, lifecycle.OperationOutcomeUnknown:
			return c.reconcileCreate(ctx, operation, sandbox)
		}
	case lifecycle.OperationExtendLease:
		return c.reconcileLease(ctx, operation, sandbox)
	case lifecycle.OperationSuspend, lifecycle.OperationResume:
		return c.reconcileDesiredState(ctx, operation, sandbox)
	case lifecycle.OperationTerminate:
		return c.reconcileTerminate(ctx, operation, sandbox)
	}
	switch operation.State {
	default:
		return Result{}, fmt.Errorf("%w: unsupported operation %q in state %q", ErrInvalidCoordinator, operation.Type, operation.State)
	}
}

func (c *Coordinator) dispatchCreate(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	if c.codingAtomic != nil {
		return c.dispatchCodingOriginal(ctx, operation, sandbox)
	}
	if c.coding != nil {
		return c.dispatchCodingCreate(ctx, operation, sandbox)
	}
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

func (c *Coordinator) dispatchCodingCreate(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{Operation: operation, Sandbox: sandbox}, err
	}
	ticket, running, provisioning, err := c.coding.repository.BeginCodingFirstCreate(ctx, operation.ID)
	if err != nil {
		return c.readCurrentCodingCreate(ctx, operation.ID, err)
	}
	if ticket.Status != codingidentity.Creating || ticket.Claim.Validate() != nil ||
		ticket.Claim.OperationID != operation.ID || ticket.Claim.AttemptID != operation.AttemptID ||
		ticket.Claim.SandboxID != sandbox.ID || ticket.Claim.Generation != sandbox.Generation ||
		ticket.Claim.Fence != operation.FencingToken || running.Validate() != nil ||
		running.Type != lifecycle.OperationCreate || running.State != lifecycle.OperationRunning ||
		running.CancelRequested || running.ID != operation.ID ||
		running.AttemptID != ticket.Claim.AttemptID || running.SandboxID != ticket.Claim.SandboxID ||
		running.FencingToken != ticket.Claim.Fence ||
		(running.RequestDigest != "" && running.RequestDigest != ticket.Claim.RequestDigest) ||
		provisioning.ObservedState != lifecycle.ObservedProvisioning ||
		provisioning.ID != sandbox.ID {
		return Result{Operation: running, Sandbox: provisioning}, ErrInvalidCoordinator
	}
	operationContext, cancel := c.operationContext(ctx, running.Deadline)
	defer cancel()
	if err := contextError(operationContext); err != nil {
		return c.markUnknownWithDispatch(ctx, running, provisioning, "dispatch_deadline", err, false)
	}
	if err := c.coding.dispatcher.DispatchCodingCreate(operationContext, running, provisioning, ticket); err != nil {
		return c.markUnknownWithDispatch(ctx, running, provisioning, "coding_dispatch_unknown", err, true)
	}
	// Dispatch accepted is not a verified control receipt. Keep both Provider
	// and finite-slot state nonterminal until exact receipt reconciliation.
	return Result{Operation: running, Sandbox: provisioning, Dispatched: true}, nil
}

// A competing Provider may have committed the first permit since the caller
// read Accepted. Report the durable observation, never the stale pre-permit
// snapshot, and never retry or dispatch from this readback path.
func (c *Coordinator) readCurrentCodingCreate(ctx context.Context, operationID string, cause error) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, errors.Join(cause, err)
	}
	readCtx, cancel := context.WithTimeout(ctx, codingConflictReadbackTimeout)
	defer cancel()
	current, err := c.repository.GetOperation(readCtx, operationID)
	if err != nil {
		return Result{}, errors.Join(cause, err)
	}
	sandbox, err := c.repository.GetSandbox(readCtx, current.SandboxID)
	if err != nil || sandbox.ID != current.SandboxID {
		if err == nil {
			err = ErrInvalidCoordinator
		}
		return Result{}, errors.Join(cause, err)
	}
	return Result{Operation: current, Sandbox: sandbox}, cause
}

func (c *Coordinator) reconcileCreate(ctx context.Context, operation lifecycle.Operation, sandbox lifecycle.Sandbox) (Result, error) {
	if c.coding != nil || c.codingAtomic != nil {
		// An existing Creating/Running or Unknown operation cannot get a second
		// create permit. Control receipt inspection is a later, explicit gate;
		// the legacy Inspect/Ready shortcut is not valid for this path.
		return Result{Operation: operation, Sandbox: sandbox}, ErrUnknownRuntime
	}
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
	if sandbox.ObservedState == lifecycle.ObservedReady && sandbox.ObservedGeneration == sandbox.Generation {
		return Result{Operation: operation, Sandbox: sandbox}, nil
	}
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
