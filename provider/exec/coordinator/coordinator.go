// Package coordinator provides the bounded provider-local ordering between
// durable exec admission, executor dispatch, and receipt attachment. It does
// not expose HTTP, select a backend, or reuse the lifecycle repository.
package coordinator

import (
	"context"
	"errors"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
)

var (
	ErrInvalidCoordinator = errors.New("invalid exec coordinator")
)

const cancellationPersistenceTimeout = 5 * time.Second

// Clock keeps acceptance and cancellation completion times deterministic in
// component tests.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Canceler remains an exported alias for callers built against the P2.2c
// coordinator boundary.
type Canceler = providerexec.Canceler

// CancellationStatus describes what this coordinator can prove. A durable
// intent is not proof of process cancellation.
type CancellationStatus string

const (
	CancellationPending   CancellationStatus = "pending"
	CancellationConfirmed CancellationStatus = "confirmed"
)

type CancellationResult struct {
	Reservation providerexec.CancellationReservation
	Status      CancellationStatus
}

type Coordinator struct {
	repository repository.Repository
	executor   providerexec.Executor
	observer   providerexec.Observer
	canceler   providerexec.Canceler
	cleaner    providerexec.ResultCleaner
	resultSink providerexec.ResultObserver
	clock      Clock
}

func New(repo repository.Repository, executor providerexec.Executor, clock Clock, canceler Canceler) (*Coordinator, error) {
	return NewWithRuntime(repo, executor, nil, canceler, nil, clock)
}

func NewWithObserver(repo repository.Repository, executor providerexec.Executor, observer providerexec.Observer, clock Clock, canceler providerexec.Canceler) (*Coordinator, error) {
	return NewWithRuntime(repo, executor, observer, canceler, nil, clock)
}

func NewWithRuntime(repo repository.Repository, executor providerexec.Executor, observer providerexec.Observer, canceler providerexec.Canceler, cleaner providerexec.ResultCleaner, clock Clock) (*Coordinator, error) {
	return newWithRuntime(repo, executor, observer, canceler, cleaner, nil, clock)
}

func NewWithRuntimeAndResultObserver(repo repository.Repository, executor providerexec.Executor, observer providerexec.Observer, canceler providerexec.Canceler, cleaner providerexec.ResultCleaner, resultSink providerexec.ResultObserver, clock Clock) (*Coordinator, error) {
	return newWithRuntime(repo, executor, observer, canceler, cleaner, resultSink, clock)
}

func newWithRuntime(repo repository.Repository, executor providerexec.Executor, observer providerexec.Observer, canceler providerexec.Canceler, cleaner providerexec.ResultCleaner, resultSink providerexec.ResultObserver, clock Clock) (*Coordinator, error) {
	if repo == nil || executor == nil || clock == nil {
		return nil, ErrInvalidCoordinator
	}
	return &Coordinator{repository: repo, executor: executor, observer: observer, canceler: canceler, cleaner: cleaner, resultSink: resultSink, clock: clock}, nil
}

// Start durably reserves an execution before invoking the executor. Replayed
// reservations are returned without dispatch: after a crash between dispatch
// and attachment, retry must not create a second process.
func (c *Coordinator) Start(ctx context.Context, request providerexec.Request) (providerexec.ExecutionReservation, error) {
	if c == nil || c.repository == nil || c.executor == nil || c.clock == nil {
		return providerexec.ExecutionReservation{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.ExecutionReservation{}, err
	}
	now := c.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return providerexec.ExecutionReservation{}, err
	}
	reservation, err := c.repository.ReserveExecutionAt(ctx, request, now)
	if err != nil || reservation.Replayed {
		return reservation, err
	}

	operationContext, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return reservation, err
	}
	reference, err := c.executor.Start(operationContext, providerexec.Invocation{
		Request: request.Clone(), StartedAt: now,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return reservation, providerexec.ErrDispatchUnknown
		}
		return reservation, err
	}
	attachment := providerexec.ExecutionAttachment{
		OperationID:        request.OperationID,
		AttemptID:          request.AttemptID,
		SandboxID:          request.SandboxID,
		FencingToken:       request.FencingToken,
		ExpectedGeneration: request.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{
			ExecutionReference: reference,
			AcceptedAt:         now,
		},
	}
	attached, err := c.repository.AttachExecution(ctx, attachment)
	if err != nil {
		// The executor has already been called. The durable reservation remains
		// unattached and retries deliberately do not dispatch again.
		return reservation, errors.Join(providerexec.ErrDispatchUnknown, err)
	}
	return attached, nil
}

// GetExecution exposes provider-local pending/attached state for recovery
// inspection without dispatching work.
func (c *Coordinator) GetExecution(ctx context.Context, operationID string) (providerexec.ExecutionRecord, error) {
	if c == nil || c.repository == nil {
		return providerexec.ExecutionRecord{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.ExecutionRecord{}, err
	}
	return c.repository.GetExecution(ctx, operationID)
}

// GetCancellation exposes durable cancellation intent. It never invokes a
// Canceler and therefore cannot claim process cancellation.
func (c *Coordinator) GetCancellation(ctx context.Context, operationID string) (providerexec.CancellationIntent, error) {
	if c == nil || c.repository == nil {
		return providerexec.CancellationIntent{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.CancellationIntent{}, err
	}
	return c.repository.GetCancellation(ctx, operationID)
}

func (c *Coordinator) GetCancellationReservation(ctx context.Context, operationID string) (providerexec.CancellationReservation, error) {
	if c == nil || c.repository == nil {
		return providerexec.CancellationReservation{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.CancellationReservation{}, err
	}
	return c.repository.GetCancellationReservation(ctx, operationID)
}

// GetResult reads retained evidence and preserves the repository's pending,
// expired, and not-found distinctions.
func (c *Coordinator) GetResult(ctx context.Context, operationID string, now time.Time) (providerexec.Result, error) {
	if c == nil || c.repository == nil {
		return providerexec.Result{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.Result{}, err
	}
	record, err := c.repository.GetExecution(ctx, operationID)
	if err != nil {
		return providerexec.Result{}, err
	}
	if c.cleaner != nil && (record.ResultExpired || record.Result != nil && !now.UTC().Before(record.Result.RetainedUntil)) {
		if err := c.cleaner.CleanupResult(ctx, record.Request.Clone()); err != nil {
			return providerexec.Result{}, err
		}
	}
	result, err := c.repository.GetResult(ctx, operationID, now)
	if err != nil {
		return providerexec.Result{}, err
	}
	if err := c.observeResult(ctx, result); err != nil {
		return providerexec.Result{}, err
	}
	return result, nil
}

// StoreOutcome persists trusted bounded terminal evidence. Known provider
// failures and unknown dispatch outcomes may be stored before a receipt is
// attached; successful application or cancellation evidence may not.
func (c *Coordinator) StoreOutcome(ctx context.Context, operationID string, startedAt, completedAt time.Time, outcome providerexec.ResultOutcome) (providerexec.Result, error) {
	if c == nil || c.repository == nil {
		return providerexec.Result{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.Result{}, err
	}
	record, err := c.repository.GetExecution(ctx, operationID)
	if err != nil {
		return providerexec.Result{}, err
	}
	if record.Result != nil {
		result := *record.Result.Clone()
		if err := c.observeResult(ctx, result); err != nil {
			return result, err
		}
		return result, nil
	}
	if startedAt.IsZero() {
		startedAt = record.ReservedAt
	}
	if completedAt.Before(startedAt) {
		completedAt = startedAt
	}
	result, err := providerexec.NewResult(record.Request, startedAt, completedAt, outcome)
	if err != nil {
		return providerexec.Result{}, err
	}
	if err := c.repository.StoreResult(ctx, result); err != nil {
		return providerexec.Result{}, err
	}
	if err := c.observeResult(ctx, result); err != nil {
		return result, err
	}
	return result, nil
}

// Reconcile observes one accepted execution without repeating dispatch. It can
// recover a lost receipt attachment by operation identity and stores terminal
// evidence exactly once.
func (c *Coordinator) Reconcile(ctx context.Context, operationID string) (providerexec.ExecutionRecord, error) {
	if c == nil || c.repository == nil || c.clock == nil {
		return providerexec.ExecutionRecord{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.ExecutionRecord{}, err
	}
	record, err := c.repository.GetExecution(ctx, operationID)
	if err != nil || record.Result != nil || record.ResultExpired || c.observer == nil {
		return record, err
	}
	observation, err := c.observer.Observe(ctx, record.Request.Clone())
	if err != nil {
		return record, err
	}
	if err := observation.Validate(); err != nil {
		return record, providerexec.ErrInvalidObservation
	}
	if record.Attached {
		if record.Dispatch.ExecutionReference != observation.ExecutionReference {
			return record, repository.ErrConflict
		}
	} else {
		attached, attachErr := c.repository.AttachExecution(ctx, providerexec.ExecutionAttachment{
			OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID,
			SandboxID: record.Request.SandboxID, FencingToken: record.Request.FencingToken,
			ExpectedGeneration: record.Request.ExpectedGeneration,
			Dispatch:           providerexec.Dispatch{ExecutionReference: observation.ExecutionReference, AcceptedAt: observation.StartedAt},
		})
		if attachErr != nil {
			return record, attachErr
		}
		record = attached.Execution
	}
	if observation.Running {
		return record.Clone(), nil
	}
	result, err := c.StoreOutcome(ctx, operationID, observation.StartedAt, observation.CompletedAt, providerexec.ResultOutcome{
		Status: observation.Status, ExitCode: observation.ExitCode, Signal: observation.Signal,
		StdoutReference: observation.StdoutReference, StderrReference: observation.StderrReference,
		Error: observation.Error,
	})
	if err != nil {
		return record, err
	}
	record.Result = result.Clone()
	terminal, err := providerexec.NewTerminalSummary(result)
	if err != nil {
		return record, err
	}
	record.Terminal = terminal.Clone()
	return record.Clone(), nil
}

func (c *Coordinator) Recover(ctx context.Context) ([]providerexec.ExecutionRecord, error) {
	if c == nil || c.repository == nil {
		return nil, ErrInvalidCoordinator
	}
	records, err := c.repository.ListExecutions(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]providerexec.ExecutionRecord, 0, len(records))
	for _, record := range records {
		if record.ResultExpired {
			if c.cleaner != nil {
				if cleanupErr := c.cleaner.CleanupResult(ctx, record.Request.Clone()); cleanupErr != nil {
					return results, cleanupErr
				}
			}
			continue
		}
		if record.Result != nil {
			if err := c.observeResult(ctx, *record.Result.Clone()); err != nil {
				return results, err
			}
			if !c.clock.Now().UTC().Before(record.Result.RetainedUntil) {
				_, expiryErr := c.GetResult(ctx, record.Request.OperationID, c.clock.Now().UTC())
				if expiryErr != nil && !errors.Is(expiryErr, repository.ErrExpired) {
					return results, expiryErr
				}
			}
			continue
		}
		reconciled, reconcileErr := c.Reconcile(ctx, record.Request.OperationID)
		if errors.Is(reconcileErr, providerexec.ErrExecutionNotFound) {
			result, storeErr := c.StoreOutcome(ctx, record.Request.OperationID, record.ReservedAt, c.clock.Now().UTC(), providerexec.ResultOutcome{
				Status: providerexec.ResultOutcomeUnknown,
				Error:  &providerexec.ResultError{Code: "SANDBOX_EXEC_OUTCOME_UNKNOWN", Message: "execution outcome requires reconciliation", Retryable: true, Outcome: providerexec.ErrorOutcomeUnknown},
			})
			if storeErr != nil {
				return results, storeErr
			}
			reconciled = record.Clone()
			reconciled.Result = result.Clone()
			reconcileErr = nil
		}
		if reconcileErr != nil {
			return results, reconcileErr
		}
		results = append(results, reconciled.Clone())
	}
	return results, nil
}

// Cancel durably records cancellation intent first. With an attached receipt
// and a configured Canceler, a successful cancellation is the only path that
// records a cancelled result. Without that proof the intent remains pending.
func (c *Coordinator) Cancel(ctx context.Context, intent providerexec.CancellationIntent) (CancellationResult, error) {
	if c == nil || c.repository == nil || c.clock == nil {
		return CancellationResult{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return CancellationResult{}, err
	}
	now := c.clock.Now().UTC()
	reservation, err := c.repository.ReserveCancellationAt(ctx, intent, now)
	if err != nil {
		return CancellationResult{}, err
	}
	if reservation.Replayed {
		intent = reservation.Intent
	}
	result := CancellationResult{Reservation: reservation, Status: CancellationPending}
	target, err := c.repository.GetExecution(ctx, intent.TargetOperationID)
	if err != nil {
		return result, err
	}
	if reservation.Replayed {
		if target.Terminal != nil && target.Terminal.Status == providerexec.ResultCancelled {
			result.Status = CancellationConfirmed
		}
		// A replay cannot safely repeat an external cancellation side effect.
		// Recovery therefore reports pending until an authorized observer stores
		// terminal evidence.
		return result, nil
	}
	if !target.Attached {
		return result, nil
	}
	if c.canceler == nil {
		return result, nil
	}
	cancelContext, cancel := context.WithDeadline(ctx, intent.Deadline)
	defer cancel()
	if err := cancelContext.Err(); err != nil {
		return result, err
	}
	attachment := providerexec.ExecutionAttachment{
		OperationID:        target.Request.OperationID,
		AttemptID:          target.Request.AttemptID,
		SandboxID:          target.Request.SandboxID,
		FencingToken:       target.Request.FencingToken,
		ExpectedGeneration: target.Request.ExpectedGeneration,
		Dispatch:           target.Dispatch,
	}
	if err := c.canceler.Cancel(cancelContext, attachment); err != nil {
		return result, err
	}
	now = c.clock.Now().UTC()
	if now.Before(target.Dispatch.AcceptedAt) {
		now = target.Dispatch.AcceptedAt
	}
	retained, err := providerexec.NewResult(target.Request, target.Dispatch.AcceptedAt, now, providerexec.ResultOutcome{Status: providerexec.ResultCancelled})
	if err != nil {
		return result, err
	}
	writeCtx, writeCancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), cancellationPersistenceTimeout)
	defer writeCancel()
	if err := c.repository.StoreResult(writeCtx, retained); err != nil {
		return result, err
	}
	if err := c.observeResult(writeCtx, retained); err != nil {
		return result, err
	}
	result.Status = CancellationConfirmed
	return result, nil
}

func (c *Coordinator) observeResult(ctx context.Context, result providerexec.Result) error {
	if c.resultSink == nil {
		return nil
	}
	return c.resultSink.ObserveResult(ctx, result)
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
