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

// Clock keeps acceptance and cancellation completion times deterministic in
// component tests.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Canceler is an optional provider-local capability. The attachment contains
// only bounded identity and an opaque execution receipt.
type Canceler interface {
	Cancel(context.Context, providerexec.ExecutionAttachment) error
}

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
	canceler   Canceler
	clock      Clock
}

func New(repo repository.Repository, executor providerexec.Executor, clock Clock, canceler Canceler) (*Coordinator, error) {
	if repo == nil || executor == nil || clock == nil {
		return nil, ErrInvalidCoordinator
	}
	return &Coordinator{repository: repo, executor: executor, canceler: canceler, clock: clock}, nil
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
	reservation, err := c.repository.ReserveExecution(ctx, request)
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
		return reservation, err
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

// GetResult reads retained evidence and preserves the repository's pending,
// expired, and not-found distinctions.
func (c *Coordinator) GetResult(ctx context.Context, operationID string, now time.Time) (providerexec.Result, error) {
	if c == nil || c.repository == nil {
		return providerexec.Result{}, ErrInvalidCoordinator
	}
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.Result{}, err
	}
	return c.repository.GetResult(ctx, operationID, now)
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
	reservation, err := c.repository.ReserveCancellation(ctx, intent)
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
		if target.Result != nil && target.Result.Status == providerexec.ResultCancelled {
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
	now := c.clock.Now().UTC()
	if now.Before(target.Dispatch.AcceptedAt) {
		now = target.Dispatch.AcceptedAt
	}
	retained, err := providerexec.NewResult(target.Request, target.Dispatch.AcceptedAt, now, providerexec.ResultOutcome{Status: providerexec.ResultCancelled})
	if err != nil {
		return result, err
	}
	if err := c.repository.StoreResult(ctx, retained); err != nil {
		return result, err
	}
	result.Status = CancellationConfirmed
	return result, nil
}
