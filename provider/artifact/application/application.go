// Package application coordinates durable artifact staging acceptance and
// explicit worker dispatch without exposing transport or repository adapters.
package application

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var ErrInvalidApplication = errors.New("invalid artifact staging application")

const persistenceTimeout = 5 * time.Second

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Application struct {
	mu        sync.Mutex
	authority artifact.Authority
	stager    artifact.Stager
	clock     Clock
}

func New(authority artifact.Authority, stager artifact.Stager, clock Clock) (*Application, error) {
	if authority == nil || stager == nil || clock == nil {
		return nil, ErrInvalidApplication
	}
	return &Application{authority: authority, stager: stager, clock: clock}, nil
}

// Accept durably records an accepted operation and never dispatches staging.
func (a *Application) Accept(ctx context.Context, request artifact.Request) (artifact.Reservation, error) {
	if err := a.ready(ctx); err != nil {
		return artifact.Reservation{}, err
	}
	now := a.clock.Now().UTC()
	if err := request.Validate(now); err != nil {
		return artifact.Reservation{}, err
	}
	return a.authority.ReserveStage(ctx, request.Clone(), now)
}

// Dispatch is an explicit worker boundary. It persists running before calling
// the stager and never repeats a running or outcome-unknown side effect.
func (a *Application) Dispatch(ctx context.Context, operationID string) (artifact.Operation, error) {
	if a == nil || a.authority == nil || a.stager == nil || a.clock == nil {
		return artifact.Operation{}, ErrInvalidApplication
	}
	if ctx == nil {
		return artifact.Operation{}, context.Canceled
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	readCtx := ctx
	if ctx.Err() != nil {
		readCtx = context.WithoutCancel(ctx)
	}
	operation, err := a.authority.GetStage(readCtx, operationID)
	if err != nil {
		return artifact.Operation{}, err
	}
	if operation.Status != artifact.OperationAccepted {
		return a.reconcileLocked(ctx, operation)
	}
	now := a.clock.Now().UTC()
	if !operation.Request.Deadline.After(now) || !operation.Request.ExpiresAt(operation.AcceptedAt).After(now) {
		return a.failBeforeDispatch(ctx, operation, artifact.FailureDeadlineExpired, artifact.ErrDeadlineExpired)
	}
	if err := contextError(ctx); err != nil {
		return a.failBeforeDispatch(ctx, operation, artifact.FailureCancelledBeforeRun, err)
	}
	running, err := artifact.Transition(operation, artifact.OperationRunning, now, "", nil)
	if err != nil {
		return artifact.Operation{}, err
	}
	if err := a.authority.UpdateStage(ctx, running, artifact.OperationAccepted); err != nil {
		return artifact.Operation{}, err
	}
	dispatchDeadline := operation.Request.Deadline
	if evidenceDeadline := operation.Request.ExpiresAt(operation.AcceptedAt); evidenceDeadline.Before(dispatchDeadline) {
		dispatchDeadline = evidenceDeadline
	}
	operationContext, cancel := context.WithTimeout(ctx, dispatchDeadline.Sub(now))
	defer cancel()
	evidence, stageErr := a.stager.Stage(operationContext, operation.Request.Clone(), operation.AcceptedAt)
	observedAt := a.observedAfter(running.ObservedAt)
	if stageErr != nil {
		if errors.Is(stageErr, artifact.ErrSourceMissing) {
			return a.finish(ctx, running, artifact.OperationFailed, artifact.FailureSourceMissing, nil, stageErr)
		}
		return a.finish(ctx, running, artifact.OperationOutcomeUnknown, artifact.FailureDispatchUnknown, nil, errors.Join(artifact.ErrOutcomeUnknown, stageErr))
	}
	switch evidence.Status {
	case artifact.StatusStaged:
		return a.finishAt(ctx, running, artifact.OperationSucceeded, "", &evidence, observedAt, nil)
	case artifact.StatusRejected:
		return a.finishAt(ctx, running, artifact.OperationFailed, artifact.FailureContentRejected, &evidence, observedAt, nil)
	default:
		return a.finishAt(ctx, running, artifact.OperationOutcomeUnknown, artifact.FailureDispatchUnknown, nil, observedAt, artifact.ErrOutcomeUnknown)
	}
}

// Reconcile advances accepted work through the explicit worker boundary and
// converts recovered running records to outcome_unknown without redispatch.
func (a *Application) Reconcile(ctx context.Context, operationID string) (artifact.Operation, error) {
	if err := a.ready(ctx); err != nil {
		return artifact.Operation{}, err
	}
	a.mu.Lock()
	operation, err := a.authority.GetStage(ctx, operationID)
	if err != nil {
		a.mu.Unlock()
		return artifact.Operation{}, err
	}
	if operation.Status == artifact.OperationAccepted {
		a.mu.Unlock()
		return a.Dispatch(ctx, operationID)
	}
	result, reconcileErr := a.reconcileLocked(ctx, operation)
	a.mu.Unlock()
	return result, reconcileErr
}

// Recover processes records in repository order. Accepted records may be
// dispatched exactly once; recovered running records are retained as unknown.
func (a *Application) Recover(ctx context.Context) ([]artifact.Operation, error) {
	if err := a.ready(ctx); err != nil {
		return nil, err
	}
	operations, err := a.authority.ListStages(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]artifact.Operation, 0, len(operations))
	recoveredUnknown := false
	for _, operation := range operations {
		if operation.Status != artifact.OperationAccepted && operation.Status != artifact.OperationRunning && operation.Status != artifact.OperationOutcomeUnknown {
			continue
		}
		result, reconcileErr := a.Reconcile(ctx, operation.Request.OperationID)
		if result.Request.OperationID != "" {
			results = append(results, result.Clone())
		}
		if reconcileErr != nil {
			if reconcileErr == artifact.ErrOutcomeUnknown {
				recoveredUnknown = true
				continue
			}
			return results, reconcileErr
		}
	}
	if recoveredUnknown {
		return results, artifact.ErrOutcomeUnknown
	}
	return results, nil
}

func (a *Application) GetOperation(ctx context.Context, operationID string) (artifact.Operation, error) {
	if err := a.ready(ctx); err != nil {
		return artifact.Operation{}, err
	}
	return a.authority.GetStage(ctx, operationID)
}

func (a *Application) GetEvidence(ctx context.Context, operationID string) (artifact.Evidence, error) {
	if err := a.ready(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	return a.authority.GetEvidence(ctx, operationID, a.clock.Now().UTC())
}

func (a *Application) reconcileLocked(ctx context.Context, operation artifact.Operation) (artifact.Operation, error) {
	switch operation.Status {
	case artifact.OperationRunning:
		return a.finish(ctx, operation, artifact.OperationOutcomeUnknown, artifact.FailureDispatchUnknown, nil, artifact.ErrOutcomeUnknown)
	case artifact.OperationOutcomeUnknown:
		return operation.Clone(), artifact.ErrOutcomeUnknown
	default:
		return operation.Clone(), nil
	}
}

func (a *Application) failBeforeDispatch(ctx context.Context, operation artifact.Operation, reason artifact.FailureReason, cause error) (artifact.Operation, error) {
	return a.finish(ctx, operation, artifact.OperationFailed, reason, nil, cause)
}

func (a *Application) finish(ctx context.Context, operation artifact.Operation, status artifact.OperationStatus, reason artifact.FailureReason, evidence *artifact.Evidence, cause error) (artifact.Operation, error) {
	return a.finishAt(ctx, operation, status, reason, evidence, a.observedAfter(operation.ObservedAt), cause)
}

func (a *Application) finishAt(ctx context.Context, operation artifact.Operation, status artifact.OperationStatus, reason artifact.FailureReason, evidence *artifact.Evidence, observedAt time.Time, cause error) (artifact.Operation, error) {
	updated, err := artifact.Transition(operation, status, observedAt, reason, evidence)
	if err != nil {
		if operation.Status == artifact.OperationRunning && status != artifact.OperationOutcomeUnknown {
			return a.finishAt(ctx, operation, artifact.OperationOutcomeUnknown, artifact.FailureDispatchUnknown, nil, observedAt, errors.Join(cause, artifact.ErrOutcomeUnknown, err))
		}
		return artifact.Operation{}, errors.Join(cause, err)
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), persistenceTimeout)
	defer cancel()
	if err := a.authority.UpdateStage(writeCtx, updated, operation.Status); err != nil {
		return artifact.Operation{}, errors.Join(cause, err)
	}
	return updated.Clone(), cause
}

func (a *Application) observedAfter(previous time.Time) time.Time {
	now := a.clock.Now().UTC()
	if now.Before(previous) {
		return previous
	}
	return now
}

func (a *Application) ready(ctx context.Context) error {
	if a == nil || a.authority == nil || a.stager == nil || a.clock == nil {
		return ErrInvalidApplication
	}
	return contextError(ctx)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
