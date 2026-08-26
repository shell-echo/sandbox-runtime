package application

import (
	"context"
	"errors"
	"math"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/coordinator"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
)

var (
	ErrSandboxNotReady = errors.New("Provider exec sandbox is not ready")
	ErrSandboxExpired  = errors.New("Provider exec sandbox lease has expired")
)

const terminalPersistenceTimeout = 5 * time.Second

type SandboxReader interface {
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
}

// Vertical composes lifecycle authority with the durable exec coordinator. It
// is single-controller application policy and contains no HTTP or Docker type.
type Vertical struct {
	coordinator *coordinator.Coordinator
	sandboxes   SandboxReader
	support     providerexec.SupportChecker
	clock       Clock
}

func NewVertical(execCoordinator *coordinator.Coordinator, sandboxes SandboxReader, clock Clock) (*Vertical, error) {
	return NewVerticalWithSupport(execCoordinator, sandboxes, nil, clock)
}

func NewVerticalWithSupport(execCoordinator *coordinator.Coordinator, sandboxes SandboxReader, support providerexec.SupportChecker, clock Clock) (*Vertical, error) {
	if execCoordinator == nil || sandboxes == nil || clock == nil {
		return nil, providerexec.ErrInvalidApplication
	}
	return &Vertical{coordinator: execCoordinator, sandboxes: sandboxes, support: support, clock: clock}, nil
}

func (a *Vertical) AcceptExec(ctx context.Context, request providerexec.Request) (provideroperation.View, error) {
	if err := a.ready(ctx); err != nil {
		return provideroperation.View{}, err
	}
	if err := request.Validate(a.clock.Now().UTC()); err != nil {
		return provideroperation.View{}, err
	}
	if existing, err := a.coordinator.GetExecution(ctx, request.OperationID); err == nil {
		return a.acceptExecReplay(ctx, request, existing)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return provideroperation.View{}, err
	}
	if a.support != nil {
		if err := a.support.CheckSupport(ctx, request.Clone()); err != nil {
			return provideroperation.View{}, err
		}
	}
	if err := a.checkSandbox(ctx, request.SandboxID, request.ExpectedGeneration); err != nil {
		return provideroperation.View{}, err
	}
	reservation, dispatchErr := a.coordinator.Start(ctx, request)
	if dispatchErr != nil && reservation.Execution.Request.OperationID != "" {
		outcome := knownDispatchFailure()
		if errors.Is(dispatchErr, providerexec.ErrDispatchUnknown) {
			outcome = unknownDispatchFailure()
		}
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), terminalPersistenceTimeout)
		_, storeErr := a.coordinator.StoreOutcome(writeCtx, request.OperationID, reservation.Execution.ReservedAt, a.clock.Now().UTC(), outcome)
		cancel()
		if storeErr != nil {
			return provideroperation.View{}, errors.Join(dispatchErr, storeErr)
		}
		record, readErr := a.coordinator.GetExecution(context.WithoutCancel(nonNilContext(ctx)), request.OperationID)
		if readErr != nil {
			return provideroperation.View{}, errors.Join(dispatchErr, readErr)
		}
		return executionView(record)
	}
	if dispatchErr != nil {
		return provideroperation.View{}, dispatchErr
	}
	return executionView(reservation.Execution)
}

func (a *Vertical) AcceptCancellation(ctx context.Context, intent providerexec.CancellationIntent) (provideroperation.View, error) {
	if err := a.ready(ctx); err != nil {
		return provideroperation.View{}, err
	}
	if err := intent.Validate(a.clock.Now().UTC()); err != nil {
		return provideroperation.View{}, err
	}
	if _, err := a.coordinator.GetCancellationReservation(ctx, intent.OperationID); err == nil {
		result, cancelErr := a.coordinator.Cancel(ctx, intent)
		if cancelErr != nil {
			return provideroperation.View{}, cancelErr
		}
		return cancellationView(result.Reservation, result.Status)
	} else if !errors.Is(err, repository.ErrNotFound) {
		return provideroperation.View{}, err
	}
	if err := a.checkSandbox(ctx, intent.SandboxID, intent.ExpectedGeneration); err != nil {
		return provideroperation.View{}, err
	}
	target, err := a.coordinator.GetExecution(ctx, intent.TargetOperationID)
	if err != nil {
		return provideroperation.View{}, err
	}
	target, err = a.expireResult(ctx, target)
	if err != nil {
		return provideroperation.View{}, err
	}
	if target.Terminal != nil {
		return provideroperation.View{}, repository.ErrAlreadyExists
	}
	target, err = a.coordinator.Reconcile(ctx, intent.TargetOperationID)
	if errors.Is(err, providerexec.ErrExecutionNotFound) {
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), terminalPersistenceTimeout)
		_, storeErr := a.coordinator.StoreOutcome(writeCtx, target.Request.OperationID, target.ReservedAt, a.clock.Now().UTC(), unknownDispatchFailure())
		cancel()
		if storeErr != nil {
			return provideroperation.View{}, storeErr
		}
		return provideroperation.View{}, repository.ErrAlreadyExists
	}
	if err != nil {
		return provideroperation.View{}, err
	}
	if target.Terminal != nil {
		return provideroperation.View{}, repository.ErrAlreadyExists
	}
	result, err := a.coordinator.Cancel(ctx, intent)
	if err != nil {
		return provideroperation.View{}, err
	}
	return cancellationView(result.Reservation, result.Status)
}

func (a *Vertical) GetResult(ctx context.Context, operationID string) (providerexec.Result, error) {
	if err := a.ready(ctx); err != nil {
		return providerexec.Result{}, err
	}
	_, reconcileErr := a.coordinator.Reconcile(ctx, operationID)
	if errors.Is(reconcileErr, providerexec.ErrExecutionNotFound) {
		record, err := a.coordinator.GetExecution(ctx, operationID)
		if err != nil {
			return providerexec.Result{}, err
		}
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), terminalPersistenceTimeout)
		_, err = a.coordinator.StoreOutcome(writeCtx, operationID, record.ReservedAt, a.clock.Now().UTC(), unknownDispatchFailure())
		cancel()
		if err != nil {
			return providerexec.Result{}, err
		}
	} else if reconcileErr != nil {
		return providerexec.Result{}, reconcileErr
	}
	return a.coordinator.GetResult(ctx, operationID, a.clock.Now().UTC())
}

func (a *Vertical) ReadOperation(ctx context.Context, operationID string) (provideroperation.View, error) {
	if err := a.ready(ctx); err != nil {
		return provideroperation.View{}, err
	}
	execution, executionErr := a.coordinator.GetExecution(ctx, operationID)
	cancellation, cancellationErr := a.coordinator.GetCancellationReservation(ctx, operationID)
	executionFound := executionErr == nil
	cancellationFound := cancellationErr == nil
	if executionFound && cancellationFound {
		return provideroperation.View{}, provideroperation.ErrConflict
	}
	if executionFound {
		var err error
		execution, err = a.expireResult(ctx, execution)
		if err != nil {
			return provideroperation.View{}, err
		}
		if execution.Result == nil && !execution.ResultExpired {
			if reconciled, err := a.coordinator.Reconcile(ctx, operationID); err == nil {
				execution = reconciled
			} else if errors.Is(err, providerexec.ErrExecutionNotFound) {
				writeCtx, cancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), terminalPersistenceTimeout)
				result, storeErr := a.coordinator.StoreOutcome(writeCtx, operationID, execution.ReservedAt, a.clock.Now().UTC(), unknownDispatchFailure())
				cancel()
				if storeErr != nil {
					return provideroperation.View{}, storeErr
				}
				execution.Result = result.Clone()
				terminal, terminalErr := providerexec.NewTerminalSummary(result)
				if terminalErr != nil {
					return provideroperation.View{}, terminalErr
				}
				execution.Terminal = terminal.Clone()
			} else {
				return provideroperation.View{}, err
			}
		}
		return executionView(execution)
	}
	if cancellationFound {
		target, err := a.coordinator.GetExecution(ctx, cancellation.Intent.TargetOperationID)
		if err != nil {
			return provideroperation.View{}, err
		}
		target, err = a.expireResult(ctx, target)
		if err != nil {
			return provideroperation.View{}, err
		}
		status := coordinator.CancellationPending
		if target.Terminal != nil && target.Terminal.Status == providerexec.ResultCancelled {
			status = coordinator.CancellationConfirmed
		}
		return cancellationView(cancellation, status)
	}
	if !errors.Is(executionErr, repository.ErrNotFound) {
		return provideroperation.View{}, executionErr
	}
	if !errors.Is(cancellationErr, repository.ErrNotFound) {
		return provideroperation.View{}, cancellationErr
	}
	return provideroperation.View{}, provideroperation.ErrNotFound
}

func (a *Vertical) acceptExecReplay(ctx context.Context, request providerexec.Request, existing providerexec.ExecutionRecord) (provideroperation.View, error) {
	reservation, err := a.coordinator.Start(ctx, request)
	if err != nil {
		return provideroperation.View{}, err
	}
	if !reservation.Replayed || reservation.Execution.Request.OperationID != existing.Request.OperationID {
		return provideroperation.View{}, repository.ErrConflict
	}
	return a.reconcileExecutionView(ctx, reservation.Execution)
}

func (a *Vertical) reconcileExecutionView(ctx context.Context, record providerexec.ExecutionRecord) (provideroperation.View, error) {
	var err error
	record, err = a.expireResult(ctx, record)
	if err != nil {
		return provideroperation.View{}, err
	}
	if record.Result == nil && !record.ResultExpired {
		if reconciled, err := a.coordinator.Reconcile(ctx, record.Request.OperationID); err == nil {
			record = reconciled
		} else if errors.Is(err, providerexec.ErrExecutionNotFound) {
			writeCtx, cancel := context.WithTimeout(context.WithoutCancel(nonNilContext(ctx)), terminalPersistenceTimeout)
			_, storeErr := a.coordinator.StoreOutcome(writeCtx, record.Request.OperationID, record.ReservedAt, a.clock.Now().UTC(), unknownDispatchFailure())
			cancel()
			if storeErr != nil {
				return provideroperation.View{}, storeErr
			}
			record, err = a.coordinator.GetExecution(ctx, record.Request.OperationID)
			if err != nil {
				return provideroperation.View{}, err
			}
		} else {
			return provideroperation.View{}, err
		}
	}
	return executionView(record)
}

func (a *Vertical) expireResult(ctx context.Context, record providerexec.ExecutionRecord) (providerexec.ExecutionRecord, error) {
	if record.Result == nil || a.clock.Now().UTC().Before(record.Result.RetainedUntil) {
		return record, nil
	}
	if _, err := a.coordinator.GetResult(ctx, record.Request.OperationID, a.clock.Now().UTC()); err != nil && !errors.Is(err, repository.ErrExpired) {
		return providerexec.ExecutionRecord{}, err
	}
	return a.coordinator.GetExecution(ctx, record.Request.OperationID)
}

func (a *Vertical) Recover(ctx context.Context) error {
	if err := a.ready(ctx); err != nil {
		return err
	}
	_, err := a.coordinator.Recover(ctx)
	return err
}

func (a *Vertical) checkSandbox(ctx context.Context, sandboxID string, expectedGeneration int64) error {
	sandbox, err := a.sandboxes.GetSandbox(ctx, sandboxID)
	if err != nil {
		return err
	}
	if sandbox.ID != sandboxID || sandbox.Generation > math.MaxInt64 || int64(sandbox.Generation) != expectedGeneration {
		return lifecycle.ErrGenerationConflict
	}
	if sandbox.DesiredState != lifecycle.DesiredReady || sandbox.ObservedState != lifecycle.ObservedReady || sandbox.ObservedGeneration != sandbox.Generation {
		return ErrSandboxNotReady
	}
	if !sandbox.LeaseExpiresAt.After(a.clock.Now().UTC()) {
		return ErrSandboxExpired
	}
	return nil
}

func (a *Vertical) ready(ctx context.Context) error {
	if a == nil || a.coordinator == nil || a.sandboxes == nil || a.clock == nil {
		return providerexec.ErrInvalidApplication
	}
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func executionView(record providerexec.ExecutionRecord) (provideroperation.View, error) {
	if record.Request.OperationID == "" || record.ReservedAt.IsZero() {
		return provideroperation.View{}, provideroperation.ErrInvalidView
	}
	view := provideroperation.View{
		OperationID: record.Request.OperationID, AttemptID: record.Request.AttemptID,
		FencingToken: record.Request.FencingToken, SandboxID: record.Request.SandboxID,
		Type: provideroperation.TypeExec, Status: provideroperation.StatusAccepted,
		ProviderOperationID: record.Request.OperationID, ResultReference: "ref:exec/" + record.Request.OperationID + "/result",
		ObservedAt: record.ReservedAt.UTC(),
	}
	if record.Attached {
		view.Status = provideroperation.StatusRunning
		view.ObservedAt = record.Dispatch.AcceptedAt.UTC()
	}
	if record.Terminal != nil {
		view.ObservedAt = record.Terminal.CompletedAt.UTC()
		switch record.Terminal.Status {
		case providerexec.ResultCompleted:
			view.Status = provideroperation.StatusSucceeded
		case providerexec.ResultFailed:
			view.Status = provideroperation.StatusFailed
		case providerexec.ResultCancelled:
			view.Status = provideroperation.StatusCancelled
		case providerexec.ResultOutcomeUnknown:
			view.Status = provideroperation.StatusOutcomeUnknown
		}
		if record.Terminal.Error != nil {
			view.Failure = &provideroperation.Failure{Code: record.Terminal.Error.Code, Retryable: record.Terminal.Error.Retryable, Outcome: string(record.Terminal.Error.Outcome)}
		}
	}
	if err := view.Validate(); err != nil {
		return provideroperation.View{}, err
	}
	return view, nil
}

func cancellationView(reservation providerexec.CancellationReservation, status coordinator.CancellationStatus) (provideroperation.View, error) {
	view := provideroperation.View{
		OperationID: reservation.Intent.OperationID, AttemptID: reservation.Intent.AttemptID,
		FencingToken: reservation.Intent.FencingToken, SandboxID: reservation.Intent.SandboxID,
		Type: provideroperation.TypeCancelExec, Status: provideroperation.StatusAccepted,
		ProviderOperationID: reservation.Intent.OperationID, ObservedAt: reservation.ReservedAt.UTC(),
	}
	if status == coordinator.CancellationConfirmed {
		view.Status = provideroperation.StatusSucceeded
	}
	if err := view.Validate(); err != nil {
		return provideroperation.View{}, err
	}
	return view, nil
}

func knownDispatchFailure() providerexec.ResultOutcome {
	return providerexec.ResultOutcome{Status: providerexec.ResultFailed, Error: &providerexec.ResultError{
		Code: "SANDBOX_EXEC_FAILED", Message: "execution could not be started", Retryable: false, Outcome: providerexec.ErrorOutcomeKnown,
	}}
}

func unknownDispatchFailure() providerexec.ResultOutcome {
	return providerexec.ResultOutcome{Status: providerexec.ResultOutcomeUnknown, Error: &providerexec.ResultError{
		Code: "SANDBOX_EXEC_OUTCOME_UNKNOWN", Message: "execution outcome requires reconciliation", Retryable: true, Outcome: providerexec.ErrorOutcomeUnknown,
	}}
}

func nonNilContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
