package lifecycle

import (
	"fmt"
	"time"
)

// StartCreate creates the provider-local requested sandbox and accepted
// operation. It does not dispatch any backend work.
func StartCreate(request CreateRequest, now time.Time) (Sandbox, Operation, error) {
	if err := request.Validate(now); err != nil {
		return Sandbox{}, Operation{}, err
	}
	sandbox := Sandbox{
		ID:                 request.Spec.SandboxID,
		TenantID:           request.Spec.TenantID,
		WorkOrderID:        request.Spec.WorkOrderID,
		WorkspaceID:        request.Spec.WorkspaceID,
		ProviderRevisionID: request.Spec.ProviderRevisionID,
		RuntimeProfile:     request.Spec.RuntimeProfile,
		Network:            request.Spec.Network,
		SandboxSlotKey:     request.Spec.SandboxSlotKey,
		DesiredState:       DesiredReady,
		ObservedState:      ObservedRequested,
		Generation:         1,
		LeaseExpiresAt:     request.Spec.LeaseExpiresAt,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	operation := Operation{
		ID:           request.OperationID,
		AttemptID:    request.AttemptID,
		FencingToken: request.FencingToken,
		SandboxID:    sandbox.ID,
		Type:         OperationCreate,
		State:        OperationAccepted,
		Deadline:     request.Deadline,
		ObservedAt:   now,
	}
	return sandbox, operation, nil
}

// CanTransitionObserved reports whether a provider observation can follow the
// current observation. Equal states are idempotent observations.
func CanTransitionObserved(from, to ObservedState) bool {
	if from == to && from.valid() {
		return true
	}
	switch from {
	case ObservedRequested:
		return to == ObservedProvisioning || to == ObservedFailed || to == ObservedTerminating
	case ObservedProvisioning:
		return to == ObservedReady || to == ObservedFailed || to == ObservedTerminating
	case ObservedReady:
		return to == ObservedSuspending || to == ObservedTerminating || to == ObservedExpired
	case ObservedSuspending:
		return to == ObservedSuspended || to == ObservedReady || to == ObservedFailed
	case ObservedSuspended:
		return to == ObservedResuming || to == ObservedTerminating || to == ObservedExpired
	case ObservedResuming:
		return to == ObservedReady || to == ObservedFailed
	case ObservedTerminating:
		return to == ObservedTerminated || to == ObservedFailed
	default:
		return false
	}
}

// ApplyObservedTransition applies one provider observation for the current
// generation. A generation can be reported only when the requested generation
// has reached its observed state.
func ApplyObservedTransition(sandbox Sandbox, next ObservedState, appliedGeneration uint64, now time.Time) (Sandbox, error) {
	if err := sandbox.Validate(); err != nil {
		return Sandbox{}, err
	}
	if !next.valid() || !CanTransitionObserved(sandbox.ObservedState, next) {
		return Sandbox{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, sandbox.ObservedState, next)
	}
	if now.IsZero() || now.Before(sandbox.CreatedAt) {
		return Sandbox{}, ErrInvalidSpec
	}
	if appliedGeneration != sandbox.Generation {
		return Sandbox{}, fmt.Errorf("%w: applied generation %d, current %d", ErrGenerationConflict, appliedGeneration, sandbox.Generation)
	}
	updated := sandbox
	updated.ObservedState = next
	updated.UpdatedAt = now
	if next == ObservedReady || next == ObservedSuspended || next == ObservedTerminated {
		updated.ObservedGeneration = appliedGeneration
	}
	return updated, nil
}

// RequestDesiredState records a new desired state and increments generation.
// It does not claim that the provider has applied the request.
func RequestDesiredState(sandbox Sandbox, desired DesiredState, expectedGeneration uint64, now time.Time) (Sandbox, error) {
	if err := sandbox.Validate(); err != nil {
		return Sandbox{}, err
	}
	if !desired.valid() {
		return Sandbox{}, ErrInvalidState
	}
	if expectedGeneration != sandbox.Generation {
		return Sandbox{}, fmt.Errorf("%w: expected %d, current %d", ErrGenerationConflict, expectedGeneration, sandbox.Generation)
	}
	if now.IsZero() || now.Before(sandbox.UpdatedAt) {
		return Sandbox{}, ErrInvalidSpec
	}
	if sandbox.ObservedState.terminal() {
		return Sandbox{}, fmt.Errorf("%w: cannot change %s", ErrInvalidTransition, sandbox.ObservedState)
	}
	if desired == sandbox.DesiredState {
		return sandbox, nil
	}
	updated := sandbox
	updated.DesiredState = desired
	updated.Generation++
	updated.UpdatedAt = now
	return updated, nil
}

// ExpireLease records an observed lease expiry without changing generation.
func ExpireLease(sandbox Sandbox, now time.Time) (Sandbox, error) {
	if err := sandbox.Validate(); err != nil {
		return Sandbox{}, err
	}
	if now.IsZero() || now.Before(sandbox.UpdatedAt) {
		return Sandbox{}, ErrInvalidSpec
	}
	if now.Before(sandbox.LeaseExpiresAt) {
		return Sandbox{}, ErrInvalidLease
	}
	if sandbox.ObservedState == ObservedExpired {
		return sandbox, nil
	}
	if sandbox.ObservedState.terminal() || !CanTransitionObserved(sandbox.ObservedState, ObservedExpired) {
		return Sandbox{}, fmt.Errorf("%w: cannot expire %s", ErrInvalidTransition, sandbox.ObservedState)
	}
	updated := sandbox
	updated.ObservedState = ObservedExpired
	updated.UpdatedAt = now
	return updated, nil
}

// CheckFencing accepts a repeated current token and rejects only older work.
func CheckFencing(current, incoming uint64) error {
	if incoming == 0 {
		return ErrStaleFencingToken
	}
	if incoming < current {
		return fmt.Errorf("%w: incoming %d, current %d", ErrStaleFencingToken, incoming, current)
	}
	return nil
}

func AdvanceFencing(current, incoming uint64) (uint64, error) {
	if err := CheckFencing(current, incoming); err != nil {
		return 0, err
	}
	if incoming > current {
		return incoming, nil
	}
	return current, nil
}

var operationTransitions = map[OperationState]map[OperationState]bool{
	OperationAccepted: {OperationRunning: true, OperationCancelled: true, OperationFailed: true, OperationOutcomeUnknown: true},
	OperationRunning:  {OperationSucceeded: true, OperationFailed: true, OperationCancelled: true, OperationOutcomeUnknown: true},
}

func transitionOperation(operation Operation, next OperationState, now time.Time, failure *Failure) (Operation, error) {
	if err := operation.Validate(); err != nil {
		return Operation{}, err
	}
	if !next.valid() {
		return Operation{}, ErrInvalidState
	}
	if operation.State == next {
		return operation, nil
	}
	if operation.State.terminal() {
		return Operation{}, ErrTerminalOperation
	}
	if !operationTransitions[operation.State][next] {
		return Operation{}, fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, operation.State, next)
	}
	if now.IsZero() || now.Before(operation.ObservedAt) {
		return Operation{}, ErrInvalidSpec
	}
	if next == OperationFailed && (failure == nil || failure.Outcome != FailureKnown) {
		return Operation{}, ErrInvalidSpec
	}
	if next == OperationOutcomeUnknown && (failure == nil || failure.Outcome != FailureUnknown) {
		return Operation{}, ErrInvalidSpec
	}
	if (next == OperationSucceeded || next == OperationCancelled) && failure != nil {
		return Operation{}, ErrInvalidSpec
	}
	updated := operation
	updated.State = next
	updated.ObservedAt = now
	updated.Failure = failure
	return updated, nil
}

func BeginOperation(operation Operation, now time.Time) (Operation, error) {
	if err := CheckDeadline(now, operation.Deadline); err != nil {
		return Operation{}, err
	}
	return transitionOperation(operation, OperationRunning, now, nil)
}

func SucceedOperation(operation Operation, now time.Time) (Operation, error) {
	return transitionOperation(operation, OperationSucceeded, now, nil)
}

func FailOperation(operation Operation, now time.Time, failure Failure) (Operation, error) {
	return transitionOperation(operation, OperationFailed, now, &failure)
}

func RequestCancellation(operation Operation, now time.Time) (Operation, error) {
	if err := operation.Validate(); err != nil {
		return Operation{}, err
	}
	if operation.State.terminal() {
		return Operation{}, ErrTerminalOperation
	}
	if now.IsZero() || now.Before(operation.ObservedAt) {
		return Operation{}, ErrInvalidSpec
	}
	operation.CancelRequested = true
	operation.ObservedAt = now
	return operation, nil
}

func ConfirmCancellation(operation Operation, now time.Time) (Operation, error) {
	if !operation.CancelRequested {
		return Operation{}, ErrCancellationRequired
	}
	return transitionOperation(operation, OperationCancelled, now, nil)
}

func MarkOutcomeUnknown(operation Operation, now time.Time, failure Failure) (Operation, error) {
	if failure.Outcome != FailureUnknown {
		return Operation{}, ErrInvalidSpec
	}
	return transitionOperation(operation, OperationOutcomeUnknown, now, &failure)
}
