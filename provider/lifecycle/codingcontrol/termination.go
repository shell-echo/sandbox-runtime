package codingcontrol

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

// ReadTermination returns one validated PG snapshot, including the original
// allocation and its current retirement or already-released projection.
// It is not a cleanup permit and must not read operation/sandbox separately.
type TerminationRepository interface {
	Repository
	ReadTermination(context.Context, string) (lifecycle.Operation, lifecycle.Sandbox, error)
	RecordCleanupDispatchResult(context.Context, string, CleanupDispatchResult) error
	RetainUnacknowledgedTermination(context.Context, string) error
}

type TerminationCoordinator struct {
	repository TerminationRepository
	cleanup    *Coordinator
}

func NewTerminationReconciler(repository TerminationRepository, observer Observer, dispatcher CleanupDispatcher, clock Clock, expected Expected) (*TerminationCoordinator, error) {
	cleanup, err := NewWithDispatcher(repository, observer, dispatcher, clock, expected)
	if err != nil {
		return nil, err
	}
	return &TerminationCoordinator{repository: repository, cleanup: cleanup}, nil
}

// ReconcileCodingTermination keeps fresh admission and historical recovery
// distinct. Dispatched means the dispatcher was called, including a lost
// reply; it never means that Released or PG termination was established.
func (c *TerminationCoordinator) ReconcileCodingTermination(ctx context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, bool, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || lifecycle.ValidateIdentifier(id) != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, false, ErrObservation
	}
	op, sb, err := c.repository.ReadTermination(ctx, id)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, false, err
	}
	if !validTerminationTuple(op, sb, id) {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, false, ErrObservation
	}
	if sb.ObservedState == lifecycle.ObservedTerminated {
		return op, sb, false, nil
	}
	dispatched := false
	switch op.State {
	case lifecycle.OperationAccepted:
		if op.CancelRequested || !c.cleanup.clock.Now().Before(op.Deadline) {
			return op, sb, false, ErrObservation
		}
		var result CleanupDispatchResult
		dispatched, result, err = c.cleanup.beginAndDispatch(ctx, id)
		if dispatched {
			err = errors.Join(err, c.repository.RecordCleanupDispatchResult(ctx, id, result))
		}
	case lifecycle.OperationRunning, lifecycle.OperationOutcomeUnknown:
		// An unacknowledged Running result may be a sender lost mid-request.
		// Persist Unknown before observing; a concurrent late ACK cannot
		// promote it. The row CAS is a no-op if ACK won or it is already final.
		err = c.repository.RetainUnacknowledgedTermination(ctx, id)
		if err == nil {
			err = c.cleanup.Finish(ctx, id)
		}
	default:
		return op, sb, false, ErrObservation
	}
	// Even after an error, a live caller may observe what actually committed.
	// Never clear the original error or turn this read into another send.
	if ctx.Err() != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, dispatched, errors.Join(err, ctx.Err())
	}
	current, sandbox, readErr := c.repository.ReadTermination(ctx, id)
	if readErr == nil && !validTerminationTuple(current, sandbox, id) {
		readErr = ErrObservation
	}
	if readErr != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, dispatched, errors.Join(err, readErr)
	}
	return current, sandbox, dispatched, err
}

func validTerminationTuple(op lifecycle.Operation, sb lifecycle.Sandbox, id string) bool {
	if op.ID != id || op.Type != lifecycle.OperationTerminate || op.SandboxID != sb.ID ||
		op.Validate() != nil || sb.Validate() != nil || sb.DesiredState != lifecycle.DesiredTerminated {
		return false
	}
	if sb.ObservedState == lifecycle.ObservedTerminated {
		return sb.ObservedGeneration == sb.Generation && (op.State == lifecycle.OperationSucceeded || op.State == lifecycle.OperationOutcomeUnknown)
	}
	switch op.State {
	case lifecycle.OperationAccepted:
		return sb.ObservedState == lifecycle.ObservedProvisioning || sb.ObservedState == lifecycle.ObservedReady
	case lifecycle.OperationRunning, lifecycle.OperationOutcomeUnknown:
		return sb.ObservedState == lifecycle.ObservedTerminating
	default:
		return false
	}
}
