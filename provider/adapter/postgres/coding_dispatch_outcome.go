package providerpostgres

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var errCodingDispatchUnchanged = errors.New("Coding dispatch state unchanged")

func (r *CodingLifecycleRepository) RecordCleanupDispatchResult(ctx context.Context, id string, result codingcontrol.CleanupDispatchResult) error {
	return r.updateCleanupDispatch(ctx, id, &result)
}

// Recovery cannot tell an in-flight sender from one lost across restart. If
// its ACK was not committed first, retain Unknown before asking Control.
func (r *CodingLifecycleRepository) RetainUnacknowledgedTermination(ctx context.Context, id string) error {
	return r.updateCleanupDispatch(ctx, id, nil)
}

func (r *CodingLifecycleRepository) updateCleanupDispatch(ctx context.Context, id string, result *codingcontrol.CleanupDispatchResult) error {
	if r == nil || r.bound == nil || ctx == nil || lifecycle.ValidateIdentifier(id) != nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err := mutateStateTriple(ctx, r.bound.store, codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker, func(m codingIdentityMarker) any { return m },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState, func(s codingidentity.State) any { return s },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			return updateCodingDispatchOutcome(ctx, *marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, id, result, time.Now().UTC())
		})
	if errors.Is(err, errCodingDispatchUnchanged) {
		err = nil
	}
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func updateCodingDispatchOutcome(ctx context.Context, marker codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy, id string, result *codingcontrol.CleanupDispatchResult, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || slots == nil || ledger == nil {
		return codingidentity.ErrConflict
	}
	op, sb, err := readCodingTerminationSnapshot(marker, *slots, *ledger, plan, specs, policy, id, now)
	if err != nil {
		return err
	}
	if sb.ObservedState == lifecycle.ObservedTerminated {
		if result == nil {
			return errCodingDispatchUnchanged
		}
		return codingidentity.ErrConflict
	}
	var reservation codingidentity.Reservation
	for _, item := range slots.Reservations {
		if item.Claim.SandboxID == sb.ID {
			reservation = item
			break
		}
	}
	binding, exists := slots.Retirements[reservation.Slot.ID]
	if !exists || reservation.Status != codingidentity.Cleaning || binding.OperationID != id {
		return codingidentity.ErrConflict
	}
	create, err := decodeCodingOriginalCreate(slots.OriginalCreates[reservation.Claim.AllocationID], now)
	if err != nil {
		return err
	}
	cleanup, err := readCodingCleanupEnvelope(*slots, plan, create, id, policy, plan.OwnerPrincipalDigest, specs)
	if err != nil {
		return err
	}
	if result != nil && result.Validate(create, cleanup, now) != nil {
		return codingidentity.ErrConflict
	}
	if result == nil && (binding.DispatchAcknowledged || op.State == lifecycle.OperationOutcomeUnknown) {
		return errCodingDispatchUnchanged
	}
	if op.State == lifecycle.OperationOutcomeUnknown {
		if result != nil && !result.Acknowledged() {
			return errCodingDispatchUnchanged
		}
		return codingidentity.ErrConflict
	}
	if op.State != lifecycle.OperationRunning || binding.DispatchAcknowledged {
		return codingidentity.ErrConflict
	}
	nextSlots := slots.Clone()
	nextLedger := newLifecycleState()
	if nextLedger.Import(ledger.Export()) != nil {
		return ErrCorrupt
	}
	if result != nil && result.Acknowledged() {
		// A late ACK cannot turn cancellation or a historical Unknown into a
		// future success. The release CAS independently checks the deadline.
		if op.CancelRequested || !now.Before(op.Deadline) {
			return codingidentity.ErrConflict
		}
		binding.DispatchAcknowledged = true
		nextSlots.Retirements[reservation.Slot.ID] = binding
	} else {
		unknown, err := lifecycle.MarkOutcomeUnknown(op, now, lifecycle.Failure{Code: "coding_cleanup_dispatch_unknown", Retryable: true, Outcome: lifecycle.FailureUnknown})
		if err != nil || nextLedger.UpdateOperation(unknown) != nil || appendCodingReadyEvent(&nextLedger, sb, unknown, "outcome-unknown", "", now) != nil {
			return codingidentity.ErrConflict
		}
	}
	if nextSlots.Validate(plan) != nil || checkCodingRetirementBarrierWithMarker(marker, nextSlots, nextLedger, nextLedger, now) != nil || ctx.Err() != nil {
		return codingidentity.ErrConflict
	}
	*slots, *ledger = nextSlots, nextLedger
	return nil
}
