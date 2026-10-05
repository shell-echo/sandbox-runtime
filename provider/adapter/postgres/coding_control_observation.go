package providerpostgres

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var _ codingcontrol.Repository = (*CodingLifecycleRepository)(nil)

func (r *CodingLifecycleRepository) ReadBeginBinding(ctx context.Context,
	terminationID string) (codingcontrol.Binding, error) {
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil ||
		lifecycle.ValidateIdentifier(terminationID) != nil ||
		lifecycle.ValidateDigest(r.bound.controlPolicyDigest) != nil {
		return codingcontrol.Binding{}, ErrUnavailable
	}
	ledger, err := readState(ctx, r.bound.store, lifecycleDocument,
		newLifecycleState, importLifecycleState)
	if err != nil {
		return codingcontrol.Binding{}, err
	}
	termination, exists := ledger.Operations[terminationID]
	if !exists || termination.Type != lifecycle.OperationTerminate {
		return codingcontrol.Binding{}, ErrCorrupt
	}
	slots, err := readState(ctx, r.bound.store, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || slots.Validate(r.bound.plan) != nil {
		return codingcontrol.Binding{}, ErrCorrupt
	}
	for _, reservation := range slots.Reservations {
		if reservation.Claim.SandboxID != termination.SandboxID {
			continue
		}
		if reservation.Status != codingidentity.Creating && reservation.Status != codingidentity.Active {
			return codingcontrol.Binding{}, ErrCorrupt
		}
		if _, retired := slots.Retirements[reservation.Slot.ID]; retired {
			return codingcontrol.Binding{}, ErrCorrupt
		}
		create, err := r.bound.ReadOriginalCreateAuthority(ctx, reservation.Claim.AllocationID)
		if err != nil || create.ControlPolicyDigest != r.bound.controlPolicyDigest ||
			validateCodingOriginalCreate(slots, ledger, r.bound.plan, create, time.Now().UTC()) != nil {
			return codingcontrol.Binding{}, ErrCorrupt
		}
		return codingcontrol.Binding{Create: create, TerminationID: terminationID}, nil
	}
	return codingcontrol.Binding{}, ErrCorrupt
}

func (r *CodingLifecycleRepository) ReadFinishBinding(ctx context.Context,
	terminationID string) (codingcontrol.Binding, error) {
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil ||
		lifecycle.ValidateIdentifier(terminationID) != nil ||
		lifecycle.ValidateDigest(r.bound.controlPolicyDigest) != nil {
		return codingcontrol.Binding{}, ErrUnavailable
	}
	slots, err := readState(ctx, r.bound.store, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || slots.Validate(r.bound.plan) != nil {
		return codingcontrol.Binding{}, ErrCorrupt
	}
	for _, reservation := range slots.Reservations {
		binding, exists := slots.Retirements[reservation.Slot.ID]
		if !exists || binding.OperationID != terminationID {
			continue
		}
		create, err := r.bound.ReadOriginalCreateAuthority(ctx, reservation.Claim.AllocationID)
		if err != nil || create.ControlPolicyDigest != r.bound.controlPolicyDigest ||
			binding.OriginalAuthorityDigest != create.Digest() {
			return codingcontrol.Binding{}, ErrCorrupt
		}
		cleanup, err := readCodingCleanupEnvelope(slots, r.bound.plan, create,
			terminationID, r.bound.controlPolicyDigest, r.bound.plan.OwnerPrincipalDigest, r.specBySlot)
		if err != nil {
			return codingcontrol.Binding{}, ErrCorrupt
		}
		return codingcontrol.Binding{Create: create, Cleanup: &cleanup,
			TerminationID: terminationID, ControlRevision: binding.ControlReceiptRevision,
			ControlStateDigest: binding.ControlReceiptStateDigest}, nil
	}
	return codingcontrol.Binding{}, ErrCorrupt
}

// BeginWithObservation accepts only the application's typed Completed result.
// The authenticated network request has already completed outside this row
// lock; all actual PG reservation/operation/authority facts are rechecked here.
func (r *CodingLifecycleRepository) BeginWithObservation(ctx context.Context,
	terminationID string, observed codingcontrol.CompletedObservation,
) (dockercontrol.CodingCleanupAuthority, error) {
	create := observed.CreateAuthority()
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil ||
		lifecycle.ValidateDigest(r.bound.controlPolicyDigest) != nil ||
		create.ControlPolicyDigest != r.bound.controlPolicyDigest ||
		observed.Validate(create) != nil || lifecycle.ValidateIdentifier(terminationID) != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	var authority dockercontrol.CodingCleanupAuthority
	err := mutateStateTriple(ctx, r.bound.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.matchesAtomic(r.bound.digest, r.bound.controlPolicyDigest) ||
				checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil ||
				validateCodingOriginalCreate(*slots, *ledger, r.bound.plan, create, now) != nil ||
				observed.UpdatedAt().After(now) {
				return codingidentity.ErrConflict
			}
			completed := dockercontrol.CodingReceipt{Authority: create,
				AuthorityDigest: create.Digest(), Status: dockercontrol.ReceiptCompleted,
				CompletionDigest:         observed.CompletionDigest(),
				CompletionEvidenceDigest: observed.CompletionEvidenceDigest(),
				UpdatedAt:                observed.UpdatedAt()}
			input := codingCleanupAdmission{Create: create, Completed: completed,
				ControlRevision:    observed.ControlRevision(),
				ControlStateDigest: observed.ControlStateDigest(),
				TerminationID:      terminationID, ControlPolicyDigest: r.bound.controlPolicyDigest,
				PeerPrincipalDigest: r.bound.plan.OwnerPrincipalDigest, SpecBySlot: r.specBySlot}
			var beginErr error
			authority, _, _, _, beginErr = beginCodingCurrentCleanup(ctx, slots, ledger,
				r.bound.plan, input, now)
			return beginErr
		})
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	if err := ctx.Err(); err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	if authority.Validate(time.Now().UTC()) != nil {
		return dockercontrol.CodingCleanupAuthority{}, dockercontrol.ErrInvalidAuthority
	}
	return authority, nil
}

func (r *CodingLifecycleRepository) FinishWithObservation(ctx context.Context,
	terminationID string, observed codingcontrol.ReleasedObservation) error {
	create, cleanup := observed.CreateAuthority(), observed.CleanupAuthority()
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil ||
		lifecycle.ValidateDigest(r.bound.controlPolicyDigest) != nil ||
		create.ControlPolicyDigest != r.bound.controlPolicyDigest ||
		lifecycle.ValidateIdentifier(terminationID) != nil || cleanup.CleanupOperationID != terminationID {
		return codingidentity.ErrConflict
	}
	err := mutateStateTriple(ctx, r.bound.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.matchesAtomic(r.bound.digest, r.bound.controlPolicyDigest) ||
				checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil ||
				validateCodingOriginalCreate(*slots, *ledger, r.bound.plan, create, now) != nil {
				return codingidentity.ErrConflict
			}
			binding, exists := slots.Retirements[create.SlotID]
			if !exists || binding.OperationID != terminationID ||
				binding.OriginalAuthorityDigest != create.Digest() ||
				binding.CleanupAuthorityDigest != cleanup.Digest() ||
				observed.Validate(create, cleanup, now, binding.ControlReceiptRevision,
					binding.ControlReceiptStateDigest) != nil {
				return codingidentity.ErrConflict
			}
			released := dockercontrol.CodingReceipt{Authority: create,
				AuthorityDigest: create.Digest(), Status: dockercontrol.ReceiptReleased,
				CompletionDigest:         observed.CompletionDigest(),
				CompletionEvidenceDigest: observed.CompletionEvidenceDigest(),
				CleanupAuthority:         cleanup, AbsenceDigest: observed.AbsenceDigest(),
				AbsenceEvidenceDigest: observed.AbsenceEvidenceDigest(), UpdatedAt: observed.UpdatedAt()}
			_, _, finishErr := finishCodingCurrentCleanup(ctx, slots, ledger, r.bound.plan,
				codingReleaseAdmission{Create: create, Cleanup: cleanup, Released: released,
					ControlRevision:    observed.ControlRevision(),
					ControlStateDigest: observed.ControlStateDigest(), SpecBySlot: r.specBySlot}, now)
			return finishErr
		})
	if err != nil {
		return err
	}
	return ctx.Err()
}
