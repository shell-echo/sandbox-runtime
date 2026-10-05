package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type codingReleaseAdmission struct {
	Create             dockercontrol.CodingCreateAuthority
	Cleanup            dockercontrol.CodingCleanupAuthority
	Released           dockercontrol.CodingReceipt
	ControlRevision    uint64
	ControlStateDigest string
	SpecBySlot         map[string]string
}

// FinishCodingCurrentCleanup is a source-only same-PG-row release CAS. The
// supplied snapshot must originate from the authenticated Control owner; its
// in-process type alone is not cross-process attestation. The release is not
// wired into provider serve while the private mTLS edge and named gates are
// absent. No Docker read or deletion occurs under this row lock.
func (r *CodingLifecycleRepository) FinishCodingCurrentCleanup(ctx context.Context,
	create dockercontrol.CodingCreateAuthority, cleanup dockercontrol.CodingCleanupAuthority,
	released dockercontrol.CodingReleasedSnapshot,
) (lifecycle.Operation, lifecycle.Sandbox, error) {
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	marker, markerErr := r.bound.readCodingMarker(ctx)
	if markerErr != nil || marker.AuthorityMode != "" ||
		marker.PlanDigest != r.bound.digest || !marker.Initialized {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrInvalidState
	}
	if released.Validate(create, cleanup) != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	input := codingReleaseAdmission{Create: create, Cleanup: cleanup, Released: released.Receipt(),
		ControlRevision: released.Revision(), ControlStateDigest: released.StateDigest(),
		SpecBySlot: r.specBySlot}
	var operation lifecycle.Operation
	var sandbox lifecycle.Sandbox
	err := mutateStateTriple(ctx, r.bound.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.Initialized || marker.PlanDigest != r.bound.digest ||
				marker.AuthorityMode != "" || marker.ControlPolicyDigest != "" ||
				checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil {
				return codingidentity.ErrInvalidState
			}
			var err error
			operation, sandbox, err = finishCodingCurrentCleanup(ctx, slots, ledger,
				r.bound.plan, input, now)
			return err
		})
	if err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if err := ctx.Err(); err != nil {
		// The commit might have happened. Reconcile the exact PG state and
		// Control tombstone read-only; never re-issue physical cleanup.
		return lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	return operation, sandbox, nil
}

// finishCodingCurrentCleanup mutates only transaction-local decoded copies.
// It does not accept a ConfirmAbsence callback or create an absence proof.
func finishCodingCurrentCleanup(ctx context.Context, slots *codingidentity.State,
	ledger *lifecyclerepository.State, plan codingidentity.Plan,
	input codingReleaseAdmission, now time.Time) (lifecycle.Operation, lifecycle.Sandbox, error) {
	stage := "admission"
	fail := func() (lifecycle.Operation, lifecycle.Sandbox, error) {
		return lifecycle.Operation{}, lifecycle.Sandbox{},
			fmt.Errorf("coding release %s: %w", stage, codingidentity.ErrConflict)
	}
	create, cleanup, released := input.Create, input.Cleanup, input.Released
	if ctx == nil || ctx.Err() != nil || slots == nil || ledger == nil || now.IsZero() ||
		slots.Validate(plan) != nil || len(input.SpecBySlot) != len(plan.Slots) ||
		input.ControlRevision == 0 || lifecycle.ValidateDigest(input.ControlStateDigest) != nil ||
		released.Status != dockercontrol.ReceiptReleased || released.Authority != create ||
		released.AuthorityDigest != create.Digest() || released.CleanupAuthority != cleanup ||
		lifecycle.ValidateDigest(released.CompletionDigest) != nil ||
		lifecycle.ValidateDigest(released.CompletionEvidenceDigest) != nil ||
		lifecycle.ValidateDigest(released.AbsenceDigest) != nil ||
		lifecycle.ValidateDigest(released.AbsenceEvidenceDigest) != nil ||
		released.UpdatedAt.IsZero() || released.UpdatedAt.After(now) ||
		released.UpdatedAt.Before(cleanup.IssuedAt) ||
		!released.UpdatedAt.Before(cleanup.ExpiresAt) ||
		create.BindControl(plan, cleanup.ControlPolicyDigest, plan.OwnerPrincipalDigest,
			input.SpecBySlot[create.SlotID], create.IssuedAt) != nil ||
		cleanup.BindControl(create, plan, cleanup.ControlPolicyDigest, plan.OwnerPrincipalDigest,
			input.SpecBySlot[create.SlotID], cleanup.IssuedAt) != nil {
		return fail()
	}
	for _, slot := range plan.Slots {
		if lifecycle.ValidateDigest(input.SpecBySlot[slot.ID]) != nil {
			return fail()
		}
	}
	stage = "current-reservation"
	index := -1
	for current, candidate := range slots.Reservations {
		if candidate.Slot.ID == create.SlotID {
			index = current
			break
		}
	}
	if index < 0 {
		return fail()
	}
	reservation := slots.Reservations[index]
	binding, exists := slots.Retirements[create.SlotID]
	if !exists || reservation.Status != codingidentity.Cleaning ||
		reservation.Claim.AllocationID != create.AllocationID ||
		reservation.Claim.SandboxID != create.SandboxID ||
		reservation.Claim.OperationID != create.OperationID ||
		reservation.Claim.AttemptID != create.AttemptID ||
		reservation.Claim.RequestDigest != create.RequestDigest ||
		reservation.Claim.Generation != create.CreationGeneration ||
		reservation.Claim.Fence != create.Fence || reservation.Claim.TenantDigest != create.TenantDigest ||
		reservation.SpecDigest != create.SpecDigest || reservation.PlanDigest != create.PlanDigest ||
		binding.Validate(reservation) != nil ||
		binding.OriginalAuthorityDigest != create.Digest() ||
		binding.CleanupAuthorityDigest != cleanup.Digest() ||
		binding.ControlCompletionDigest != released.CompletionDigest ||
		binding.ControlEvidenceDigest != released.CompletionEvidenceDigest ||
		input.ControlRevision <= binding.ControlReceiptRevision ||
		input.ControlStateDigest == binding.ControlReceiptStateDigest {
		return fail()
	}
	storedCleanup, err := readCodingCleanupEnvelope(*slots, plan, create,
		binding.OperationID, cleanup.ControlPolicyDigest, plan.OwnerPrincipalDigest,
		input.SpecBySlot)
	if err != nil || storedCleanup != cleanup ||
		binding.OperationID != cleanup.CleanupOperationID ||
		binding.AttemptID != cleanup.CleanupAttemptID ||
		binding.RequestDigest != cleanup.CleanupRequestDigest ||
		binding.CurrentGeneration != cleanup.CurrentGeneration ||
		binding.CurrentFence != cleanup.CleanupFence {
		return fail()
	}
	stage = "original-operation"
	original, err := ledger.GetOperation(create.OperationID)
	if err != nil || original.Validate() != nil || original.ID != create.OperationID ||
		original.Type != lifecycle.OperationCreate ||
		(original.State != lifecycle.OperationRunning &&
			original.State != lifecycle.OperationSucceeded &&
			original.State != lifecycle.OperationOutcomeUnknown) ||
		original.SandboxID != create.SandboxID || original.AttemptID != create.AttemptID ||
		original.FencingToken != create.Fence ||
		(original.RequestDigest != "" && original.RequestDigest != create.RequestDigest) ||
		!codingStoredIdempotencyMatches(ledger, original, create.RequestDigest,
			create.ProviderRevisionID, false) {
		return fail()
	}
	stage = "current-operation"
	operation, err := ledger.GetOperation(binding.OperationID)
	if err != nil || operation.Validate() != nil || operation.ID != binding.OperationID ||
		operation.Type != lifecycle.OperationTerminate ||
		(operation.State != lifecycle.OperationRunning &&
			operation.State != lifecycle.OperationOutcomeUnknown) ||
		operation.SandboxID != create.SandboxID ||
		operation.AttemptID != binding.AttemptID ||
		operation.RequestDigest != binding.RequestDigest ||
		operation.FencingToken != binding.CurrentFence ||
		!operation.Deadline.Equal(cleanup.OperationDeadline) ||
		!codingStoredIdempotencyMatches(ledger, operation, binding.RequestDigest,
			create.ProviderRevisionID, true) {
		return fail()
	}
	stage = "current-sandbox-and-lease"
	sandbox, err := ledger.GetSandbox(create.SandboxID)
	if err != nil || sandbox.Validate() != nil || sandbox.ID != create.SandboxID ||
		sandbox.ProviderRevisionID != create.ProviderRevisionID ||
		sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.DesiredState != lifecycle.DesiredTerminated ||
		sandbox.ObservedState != lifecycle.ObservedTerminating ||
		sandbox.Generation != binding.CurrentGeneration ||
		ledger.Fencing[sandbox.ProviderRevisionID+"\x00"+sandbox.ID] != binding.CurrentFence {
		return fail()
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil || tenantDigest != create.TenantDigest {
		return fail()
	}
	lease, err := ledger.GetLease(sandbox.ID)
	if err != nil || lease.Validate() != nil || lease.SandboxID != sandbox.ID ||
		lease.Generation != sandbox.Generation || lease.FencingToken != binding.CurrentFence ||
		!lease.ExpiresAt.Equal(sandbox.LeaseExpiresAt) {
		return fail()
	}
	stage = "transaction-transition"
	terminated, err := lifecycle.ApplyObservedTransition(sandbox,
		lifecycle.ObservedTerminated, sandbox.Generation, now)
	if err != nil || ledger.UpdateSandbox(terminated, sandbox.Generation, binding.CurrentFence) != nil {
		return fail()
	}
	result := operation
	if operation.State == lifecycle.OperationRunning {
		result, err = lifecycle.SucceedOperation(operation, now)
		if err != nil || ledger.UpdateOperation(result) != nil {
			return fail()
		}
	}
	slots.Reservations = slices.Delete(slots.Reservations, index, index+1)
	delete(slots.Retirements, create.SlotID)
	if slots.Validate(plan) != nil {
		return fail()
	}
	stage = "terminated-event"
	eventSum := sha256.Sum256([]byte(result.ID + "\x00" + string(result.State) + "\x00terminated"))
	_, err = ledger.AppendEvent(lifecycle.Event{ID: "event-" + hex.EncodeToString(eventSum[:]),
		SandboxID: terminated.ID, OperationID: result.ID, Generation: terminated.Generation,
		FencingToken: result.FencingToken, Kind: "terminated", OccurredAt: now})
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	return result, terminated, nil
}
