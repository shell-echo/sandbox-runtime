package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var errCodingAlreadyReady = errors.New("Coding readiness already committed")
var _ codingcontrol.CreateRepository = (*CodingLifecycleRepository)(nil)

func (r *CodingLifecycleRepository) ReadCreateBinding(ctx context.Context, operationID string) (dockercontrol.CodingCreateAuthority, error) {
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil || lifecycle.ValidateIdentifier(operationID) != nil {
		return dockercontrol.CodingCreateAuthority{}, ErrUnavailable
	}
	if err := r.bound.readAtomicMarker(ctx); err != nil {
		return dockercontrol.CodingCreateAuthority{}, err
	}
	slots, err := readState(ctx, r.bound.store, codingIdentityStateDocument, func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil || slots.Validate(r.bound.plan) != nil {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	for _, reservation := range slots.Reservations {
		if reservation.Claim.OperationID != operationID {
			continue
		}
		if reservation.Status != codingidentity.Creating && reservation.Status != codingidentity.Active {
			return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
		}
		if _, retiring := slots.Retirements[reservation.Slot.ID]; retiring {
			return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
		}
		return r.bound.ReadOriginalCreateAuthority(ctx, reservation.Claim.AllocationID)
	}
	return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
}

func (r *CodingLifecycleRepository) CompleteCreateWithObservation(ctx context.Context, operationID string, observed codingcontrol.CreateObservation) (lifecycle.Operation, lifecycle.Sandbox, error) {
	var operation lifecycle.Operation
	var sandbox lifecycle.Sandbox
	create := observed.CreateAuthority()
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil || operationID != create.OperationID ||
		create.ControlPolicyDigest != r.bound.controlPolicyDigest || observed.Validate(create, time.Now().UTC()) != nil {
		return operation, sandbox, codingidentity.ErrConflict
	}
	err := mutateStateTriple(ctx, r.bound.store, codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker, func(m codingIdentityMarker) any { return m },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState, func(s codingidentity.State) any { return s },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.matchesAtomic(r.bound.digest, r.bound.controlPolicyDigest) || checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil {
				return codingidentity.ErrConflict
			}
			var err error
			operation, sandbox, err = completeCodingCreate(ctx, slots, ledger, r.bound.plan, r.specBySlot, observed, now)
			if err != nil {
				return err
			}
			return checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now)
		})
	// The sentinel aborts the transaction before its UPDATE/revision increment.
	// Only the exact already-committed current tuple can produce these values.
	if errors.Is(err, errCodingAlreadyReady) {
		err = nil
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	return operation, sandbox, nil
}

func completionBinding(o codingcontrol.CreateObservation) codingidentity.CreateCompletionBinding {
	c := o.CreateAuthority()
	return codingidentity.CreateCompletionBinding{AllocationID: c.AllocationID, SlotID: c.SlotID, AuthorityDigest: c.Digest(),
		ControlRevision: o.ControlRevision(), ControlStateDigest: o.ControlStateDigest(), CompletionDigest: o.CompletionDigest(),
		EvidenceDigest: o.CompletionEvidenceDigest(), UpdatedAt: o.UpdatedAt()}
}

func completeCodingCreate(ctx context.Context, slots *codingidentity.State, ledger *lifecyclerepository.State, plan codingidentity.Plan,
	specs map[string]string, observed codingcontrol.CreateObservation, now time.Time) (lifecycle.Operation, lifecycle.Sandbox, error) {
	fail := func() (lifecycle.Operation, lifecycle.Sandbox, error) {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	c := observed.CreateAuthority()
	if ctx == nil || ctx.Err() != nil || slots == nil || ledger == nil || observed.Validate(c, now) != nil ||
		validateCodingOriginalCreate(*slots, *ledger, plan, c, now) != nil || len(specs) != len(plan.Slots) ||
		c.BindControl(plan, c.ControlPolicyDigest, plan.OwnerPrincipalDigest, specs[c.SlotID], c.IssuedAt) != nil {
		return fail()
	}
	for _, slot := range plan.Slots {
		if lifecycle.ValidateDigest(specs[slot.ID]) != nil {
			return fail()
		}
	}
	var reservation codingidentity.Reservation
	for _, item := range slots.Reservations {
		if item.Slot.ID == c.SlotID {
			reservation = item
			break
		}
	}
	if reservation.Claim.AllocationID != c.AllocationID || (reservation.Status != codingidentity.Creating && reservation.Status != codingidentity.Active) {
		return fail()
	}
	if _, exists := slots.Retirements[c.SlotID]; exists {
		return fail()
	}
	op := ledger.Operations[c.OperationID]
	sb := ledger.Sandboxes[c.SandboxID]
	lease, exists := ledger.Leases[c.SandboxID]
	if !exists || lease.Validate() != nil || sb.Generation != c.CreationGeneration || sb.DesiredState != lifecycle.DesiredReady ||
		lease.SandboxID != sb.ID || lease.Generation != sb.Generation || lease.FencingToken != c.Fence ||
		!lease.ExpiresAt.Equal(sb.LeaseExpiresAt) || !lease.ExpiresAt.After(now) ||
		ledger.Fencing[sb.ProviderRevisionID+"\x00"+sb.ID] != c.Fence || sb.UpdatedAt.After(now) || op.ObservedAt.After(now) {
		return fail()
	}
	// Even a forged same-generation successor cannot race readiness admission.
	for id, other := range ledger.Operations {
		if id != op.ID && other.SandboxID == sb.ID {
			return fail()
		}
	}
	binding := completionBinding(observed)
	if reservation.Status == codingidentity.Active {
		stored, ok := slots.CreateCompletions[c.AllocationID]
		if !ok || stored != binding || sb.ObservedState != lifecycle.ObservedReady ||
			(op.State != lifecycle.OperationSucceeded && op.State != lifecycle.OperationOutcomeUnknown) {
			return fail()
		}
		return op, sb, errCodingAlreadyReady
	}
	if _, exists := slots.CreateCompletions[c.AllocationID]; exists {
		return fail()
	}
	if sb.ObservedState != lifecycle.ObservedProvisioning || (op.State != lifecycle.OperationRunning && op.State != lifecycle.OperationOutcomeUnknown) {
		return fail()
	}
	// Work on copies so event collisions/failed transitions cannot leave even
	// an in-process partial result. The PG transaction commits all three docs.
	nextSlots := slots.Clone()
	nextLedger := newLifecycleState()
	if nextLedger.Import(ledger.Export()) != nil {
		return fail()
	}
	if _, err := nextSlots.CompleteCreate(plan, reservation); err != nil {
		return fail()
	}
	if nextSlots.CreateCompletions == nil {
		nextSlots.CreateCompletions = make(map[string]codingidentity.CreateCompletionBinding)
	}
	nextSlots.CreateCompletions[c.AllocationID] = binding
	result := op
	var err error
	if op.State == lifecycle.OperationRunning {
		if op.CancelRequested || !now.Before(op.Deadline) {
			result, err = lifecycle.MarkOutcomeUnknown(op, now, lifecycle.Failure{Code: "coding_create_completion_late", Retryable: true, Outcome: lifecycle.FailureUnknown})
		} else {
			result, err = lifecycle.SucceedOperation(op, now)
		}
		if err != nil || nextLedger.UpdateOperation(result) != nil {
			return fail()
		}
		if result.State == lifecycle.OperationOutcomeUnknown && appendCodingReadyEvent(&nextLedger, sb, result, "outcome-unknown", "", now) != nil {
			return fail()
		}
	}
	ready, err := lifecycle.ApplyObservedTransition(sb, lifecycle.ObservedReady, sb.Generation, now)
	if err != nil || nextLedger.UpdateSandbox(ready, sb.Generation, c.Fence) != nil {
		return fail()
	}
	kind := "ready"
	if result.State == lifecycle.OperationOutcomeUnknown {
		kind = "reconciled-ready"
	}
	if appendCodingReadyEvent(&nextLedger, ready, result, kind, binding.CompletionDigest, now) != nil || nextSlots.Validate(plan) != nil || ctx.Err() != nil {
		return fail()
	}
	*slots = nextSlots
	*ledger = nextLedger
	return result, ready, nil
}

func appendCodingReadyEvent(ledger *lifecyclerepository.State, sandbox lifecycle.Sandbox, operation lifecycle.Operation, kind, digest string, now time.Time) error {
	sum := sha256.Sum256([]byte(operation.ID + "\x00" + string(operation.State) + "\x00" + kind))
	_, err := ledger.AppendEvent(lifecycle.Event{ID: "event-" + hex.EncodeToString(sum[:]), SandboxID: sandbox.ID, OperationID: operation.ID,
		Generation: sandbox.Generation, FencingToken: operation.FencingToken, Kind: kind, DataDigest: digest, OccurredAt: now})
	return err
}
