package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var errCodingLeaseUnchanged = errors.New("Coding lease result already retained")

// The v3 lease effect is entirely in PG. Commit admission, completion and
// both events together so later mutations cannot strand a new Accepted lease.
// Legacy and all non-lease mutations retain their existing guarded path.
func (r *CodingLifecycleRepository) ReserveMutation(ctx context.Context, key, digest string, expected uint64, sandbox lifecycle.Sandbox, operation lifecycle.Operation, event lifecycle.Event) (lifecyclerepository.MutationResult, error) {
	if r == nil || r.bound == nil || r.LifecycleRepository == nil {
		return lifecyclerepository.MutationResult{}, ErrUnavailable
	}
	if operation.Type != lifecycle.OperationExtendLease || r.bound.controlPolicyDigest == "" {
		return r.LifecycleRepository.ReserveMutation(ctx, key, digest, expected, sandbox, operation, event)
	}
	var result lifecyclerepository.MutationResult
	err := r.mutateCodingLease(ctx, func(marker codingIdentityMarker, slots codingidentity.State, ledger *lifecyclerepository.State, now time.Time) error {
		var err error
		result, err = reserveCodingLease(ctx, marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest,
			key, digest, expected, sandbox, operation, event, now)
		return err
	})
	if err != nil {
		return lifecyclerepository.MutationResult{}, err
	}
	return result, nil
}

// Recovery never renews expiry or invokes Control. Historical successful
// results are read-only; older unfinished results require the exact current
// admission because their retained event contains no historical expiry.
func (r *CodingLifecycleRepository) ReconcileCodingLease(ctx context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, error) {
	var operation lifecycle.Operation
	var sandbox lifecycle.Sandbox
	err := r.mutateCodingLease(ctx, func(marker codingIdentityMarker, slots codingidentity.State, ledger *lifecyclerepository.State, now time.Time) error {
		var err error
		operation, sandbox, err = completeCodingLease(ctx, marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, id, now)
		return err
	})
	if err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	return operation, sandbox, nil
}

func (r *CodingLifecycleRepository) mutateCodingLease(ctx context.Context, mutation func(codingIdentityMarker, codingidentity.State, *lifecyclerepository.State, time.Time) error) error {
	if r == nil || r.bound == nil || r.bound.store == nil || ctx == nil || mutation == nil {
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
			return mutation(*marker, *slots, ledger, time.Now().UTC())
		})
	if errors.Is(err, errCodingLeaseUnchanged) {
		err = nil // The sentinel rolls back without an UPDATE or revision change.
	}
	if err == nil {
		err = ctx.Err()
	}
	return err
}

func reserveCodingLease(ctx context.Context, marker codingIdentityMarker, slots codingidentity.State, ledger *lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy, key, digest string, expected uint64, sandbox lifecycle.Sandbox,
	operation lifecycle.Operation, event lifecycle.Event, now time.Time) (lifecyclerepository.MutationResult, error) {
	fail := func() (lifecyclerepository.MutationResult, error) {
		return lifecyclerepository.MutationResult{}, codingidentity.ErrConflict
	}
	if ctx == nil || ctx.Err() != nil || ledger == nil || operation.Type != lifecycle.OperationExtendLease ||
		!validCodingLeaseState(marker, slots, *ledger, plan, specs, policy, now) {
		return fail()
	}
	next := newLifecycleState()
	if next.Import(ledger.Export()) != nil {
		return fail()
	}
	result, err := next.ReserveMutation(key, digest, expected, sandbox, operation, event)
	if err != nil {
		return lifecyclerepository.MutationResult{}, err
	}
	if result.Replayed {
		// State.ReserveMutation's replay check is intentionally narrower.
		// A typed replay must not substitute a different authority tuple.
		retained := result.Operation
		retained.State, retained.ObservedAt, retained.Failure = operation.State, operation.ObservedAt, operation.Failure
		if operation.State != lifecycle.OperationAccepted || operation.CancelRequested || operation.Failure != nil ||
			key != operation.IdempotencyKey || digest != operation.RequestDigest || sandbox.ID != result.Sandbox.ID ||
			expected != sandbox.Generation || !reflect.DeepEqual(retained, operation) {
			return fail()
		}
	} else {
		old := ledger.Sandboxes[sandbox.ID]
		if !now.Before(operation.Deadline) || !old.LeaseExpiresAt.After(now) || operation.ObservedAt.After(now) ||
			checkCodingRetirementBarrierWithMarker(marker, slots, *ledger, next, now) != nil {
			return fail()
		}
	}
	op, sb, err := completeCodingLease(ctx, marker, slots, &next, plan, specs, policy, result.Operation.ID, now)
	if err != nil && !errors.Is(err, errCodingLeaseUnchanged) {
		return fail()
	}
	result.Operation, result.Sandbox = op, sb
	if errors.Is(err, errCodingLeaseUnchanged) {
		return result, err // Exact replay; never write another event/revision.
	}
	if ctx.Err() != nil {
		return fail()
	}
	*ledger = next
	return result, nil
}

func validCodingLeaseState(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy string, now time.Time) bool {
	digest, err := plan.Digest()
	if err != nil || !marker.matchesAtomic(digest, policy) || slots.Validate(plan) != nil || len(specs) != len(plan.Slots) ||
		checkCodingRetirementBarrierWithMarker(marker, slots, ledger, ledger, now) != nil {
		return false
	}
	for _, slot := range plan.Slots {
		if lifecycle.ValidateDigest(specs[slot.ID]) != nil {
			return false
		}
	}
	return true
}

func completeCodingLease(ctx context.Context, marker codingIdentityMarker, slots codingidentity.State, ledger *lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy, id string, now time.Time) (lifecycle.Operation, lifecycle.Sandbox, error) {
	fail := func() (lifecycle.Operation, lifecycle.Sandbox, error) {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	if ctx == nil || ctx.Err() != nil || ledger == nil || lifecycle.ValidateIdentifier(id) != nil ||
		!validCodingLeaseState(marker, slots, *ledger, plan, specs, policy, now) {
		return fail()
	}
	op, exists := ledger.Operations[id]
	sb, hasSandbox := ledger.Sandboxes[op.SandboxID]
	if !exists || !hasSandbox || op.ID != id || op.Type != lifecycle.OperationExtendLease || op.Validate() != nil || sb.Validate() != nil ||
		op.ObservedAt.After(now) || sb.UpdatedAt.After(now) || !codingStoredIdempotencyMatches(ledger, op, op.RequestDigest, sb.ProviderRevisionID, true) {
		return fail()
	}
	var original dockercontrol.CodingCreateAuthority
	count := 0
	for _, record := range slots.OriginalCreates {
		c, err := decodeCodingOriginalCreate(record, now)
		if err != nil {
			return fail()
		}
		if c.SandboxID == sb.ID {
			original, count = c, count+1
		}
	}
	completion, completed := slots.CreateCompletions[original.AllocationID]
	if count != 1 || !completed || original.ControlPolicyDigest != policy || original.SpecDigest != specs[original.SlotID] ||
		validateCodingOriginalCreate(slots, *ledger, plan, original, now) != nil || !validCodingCompletion(completion, original, now) {
		return fail()
	}
	var admitted lifecycle.Event
	count = 0
	for _, e := range ledger.Events[sb.ID] {
		if e.OperationID == id && e.Kind == "lease-extended" {
			admitted, count = e, count+1
		}
	}
	if count > 1 || (count == 1 && (admitted.Validate() != nil || admitted.ID != codingAdmissionEventID(id, "lease-extended") ||
		admitted.SandboxID != sb.ID || admitted.Generation != original.CreationGeneration || admitted.FencingToken != op.FencingToken ||
		admitted.DataDigest != op.RequestDigest || !admitted.OccurredAt.Before(op.Deadline) || admitted.OccurredAt.After(op.ObservedAt) ||
		admitted.OccurredAt.Before(completion.UpdatedAt))) || op.FencingToken < original.Fence {
		return fail()
	}
	if op.State == lifecycle.OperationSucceeded {
		// Generic writers cannot fabricate this terminal outcome. Validate
		// retained events, or prove they precede the finite retained window.
		events := ledger.Events[sb.ID]
		if len(events) == 0 {
			return fail()
		}
		first := events[0]
		if first.OccurredAt.After(now) {
			return fail()
		}
		pruned := first.Sequence > 1
		successCount := 0
		var success lifecycle.Event
		for _, e := range events {
			if e.ID == codingLeaseSuccessEventID(id) || (e.OperationID == id && e.Kind == "lease-renewal-succeeded") {
				success, successCount = e, successCount+1
			}
		}
		if successCount == 0 {
			if count != 0 || !pruned || !op.ObservedAt.Before(first.OccurredAt) {
				return fail()
			}
		} else if successCount != 1 || success.ID != codingLeaseSuccessEventID(id) || success.Validate() != nil ||
			success.OperationID != id || success.SandboxID != sb.ID || success.Kind != "lease-renewal-succeeded" ||
			success.Generation != original.CreationGeneration || success.FencingToken != op.FencingToken ||
			success.DataDigest != "" || !success.OccurredAt.Equal(op.ObservedAt) ||
			(count == 1 && success.Sequence != admitted.Sequence+1) ||
			(count == 0 && (!pruned || success.Sequence != first.Sequence)) {
			return fail()
		}
		return op, sb, errCodingLeaseUnchanged
	}
	if count != 1 {
		return fail()
	}
	// Older pending records have no historical expiry proof. Only the latest
	// exact admission can be completed; never rewrite a superseding lease.
	lease, hasLease := ledger.Leases[sb.ID]
	if op.State != lifecycle.OperationAccepted || op.CancelRequested || !op.ObservedAt.Equal(admitted.OccurredAt) || !hasLease || lease.Validate() != nil ||
		lease.SandboxID != sb.ID || lease.Generation != sb.Generation || lease.FencingToken != op.FencingToken || !lease.ExpiresAt.Equal(sb.LeaseExpiresAt) ||
		ledger.Fencing[sb.ProviderRevisionID+"\x00"+sb.ID] != op.FencingToken || sb.Generation != original.CreationGeneration ||
		sb.ObservedGeneration != sb.Generation || sb.DesiredState != lifecycle.DesiredReady || sb.ObservedState != lifecycle.ObservedReady ||
		!sb.UpdatedAt.Equal(admitted.OccurredAt) || ledger.EventLatest[sb.ID] != admitted.Sequence {
		return fail()
	}
	active := false
	for _, r := range slots.Reservations {
		if r.Claim.AllocationID == original.AllocationID {
			_, retiring := slots.Retirements[r.Slot.ID]
			active = r.Status == codingidentity.Active && !retiring
		}
	}
	if !active {
		return fail()
	}
	// Admission already committed the DB-only effect before its deadline.
	// Reconstruct that transition at admission time, even on a later read;
	// this does not extend expiry, authorize work or reopen a dispatch window.
	running, err := lifecycle.BeginOperation(op, admitted.OccurredAt)
	if err != nil {
		return fail()
	}
	succeeded, err := lifecycle.SucceedOperation(running, now)
	if err != nil {
		return fail()
	}
	for _, e := range ledger.Events[sb.ID] {
		if e.ID == codingLeaseSuccessEventID(id) {
			return fail()
		}
	}
	next := newLifecycleState()
	if next.Import(ledger.Export()) != nil || next.UpdateOperation(succeeded) != nil ||
		appendCodingReadyEvent(&next, sb, succeeded, "lease-renewal-succeeded", "", now) != nil ||
		next.EventLatest[sb.ID] != admitted.Sequence+1 ||
		checkCodingRetirementBarrierWithMarker(marker, slots, next, next, now) != nil || ctx.Err() != nil {
		return fail()
	}
	*ledger = next
	return succeeded, sb, nil
}

func codingLeaseSuccessEventID(id string) string {
	sum := sha256.Sum256([]byte(id + "\x00" + string(lifecycle.OperationSucceeded) + "\x00lease-renewal-succeeded"))
	return "event-" + hex.EncodeToString(sum[:])
}
