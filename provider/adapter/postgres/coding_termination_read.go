package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

var _ codingcontrol.TerminationRepository = (*CodingLifecycleRepository)(nil)

// One SELECT gives all authority documents the same MVCC snapshot, without a
// write lock or revision change. Later admission/release still rechecks its
// tuple under the row lock; this result never grants a dispatch capability.
func (r *CodingLifecycleRepository) ReadTermination(ctx context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, error) {
	if r == nil || r.bound == nil || r.bound.store == nil || r.bound.store.pool == nil || ctx == nil || lifecycle.ValidateIdentifier(id) != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	store := r.bound.store
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var markerDocument, slotsDocument, ledgerDocument, intentsDocument, legacyDocument, fencesDocument []byte
	err := store.pool.QueryRow(opCtx, `SELECT documents->$1,documents->$2,documents->$3,documents->$4,documents->$5,documents->$6 FROM sandbox_runtime_provider.control_state WHERE singleton`,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument, codingExecIntentDocument, execDocument, codingExecFenceDocument).Scan(&markerDocument, &slotsDocument, &ledgerDocument, &intentsDocument, &legacyDocument, &fencesDocument)
	if err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, stateError(ctx, opCtx, err)
	}
	if _, err := decodeCodingExecIsolation(markerDocument, intentsDocument, legacyDocument, ledgerDocument, slotsDocument, fencesDocument, time.Now().UTC()); err != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, ErrCorrupt
	}
	marker, slots, ledger := codingIdentityMarker{}, codingidentity.State{}, newLifecycleState()
	for _, item := range []struct {
		document []byte
		decode   func(json.RawMessage) error
	}{
		{markerDocument, func(raw json.RawMessage) error { return importCodingIdentityMarker(&marker, raw) }},
		{slotsDocument, func(raw json.RawMessage) error { return importCodingIdentityState(&slots, raw) }},
		{ledgerDocument, func(raw json.RawMessage) error { return importLifecycleState(&ledger, raw) }},
	} {
		raw, exists, err := decodeStoredDocument(item.document)
		if err != nil || !exists || item.decode(raw) != nil {
			return lifecycle.Operation{}, lifecycle.Sandbox{}, ErrCorrupt
		}
	}
	op, sb, err := readCodingTerminationSnapshot(marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, id, time.Now().UTC())
	if opCtx.Err() != nil {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, stateError(ctx, opCtx, opCtx.Err())
	}
	return op, sb, err
}

func readCodingTerminationSnapshot(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy, id string, now time.Time) (lifecycle.Operation, lifecycle.Sandbox, error) {
	fail := func() (lifecycle.Operation, lifecycle.Sandbox, error) {
		return lifecycle.Operation{}, lifecycle.Sandbox{}, ErrCorrupt
	}
	planDigest, err := plan.Digest()
	if err != nil || !marker.matchesAtomic(planDigest, policy) || slots.Validate(plan) != nil ||
		checkCodingRetirementBarrierWithMarker(marker, slots, ledger, ledger, now) != nil || len(specs) != len(plan.Slots) {
		return fail()
	}
	op, ok := ledger.Operations[id]
	sb, exists := ledger.Sandboxes[op.SandboxID]
	lease, hasLease := ledger.Leases[sb.ID]
	if !ok || !exists || !hasLease || op.Validate() != nil || sb.Validate() != nil || lease.Validate() != nil ||
		op.ID != id || op.Type != lifecycle.OperationTerminate || op.SandboxID != sb.ID ||
		sb.DesiredState != lifecycle.DesiredTerminated || op.ObservedAt.After(now) || sb.UpdatedAt.After(now) ||
		lease.SandboxID != sb.ID || lease.Generation != sb.Generation || !lease.ExpiresAt.Equal(sb.LeaseExpiresAt) ||
		lease.FencingToken != op.FencingToken || ledger.Fencing[sb.ProviderRevisionID+"\x00"+sb.ID] != op.FencingToken ||
		!codingStoredIdempotencyMatches(&ledger, op, op.RequestDigest, sb.ProviderRevisionID, true) {
		return fail()
	}
	var original dockercontrol.CodingCreateAuthority
	count := 0
	for _, record := range slots.OriginalCreates {
		candidate, err := decodeCodingOriginalCreate(record, now)
		if err != nil {
			return fail()
		}
		if candidate.SandboxID == sb.ID {
			original = candidate
			count++
		}
	}
	if count != 1 || original.ControlPolicyDigest != policy || original.SpecDigest != specs[original.SlotID] ||
		validateCodingOriginalCreate(slots, ledger, plan, original, now) != nil || sb.Generation <= original.CreationGeneration || op.FencingToken < original.Fence {
		return fail()
	}
	var reservation codingidentity.Reservation
	for _, item := range slots.Reservations {
		if item.Claim.AllocationID == original.AllocationID {
			reservation = item
		}
	}
	if reservation.Claim.AllocationID == "" {
		// A reused slot may belong to someone else. Only the old sandbox's
		// frozen terminated projection is returned, never the new occupant.
		if sb.ObservedState != lifecycle.ObservedTerminated || sb.ObservedGeneration != sb.Generation ||
			(op.State != lifecycle.OperationSucceeded && op.State != lifecycle.OperationOutcomeUnknown) {
			return fail()
		}
		sum := sha256.Sum256([]byte(op.ID + "\x00" + string(op.State) + "\x00terminated"))
		found := false
		for _, event := range ledger.Events[sb.ID] {
			if event.ID == "event-"+hex.EncodeToString(sum[:]) && event.SandboxID == sb.ID && event.OperationID == id &&
				event.Kind == "terminated" && event.Generation == sb.Generation && event.FencingToken == op.FencingToken &&
				event.DataDigest == "" && !event.OccurredAt.Before(op.ObservedAt) && !event.OccurredAt.After(now) {
				found = true
			}
		}
		if !found {
			return fail()
		}
		return op, sb, nil
	}
	switch op.State {
	case lifecycle.OperationAccepted:
		if reservation.Status != codingidentity.Creating && reservation.Status != codingidentity.Active {
			return fail()
		}
		if _, retired := slots.Retirements[reservation.Slot.ID]; retired {
			return fail()
		}
	case lifecycle.OperationRunning, lifecycle.OperationOutcomeUnknown:
		binding, retired := slots.Retirements[reservation.Slot.ID]
		if reservation.Status != codingidentity.Cleaning || !retired || binding.OperationID != id ||
			!validStoredRetirement(binding, reservation, ledger) {
			return fail()
		}
		if _, err := readCodingCleanupEnvelope(slots, plan, original, id, policy, plan.OwnerPrincipalDigest, specs); err != nil {
			return fail()
		}
	default:
		return fail()
	}
	return op, sb, nil
}
