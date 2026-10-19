package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

// ReadCodingRuntime reads all authority documents with one MVCC SELECT, without
// acquiring a write lock or advancing a revision. The result is preflight
// evidence only, never a replacement for same-row durable mutation admission.
func (r *CodingLifecycleRepository) ReadCodingRuntime(ctx context.Context, id string) (codingcontrol.RuntimeSnapshot, error) {
	if r == nil || r.bound == nil || r.bound.store == nil || r.bound.store.pool == nil || ctx == nil || lifecycle.ValidateIdentifier(id) != nil {
		return codingcontrol.RuntimeSnapshot{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return codingcontrol.RuntimeSnapshot{}, err
	}
	store := r.bound.store
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var markerDocument, slotsDocument, ledgerDocument, intentsDocument, legacyDocument, fencesDocument []byte
	err := store.pool.QueryRow(opCtx, `SELECT documents->$1,documents->$2,documents->$3,documents->$4,documents->$5,documents->$6 FROM sandbox_runtime_provider.control_state WHERE singleton`,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument, codingExecIntentDocument, execDocument, codingExecFenceDocument).Scan(&markerDocument, &slotsDocument, &ledgerDocument, &intentsDocument, &legacyDocument, &fencesDocument)
	if err != nil {
		return codingcontrol.RuntimeSnapshot{}, stateError(ctx, opCtx, err)
	}
	if _, err := decodeCodingExecIsolation(markerDocument, intentsDocument, legacyDocument, ledgerDocument, slotsDocument, fencesDocument, time.Now().UTC()); err != nil {
		return codingcontrol.RuntimeSnapshot{}, ErrCorrupt
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
			return codingcontrol.RuntimeSnapshot{}, ErrCorrupt
		}
	}
	snapshot, err := readCodingRuntimeSnapshot(marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, id, time.Now().UTC())
	if opCtx.Err() != nil {
		return codingcontrol.RuntimeSnapshot{}, stateError(ctx, opCtx, opCtx.Err())
	}
	return snapshot, err
}

func readCodingRuntimeSnapshot(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy, id string, now time.Time) (codingcontrol.RuntimeSnapshot, error) {
	fail := func() (codingcontrol.RuntimeSnapshot, error) {
		return codingcontrol.RuntimeSnapshot{}, codingcontrol.ErrRuntimePreflight
	}
	planDigest, err := plan.Digest()
	if err != nil || now.IsZero() || lifecycle.ValidateIdentifier(id) != nil || !marker.matchesAtomic(planDigest, policy) ||
		slots.Validate(plan) != nil || len(specs) != len(plan.Slots) || checkCodingRetirementBarrierWithMarker(marker, slots, ledger, ledger, now) != nil {
		return fail()
	}
	for _, slot := range plan.Slots {
		if lifecycle.ValidateDigest(specs[slot.ID]) != nil {
			return fail()
		}
	}
	sb, exists := ledger.Sandboxes[id]
	lease, hasLease := ledger.Leases[id]
	if !exists || !hasLease || sb.Validate() != nil || lease.Validate() != nil || sb.ID != id || sb.UpdatedAt.After(now) ||
		sb.DesiredState != lifecycle.DesiredReady || sb.ObservedState != lifecycle.ObservedReady || sb.ObservedGeneration != sb.Generation ||
		lease.SandboxID != id || lease.Generation != sb.Generation || !lease.ExpiresAt.Equal(sb.LeaseExpiresAt) || !lease.ExpiresAt.After(now) ||
		ledger.Fencing[sb.ProviderRevisionID+"\x00"+id] != lease.FencingToken {
		return fail()
	}
	var current codingidentity.Reservation
	count := 0
	for _, reservation := range slots.Reservations {
		if reservation.Claim.SandboxID == id {
			current, count = reservation, count+1
		}
	}
	if count != 1 || current.Status != codingidentity.Active || current.Claim.Generation != sb.Generation || lease.FencingToken < current.Claim.Fence {
		return fail()
	}
	if _, retired := slots.Retirements[current.Slot.ID]; retired {
		return fail()
	}
	original, err := decodeCodingOriginalCreate(slots.OriginalCreates[current.Claim.AllocationID], now)
	completion, completed := slots.CreateCompletions[current.Claim.AllocationID]
	createOperation := ledger.Operations[original.OperationID]
	if err != nil || !completed || original.ControlPolicyDigest != policy || original.SpecDigest != specs[current.Slot.ID] ||
		original.AllocationID != current.Claim.AllocationID || original.SandboxID != id ||
		(createOperation.State != lifecycle.OperationSucceeded && createOperation.State != lifecycle.OperationOutcomeUnknown) || createOperation.ObservedAt.After(now) ||
		validateCodingOriginalCreate(slots, ledger, plan, original, now) != nil || !validCodingCompletion(completion, original, now) {
		return fail()
	}
	return codingcontrol.RuntimeSnapshot{Sandbox: sb, Lease: lease, ProfileDigest: plan.ProfileDigest,
		ControlPolicyDigest: policy, ProviderPrincipalDigest: plan.OwnerPrincipalDigest, ObservedAt: now}, nil
}

var _ codingcontrol.RuntimeReader = (*CodingLifecycleRepository)(nil)
