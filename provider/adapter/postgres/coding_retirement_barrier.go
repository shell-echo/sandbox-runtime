package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

// All generic Provider lifecycle writers use this same control_state row lock.
// A Coding retirement is read under that lock before the lifecycle document
// is committed, including when a caller constructs a separate generic
// LifecycleRepository. No SQL lock survives the transaction or Docker I/O.
func mutateLifecycleWithRetirementGuard(ctx context.Context, store *Store,
	mutation func(*lifecyclerepository.State) error) error {
	if store == nil || store.pool == nil || ctx == nil || mutation == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return stateError(ctx, opCtx, err)
	}
	defer rollbackBounded(tx, store.operationTimeout)
	var markerDocument, slotsDocument, ledgerDocument []byte
	if err := tx.QueryRow(opCtx, `SELECT documents->$1,documents->$2,documents->$3 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument).
		Scan(&markerDocument, &slotsDocument, &ledgerDocument); err != nil {
		return stateError(ctx, opCtx, err)
	}
	marker := codingIdentityMarker{}
	slots := codingidentity.State{}
	ledger := newLifecycleState()
	for _, item := range []struct {
		document []byte
		decode   func(json.RawMessage) error
	}{
		{markerDocument, func(raw json.RawMessage) error { return importCodingIdentityMarker(&marker, raw) }},
		{slotsDocument, func(raw json.RawMessage) error { return importCodingIdentityState(&slots, raw) }},
		{ledgerDocument, func(raw json.RawMessage) error { return importLifecycleState(&ledger, raw) }},
	} {
		decoded, exists, err := decodeStoredDocument(item.document)
		if err != nil {
			return err
		}
		if exists && item.decode(decoded) != nil {
			return ErrCorrupt
		}
	}
	if marker.validate() != nil {
		return ErrCorrupt
	}
	if marker.Initialized {
		if !slots.Initialized || slots.Version != codingidentity.Version ||
			slots.PlanDigest != marker.PlanDigest || marker.PlanDigest == "" {
			return ErrCorrupt
		}
	} else if marker.PlanDigest != "" || slots.Initialized || slots.Version != 0 ||
		slots.PlanDigest != "" || slots.Reservations != nil || slots.Retirements != nil ||
		slots.OriginalCreates != nil {
		return ErrCorrupt
	}
	before := newLifecycleState()
	if before.Import(ledger.Export()) != nil {
		return ErrCorrupt
	}
	if err := mutation(&ledger); err != nil {
		return err
	}
	if err := checkCodingRetirementBarrierWithMarker(marker, slots, before, ledger,
		time.Now().UTC()); err != nil {
		return err
	}
	stored, err := encodeStoredState(exportLifecycleState(ledger))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state
SET documents=jsonb_set(documents,ARRAY[$1]::text[],$2::jsonb,true),revision=revision+1,updated_at=clock_timestamp()
WHERE singleton`, lifecycleDocument, stored); err != nil {
		return stateError(ctx, opCtx, err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return stateError(ctx, opCtx, err)
	}
	return nil
}

func checkCodingRetirementBarrierWithMarker(marker codingIdentityMarker,
	slots codingidentity.State, before, after lifecyclerepository.State, now time.Time) error {
	if marker.validate() != nil || marker.Initialized != slots.Initialized ||
		marker.PlanDigest != slots.PlanDigest {
		return ErrCorrupt
	}
	if err := checkCodingRetirementBarrier(slots, before, after, now); err != nil {
		return err
	}
	if marker.AuthorityMode != codingAtomicOriginalMode {
		if len(slots.OriginalCreates) != 0 {
			return ErrCorrupt
		}
		return nil
	}
	for allocationID, record := range slots.OriginalCreates {
		original, err := decodeCodingOriginalCreate(record, now)
		if err != nil || original.AllocationID != allocationID ||
			original.PlanDigest != marker.PlanDigest ||
			original.ControlPolicyDigest != marker.ControlPolicyDigest {
			return ErrCorrupt
		}
	}
	for _, reservation := range slots.Reservations {
		if reservation.Status != codingidentity.Creating &&
			reservation.Status != codingidentity.Active &&
			reservation.Status != codingidentity.Cleaning {
			return ErrCorrupt
		}
		record, exists := slots.OriginalCreates[reservation.Claim.AllocationID]
		original, err := decodeCodingOriginalCreate(record, now)
		claim := reservation.Claim
		if !exists || err != nil || original.ControlPolicyDigest != marker.ControlPolicyDigest ||
			original.PlanDigest != marker.PlanDigest || original.SpecDigest != reservation.SpecDigest ||
			original.SlotID != reservation.Slot.ID || original.AllocationID != claim.AllocationID ||
			original.SandboxID != claim.SandboxID || original.OperationID != claim.OperationID ||
			original.AttemptID != claim.AttemptID || original.RequestDigest != claim.RequestDigest ||
			original.TenantDigest != claim.TenantDigest ||
			original.CreationGeneration != claim.Generation || original.Fence != claim.Fence {
			return ErrCorrupt
		}
		operation, operationExists := after.Operations[original.OperationID]
		sandbox, sandboxExists := after.Sandboxes[original.SandboxID]
		tenantDigest, tenantErr := codingidentity.TenantDigestForID(sandbox.TenantID)
		if !operationExists || !sandboxExists || operation.Validate() != nil ||
			sandbox.Validate() != nil || operation.Type != lifecycle.OperationCreate ||
			operation.ID != original.OperationID || operation.SandboxID != original.SandboxID ||
			operation.AttemptID != original.AttemptID || operation.FencingToken != original.Fence ||
			(operation.RequestDigest != "" && operation.RequestDigest != original.RequestDigest) ||
			!operation.Deadline.Equal(original.OperationDeadline) ||
			sandbox.ProviderRevisionID != original.ProviderRevisionID ||
			sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
			sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
			sandbox.Generation < original.CreationGeneration || tenantErr != nil ||
			tenantDigest != original.TenantDigest ||
			!codingStoredIdempotencyMatches(&after, operation, original.RequestDigest,
				original.ProviderRevisionID, false) {
			return ErrCorrupt
		}
		if reservation.Status == codingidentity.Cleaning {
			binding, exists := slots.Retirements[reservation.Slot.ID]
			if !exists || binding.OriginalAuthorityDigest != original.Digest() {
				return ErrCorrupt
			}
		}
	}
	return nil
}

// Only an exact Running -> OutcomeUnknown update of the already-bound
// terminate attempt (and its matching outcome-unknown event) may change a
// protected allocation through the generic writer. The dedicated final
// release CAS is the sole writer that removes the retirement and succeeds or
// retains the terminal operation. Unknown never becomes Succeeded here.
func checkCodingRetirementBarrier(slots codingidentity.State,
	before, after lifecyclerepository.State, now time.Time) error {
	if !slots.Initialized {
		if slots.Version != 0 || slots.PlanDigest != "" || slots.Reservations != nil ||
			slots.Retirements != nil || slots.OriginalCreates != nil {
			return ErrCorrupt
		}
		return nil
	}
	if slots.Version != codingidentity.Version ||
		lifecycle.ValidateDigest(slots.PlanDigest) != nil || slots.Reservations == nil ||
		len(slots.Reservations) > codingidentity.LocalCandidateCapacity ||
		len(slots.OriginalCreates) > codingidentity.MaxOriginalCreateEnvelopes || now.IsZero() {
		return ErrCorrupt
	}
	for allocationID, record := range slots.OriginalCreates {
		original, err := decodeCodingOriginalCreate(record, now)
		if err != nil || original.AllocationID != allocationID {
			return ErrCorrupt
		}
	}
	reservations := make(map[string]codingidentity.Reservation, len(slots.Reservations))
	sandboxes, allocations, operations := map[string]bool{}, map[string]bool{}, map[string]bool{}
	uids, gids := map[uint32]bool{}, map[uint32]bool{}
	previous := ""
	for _, reservation := range slots.Reservations {
		claim := reservation.Claim
		if reservation.Slot.Validate() != nil || claim.Validate() != nil ||
			lifecycle.ValidateDigest(reservation.SpecDigest) != nil ||
			reservation.PlanDigest != slots.PlanDigest || reservation.Slot.ID <= previous ||
			sandboxes[claim.SandboxID] || allocations[claim.AllocationID] ||
			operations[claim.OperationID] || uids[reservation.Slot.WorkloadUID] ||
			gids[reservation.Slot.WorkloadGID] {
			return ErrCorrupt
		}
		switch reservation.Status {
		case codingidentity.Reserved, codingidentity.Creating, codingidentity.Active, codingidentity.Cleaning:
		default:
			return ErrCorrupt
		}
		previous = reservation.Slot.ID
		reservations[previous] = reservation
		sandboxes[claim.SandboxID], allocations[claim.AllocationID], operations[claim.OperationID] = true, true, true
		uids[reservation.Slot.WorkloadUID], gids[reservation.Slot.WorkloadGID] = true, true
		if reservation.Status == codingidentity.Cleaning {
			binding, exists := slots.Retirements[reservation.Slot.ID]
			if !exists || binding.Validate(reservation) != nil {
				return ErrCorrupt
			}
		}
	}
	type protectedRetirement struct {
		binding  codingidentity.RetirementBinding
		original codingidentity.Claim
	}
	protected := make(map[string]protectedRetirement, len(slots.Retirements))
	retirementOperations := map[string]bool{}
	for slotID, binding := range slots.Retirements {
		reservation, exists := reservations[slotID]
		if !exists || binding.Validate(reservation) != nil ||
			protected[reservation.Claim.SandboxID].binding.OperationID != "" ||
			retirementOperations[binding.OperationID] ||
			!validStoredRetirement(binding, reservation, before) {
			return ErrCorrupt
		}
		if record, present := slots.OriginalCreates[reservation.Claim.AllocationID]; present {
			original, err := decodeCodingOriginalCreate(record, now)
			if err != nil || original.Digest() != binding.OriginalAuthorityDigest ||
				original.SlotID != slotID || original.SandboxID != reservation.Claim.SandboxID {
				return ErrCorrupt
			}
		}
		retirementOperations[binding.OperationID] = true
		protected[reservation.Claim.SandboxID] = protectedRetirement{binding: binding,
			original: reservation.Claim}
	}
	for sandboxID, protected := range protected {
		binding, originalClaim := protected.binding, protected.original
		original, exists := before.Sandboxes[sandboxID]
		current, stillExists := after.Sandboxes[sandboxID]
		oldLease, leaseExists := before.Leases[sandboxID]
		newLease, leaseStillExists := after.Leases[sandboxID]
		scope := original.ProviderRevisionID + "\x00" + sandboxID
		if !exists || !stillExists || !leaseExists || !leaseStillExists ||
			!reflect.DeepEqual(original, current) || !reflect.DeepEqual(oldLease, newLease) ||
			before.Fencing[scope] != binding.CurrentFence ||
			after.Fencing[scope] != binding.CurrentFence ||
			original.Generation != binding.CurrentGeneration ||
			oldLease.Generation != binding.CurrentGeneration ||
			oldLease.FencingToken != binding.CurrentFence {
			return lifecyclerepository.ErrRetirementBlocked
		}
		for operationID, old := range before.Operations {
			if old.SandboxID != sandboxID {
				continue
			}
			newOperation, exists := after.Operations[operationID]
			if !exists || !sameProtectedOperation(old, newOperation, binding, originalClaim) {
				return lifecyclerepository.ErrRetirementBlocked
			}
		}
		for operationID, current := range after.Operations {
			if current.SandboxID == sandboxID {
				if _, existed := before.Operations[operationID]; !existed {
					return lifecyclerepository.ErrRetirementBlocked
				}
			}
		}
		for key, old := range before.Idempotency {
			if old.Operation.SandboxID != sandboxID {
				continue
			}
			newRecord, exists := after.Idempotency[key]
			if !exists || old.Scope != newRecord.Scope || old.Key != newRecord.Key ||
				old.RequestDigest != newRecord.RequestDigest ||
				!sameProtectedOperation(old.Operation, newRecord.Operation, binding, originalClaim) ||
				!reflect.DeepEqual(newRecord.Operation, after.Operations[old.Operation.ID]) {
				return lifecyclerepository.ErrRetirementBlocked
			}
		}
		for key, currentRecord := range after.Idempotency {
			if currentRecord.Operation.SandboxID == sandboxID {
				if _, existed := before.Idempotency[key]; !existed {
					return lifecyclerepository.ErrRetirementBlocked
				}
			}
		}
		if !protectedEventsUnchangedOrUnknown(before, after, sandboxID, binding, originalClaim, now) {
			return lifecyclerepository.ErrRetirementBlocked
		}
	}
	return nil
}

func validStoredRetirement(binding codingidentity.RetirementBinding,
	reservation codingidentity.Reservation, state lifecyclerepository.State) bool {
	claim := reservation.Claim
	sandbox, sandboxExists := state.Sandboxes[claim.SandboxID]
	lease, leaseExists := state.Leases[claim.SandboxID]
	original, originalExists := state.Operations[claim.OperationID]
	current, currentExists := state.Operations[binding.OperationID]
	tenantDigest, tenantError := codingidentity.TenantDigestForID(sandbox.TenantID)
	if !sandboxExists || !leaseExists || !originalExists || !currentExists ||
		sandbox.Validate() != nil || lease.Validate() != nil || original.Validate() != nil ||
		current.Validate() != nil || sandbox.ID != claim.SandboxID ||
		tenantError != nil || tenantDigest != claim.TenantDigest ||
		sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.DesiredState != lifecycle.DesiredTerminated ||
		sandbox.ObservedState != lifecycle.ObservedTerminating ||
		sandbox.Generation != binding.CurrentGeneration ||
		state.Fencing[sandbox.ProviderRevisionID+"\x00"+claim.SandboxID] != binding.CurrentFence ||
		lease.SandboxID != claim.SandboxID || lease.Generation != binding.CurrentGeneration ||
		lease.FencingToken != binding.CurrentFence || !lease.ExpiresAt.Equal(sandbox.LeaseExpiresAt) ||
		original.ID != claim.OperationID || original.SandboxID != claim.SandboxID ||
		original.Type != lifecycle.OperationCreate || original.AttemptID != claim.AttemptID ||
		original.FencingToken != claim.Fence ||
		(original.RequestDigest != "" && original.RequestDigest != claim.RequestDigest) ||
		(original.State != lifecycle.OperationRunning && original.State != lifecycle.OperationSucceeded &&
			original.State != lifecycle.OperationOutcomeUnknown) ||
		current.ID != binding.OperationID || current.SandboxID != claim.SandboxID ||
		current.Type != lifecycle.OperationTerminate || current.AttemptID != binding.AttemptID ||
		current.FencingToken != binding.CurrentFence || current.RequestDigest != binding.RequestDigest ||
		(current.State != lifecycle.OperationRunning && current.State != lifecycle.OperationOutcomeUnknown) ||
		!codingStoredIdempotencyMatches(&state, original, claim.RequestDigest, sandbox.ProviderRevisionID, false) ||
		!codingStoredIdempotencyMatches(&state, current, binding.RequestDigest, sandbox.ProviderRevisionID, true) {
		return false
	}
	var raw dockercontrol.CodingCleanupAuthority
	if json.Unmarshal([]byte(binding.CleanupAuthorityDocument), &raw) != nil {
		return false
	}
	cleanup, err := dockercontrol.DecodeCodingCleanupAuthority([]byte(binding.CleanupAuthorityDocument), raw.IssuedAt)
	return err == nil && cleanup.Digest() == binding.CleanupAuthorityDigest &&
		cleanup.OriginalAuthorityDigest == binding.OriginalAuthorityDigest &&
		cleanup.AllocationID == claim.AllocationID && cleanup.SandboxID == claim.SandboxID &&
		cleanup.TenantDigest == claim.TenantDigest && cleanup.PlanDigest == reservation.PlanDigest &&
		cleanup.SlotID == reservation.Slot.ID && cleanup.ProviderRevisionID == sandbox.ProviderRevisionID &&
		cleanup.BirthGeneration == claim.Generation && cleanup.BirthFence == claim.Fence &&
		cleanup.CleanupOperationID == binding.OperationID && cleanup.CleanupAttemptID == binding.AttemptID &&
		cleanup.CleanupRequestDigest == binding.RequestDigest &&
		cleanup.CurrentGeneration == binding.CurrentGeneration && cleanup.CleanupFence == binding.CurrentFence &&
		cleanup.OperationDeadline.Equal(current.Deadline)
}

func sameProtectedOperation(old, current lifecycle.Operation,
	binding codingidentity.RetirementBinding, original codingidentity.Claim) bool {
	if reflect.DeepEqual(old, current) {
		return true
	}
	currentAttempt := old.ID == binding.OperationID && old.AttemptID == binding.AttemptID &&
		old.RequestDigest == binding.RequestDigest && old.FencingToken == binding.CurrentFence &&
		old.Type == lifecycle.OperationTerminate
	originalAttempt := old.ID == original.OperationID && old.AttemptID == original.AttemptID &&
		old.FencingToken == original.Fence && old.Type == lifecycle.OperationCreate &&
		(old.RequestDigest == "" || old.RequestDigest == original.RequestDigest)
	if (!currentAttempt && !originalAttempt) ||
		old.State != lifecycle.OperationRunning || current.State != lifecycle.OperationOutcomeUnknown ||
		current.Failure == nil || current.Failure.Outcome != lifecycle.FailureUnknown ||
		current.ObservedAt.Before(old.ObservedAt) {
		return false
	}
	normalized := current
	normalized.State, normalized.ObservedAt, normalized.Failure = old.State, old.ObservedAt, old.Failure
	return reflect.DeepEqual(old, normalized)
}

func protectedEventsUnchangedOrUnknown(before, after lifecyclerepository.State,
	sandboxID string, binding codingidentity.RetirementBinding, original codingidentity.Claim, now time.Time) bool {
	oldEvents, newEvents := before.Events[sandboxID], after.Events[sandboxID]
	oldLatest, newLatest := before.EventLatest[sandboxID], after.EventLatest[sandboxID]
	if oldLatest == newLatest && reflect.DeepEqual(oldEvents, newEvents) {
		return true
	}
	if newLatest != oldLatest+1 || len(newEvents) == 0 {
		return false
	}
	last := newEvents[len(newEvents)-1]
	operation := after.Operations[last.OperationID]
	if operation.State != lifecycle.OperationOutcomeUnknown ||
		last.OperationID != binding.OperationID && last.OperationID != original.OperationID {
		return false
	}
	generation, fence := binding.CurrentGeneration, binding.CurrentFence
	if last.OperationID == original.OperationID {
		generation, fence = original.Generation, original.Fence
	}
	sum := sha256.Sum256([]byte(last.OperationID + "\x00" +
		string(lifecycle.OperationOutcomeUnknown) + "\x00outcome-unknown"))
	if last.ID != "event-"+hex.EncodeToString(sum[:]) || last.Sequence != newLatest ||
		last.SandboxID != sandboxID ||
		last.Generation != generation || last.FencingToken != fence || operation.FencingToken != fence ||
		last.Kind != "outcome-unknown" || last.DataDigest != "" || last.OccurredAt.IsZero() ||
		last.OccurredAt.Before(operation.ObservedAt) || last.OccurredAt.After(now) {
		return false
	}
	prefix := newEvents[:len(newEvents)-1]
	return reflect.DeepEqual(oldEvents, prefix) ||
		len(oldEvents) == len(prefix)+1 && reflect.DeepEqual(oldEvents[1:], prefix)
}
