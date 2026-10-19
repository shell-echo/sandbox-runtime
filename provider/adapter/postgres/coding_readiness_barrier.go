package providerpostgres

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func codingAdmissionEventID(operationID, kind string) string {
	sum := sha256.Sum256([]byte(operationID + "\x00" + kind))
	return "event-" + hex.EncodeToString(sum[:])
}

// Includes released originals: slot reuse cannot rewrite historical Unknown.
func checkCodingReadinessBarrier(slots codingidentity.State, before, after lifecyclerepository.State, now time.Time) error {
	if len(slots.CreateCompletions) > len(slots.OriginalCreates) {
		return ErrCorrupt
	}
	for allocation, binding := range slots.CreateCompletions {
		record, exists := slots.OriginalCreates[allocation]
		original, err := decodeCodingOriginalCreate(record, now)
		if !exists || err != nil || !validCodingCompletion(binding, original, now) {
			return ErrCorrupt
		}
	}
	for allocation, record := range slots.OriginalCreates {
		original, err := decodeCodingOriginalCreate(record, now)
		if err != nil {
			return ErrCorrupt
		}
		old, oldExists := before.Operations[original.OperationID]
		current, exists := after.Operations[original.OperationID]
		if !oldExists || !exists || current.Validate() != nil || !sameCodingOriginalOutcome(old, current, now) ||
			!codingStoredIdempotencyMatches(&after, current, original.RequestDigest, original.ProviderRevisionID, false) {
			return lifecyclerepository.ErrRetirementBlocked
		}
		_, completed := slots.CreateCompletions[allocation]
		if current.State == lifecycle.OperationSucceeded && !completed {
			return ErrCorrupt
		}
		oldEvents := map[string]lifecycle.Event{}
		for _, event := range before.Events[original.SandboxID] {
			oldEvents[event.ID] = event
		}
		for _, event := range after.Events[original.SandboxID] {
			if event.OperationID == original.OperationID && (event.Kind == "ready" || event.Kind == "reconciled-ready") {
				if oldEvent, ok := oldEvents[event.ID]; !ok || oldEvent != event {
					return lifecyclerepository.ErrRetirementBlocked
				}
			}
		}
		live := false
		for _, reservation := range slots.Reservations {
			if reservation.Claim.AllocationID == allocation {
				live = true
				break
			}
		}
		if !live {
			// A released allocation has no runtime authority left. Preserve its
			// full projection, apart from the original conservative Unknown path.
			history := codingidentity.Reservation{Claim: codingidentity.Claim{SandboxID: original.SandboxID, OperationID: original.OperationID,
				Generation: original.CreationGeneration, Fence: original.Fence}}
			if !codingUnretiredProjection(history, before, after, now) {
				return lifecyclerepository.ErrRetirementBlocked
			}
		}
	}
	for _, reservation := range slots.Reservations {
		binding, hasCompletion := slots.CreateCompletions[reservation.Claim.AllocationID]
		if hasCompletion && (binding.SlotID != reservation.Slot.ID || binding.AuthorityDigest != slots.OriginalCreates[reservation.Claim.AllocationID].Digest) {
			return ErrCorrupt
		}
		old, exists := before.Sandboxes[reservation.Claim.SandboxID]
		current, stillExists := after.Sandboxes[reservation.Claim.SandboxID]
		if !exists || !stillExists {
			return ErrCorrupt
		}
		switch reservation.Status {
		case codingidentity.Creating:
			if hasCompletion || current.ObservedState != lifecycle.ObservedProvisioning || current.ObservedGeneration != old.ObservedGeneration {
				return lifecyclerepository.ErrRetirementBlocked
			}
			if !codingUnretiredProjection(reservation, before, after, now) {
				return lifecyclerepository.ErrRetirementBlocked
			}

		case codingidentity.Active:
			if !hasCompletion || current.ObservedState != lifecycle.ObservedReady || current.ObservedGeneration != old.ObservedGeneration || current.ObservedGeneration != reservation.Claim.Generation {
				return ErrCorrupt
			}
			if !codingUnretiredProjection(reservation, before, after, now) {
				return lifecyclerepository.ErrRetirementBlocked
			}
		case codingidentity.Cleaning:
			if hasCompletion {
				retirement := slots.Retirements[reservation.Slot.ID]
				if retirement.ControlCompletionDigest != binding.CompletionDigest || retirement.ControlEvidenceDigest != binding.EvidenceDigest || !codingCompletionFloor(binding, retirement.ControlReceiptRevision, retirement.ControlReceiptStateDigest) {
					return ErrCorrupt
				}
			}
		}
	}
	return nil
}

func validCodingCompletion(b codingidentity.CreateCompletionBinding, c dockercontrol.CodingCreateAuthority, now time.Time) bool {
	return b.Validate() == nil && b.AllocationID == c.AllocationID && b.SlotID == c.SlotID && b.AuthorityDigest == c.Digest() && !b.UpdatedAt.After(now) && c.Validate(b.UpdatedAt) == nil
}

func codingCompletionFloor(b codingidentity.CreateCompletionBinding, revision uint64, stateDigest string) bool {
	return revision == b.ControlRevision && stateDigest == b.ControlStateDigest || revision > b.ControlRevision && stateDigest != b.ControlStateDigest
}

func sameCodingOriginalOutcome(old, current lifecycle.Operation, now time.Time) bool {
	if reflect.DeepEqual(old, current) {
		return true
	}
	if old.State != lifecycle.OperationRunning || current.State != lifecycle.OperationOutcomeUnknown || current.Failure == nil || current.ObservedAt.After(now) {
		return false
	}
	want, err := lifecycle.MarkOutcomeUnknown(old, current.ObservedAt, *current.Failure)
	return err == nil && reflect.DeepEqual(want, current)
}

// Reconstruct only allowed generic writes, then compare the entire protected
// sandbox projection. Other sandboxes may progress independently in this row.
func codingUnretiredProjection(r codingidentity.Reservation, before, after lifecyclerepository.State, now time.Time) bool {
	id := r.Claim.SandboxID
	expected := newLifecycleState()
	if expected.Import(before.Export()) != nil {
		return false
	}
	original := after.Operations[r.Claim.OperationID]
	if !reflect.DeepEqual(original, before.Operations[original.ID]) {
		if !sameCodingOriginalOutcome(before.Operations[original.ID], original, now) || expected.UpdateOperation(original) != nil {
			return false
		}
	}
	var admitted lifecycle.Operation
	newCount := 0
	for operationID, op := range after.Operations {
		if op.SandboxID == id {
			if _, exists := before.Operations[operationID]; !exists {
				admitted = op
				newCount++
			}
		}
	}
	if newCount > 1 {
		return false
	}
	if newCount == 1 {
		if r.Status != codingidentity.Creating && r.Status != codingidentity.Active {
			return false
		}
		old := before.Sandboxes[id]
		mutation := lifecycle.MutationRequest{OperationID: admitted.ID, AttemptID: admitted.AttemptID, FencingToken: admitted.FencingToken,
			IdempotencyKey: admitted.IdempotencyKey, RequestDigest: admitted.RequestDigest, Deadline: admitted.Deadline, ExpectedGeneration: old.Generation}
		if admitted.ObservedAt.After(now) || mutation.Validate(admitted.ObservedAt) != nil {
			return false
		}
		var updated lifecycle.Sandbox
		var operation lifecycle.Operation
		var err error
		switch admitted.Type {
		case lifecycle.OperationTerminate:
			updated, operation, err = lifecycle.StartTerminate(old, lifecycle.TerminateRequest{MutationRequest: mutation, Reason: "readiness-guard"}, admitted.ObservedAt)
		case lifecycle.OperationExtendLease:
			if r.Status != codingidentity.Active || old.DesiredState != lifecycle.DesiredReady || !old.LeaseExpiresAt.After(admitted.ObservedAt) {
				return false
			}
			// The calling application owns the configured lease horizon. This
			// guard enforces an exact, positive whole-second renewal admission;
			// it never accepts a bare lease replacement or changes identity.
			expiry := after.Sandboxes[id].LeaseExpiresAt
			delta := expiry.Sub(old.LeaseExpiresAt)
			if delta <= 0 || delta%time.Second != 0 || !old.LeaseExpiresAt.Add(delta).Equal(expiry) {
				return false
			}
			updated = old
			updated.LeaseExpiresAt = expiry
			updated.UpdatedAt = admitted.ObservedAt
			operation = lifecycle.Operation{ID: admitted.ID, AttemptID: admitted.AttemptID, FencingToken: admitted.FencingToken, SandboxID: id,
				Type: lifecycle.OperationExtendLease, State: lifecycle.OperationAccepted, Deadline: admitted.Deadline, ObservedAt: admitted.ObservedAt,
				IdempotencyKey: admitted.IdempotencyKey, RequestDigest: admitted.RequestDigest}
		default:
			return false
		}
		if err != nil || !reflect.DeepEqual(operation, admitted) {
			return false
		}
		var event lifecycle.Event
		count := 0
		for _, e := range after.Events[id] {
			if e.Sequence == before.EventLatest[id]+1 {
				event = e
				count++
			}
		}
		if count != 1 || event.OperationID != admitted.ID || !event.OccurredAt.Equal(admitted.ObservedAt) ||
			event.DataDigest != admitted.RequestDigest || event.ID != codingAdmissionEventID(admitted.ID, event.Kind) {
			return false
		}
		if admitted.Type == lifecycle.OperationTerminate {
			if event.Kind != "termination-requested" && event.Kind != "lease-expired" {
				return false
			}
			if event.Kind == "lease-expired" {
				lease := before.Leases[id]
				expiry := lifecycle.LeaseExpiryTermination(old, lease, admitted.ObservedAt)
				if lease.Validate() != nil || lease.SandboxID != id || !lease.ExpiresAt.Equal(old.LeaseExpiresAt) || lease.Generation != old.Generation ||
					lease.ExpiresAt.After(admitted.ObservedAt) || mutation != expiry.MutationRequest {
					return false
				}
			}
		} else if event.Kind != "lease-extended" {
			return false
		}
		if _, err := expected.ReserveMutation(admitted.IdempotencyKey, admitted.RequestDigest, old.Generation, updated, operation, event); err != nil {
			return false
		}
	}
	// Existing dispatch failure recording is two writes: operation then event.
	// Permit only its exact deterministic original Unknown event, including
	// retention truncation, by applying the real state method to our copy.
	if !reflect.DeepEqual(expected.Events[id], after.Events[id]) || expected.EventLatest[id] != after.EventLatest[id] {
		events := after.Events[id]
		if len(events) == 0 || after.EventLatest[id] != expected.EventLatest[id]+1 {
			return false
		}
		event := events[len(events)-1]
		if original.State != lifecycle.OperationOutcomeUnknown || event.OperationID != original.ID || event.Kind != "outcome-unknown" || event.DataDigest != "" ||
			event.Generation != r.Claim.Generation || event.FencingToken != r.Claim.Fence || event.OccurredAt.Before(original.ObservedAt) || event.OccurredAt.After(now) {
			return false
		}
		birth := before.Sandboxes[id]
		birth.Generation = r.Claim.Generation
		if appendCodingReadyEvent(&expected, birth, original, "outcome-unknown", "", event.OccurredAt) != nil {
			return false
		}
	}
	if !reflect.DeepEqual(expected.Sandboxes[id], after.Sandboxes[id]) || expected.Leases[id] != after.Leases[id] ||
		expected.Fencing[before.Sandboxes[id].ProviderRevisionID+"\x00"+id] != after.Fencing[before.Sandboxes[id].ProviderRevisionID+"\x00"+id] ||
		!reflect.DeepEqual(expected.Events[id], after.Events[id]) || expected.EventLatest[id] != after.EventLatest[id] {
		return false
	}
	for operationID, op := range expected.Operations {
		if op.SandboxID == id {
			if !reflect.DeepEqual(op, after.Operations[operationID]) {
				return false
			}
		}
	}
	for operationID, op := range after.Operations {
		if op.SandboxID == id {
			if !reflect.DeepEqual(op, expected.Operations[operationID]) {
				return false
			}
		}
	}
	for key, item := range expected.Idempotency {
		if item.Operation.SandboxID == id {
			if !reflect.DeepEqual(item, after.Idempotency[key]) {
				return false
			}
		}
	}
	for key, item := range after.Idempotency {
		if item.Operation.SandboxID == id {
			if !reflect.DeepEqual(item, expected.Idempotency[key]) {
				return false
			}
		}
	}
	return true
}
