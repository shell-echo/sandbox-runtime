package codingidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestCodingRetirementBindingTracksCurrentCleaningSlot(t *testing.T) {
	plan := testPlan()
	state, err := NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(state)
	if err != nil || bytes.Contains(before, []byte("retirements")) {
		t.Fatal("empty retirement map changed existing canonical state")
	}
	claim := testClaim("retirement")
	reserved, err := state.Reserve(plan, claim, testSpecs(plan), func(Claim) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	creating, err := state.BeginCreate(plan, reserved)
	if err != nil {
		t.Fatal(err)
	}
	active, err := state.CompleteCreate(plan, creating)
	if err != nil {
		t.Fatal(err)
	}
	cleaning, err := state.BeginCleanup(plan, active)
	if err != nil {
		t.Fatal(err)
	}
	binding := RetirementBinding{OriginalAllocationID: claim.AllocationID,
		OriginalAuthorityDigest: testDigest("a"), OriginalGeneration: claim.Generation,
		OriginalFence: claim.Fence, OperationID: "terminate-retirement",
		AttemptID: "attempt-retirement", RequestDigest: testDigest("b"),
		CurrentGeneration: claim.Generation + 1, CurrentFence: claim.Fence,
		ControlReceiptRevision: 3, ControlReceiptStateDigest: testDigest("c"),
		ControlCompletionDigest: testDigest("d"), ControlEvidenceDigest: testDigest("e"),
		CleanupAuthorityDocument: `{}`, CleanupAuthorityDigest: testDigest("f")}
	state.Retirements = map[string]RetirementBinding{cleaning.Slot.ID: binding}
	if state.Validate(plan) != nil {
		t.Fatal("same-fence current retirement binding rejected")
	}
	copy := state.Clone()
	delete(copy.Retirements, cleaning.Slot.ID)
	if len(state.Retirements) != 1 {
		t.Fatal("clone shared retirement map")
	}
	wrong := state.Clone()
	item := wrong.Retirements[cleaning.Slot.ID]
	item.CurrentFence = claim.Fence - 1
	wrong.Retirements[cleaning.Slot.ID] = item
	if wrong.Validate(plan) == nil {
		t.Fatal("below-birth cleanup fence accepted")
	}
	wrong = state.Clone()
	wrong.Retirements[plan.Slots[1].ID] = binding
	if wrong.Validate(plan) == nil {
		t.Fatal("retirement attached to unoccupied slot")
	}
	proof, err := ConfirmAbsence(context.Background(), cleaning,
		func(context.Context, Reservation) error { return nil })
	if err != nil || state.CompleteCleanup(plan, cleaning, proof) != nil ||
		len(state.Reservations) != 0 || len(state.Retirements) != 0 || state.Validate(plan) != nil {
		t.Fatalf("released slot retained retirement binding: %v", err)
	}
}
