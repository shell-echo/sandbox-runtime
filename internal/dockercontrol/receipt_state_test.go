package dockercontrol

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
)

func testReceiptBinding(a CodingCreateAuthority, plan codingidentity.Plan) CodingReceiptBinding {
	scope := testControlDigest("7")
	observed, _ := projectCodingDaemonInfo(codingInfoFixture(), scope)
	return CodingReceiptBinding{Plan: plan, SpecBySlot: map[string]string{
		plan.Slots[0].ID: testControlDigest("c"), plan.Slots[1].ID: testControlDigest("d")},
		ProfileDigest:           a.ProfileDigest,
		DaemonDigest:            observed.IdentityDigest,
		DaemonEnvironmentDigest: observed.EnvironmentDigest,
		EndpointScopeDigest:     scope, RuntimePlatform: observed.Platform,
		ControlPolicyDigest: a.ControlPolicyDigest, PeerPrincipalDigest: a.PeerPrincipalDigest,
		PlanDigest: a.PlanDigest, Capacity: 2}
}

func testReceiptAuthority(t *testing.T) (CodingCreateAuthority, codingidentity.Plan, time.Time) {
	t.Helper()
	ticket, operation, sandbox, plan, now := testCodingCreate(t)
	a, err := NewCodingCreateAuthority(t.Context(), ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	return a, plan, now
}

func otherReceiptAuthority(t *testing.T, id string, slotIndex int, now time.Time) CodingCreateAuthority {
	t.Helper()
	ticket, operation, sandbox, plan, _ := testCodingCreate(t)
	sandbox.ID += "-" + id
	operation.ID += "-" + id
	operation.SandboxID = sandbox.ID
	operation.AttemptID += "-" + id
	allocationID, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID,
		sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Slot = plan.Slots[slotIndex]
	if slotIndex == 1 {
		ticket.SpecDigest = testControlDigest("d")
	}
	ticket.Claim.SandboxID = sandbox.ID
	ticket.Claim.OperationID = operation.ID
	ticket.Claim.AttemptID = operation.AttemptID
	ticket.Claim.AllocationID = allocationID
	a, err := NewCodingCreateAuthority(t.Context(), ticket, operation, sandbox, plan,
		testControlDigest("e"), testControlDigest("f"), now)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCodingReceiptStateUnknownReplayAndCapacity(t *testing.T) {
	a, plan, now := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	state, err := NewCodingReceiptState(binding)
	if err != nil || state.Validate(binding) != nil {
		t.Fatalf("new state = %#v, %v", state, err)
	}
	next, receipt, fresh, err := state.beginUnknown(binding, a, now)
	if err != nil || !fresh || receipt.Status != ReceiptUnknown || next.Revision != 2 || next.Validate(binding) != nil {
		t.Fatalf("first unknown = %#v, %t, %v", receipt, fresh, err)
	}
	replayed, old, fresh, err := next.beginUnknown(binding, a, now)
	if err != nil || fresh || replayed.StateDigest != next.StateDigest || old != receipt {
		t.Fatalf("replay = %#v, %t, %v", old, fresh, err)
	}
	changed := a
	changed.Fence++
	changed.RequestID = codingRequestID(changed)
	if changed.RequestID == a.RequestID || changed.EffectID != a.EffectID {
		t.Fatal("request/effect keys did not separate")
	}
	if _, _, _, err := next.beginUnknown(binding, changed, now); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("same effect with new fence/request = %v", err)
	}
	changed = a
	changed.AttemptID = "attempt-2"
	changed.RequestID = codingRequestID(changed)
	if _, _, _, err := next.beginUnknown(binding, changed, now); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("same allocation with new attempt = %v", err)
	}
	second := otherReceiptAuthority(t, "b", 1, now)
	secondState, _, fresh, err := next.beginUnknown(binding, second, now)
	if err != nil || !fresh || secondState.Validate(binding) != nil {
		t.Fatalf("second allocation = %t, %v", fresh, err)
	}
	third := otherReceiptAuthority(t, "c", 1, now)
	if _, _, _, err := secondState.beginUnknown(binding, third, now); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("third allocation colliding with occupied physical slot = %v", err)
	}
	if _, _, _, err := next.beginUnknown(binding, a, now.Add(MaxAuthorityAge)); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("expired authority replay = %v", err)
	}
}

func TestCodingReceiptStateRejectsCorruption(t *testing.T) {
	a, plan, now := testReceiptAuthority(t)
	binding := testReceiptBinding(a, plan)
	state, _ := NewCodingReceiptState(binding)
	state, _, _, _ = state.beginUnknown(binding, a, now)
	for name, corrupt := range map[string]func(*CodingReceiptState){
		"binding": func(s *CodingReceiptState) { s.ProfileDigest = testControlDigest("0") },
		"daemon":  func(s *CodingReceiptState) { s.DaemonDigest = testControlDigest("0"); s.StateDigest = s.digest() },
		"digest":  func(s *CodingReceiptState) { s.StateDigest = testControlDigest("0") },
		"spec map": func(s *CodingReceiptState) {
			s.SpecMapDigest = testControlDigest("0")
			s.StateDigest = s.digest()
		},
		"status": func(s *CodingReceiptState) {
			s.Records[0].Status = ReceiptReleased
			s.StateDigest = s.digest()
		},
		"duplicate": func(s *CodingReceiptState) {
			s.Records = append(s.Records, s.Records[0])
			s.StateDigest = s.digest()
		},
		"authority": func(s *CodingReceiptState) {
			s.Records[0].Authority.Fence++
			s.StateDigest = s.digest()
		},
		"future update": func(s *CodingReceiptState) {
			s.Records[0].UpdatedAt = s.Records[0].Authority.IssuedAt.Add(-time.Second)
			s.StateDigest = s.digest()
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := state.Clone()
			corrupt(&copy)
			if !errors.Is(copy.Validate(binding), ErrInvalidReceiptState) {
				t.Fatal("corrupt receipt accepted")
			}
		})
	}
}

func TestCodingReceiptStateCleanupIntentIsSeparateFromCreateEffect(t *testing.T) {
	create, _, operation, sandbox, plan, now := testCodingCleanup(t)
	binding := testReceiptBinding(create, plan)
	state, err := NewCodingReceiptState(binding)
	if err != nil {
		t.Fatal(err)
	}
	state, _, _, err = state.beginUnknown(binding, create, now)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewCodingCleanupAuthority(t.Context(), create,
		codingidentity.Reservation{PlanDigest: create.PlanDigest, Slot: plan.Slots[0],
			Claim: codingidentity.Claim{TenantDigest: create.TenantDigest, SandboxID: create.SandboxID,
				AllocationID: create.AllocationID, OperationID: create.OperationID,
				AttemptID: create.AttemptID, RequestDigest: create.RequestDigest,
				Generation: create.CreationGeneration, Fence: create.Fence},
			SpecDigest: create.SpecDigest, Status: codingidentity.Cleaning},
		operation, sandbox, plan, binding.ControlPolicyDigest, binding.PeerPrincipalDigest, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := state.beginCleanup(binding, create.RequestID, intent, now); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("Unknown effect entered cleanup without quiescence: %v", err)
	}
	// Trusted Completion proof production code is deliberately not available
	// yet. This local fixture isolates the cleanup state transition only.
	state.Records[0].Status = ReceiptCompleted
	state.Records[0].CompletionDigest = testControlDigest("9")
	state.Records[0].CompletionEvidenceDigest = testControlDigest("8")
	state.StateDigest = state.digest()
	if state.Validate(binding) != nil {
		t.Fatal("completed fixture invalid")
	}
	newerCompletion := state.Clone()
	newerCompletion.Records[0].UpdatedAt = now.Add(time.Second)
	newerCompletion.StateDigest = newerCompletion.digest()
	if _, _, _, err := newerCompletion.beginCleanup(binding, create.RequestID,
		intent, now.Add(time.Second)); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("cleanup intent predating completion admitted: %v", err)
	}
	next, receipt, fresh, err := state.beginCleanup(binding, create.RequestID, intent, now)
	if err != nil || !fresh || receipt.Status != ReceiptCompleted ||
		receipt.CleanupAuthority != intent || next.Revision != state.Revision+1 || next.Validate(binding) != nil {
		t.Fatalf("durable cleanup intent = %#v, %t, %v", receipt, fresh, err)
	}
	if _, _, fresh, err := next.beginCleanup(binding, create.RequestID, intent, now); err != nil || fresh {
		t.Fatalf("cleanup replay became new permit: %t, %v", fresh, err)
	}
	changed := intent
	changed.CleanupFence++
	changed.RequestID = codingCleanupRequestID(changed)
	if _, _, _, err := next.beginCleanup(binding, create.RequestID, changed, now); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("different cleanup fence displaced intent: %v", err)
	}
	corrupt := next.Clone()
	corrupt.Records[0].CleanupAuthority.EffectID = testControlDigest("0")
	corrupt.StateDigest = corrupt.digest()
	if corrupt.Validate(binding) == nil {
		t.Fatal("foreign-effect cleanup intent validated")
	}
}
