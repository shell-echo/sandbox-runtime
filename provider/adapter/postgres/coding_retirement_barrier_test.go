package providerpostgres

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func copyCodingBarrierLedger(t *testing.T, source lifecyclerepository.State) lifecyclerepository.State {
	t.Helper()
	copy := lifecyclerepository.NewState()
	if err := copy.Import(source.Export()); err != nil {
		t.Fatal(err)
	}
	return copy
}

func TestCodingRetirementBarrierRejectsGenericWritePaths(t *testing.T) {
	for name, mutation := range map[string]func(*testing.T, *lifecyclerepository.State, string, string, time.Time){
		"higher fence": func(t *testing.T, state *lifecyclerepository.State, sandboxID, _ string, _ time.Time) {
			sandbox := state.Sandboxes[sandboxID]
			state.Fencing[sandbox.ProviderRevisionID+"\x00"+sandboxID]++
		},
		"generic mutation higher fence": func(t *testing.T, state *lifecyclerepository.State, sandboxID, operationID string, now time.Time) {
			oldSandbox := state.Sandboxes[sandboxID]
			updated := oldSandbox
			updated.Generation++
			updated.UpdatedAt = now.Add(time.Second)
			operation := state.Operations[operationID]
			operation.ID = "new-terminate-operation"
			operation.AttemptID = "new-terminate-attempt"
			operation.FencingToken++
			operation.State = lifecycle.OperationAccepted
			operation.ObservedAt = updated.UpdatedAt
			operation.Deadline = updated.UpdatedAt.Add(time.Minute)
			operation.IdempotencyKey = "new-terminate-idempotency"
			operation.RequestDigest = codingTestDigest("b")
			operation.Failure = nil
			_, err := state.ReserveMutation(operation.IdempotencyKey, operation.RequestDigest,
				oldSandbox.Generation, updated, operation, lifecycle.Event{
					ID: "event-new-terminate-operation", SandboxID: sandboxID,
					OperationID: operation.ID, Generation: updated.Generation,
					FencingToken: operation.FencingToken, Kind: "termination-requested",
					OccurredAt: updated.UpdatedAt})
			if err != nil {
				t.Fatalf("prepare generic higher-fence mutation: %v", err)
			}
		},
		"sandbox transition": func(t *testing.T, state *lifecyclerepository.State, sandboxID, _ string, now time.Time) {
			old := state.Sandboxes[sandboxID]
			updated, err := lifecycle.ApplyObservedTransition(old, lifecycle.ObservedTerminated,
				old.Generation, now)
			if err != nil || state.UpdateSandbox(updated, old.Generation,
				state.Fencing[old.ProviderRevisionID+"\x00"+sandboxID]) != nil {
				t.Fatalf("prepare generic sandbox write: %v", err)
			}
		},
		"lease replacement": func(t *testing.T, state *lifecyclerepository.State, sandboxID, _ string, _ time.Time) {
			lease := state.Leases[sandboxID]
			lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute)
			sandbox := state.Sandboxes[sandboxID]
			if err := state.ReplaceLease(lease, state.Fencing[sandbox.ProviderRevisionID+"\x00"+sandboxID]); err != nil {
				t.Fatal(err)
			}
		},
		"terminal rewrite": func(t *testing.T, state *lifecyclerepository.State, _ string, operationID string, now time.Time) {
			old := state.Operations[operationID]
			updated, err := lifecycle.SucceedOperation(old, now)
			if err != nil || state.UpdateOperation(updated) != nil {
				t.Fatalf("prepare generic terminal rewrite: %v", err)
			}
		},
		"event": func(t *testing.T, state *lifecyclerepository.State, sandboxID, operationID string, now time.Time) {
			sandbox := state.Sandboxes[sandboxID]
			operation := state.Operations[operationID]
			_, err := state.AppendEvent(lifecycle.Event{ID: "event-generic-retirement-bypass",
				SandboxID: sandboxID, OperationID: operationID, Generation: sandbox.Generation,
				FencingToken: operation.FencingToken, Kind: "terminated", OccurredAt: now})
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
			before := copyCodingBarrierLedger(t, fixture.ledger)
			after := copyCodingBarrierLedger(t, fixture.ledger)
			mutation(t, &after, input.Create.SandboxID, input.Cleanup.CleanupOperationID, now)
			if err := checkCodingRetirementBarrier(fixture.slots, before, after, now); !errors.Is(err, lifecyclerepository.ErrRetirementBlocked) {
				t.Fatalf("generic writer bypassed durable retirement: %v", err)
			}
		})
	}
}

func TestCodingRetirementBarrierAllowsExactUnknownAndUnrelatedState(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationOutcomeUnknown)
	before := copyCodingBarrierLedger(t, fixture.ledger)
	after := copyCodingBarrierLedger(t, fixture.ledger)
	operation := after.Operations[input.Cleanup.CleanupOperationID]
	unknown, err := lifecycle.MarkOutcomeUnknown(operation, now,
		lifecycle.Failure{Code: "response_unknown", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil || after.UpdateOperation(unknown) != nil {
		t.Fatalf("prepare same-attempt Unknown: %v", err)
	}
	if err := checkCodingRetirementBarrier(fixture.slots, before, after, now); err != nil {
		t.Fatalf("same-attempt Unknown blocked: %v", err)
	}
	sum := sha256.Sum256([]byte(unknown.ID + "\x00" + string(unknown.State) + "\x00outcome-unknown"))
	_, err = after.AppendEvent(lifecycle.Event{ID: "event-" + hex.EncodeToString(sum[:]),
		SandboxID: unknown.SandboxID, OperationID: unknown.ID,
		Generation:   fixture.ledger.Sandboxes[unknown.SandboxID].Generation,
		FencingToken: unknown.FencingToken, Kind: "outcome-unknown", OccurredAt: now})
	if err != nil || checkCodingRetirementBarrier(fixture.slots, before, after, now) != nil {
		t.Fatalf("matching Unknown event blocked: %v", err)
	}
	// An unrelated sandbox remains writable in the same Provider row.
	unrelated := copyCodingBarrierLedger(t, before)
	other := fixture.ledger.Sandboxes[input.Create.SandboxID]
	other.ID = "other-sandbox"
	unrelated.Sandboxes[other.ID] = other
	unrelated.Fencing[other.ProviderRevisionID+"\x00"+other.ID] = 1
	if err := checkCodingRetirementBarrier(fixture.slots, before, unrelated, now); err != nil {
		t.Fatalf("unrelated sandbox was frozen: %v", err)
	}
}

func TestCodingRetirementBarrierAllowsOnlyExactMutationReplay(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	before := copyCodingBarrierLedger(t, fixture.ledger)
	after := copyCodingBarrierLedger(t, fixture.ledger)
	sandbox := after.Sandboxes[input.Create.SandboxID]
	running := after.Operations[input.Cleanup.CleanupOperationID]
	accepted := running
	accepted.State = lifecycle.OperationAccepted
	_, err := after.ReserveMutation(accepted.IdempotencyKey, accepted.RequestDigest,
		sandbox.Generation, sandbox, accepted, lifecycle.Event{ID: "event-exact-replay",
			SandboxID: sandbox.ID, OperationID: accepted.ID, Generation: sandbox.Generation,
			FencingToken: accepted.FencingToken, Kind: "termination-requested", OccurredAt: now})
	if err != nil || checkCodingRetirementBarrier(fixture.slots, before, after, now) != nil {
		t.Fatalf("exact accepted mutation replay changed retirement: %v", err)
	}
	accepted.AttemptID = "different-attempt"
	if _, err := after.ReserveMutation(accepted.IdempotencyKey, accepted.RequestDigest,
		sandbox.Generation, sandbox, accepted, lifecycle.Event{ID: "event-different-attempt",
			SandboxID: sandbox.ID, OperationID: accepted.ID, Generation: sandbox.Generation,
			FencingToken: accepted.FencingToken, Kind: "termination-requested", OccurredAt: now}); !errors.Is(err, lifecyclerepository.ErrIdempotencyConflict) {
		t.Fatalf("different attempt was replayed: %v", err)
	}
}

func TestCodingRetirementBarrierAllowsHistoricalCreateToBecomeUnknown(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	// The normal bounded fixture pre-completes the original create. Model the
	// separately legal case where its old response remains Running while a
	// trustworthy Control Completed proof admits current termination.
	oldCreate := fixture.ledger.Operations[input.Create.OperationID]
	oldCreate.State = lifecycle.OperationRunning
	oldCreate.Failure = nil
	if err := fixture.ledger.UpdateOperation(oldCreate); err != nil {
		t.Fatal(err)
	}
	before := copyCodingBarrierLedger(t, fixture.ledger)
	after := copyCodingBarrierLedger(t, fixture.ledger)
	create := after.Operations[input.Create.OperationID]
	unknown, err := lifecycle.MarkOutcomeUnknown(create, now,
		lifecycle.Failure{Code: "old_create_response_unknown", Retryable: true,
			Outcome: lifecycle.FailureUnknown})
	if err != nil || after.UpdateOperation(unknown) != nil {
		t.Fatalf("prepare historical create Unknown: %v", err)
	}
	if err := checkCodingRetirementBarrier(fixture.slots, before, after, now); err != nil {
		t.Fatalf("historical create same-attempt Unknown blocked: %v", err)
	}
	sum := sha256.Sum256([]byte(unknown.ID + "\x00" + string(unknown.State) + "\x00outcome-unknown"))
	event := lifecycle.Event{ID: "event-" + hex.EncodeToString(sum[:]),
		SandboxID: unknown.SandboxID, OperationID: unknown.ID,
		Generation:   fixture.slots.Reservations[0].Claim.Generation,
		FencingToken: fixture.slots.Reservations[0].Claim.Fence,
		Kind:         "outcome-unknown", OccurredAt: now}
	if _, err := after.AppendEvent(event); err != nil ||
		checkCodingRetirementBarrier(fixture.slots, before, after, now) != nil {
		t.Fatalf("historical birth-bound Unknown event blocked: %v", err)
	}
	if _, err := after.AppendEvent(event); err != nil ||
		checkCodingRetirementBarrier(fixture.slots, before, after, now) != nil {
		t.Fatalf("identical Unknown event replay changed retirement: %v", err)
	}
	terminal := copyCodingBarrierLedger(t, after)
	if err := checkCodingRetirementBarrier(fixture.slots, after, terminal, now); err != nil {
		t.Fatalf("terminal Unknown should remain unchanged: %v", err)
	}
}

func TestCodingRetirementBarrierDoesNotBroadenHistoricalFence(t *testing.T) {
	fixture := testCodingCleanupPGFixture(t, lifecycle.OperationSucceeded, 8)
	if _, _, _, _, err := beginCodingCurrentCleanup(t.Context(), &fixture.slots,
		&fixture.ledger, fixture.plan, fixture.input, fixture.now); err != nil {
		t.Fatal(err)
	}
	create := fixture.ledger.Operations[fixture.input.Create.OperationID]
	create.State, create.Failure = lifecycle.OperationRunning, nil
	fixture.ledger.Operations[create.ID] = create
	for key, record := range fixture.ledger.Idempotency {
		if record.Operation.ID == create.ID {
			record.Operation = create
			fixture.ledger.Idempotency[key] = record
		}
	}
	before := copyCodingBarrierLedger(t, fixture.ledger)
	unknown, err := lifecycle.MarkOutcomeUnknown(create, fixture.now.Add(time.Second),
		lifecycle.Failure{Code: "old_response_unknown", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.ledger.UpdateOperation(unknown); !errors.Is(err, lifecycle.ErrStaleFencingToken) {
		t.Fatalf("State.UpdateOperation accepted old create fence: %v", err)
	}
	if err := checkCodingRetirementBarrier(fixture.slots, before, fixture.ledger, fixture.now.Add(time.Second)); err != nil {
		t.Fatalf("rejected State update changed ledger: %v", err)
	}
}

func TestCodingRetirementBarrierRejectsMalformedStoredBindings(t *testing.T) {
	for name, mutate := range map[string]func(*codingCleanupPGFixture){
		"nil reservations": func(f *codingCleanupPGFixture) { f.slots.Reservations = nil },
		"duplicate slot": func(f *codingCleanupPGFixture) {
			f.slots.Reservations = append(f.slots.Reservations, f.slots.Reservations[0])
		},
		"orphan retirement": func(f *codingCleanupPGFixture) {
			f.slots.Retirements["coding-0001"] = f.slots.Retirements[f.slots.Reservations[0].Slot.ID]
		},
		"wrong allocation": func(f *codingCleanupPGFixture) {
			f.slots.Reservations[0].Claim.AllocationID = "codingalloc-" + codingTestDigest("0")[7:]
		},
		"wrong lifecycle fence": func(f *codingCleanupPGFixture) {
			sandbox := f.ledger.Sandboxes[f.slots.Reservations[0].Claim.SandboxID]
			f.ledger.Fencing[sandbox.ProviderRevisionID+"\x00"+sandbox.ID]++
		},
		"wrong cleanup operation": func(f *codingCleanupPGFixture) {
			for key, binding := range f.slots.Retirements {
				binding.OperationID = "other-operation"
				f.slots.Retirements[key] = binding
			}
		},
		"wrong cleanup envelope": func(f *codingCleanupPGFixture) {
			for key, binding := range f.slots.Retirements {
				binding.CleanupAuthorityDocument = `{"not":"canonical"}`
				f.slots.Retirements[key] = binding
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, _, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
			mutate(&fixture)
			if err := checkCodingRetirementBarrier(fixture.slots, fixture.ledger, fixture.ledger, now); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("malformed durable retirement admitted: %v", err)
			}
		})
	}
	if codingidentity.LocalCandidateCapacity < 2 {
		t.Fatal("structural test assumes two finite slots")
	}
}

func TestCodingRetirementBarrierRejectsCleaningWithoutBinding(t *testing.T) {
	fixture, _, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	before := copyCodingBarrierLedger(t, fixture.ledger)
	fixture.slots.Retirements = nil
	if err := checkCodingRetirementBarrier(fixture.slots, before, before, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("partial Cleaning state bypassed barrier: %v", err)
	}
}
