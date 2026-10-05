package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func testCodingReleasePGFixture(t *testing.T, outcome lifecycle.OperationState) (
	codingCleanupPGFixture, codingReleaseAdmission, time.Time) {
	t.Helper()
	fixture := testCodingCleanupPGFixture(t, outcome, 7)
	cleanup, _, _, _, err := beginCodingCurrentCleanup(t.Context(), &fixture.slots,
		&fixture.ledger, fixture.plan, fixture.input, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	released := fixture.input.Completed
	released.Status = dockercontrol.ReceiptReleased
	released.CleanupAuthority = cleanup
	released.AbsenceDigest = codingTestDigest("4")
	released.AbsenceEvidenceDigest = codingTestDigest("5")
	released.UpdatedAt = fixture.now.Add(time.Second)
	input := codingReleaseAdmission{Create: fixture.input.Create, Cleanup: cleanup,
		Released: released, ControlRevision: fixture.input.ControlRevision + 2,
		ControlStateDigest: codingTestDigest("6"), SpecBySlot: fixture.input.SpecBySlot}
	return fixture, input, fixture.now.Add(2 * time.Second)
}

func TestCodingCurrentReleaseCASPreservesHistoricalCreate(t *testing.T) {
	for _, historical := range []lifecycle.OperationState{
		lifecycle.OperationSucceeded, lifecycle.OperationOutcomeUnknown,
	} {
		t.Run(string(historical), func(t *testing.T) {
			fixture, input, now := testCodingReleasePGFixture(t, historical)
			original, err := fixture.ledger.GetOperation(input.Create.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			operation, sandbox, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
				&fixture.ledger, fixture.plan, input, now)
			if err != nil || operation.State != lifecycle.OperationSucceeded ||
				sandbox.ObservedState != lifecycle.ObservedTerminated ||
				sandbox.ObservedGeneration != sandbox.Generation ||
				len(fixture.slots.Reservations) != 0 || len(fixture.slots.Retirements) != 0 ||
				fixture.slots.Validate(fixture.plan) != nil {
				t.Fatalf("exact PG release CAS: %#v, %#v, %v", operation, sandbox, err)
			}
			retained, err := fixture.ledger.GetOperation(original.ID)
			if err != nil || !reflect.DeepEqual(retained, original) {
				t.Fatal("PG release rewrote historical create operation")
			}
			events, err := fixture.ledger.ListEvents(sandbox.ID, 0, 10)
			if err != nil || len(events) != 4 || events[3].Kind != "terminated" ||
				events[3].OperationID != operation.ID {
				t.Fatalf("terminated event not atomic with release: %#v, %v", events, err)
			}
			if _, _, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
				&fixture.ledger, fixture.plan, input, now); !errors.Is(err, codingidentity.ErrConflict) {
				t.Fatalf("Released snapshot replayed PG slot release: %v", err)
			}
		})
	}
}

func TestCodingCurrentReleaseCASKeepsUnknownTerminationTerminal(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationOutcomeUnknown)
	operation, err := fixture.ledger.GetOperation(input.Cleanup.CleanupOperationID)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := lifecycle.MarkOutcomeUnknown(operation, now.Add(-time.Second),
		lifecycle.Failure{Code: "delete_response_lost", Retryable: true,
			Outcome: lifecycle.FailureUnknown})
	if err != nil || fixture.ledger.UpdateOperation(unknown) != nil {
		t.Fatalf("prepare current Unknown termination: %v", err)
	}
	result, sandbox, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
		&fixture.ledger, fixture.plan, input, now)
	if err != nil || result.State != lifecycle.OperationOutcomeUnknown ||
		!reflect.DeepEqual(result, unknown) || sandbox.ObservedState != lifecycle.ObservedTerminated ||
		len(fixture.slots.Reservations) != 0 {
		t.Fatalf("Unknown termination was rewritten or held after release proof: %#v, %v", result, err)
	}
}

func TestCodingCurrentReleaseCASAcceptsVerifiedReleaseAfterIntentExpiry(t *testing.T) {
	fixture, input, _ := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	// Control formed Released within the original cleanup authority window.
	// A later PG repair consumes that historical result without renewing the
	// expired authority or repeating any Docker operation.
	late := input.Cleanup.ExpiresAt.Add(time.Minute)
	result, sandbox, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
		&fixture.ledger, fixture.plan, input, late)
	if err != nil || result.State != lifecycle.OperationSucceeded ||
		sandbox.ObservedState != lifecycle.ObservedTerminated {
		t.Fatalf("historically valid Released proof could not finish PG CAS: %#v, %v", result, err)
	}
}

func TestCodingCurrentReleaseCASRejectsStaleProofAndOccupant(t *testing.T) {
	for name, mutate := range map[string]func(*codingCleanupPGFixture, *codingReleaseAdmission){
		"Control not Released": func(_ *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.Released.Status = dockercontrol.ReceiptCompleted
		},
		"missing absence evidence": func(_ *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.Released.AbsenceEvidenceDigest = ""
		},
		"release after intent expiry": func(_ *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.Released.UpdatedAt = input.Cleanup.ExpiresAt
		},
		"release before intent": func(_ *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.Released.UpdatedAt = input.Cleanup.IssuedAt.Add(-time.Nanosecond)
		},
		"stale Control revision": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.ControlRevision = f.slots.Retirements[input.Create.SlotID].ControlReceiptRevision
		},
		"stale Control state": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.ControlStateDigest = f.slots.Retirements[input.Create.SlotID].ControlReceiptStateDigest
		},
		"wrong cleanup intent": func(_ *codingCleanupPGFixture, input *codingReleaseAdmission) {
			input.Released.CleanupAuthority.CleanupAttemptID = "other-attempt"
		},
		"new occupant": func(f *codingCleanupPGFixture, _ *codingReleaseAdmission) {
			f.slots.Reservations[0].Claim.AllocationID = "codingalloc-" + codingTestDigest("0")[7:]
		},
		"retirement operation drift": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			binding := f.slots.Retirements[input.Create.SlotID]
			binding.OperationID = "different-operation"
			f.slots.Retirements[input.Create.SlotID] = binding
		},
		"new fence highwater": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			f.ledger.Fencing[input.Create.ProviderRevisionID+"\x00"+input.Create.SandboxID]++
		},
		"lease alias": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			lease := f.ledger.Leases[input.Create.SandboxID]
			lease.SandboxID = "other-sandbox"
			f.ledger.Leases[input.Create.SandboxID] = lease
		},
		"current operation alias": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			operation := f.ledger.Operations[input.Cleanup.CleanupOperationID]
			operation.ID = "other-operation"
			f.ledger.Operations[input.Cleanup.CleanupOperationID] = operation
		},
		"operation deadline drift": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			operation := f.ledger.Operations[input.Cleanup.CleanupOperationID]
			operation.Deadline = operation.Deadline.Add(time.Second)
			if err := f.ledger.UpdateOperation(operation); err != nil {
				panic(err)
			}
		},
		"original operation alias": func(f *codingCleanupPGFixture, input *codingReleaseAdmission) {
			operation := f.ledger.Operations[input.Create.OperationID]
			operation.ID = "other-operation"
			f.ledger.Operations[input.Create.OperationID] = operation
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationOutcomeUnknown)
			mutate(&fixture, &input)
			if _, _, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
				&fixture.ledger, fixture.plan, input, now); !errors.Is(err, codingidentity.ErrConflict) {
				t.Fatalf("stale release/new occupant admitted: %v", err)
			}
		})
	}
}

func TestCodingCurrentReleaseCASAbortsOnCancelAndEventCollision(t *testing.T) {
	fixture, input, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, _, err := finishCodingCurrentCleanup(canceled, &fixture.slots,
		&fixture.ledger, fixture.plan, input, now); err == nil ||
		fixture.slots.Reservations[0].Status != codingidentity.Cleaning {
		t.Fatalf("canceled release mutated PG-local state: %v", err)
	}
	operationID := input.Cleanup.CleanupOperationID
	sum := sha256.Sum256([]byte(operationID + "\x00succeeded\x00terminated"))
	event := lifecycle.Event{ID: "event-" + hex.EncodeToString(sum[:]),
		SandboxID: input.Create.SandboxID, OperationID: operationID,
		Generation: input.Cleanup.CurrentGeneration, FencingToken: input.Cleanup.CleanupFence,
		Kind: "conflicting-event", OccurredAt: now.Add(-time.Second)}
	if _, err := fixture.ledger.AppendEvent(event); err != nil {
		t.Fatal(err)
	}
	if _, _, err := finishCodingCurrentCleanup(t.Context(), &fixture.slots,
		&fixture.ledger, fixture.plan, input, now); !errors.Is(err, codingidentity.ErrConflict) {
		t.Fatalf("terminated event collision admitted: %v", err)
	}
}
