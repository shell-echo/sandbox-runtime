package providerpostgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type codingCleanupPGFixture struct {
	plan   codingidentity.Plan
	slots  codingidentity.State
	ledger lifecyclerepository.State
	input  codingCleanupAdmission
	now    time.Time
}

func testCodingCleanupPGFixture(t *testing.T, createOutcome lifecycle.OperationState,
	cleanupFence uint64) codingCleanupPGFixture {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Millisecond)
	plan := codingBoundTestPlan()
	slots, err := codingidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := testCodingAcceptedCreate(t, start, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	ticket, runningCreate, provisioning, err := beginCodingFirstCreate(&slots, &ledger,
		plan, "operation-1", codingBoundSpecs(plan), start)
	if err != nil {
		t.Fatal(err)
	}
	create, err := dockercontrol.NewCodingCreateAuthority(context.Background(), ticket,
		runningCreate, provisioning, plan, codingTestDigest("f"), plan.OwnerPrincipalDigest, start)
	if err != nil {
		t.Fatal(err)
	}
	currentSandbox := provisioning
	when := start.Add(time.Second)
	switch createOutcome {
	case lifecycle.OperationSucceeded:
		ready, err := lifecycle.ApplyObservedTransition(provisioning, lifecycle.ObservedReady,
			provisioning.Generation, when)
		if err != nil || ledger.UpdateSandbox(ready, provisioning.Generation, runningCreate.FencingToken) != nil {
			t.Fatalf("ready create fixture: %v", err)
		}
		succeeded, err := lifecycle.SucceedOperation(runningCreate, when)
		if err != nil || ledger.UpdateOperation(succeeded) != nil {
			t.Fatalf("succeeded create fixture: %v", err)
		}
		active, err := slots.CompleteCreate(plan, ticket)
		if err != nil {
			t.Fatal(err)
		}
		_ = active
		currentSandbox = ready
	case lifecycle.OperationOutcomeUnknown:
		failure := lifecycle.Failure{Code: "create_result_lost", Retryable: true,
			Outcome: lifecycle.FailureUnknown}
		unknown, err := lifecycle.MarkOutcomeUnknown(runningCreate, when, failure)
		if err != nil || ledger.UpdateOperation(unknown) != nil {
			t.Fatalf("unknown create fixture: %v", err)
		}
	default:
		t.Fatal("unsupported create outcome fixture")
	}
	terminateAt := start.Add(2 * time.Second)
	request := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
		OperationID: "termination-1", AttemptID: "termination-attempt-1",
		FencingToken: cleanupFence, IdempotencyKey: "termination-key-1",
		RequestDigest: codingTestDigest("7"), Deadline: terminateAt.Add(time.Minute),
		ExpectedGeneration: currentSandbox.Generation}, Reason: "operator request"}
	updated, accepted, err := lifecycle.StartTerminate(currentSandbox, request, terminateAt)
	if err != nil {
		t.Fatal(err)
	}
	event := lifecycle.Event{ID: "event-termination-requested-1",
		SandboxID: updated.ID, OperationID: accepted.ID, Generation: updated.Generation,
		FencingToken: accepted.FencingToken, Kind: "termination-requested",
		DataDigest: request.RequestDigest, OccurredAt: terminateAt}
	if _, err := ledger.ReserveMutation(request.IdempotencyKey, request.RequestDigest,
		request.ExpectedGeneration, updated, accepted, event); err != nil {
		t.Fatal(err)
	}
	completed := dockercontrol.CodingReceipt{Authority: create, AuthorityDigest: create.Digest(),
		Status: dockercontrol.ReceiptCompleted, CompletionDigest: codingTestDigest("8"),
		CompletionEvidenceDigest: codingTestDigest("9"), UpdatedAt: terminateAt}
	input := codingCleanupAdmission{Create: create, Completed: completed,
		ControlRevision: 3, ControlStateDigest: codingTestDigest("a"),
		TerminationID: accepted.ID, ControlPolicyDigest: create.ControlPolicyDigest,
		PeerPrincipalDigest: plan.OwnerPrincipalDigest, SpecBySlot: codingBoundSpecs(plan)}
	return codingCleanupPGFixture{plan: plan, slots: slots, ledger: ledger,
		input: input, now: terminateAt.Add(time.Second)}
}

func TestCodingCurrentCleanupBindsPGAndHistoricalCreateOutcome(t *testing.T) {
	for _, outcome := range []lifecycle.OperationState{
		lifecycle.OperationSucceeded, lifecycle.OperationOutcomeUnknown,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			fixture := testCodingCleanupPGFixture(t, outcome, 7)
			originalCreate, err := fixture.ledger.GetOperation(fixture.input.Create.OperationID)
			if err != nil {
				t.Fatal(err)
			}
			authority, cleaning, running, terminating, err := beginCodingCurrentCleanup(
				context.Background(), &fixture.slots, &fixture.ledger, fixture.plan, fixture.input, fixture.now)
			if err != nil || authority.Validate(fixture.now) != nil ||
				cleaning.Status != codingidentity.Cleaning || running.State != lifecycle.OperationRunning ||
				terminating.ObservedState != lifecycle.ObservedTerminating ||
				authority.CleanupFence != fixture.input.Create.Fence ||
				fixture.slots.Validate(fixture.plan) != nil {
				t.Fatalf("current cleanup permit: %#v, %#v, %v", authority, cleaning, err)
			}
			storedCreate, err := fixture.ledger.GetOperation(originalCreate.ID)
			if err != nil || !reflect.DeepEqual(storedCreate, originalCreate) {
				t.Fatal("old create outcome was rewritten")
			}
			binding := fixture.slots.Retirements[cleaning.Slot.ID]
			authorityDocument, err := dockercontrol.EncodeCodingCleanupAuthority(authority)
			if err != nil {
				t.Fatal(err)
			}
			if binding.OperationID != running.ID || binding.CurrentFence != running.FencingToken ||
				binding.ControlReceiptRevision != fixture.input.ControlRevision ||
				binding.ControlEvidenceDigest != fixture.input.Completed.CompletionEvidenceDigest ||
				binding.CleanupAuthorityDocument != string(authorityDocument) ||
				binding.CleanupAuthorityDigest != authority.Digest() {
				t.Fatal("PG retirement binding did not retain Control/source identity")
			}
			readback, err := readCodingCleanupEnvelope(fixture.slots, fixture.plan,
				fixture.input.Create, running.ID, fixture.input.ControlPolicyDigest,
				fixture.input.PeerPrincipalDigest, fixture.input.SpecBySlot)
			if err != nil || readback != authority {
				t.Fatalf("PG response-loss readback changed cleanup envelope: %#v, %v", readback, err)
			}
			if _, err := readCodingCleanupEnvelope(fixture.slots, fixture.plan,
				fixture.input.Create, "termination-other", fixture.input.ControlPolicyDigest,
				fixture.input.PeerPrincipalDigest, fixture.input.SpecBySlot); err == nil {
				t.Fatal("different terminate operation read old cleanup envelope")
			}
			tampered := fixture.slots.Clone()
			changed := tampered.Retirements[cleaning.Slot.ID]
			changed.CleanupAuthorityDocument += " "
			tampered.Retirements[cleaning.Slot.ID] = changed
			if _, err := readCodingCleanupEnvelope(tampered, fixture.plan,
				fixture.input.Create, running.ID, fixture.input.ControlPolicyDigest,
				fixture.input.PeerPrincipalDigest, fixture.input.SpecBySlot); err == nil {
				t.Fatal("noncanonical cleanup envelope replayed")
			}
			events, err := fixture.ledger.ListEvents(terminating.ID, 0, 10)
			if err != nil || len(events) != 3 || events[2].Kind != "terminating" {
				t.Fatalf("current terminating event missing: %#v, %v", events, err)
			}
			if _, _, _, _, err := beginCodingCurrentCleanup(context.Background(), &fixture.slots, &fixture.ledger,
				fixture.plan, fixture.input, fixture.now); !errors.Is(err, codingidentity.ErrConflict) {
				t.Fatalf("replayed cleanup dispatched again: %v", err)
			}
		})
	}
}

func TestCodingCurrentCleanupRejectsUntrustedOrStaleBindings(t *testing.T) {
	for name, mutate := range map[string]func(*codingCleanupPGFixture){
		"control unknown":   func(f *codingCleanupPGFixture) { f.input.Completed.Status = dockercontrol.ReceiptUnknown },
		"control authority": func(f *codingCleanupPGFixture) { f.input.Completed.AuthorityDigest = codingTestDigest("0") },
		"control evidence":  func(f *codingCleanupPGFixture) { f.input.Completed.CompletionEvidenceDigest = "" },
		"missing other slot spec": func(f *codingCleanupPGFixture) {
			delete(f.input.SpecBySlot, f.plan.Slots[1].ID)
		},
		"slot drift":      func(f *codingCleanupPGFixture) { f.slots.Reservations[0].Slot = f.plan.Slots[1] },
		"claim drift":     func(f *codingCleanupPGFixture) { f.slots.Reservations[0].Claim.Fence++ },
		"stale highwater": func(f *codingCleanupPGFixture) { f.ledger.Fencing["revision-1\x00sandbox-1"]++ },
		"missing termination idempotency": func(f *codingCleanupPGFixture) {
			delete(f.ledger.Idempotency, "revision-1\x00termination-key-1")
		},
		"wrong termination attempt": func(f *codingCleanupPGFixture) {
			op := f.ledger.Operations["termination-1"]
			op.AttemptID = "other-attempt"
			f.ledger.Operations[op.ID] = op
		},
		"original map key alias": func(f *codingCleanupPGFixture) {
			op := f.ledger.Operations["operation-1"]
			op.ID = "operation-other"
			f.ledger.Operations["operation-1"] = op
		},
		"termination map key alias": func(f *codingCleanupPGFixture) {
			op := f.ledger.Operations["termination-1"]
			op.ID = "termination-other"
			f.ledger.Operations["termination-1"] = op
		},
		"lease map key alias": func(f *codingCleanupPGFixture) {
			lease := f.ledger.Leases["sandbox-1"]
			lease.SandboxID = "sandbox-other"
			f.ledger.Leases["sandbox-1"] = lease
		},
		"new occupant": func(f *codingCleanupPGFixture) {
			f.slots.Reservations[0].Claim.AllocationID = "codingalloc-" + codingTestDigest("0")[7:]
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := testCodingCleanupPGFixture(t, lifecycle.OperationSucceeded, 8)
			mutate(&fixture)
			if _, _, _, _, err := beginCodingCurrentCleanup(context.Background(), &fixture.slots, &fixture.ledger,
				fixture.plan, fixture.input, fixture.now); err == nil {
				t.Fatal("stale/untrusted PG cleanup binding admitted")
			}
		})
	}
}

func TestCodingCurrentCleanupClampsParentDeadlineAndRejectsCancel(t *testing.T) {
	fixture := testCodingCleanupPGFixture(t, lifecycle.OperationSucceeded, 7)
	parentDeadline := fixture.now.Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), parentDeadline)
	defer cancel()
	authority, _, _, _, err := beginCodingCurrentCleanup(ctx, &fixture.slots,
		&fixture.ledger, fixture.plan, fixture.input, fixture.now)
	if err != nil || !authority.ExpiresAt.Equal(parentDeadline) ||
		authority.Validate(fixture.now) != nil ||
		fixture.slots.Retirements[fixture.plan.Slots[0].ID].CleanupAuthorityDocument == "" {
		t.Fatalf("PG cleanup permit ignored shorter parent deadline: %#v, %v", authority, err)
	}
	readback, err := readCodingCleanupEnvelope(fixture.slots, fixture.plan,
		fixture.input.Create, fixture.input.TerminationID, fixture.input.ControlPolicyDigest,
		fixture.input.PeerPrincipalDigest, fixture.input.SpecBySlot)
	if err != nil || readback != authority || !readback.ExpiresAt.Equal(parentDeadline) {
		t.Fatalf("response loss refreshed parent-clamped expiry: %#v, %v", readback, err)
	}
	canceled := testCodingCleanupPGFixture(t, lifecycle.OperationSucceeded, 7)
	canceledCtx, stop := context.WithCancel(t.Context())
	stop()
	if _, _, _, _, err := beginCodingCurrentCleanup(canceledCtx, &canceled.slots,
		&canceled.ledger, canceled.plan, canceled.input, canceled.now); err == nil {
		t.Fatal("canceled PG cleanup admission returned a permit")
	}
	if canceled.slots.Reservations[0].Status != codingidentity.Active ||
		canceled.ledger.Operations["termination-1"].State != lifecycle.OperationAccepted {
		t.Fatal("canceled admission changed transaction-local state")
	}
}

func acceptCodingSecondTerminate(t *testing.T, fixture *codingCleanupPGFixture) lifecycle.Operation {
	t.Helper()
	sandbox, err := fixture.ledger.GetSandbox(fixture.input.Create.SandboxID)
	if err != nil {
		t.Fatal(err)
	}
	request := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{
		OperationID: "termination-2", AttemptID: "termination-attempt-2",
		FencingToken: fixture.input.Create.Fence, IdempotencyKey: "termination-key-2",
		RequestDigest: codingTestDigest("6"), Deadline: fixture.now.Add(time.Minute),
		ExpectedGeneration: sandbox.Generation}, Reason: "repeat terminate"}
	updated, operation, err := lifecycle.StartTerminate(sandbox, request, fixture.now)
	if err != nil || updated.Generation != sandbox.Generation {
		t.Fatalf("repeat terminate incremented generation: %v", err)
	}
	event := lifecycle.Event{ID: "event-termination-requested-2",
		SandboxID: updated.ID, OperationID: operation.ID, Generation: updated.Generation,
		FencingToken: operation.FencingToken, Kind: "termination-requested",
		DataDigest: request.RequestDigest, OccurredAt: fixture.now}
	if _, err := fixture.ledger.ReserveMutation(request.IdempotencyKey, request.RequestDigest,
		request.ExpectedGeneration, updated, operation, event); err != nil {
		t.Fatal(err)
	}
	return operation
}

func TestCodingCurrentCleanupRepeatedGenerationAndSameFenceCompetition(t *testing.T) {
	for _, firstAdmitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "second-is-current", true: "first-already-dispatched"}[firstAdmitted], func(t *testing.T) {
			fixture := testCodingCleanupPGFixture(t, lifecycle.OperationSucceeded, 7)
			if firstAdmitted {
				if _, _, _, _, err := beginCodingCurrentCleanup(context.Background(), &fixture.slots,
					&fixture.ledger, fixture.plan, fixture.input, fixture.now); err != nil {
					t.Fatal(err)
				}
			}
			second := acceptCodingSecondTerminate(t, &fixture)
			fixture.input.TerminationID = second.ID
			authority, _, _, _, err := beginCodingCurrentCleanup(context.Background(), &fixture.slots,
				&fixture.ledger, fixture.plan, fixture.input, fixture.now.Add(time.Second))
			if firstAdmitted {
				if !errors.Is(err, codingidentity.ErrConflict) {
					t.Fatalf("same-fence competing operation got second permit: %v", err)
				}
			} else if err != nil || authority.CurrentGeneration != 2 ||
				authority.CleanupFence != fixture.input.Create.Fence || authority.CleanupOperationID != second.ID {
				t.Fatalf("valid repeated-generation current termination rejected: %#v, %v", authority, err)
			}
		})
	}
}
