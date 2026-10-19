package providerpostgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type leaseAdmissionFixture struct {
	readyFixture
	request lifecycle.LeaseRequest
	sandbox lifecycle.Sandbox
	op      lifecycle.Operation
	event   lifecycle.Event
}

func newLeaseAdmission(t *testing.T) leaseAdmissionFixture {
	t.Helper()
	f := newReadyFixture(t)
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	return nextLeaseAdmission(t, f, "lease-one", f.create.Fence+1)
}

func nextLeaseAdmission(t *testing.T, f readyFixture, id string, fence uint64) leaseAdmissionFixture {
	t.Helper()
	sb := f.ledger.Sandboxes[f.create.SandboxID]
	req := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: id, AttemptID: id + "-attempt", IdempotencyKey: id + "-key",
		RequestDigest: codingTestDigest("2"), FencingToken: fence, ExpectedGeneration: sb.Generation, Deadline: f.now.Add(time.Minute)}, ExtendSeconds: 60}
	updated, _, op, err := lifecycle.StartLeaseRenewal(sb, req, 7200, f.now)
	if err != nil {
		t.Fatal(err)
	}
	event := lifecycle.Event{ID: codingAdmissionEventID(id, "lease-extended"), SandboxID: sb.ID, OperationID: id, Generation: sb.Generation,
		FencingToken: fence, Kind: "lease-extended", DataDigest: req.RequestDigest, OccurredAt: f.now}
	return leaseAdmissionFixture{f, req, updated, op, event}
}

func (f *leaseAdmissionFixture) reserve(ctx context.Context) (lifecyclerepository.MutationResult, error) {
	return reserveCodingLease(ctx, f.marker, f.slots, &f.ledger, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest,
		f.request.IdempotencyKey, f.request.RequestDigest, f.request.ExpectedGeneration, f.sandbox, f.op, f.event, f.now)
}
func (f *leaseAdmissionFixture) reconcile(ctx context.Context) (lifecycle.Operation, lifecycle.Sandbox, error) {
	return completeCodingLease(ctx, f.marker, f.slots, &f.ledger, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, f.op.ID, f.now)
}
func (f *leaseAdmissionFixture) admitOnly(t *testing.T) {
	t.Helper()
	before := copyCodingBarrierLedger(t, f.ledger)
	if _, err := f.ledger.ReserveMutation(f.request.IdempotencyKey, f.request.RequestDigest, f.request.ExpectedGeneration, f.sandbox, f.op, f.event); err != nil {
		t.Fatal(err)
	}
	if err := f.guard(before, f.ledger); err != nil {
		t.Fatal(err)
	}
}

func TestCodingLeaseAtomicAdmissionCompletionAndReplay(t *testing.T) {
	f := newLeaseAdmission(t)
	oldSB := f.ledger.Sandboxes[f.sandbox.ID]
	oldSlots := f.slots.Clone()
	sequence := f.ledger.EventLatest[f.sandbox.ID]
	result, err := f.reserve(t.Context())
	if err != nil || result.Replayed || result.Operation.State != lifecycle.OperationSucceeded || result.Sandbox.Generation != oldSB.Generation ||
		!result.Sandbox.LeaseExpiresAt.Equal(oldSB.LeaseExpiresAt.Add(time.Minute)) || f.ledger.EventLatest[f.sandbox.ID] != sequence+2 ||
		!reflect.DeepEqual(f.slots, oldSlots) || !codingStoredIdempotencyMatches(&f.ledger, result.Operation, f.op.RequestDigest, oldSB.ProviderRevisionID, true) {
		t.Fatalf("atomic lease result: %#v %v", result, err)
	}
	before := f.ledger.Export()
	if replay, err := f.reserve(t.Context()); !errors.Is(err, errCodingLeaseUnchanged) || !replay.Replayed || !reflect.DeepEqual(replay.Operation, result.Operation) {
		t.Fatalf("replay: %#v %v", replay, err)
	}
	if op, _, err := f.reconcile(t.Context()); !errors.Is(err, errCodingLeaseUnchanged) || !reflect.DeepEqual(op, result.Operation) || !reflect.DeepEqual(before, f.ledger.Export()) {
		t.Fatalf("retained result mutated: %#v %v", op, err)
	}
}

func TestCodingLeaseAdmissionRejectsStaleInputsAtomically(t *testing.T) {
	for _, name := range []string{"deadline at lock", "lease expired at lock", "fence", "generation", "wrong event", "wrong marker", "cancel context"} {
		t.Run(name, func(t *testing.T) {
			f := newLeaseAdmission(t)
			ctx := t.Context()
			switch name {
			case "deadline at lock":
				f.now = f.op.Deadline
			case "lease expired at lock":
				f.now = f.ledger.Sandboxes[f.sandbox.ID].LeaseExpiresAt
				f.op.Deadline = f.now.Add(time.Minute)
			case "fence":
				f.op.FencingToken = f.create.Fence - 1
			case "generation":
				f.request.ExpectedGeneration++
			case "wrong event":
				f.event.ID = "forged-event"
			case "wrong marker":
				f.marker.ControlPolicyDigest = codingTestDigest("0")
			case "cancel context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			before := f.ledger.Export()
			if _, err := f.reserve(ctx); err == nil || !reflect.DeepEqual(before, f.ledger.Export()) {
				t.Fatalf("unsafe admission %s: %v", name, err)
			}
		})
	}
}

func TestCodingLeaseReplayRejectsSubstitutedAuthority(t *testing.T) {
	for _, field := range []string{"sandbox", "fence", "deadline", "key", "generation", "attempt", "type"} {
		t.Run(field, func(t *testing.T) {
			f := newLeaseAdmission(t)
			if _, err := f.reserve(t.Context()); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "sandbox":
				f.sandbox.ID = "other-sandbox"
			case "fence":
				f.op.FencingToken++
			case "deadline":
				f.op.Deadline = f.op.Deadline.Add(time.Second)
			case "key":
				f.op.IdempotencyKey = "different-key"
			case "generation":
				f.request.ExpectedGeneration++
			case "attempt":
				f.op.AttemptID = "other-attempt"
			case "type":
				f.op.Type = lifecycle.OperationTerminate
			}
			before := f.ledger.Export()
			if _, err := f.reserve(t.Context()); err == nil || errors.Is(err, errCodingLeaseUnchanged) || !reflect.DeepEqual(before, f.ledger.Export()) {
				t.Fatalf("substituted replay %s: %v", field, err)
			}
		})
	}
}

func TestCodingLeaseHistoricalCurrentAdmissionUsesKnownCommit(t *testing.T) {
	f := newLeaseAdmission(t)
	f.admitOnly(t)
	beforeSB, beforeLease := f.ledger.Sandboxes[f.sandbox.ID], f.ledger.Leases[f.sandbox.ID]
	f.now = beforeSB.LeaseExpiresAt.Add(time.Second)
	op, sb, err := f.reconcile(t.Context())
	if err != nil || op.State != lifecycle.OperationSucceeded || !reflect.DeepEqual(sb, beforeSB) || f.ledger.Leases[sb.ID] != beforeLease {
		t.Fatalf("known old DB effect was not completed without renewal: %#v %v", op, err)
	}
}

func TestCodingLeaseSupersededPendingAndCompletedHistory(t *testing.T) {
	for _, completed := range []bool{false, true} {
		for _, higherFence := range []bool{false, true} {
			f := newLeaseAdmission(t)
			if completed {
				if _, err := f.reserve(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				f.admitOnly(t)
			}
			fence := f.op.FencingToken
			if higherFence {
				fence++
			}
			// Same timestamp AND same fence must not alias the prior admission.
			next := nextLeaseAdmission(t, f.readyFixture, "lease-two", fence)
			if _, err := next.reserve(t.Context()); err != nil {
				t.Fatal(err)
			}
			f.ledger = next.ledger
			before := f.ledger.Export()
			op, _, err := f.reconcile(t.Context())
			if completed {
				if !errors.Is(err, errCodingLeaseUnchanged) || op.State != lifecycle.OperationSucceeded {
					t.Fatalf("historical completed: %v", err)
				}
			} else if err == nil || errors.Is(err, errCodingLeaseUnchanged) {
				t.Fatal("superseded Accepted was promoted")
			}
			if !reflect.DeepEqual(before, f.ledger.Export()) {
				t.Fatal("historical read rewrote current lease")
			}
		}
	}
}

func TestCodingLeaseGenericCompletionAndEventCollisionBlocked(t *testing.T) {
	f := newLeaseAdmission(t)
	f.admitOnly(t)
	before := copyCodingBarrierLedger(t, f.ledger)
	op, _ := lifecycle.BeginOperation(f.op, f.now)
	op, _ = lifecycle.SucceedOperation(op, f.now)
	after := copyCodingBarrierLedger(t, f.ledger)
	if err := after.UpdateOperation(op); err != nil {
		t.Fatal(err)
	}
	if f.guard(before, after) == nil {
		t.Fatal("generic writer fabricated lease success")
	}
	event := lifecycle.Event{ID: codingLeaseSuccessEventID(f.op.ID), SandboxID: f.sandbox.ID, OperationID: f.op.ID,
		Kind: "lease-renewal-succeeded", Generation: f.sandbox.Generation, FencingToken: f.op.FencingToken, OccurredAt: f.now}
	if _, err := f.ledger.AppendEvent(event); err != nil {
		t.Fatal(err)
	}
	snapshot := f.ledger.Export()
	if _, _, err := f.reconcile(t.Context()); err == nil || !reflect.DeepEqual(snapshot, f.ledger.Export()) {
		t.Fatal("collision accepted or partial write")
	}
}

func TestCodingLeaseTerminalReadAfterEventRetention(t *testing.T) {
	f := newLeaseAdmission(t)
	if _, err := f.reserve(t.Context()); err != nil {
		t.Fatal(err)
	}
	events := f.ledger.Events[f.sandbox.ID]
	success := events[len(events)-1]
	// Admission alone fell below the retained floor.
	f.ledger.Events[f.sandbox.ID] = []lifecycle.Event{success}
	if _, _, err := f.reconcile(t.Context()); !errors.Is(err, errCodingLeaseUnchanged) {
		t.Fatalf("admission pruned: %v", err)
	}
	// Both events fell below a later retained window. The immutable operation,
	// idempotency and original allocation remain; no history is manufactured.
	f.now = f.now.Add(time.Second)
	next := nextLeaseAdmission(t, f.readyFixture, "later-lease", f.op.FencingToken+1)
	if _, err := next.reserve(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.ledger = next.ledger
	retained := f.ledger.Events[f.sandbox.ID]
	later := retained[len(retained)-1]
	f.ledger.Events[f.sandbox.ID] = []lifecycle.Event{later}
	before := f.ledger.Export()
	if _, _, err := f.reconcile(t.Context()); !errors.Is(err, errCodingLeaseUnchanged) || !reflect.DeepEqual(before, f.ledger.Export()) {
		t.Fatalf("both pruned: %v", err)
	}
	f.ledger.Events[f.sandbox.ID][0].OccurredAt = f.now.Add(time.Second)
	if _, _, err := f.reconcile(t.Context()); err == nil || errors.Is(err, errCodingLeaseUnchanged) {
		t.Fatal("future event floor accepted")
	}
	f.ledger.Events[f.sandbox.ID][0].OccurredAt = success.OccurredAt
	if _, _, err := f.reconcile(t.Context()); err == nil || errors.Is(err, errCodingLeaseUnchanged) {
		t.Fatal("ambiguous equal-time event floor accepted")
	}
	// A missing recent success inside the retained window is not pruning.
	f.ledger.Events[f.sandbox.ID] = events[:len(events)-1]
	f.ledger.EventLatest[f.sandbox.ID] = success.Sequence - 1
	if _, _, err := f.reconcile(t.Context()); err == nil || errors.Is(err, errCodingLeaseUnchanged) {
		t.Fatal("missing recent terminal event accepted")
	}
}
