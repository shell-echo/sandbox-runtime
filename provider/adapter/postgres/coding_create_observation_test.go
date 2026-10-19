package providerpostgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

// Component-only observation fixture uses the real application constructor;
// it cannot attest a production mTLS/CRL identity or real Control completion.
type readyObservationFixture struct {
	create      dockercontrol.CodingCreateAuthority
	response    codingcontrolprotocol.Response
	observation codingcontrol.CreateObservation
	now         time.Time
}

func (f *readyObservationFixture) Now() time.Time { return f.now }
func (f *readyObservationFixture) ReadCreateBinding(context.Context, string) (dockercontrol.CodingCreateAuthority, error) {
	return f.create, nil
}
func (f *readyObservationFixture) Observe(context.Context, codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	return f.response, nil
}
func (f *readyObservationFixture) CompleteCreateWithObservation(_ context.Context, _ string, o codingcontrol.CreateObservation) (lifecycle.Operation, lifecycle.Sandbox, error) {
	f.observation = o
	return lifecycle.Operation{}, lifecycle.Sandbox{}, nil
}

func readyObservation(t *testing.T, c dockercontrol.CodingCreateAuthority, now time.Time) codingcontrol.CreateObservation {
	t.Helper()
	f := &readyObservationFixture{create: c, now: now, response: codingcontrolprotocol.Response{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus, Status: codingcontrolprotocol.StatusCompleted,
		CreateAuthorityDigest: c.Digest(), EffectID: c.EffectID, ControlRevision: 3, ControlStateDigest: codingTestDigest("a"),
		CompletionDigest: codingTestDigest("8"), CompletionEvidenceDigest: codingTestDigest("9"), UpdatedAt: c.IssuedAt.Add(time.Second)}}
	s, err := codingcontrol.NewCreateReadback(f, f, f, codingcontrol.Expected{ProfileDigest: c.ProfileDigest, ControlPolicyDigest: c.ControlPolicyDigest, ProviderPrincipalDigest: c.PeerPrincipalDigest})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.ReconcileCodingCreate(t.Context(), c.OperationID); err != nil {
		t.Fatal(err)
	}
	return f.observation
}

type readyFixture struct {
	slots    codingidentity.State
	ledger   lifecyclerepository.State
	plan     codingidentity.Plan
	create   dockercontrol.CodingCreateAuthority
	observed codingcontrol.CreateObservation
	now      time.Time
	marker   codingIdentityMarker
}

func newReadyFixture(t *testing.T) readyFixture {
	t.Helper()
	start := time.Now().UTC().Truncate(time.Millisecond).Add(-2 * time.Second)
	plan := codingBoundTestPlan()
	slots, err := codingidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	ledger := testCodingAcceptedCreate(t, start, "revision-1", "tenant-1", "sandbox-1", "operation-1")
	_, _, _, c, err := beginCodingFirstCreateWithAuthority(t.Context(), &slots, &ledger, plan, "operation-1", codingBoundSpecs(plan), codingTestDigest("f"), start)
	if err != nil {
		t.Fatal(err)
	}
	now := start.Add(2 * time.Second)
	return readyFixture{slots: slots, ledger: ledger, plan: plan, create: c, observed: readyObservation(t, c, now), now: now,
		marker: codingIdentityMarker{Initialized: true, PlanDigest: slots.PlanDigest, AuthorityMode: codingAtomicOriginalMode, ControlPolicyDigest: c.ControlPolicyDigest}}
}
func (f *readyFixture) complete(ctx context.Context) (lifecycle.Operation, lifecycle.Sandbox, error) {
	return completeCodingCreate(ctx, &f.slots, &f.ledger, f.plan, codingBoundSpecs(f.plan), f.observed, f.now)
}
func (f *readyFixture) guard(before, after lifecyclerepository.State) error {
	return checkCodingRetirementBarrierWithMarker(f.marker, f.slots, before, after, f.now)
}

func TestCodingReadyAtomicOutcomeAndDurableHistory(t *testing.T) {
	for _, name := range []string{"running", "unknown", "late running", "cancelled running"} {
		t.Run(name, func(t *testing.T) {
			f := newReadyFixture(t)
			original := f.ledger.Operations[f.create.OperationID]
			if name == "unknown" {
				var err error
				original, err = lifecycle.MarkOutcomeUnknown(original, f.now.Add(-time.Second), lifecycle.Failure{Code: "lost_reply", Retryable: true, Outcome: lifecycle.FailureUnknown})
				if err != nil || f.ledger.UpdateOperation(original) != nil {
					t.Fatal(err)
				}
			}
			if name == "late running" {
				f.now = original.Deadline.Add(time.Second)
			}
			if name == "cancelled running" {
				original.CancelRequested = true
				if f.ledger.UpdateOperation(original) != nil {
					t.Fatal("cancel fixture")
				}
			}
			if err := f.guard(f.ledger, f.ledger); err != nil {
				t.Fatal(err)
			}
			result, ready, err := f.complete(t.Context())
			want := lifecycle.OperationOutcomeUnknown
			if name == "running" {
				want = lifecycle.OperationSucceeded
			}
			if err != nil || result.State != want || ready.ObservedState != lifecycle.ObservedReady || f.slots.Reservations[0].Status != codingidentity.Active {
				t.Fatalf("atomic ready: %s %s %v", result.State, ready.ObservedState, err)
			}
			if name == "unknown" && !reflect.DeepEqual(original, result) {
				t.Fatal("rewrote historical Unknown")
			}
			if got := f.slots.CreateCompletions[f.create.AllocationID]; got != completionBinding(f.observed) {
				t.Fatal("lost full readiness evidence")
			}
			if err := f.guard(f.ledger, f.ledger); err != nil {
				t.Fatal(err)
			}
			before := copyCodingBarrierLedger(t, f.ledger)
			slots := f.slots.Clone()
			if _, _, err := f.complete(t.Context()); !errors.Is(err, errCodingAlreadyReady) || !reflect.DeepEqual(before, f.ledger) || !reflect.DeepEqual(slots, f.slots) {
				t.Fatalf("idempotent read changed state: %v", err)
			}
			unknownEvents, readyEvents := 0, 0
			for _, e := range f.ledger.Events[ready.ID] {
				if e.Kind == "outcome-unknown" {
					unknownEvents++
				}
				if e.Kind == "ready" || e.Kind == "reconciled-ready" {
					readyEvents++
				}
			}
			wantUnknown := 0
			if name == "late running" || name == "cancelled running" {
				wantUnknown = 1
			}
			if readyEvents != 1 || unknownEvents != wantUnknown {
				t.Fatalf("event counts %d %d", readyEvents, unknownEvents)
			}
			clone := f.slots.Clone()
			b := clone.CreateCompletions[f.create.AllocationID]
			b.EvidenceDigest = codingTestDigest("0")
			clone.CreateCompletions[f.create.AllocationID] = b
			if f.slots.CreateCompletions[f.create.AllocationID].EvidenceDigest == b.EvidenceDigest {
				t.Fatal("history clone aliased")
			}
		})
	}
}

func TestCodingReadyRejectsStaleTupleWithoutPartialWrites(t *testing.T) {
	for _, name := range []string{"expired lease", "fence", "generation", "tenant", "spec", "original bytes", "retiring", "event collision", "cancel context", "missing receipt", "future source", "active no proof"} {
		t.Run(name, func(t *testing.T) {
			f := newReadyFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sb := f.ledger.Sandboxes[f.create.SandboxID]
			switch name {
			case "expired lease":
				f.now = sb.LeaseExpiresAt
			case "fence":
				f.ledger.Fencing[sb.ProviderRevisionID+"\x00"+sb.ID]++
			case "generation":
				sb.Generation++
				f.ledger.Sandboxes[sb.ID] = sb
				lease := f.ledger.Leases[sb.ID]
				lease.Generation = sb.Generation
				f.ledger.Leases[sb.ID] = lease
			case "tenant":
				sb.TenantID = "other-tenant"
				f.ledger.Sandboxes[sb.ID] = sb
			case "spec":
				f.slots.Reservations[0].SpecDigest = codingTestDigest("0")
			case "original bytes":
				r := f.slots.OriginalCreates[f.create.AllocationID]
				r.Document += " "
				f.slots.OriginalCreates[f.create.AllocationID] = r
			case "retiring":
				sb.DesiredState = lifecycle.DesiredTerminated
				f.ledger.Sandboxes[sb.ID] = sb
			case "event collision":
				op := f.ledger.Operations[f.create.OperationID]
				op.State = lifecycle.OperationSucceeded
				if appendCodingReadyEvent(&f.ledger, sb, op, "ready", codingTestDigest("0"), f.now) != nil {
					t.Fatal("event fixture")
				}
			case "cancel context":
				cancel()
			case "missing receipt":
				f.observed = codingcontrol.CreateObservation{}
			case "future source":
				f.now = f.create.IssuedAt
			case "active no proof":
				f.slots.Reservations[0].Status = codingidentity.Active
			}
			before := copyCodingBarrierLedger(t, f.ledger)
			slots := f.slots.Clone()
			if _, _, err := f.complete(ctx); err == nil {
				t.Fatal("bad tuple admitted")
			}
			if !reflect.DeepEqual(slots, f.slots) || !reflect.DeepEqual(before, f.ledger) {
				t.Fatal("failed CAS left partial mutation")
			}
		})
	}
}

func TestCodingGenericWriterCannotManufactureReadiness(t *testing.T) {
	for _, name := range []string{"ready", "success", "lease renewal", "ready event", "active unknown success", "released unknown success", "active no proof"} {
		t.Run(name, func(t *testing.T) {
			f := newReadyFixture(t)
			if name == "active unknown success" || name == "released unknown success" {
				op, _ := lifecycle.MarkOutcomeUnknown(f.ledger.Operations[f.create.OperationID], f.now, lifecycle.Failure{Code: "lost", Outcome: lifecycle.FailureUnknown})
				if f.ledger.UpdateOperation(op) != nil {
					t.Fatal("unknown fixture")
				}
				if _, _, err := f.complete(t.Context()); err != nil {
					t.Fatal(err)
				}
				if name == "released unknown success" {
					f.slots.Reservations = []codingidentity.Reservation{}
				}
			}
			before := copyCodingBarrierLedger(t, f.ledger)
			after := copyCodingBarrierLedger(t, f.ledger)
			sb := after.Sandboxes[f.create.SandboxID]
			op := after.Operations[f.create.OperationID]
			switch name {
			case "ready":
				next, _ := lifecycle.ApplyObservedTransition(sb, lifecycle.ObservedReady, sb.Generation, f.now)
				if after.UpdateSandbox(next, sb.Generation, op.FencingToken) != nil {
					t.Fatal("ordinary ready fixture")
				}
			case "success", "active unknown success", "released unknown success":
				op.State = lifecycle.OperationSucceeded
				op.Failure = nil
				after.Operations[op.ID] = op
				for key, r := range after.Idempotency {
					if r.Operation.ID == op.ID {
						r.Operation = op
						after.Idempotency[key] = r
					}
				}
			case "lease renewal":
				lease := after.Leases[sb.ID]
				lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute)
				if after.ReplaceLease(lease, op.FencingToken) != nil {
					t.Fatal("ordinary lease fixture")
				}
			case "ready event":
				if appendCodingReadyEvent(&after, sb, op, "ready", "", f.now) != nil {
					t.Fatal("ordinary event fixture")
				}
			case "active no proof":
				f.slots.Reservations[0].Status = codingidentity.Active
			}
			if f.guard(before, after) == nil {
				t.Fatal("generic readiness bypass")
			}
		})
	}
}

func admitReadyTermination(t *testing.T, f *readyFixture) lifecycle.Operation {
	t.Helper()
	sb := f.ledger.Sandboxes[f.create.SandboxID]
	r := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "termination-1", AttemptID: "term-attempt-1", FencingToken: f.create.Fence + 1,
		IdempotencyKey: "term-key-1", RequestDigest: codingTestDigest("2"), Deadline: f.now.Add(time.Minute), ExpectedGeneration: sb.Generation}, Reason: "test"}
	updated, op, err := lifecycle.StartTerminate(sb, r, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.ledger.ReserveMutation(r.IdempotencyKey, r.RequestDigest, r.ExpectedGeneration, updated, op, lifecycle.Event{ID: codingAdmissionEventID(op.ID, "termination-requested"), SandboxID: sb.ID, OperationID: op.ID, Generation: updated.Generation, FencingToken: op.FencingToken, Kind: "termination-requested", DataDigest: r.RequestDigest, OccurredAt: f.now}); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestCodingReadyAndTerminationOrderPreservesCleanup(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminate first", true: "ready first"}[published], func(t *testing.T) {
			f := newReadyFixture(t)
			if published {
				if _, _, err := f.complete(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			before := copyCodingBarrierLedger(t, f.ledger)
			term := admitReadyTermination(t, &f)
			if err := f.guard(before, f.ledger); err != nil {
				t.Fatalf("normal termination blocked: %v", err)
			}
			if _, _, err := f.complete(t.Context()); err == nil || errors.Is(err, errCodingAlreadyReady) {
				t.Fatal("stale Ready beat termination")
			}
			input := codingCleanupAdmission{Create: f.create, Completed: dockercontrol.CodingReceipt{Authority: f.create, AuthorityDigest: f.create.Digest(), Status: dockercontrol.ReceiptCompleted,
				CompletionDigest: f.observed.CompletionDigest(), CompletionEvidenceDigest: f.observed.CompletionEvidenceDigest(), UpdatedAt: f.observed.UpdatedAt()},
				ControlRevision: f.observed.ControlRevision(), ControlStateDigest: f.observed.ControlStateDigest(), TerminationID: term.ID, ControlPolicyDigest: f.create.ControlPolicyDigest,
				PeerPrincipalDigest: f.create.PeerPrincipalDigest, SpecBySlot: codingBoundSpecs(f.plan)}
			cleanup, _, _, _, err := beginCodingCurrentCleanup(t.Context(), &f.slots, &f.ledger, f.plan, input, f.now)
			if err != nil || f.slots.Reservations[0].Status != codingidentity.Cleaning {
				t.Fatalf("direct cleanup: %v", err)
			}
			if err = f.guard(f.ledger, f.ledger); err != nil {
				t.Fatal(err)
			}
			released := dockercontrol.CodingReceipt{Authority: f.create, AuthorityDigest: f.create.Digest(), CleanupAuthority: cleanup, Status: dockercontrol.ReceiptReleased,
				CompletionDigest: input.Completed.CompletionDigest, CompletionEvidenceDigest: input.Completed.CompletionEvidenceDigest, AbsenceDigest: codingTestDigest("4"), AbsenceEvidenceDigest: codingTestDigest("5"), UpdatedAt: f.now.Add(time.Second)}
			_, _, err = finishCodingCurrentCleanup(t.Context(), &f.slots, &f.ledger, f.plan, codingReleaseAdmission{Create: f.create, Cleanup: cleanup, Released: released, ControlRevision: 4, ControlStateDigest: codingTestDigest("b"), SpecBySlot: codingBoundSpecs(f.plan)}, f.now.Add(time.Second))
			if err != nil || len(f.slots.Reservations) != 0 {
				t.Fatalf("release: %v", err)
			}
			if _, exists := f.slots.CreateCompletions[f.create.AllocationID]; exists != published {
				t.Fatal("readiness history lost/invented")
			}
			if err = f.guard(f.ledger, f.ledger); err != nil {
				t.Fatal(err)
			}
			// Release keeps immutable readiness history, but cannot let generic
			// writers resurrect the old sandbox or lend proof to a new occupant.
			beforeRelease := copyCodingBarrierLedger(t, f.ledger)
			resurrected := copyCodingBarrierLedger(t, f.ledger)
			old := resurrected.Sandboxes[f.create.SandboxID]
			old.ObservedState = lifecycle.ObservedReady
			if resurrected.UpdateSandbox(old, old.Generation, cleanup.CleanupFence) != nil {
				t.Fatal("resurrection fixture")
			}
			if f.guard(beforeRelease, resurrected) == nil {
				t.Fatal("released runtime resurrected by generic writer")
			}
			f.now = f.now.Add(2 * time.Second)
			extra := testCodingAcceptedCreate(t, f.now, "revision-2", "tenant-2", "sandbox-2", "operation-2")
			for _, record := range extra.Idempotency {
				if _, err := f.ledger.ReserveCreate(record.Key, record.RequestDigest, extra.Sandboxes["sandbox-2"], record.Operation); err != nil {
					t.Fatal(err)
				}
			}
			_, _, _, next, err := beginCodingFirstCreateWithAuthority(t.Context(), &f.slots, &f.ledger, f.plan, "operation-2", codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, f.now)
			if err != nil || next.SlotID != f.create.SlotID || next.AllocationID == f.create.AllocationID {
				t.Fatalf("fresh slot occupant: %v", err)
			}
			if err := f.guard(f.ledger, f.ledger); err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.complete(t.Context()); err == nil {
				t.Fatal("old observation authorized a new occupant")
			}
			if published {
				bad := f.slots.Clone()
				bad.CreateCompletions[next.AllocationID] = bad.CreateCompletions[f.create.AllocationID]
				if bad.Validate(f.plan) == nil {
					t.Fatal("old proof lent to new allocation")
				}
			}
		})
	}
}

func TestCodingReadinessHistoryRejectsMalformedBindings(t *testing.T) {
	for _, name := range []string{"key", "slot", "authority", "revision", "evidence", "time", "orphan"} {
		t.Run(name, func(t *testing.T) {
			f := newReadyFixture(t)
			if _, _, err := f.complete(t.Context()); err != nil {
				t.Fatal(err)
			}
			b := f.slots.CreateCompletions[f.create.AllocationID]
			switch name {
			case "key":
				b.AllocationID = "invalid"
			case "slot":
				b.SlotID = "other-slot"
			case "authority":
				b.AuthorityDigest = codingTestDigest("0")
			case "revision":
				b.ControlRevision = 0
			case "evidence":
				b.EvidenceDigest = ""
			case "time":
				b.UpdatedAt = time.Time{}
			case "orphan":
				delete(f.slots.OriginalCreates, f.create.AllocationID)
			}
			f.slots.CreateCompletions[f.create.AllocationID] = b
			if f.slots.Validate(f.plan) == nil || f.guard(f.ledger, f.ledger) == nil {
				t.Fatal("malformed history accepted")
			}
		})
	}
}

func TestCodingReadinessGuardAcceptsExactLeaseExpiryTermination(t *testing.T) {
	f := newReadyFixture(t)
	before := copyCodingBarrierLedger(t, f.ledger)
	sb := f.ledger.Sandboxes[f.create.SandboxID]
	lease := f.ledger.Leases[sb.ID]
	f.now = lease.ExpiresAt
	request := lifecycle.LeaseExpiryTermination(sb, lease, f.now)
	updated, op, err := lifecycle.StartTerminate(sb, request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.ledger.ReserveMutation(request.IdempotencyKey, request.RequestDigest, sb.Generation, updated, op, lifecycle.Event{
		ID: codingAdmissionEventID(op.ID, "lease-expired"), SandboxID: sb.ID, OperationID: op.ID, Generation: updated.Generation, FencingToken: op.FencingToken,
		Kind: "lease-expired", DataDigest: request.RequestDigest, OccurredAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.guard(before, f.ledger); err != nil {
		t.Fatal(err)
	}
}

func TestCodingActiveRejectsBareTerminationWithoutOperation(t *testing.T) {
	f := newReadyFixture(t)
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := copyCodingBarrierLedger(t, f.ledger)
	after := copyCodingBarrierLedger(t, f.ledger)
	sb := after.Sandboxes[f.create.SandboxID]
	next := sb
	next.DesiredState = lifecycle.DesiredTerminated
	next.Generation++
	if err := after.UpdateSandbox(next, sb.Generation, f.create.Fence); err != nil {
		t.Fatal(err)
	}
	if err := f.guard(before, after); err == nil {
		t.Fatal("bare generic termination bypassed admission")
	}
}

func TestCodingUnretiredProjectionRejectsGenericSideWrites(t *testing.T) {
	for _, active := range []bool{false, true} {
		for _, name := range []string{"termination running", "termination success", "fake event", "bare lease", "idempotency removal", "sandbox identity"} {
			t.Run(map[bool]string{false: "creating", true: "active"}[active]+"/"+name, func(t *testing.T) {
				f := newReadyFixture(t)
				if active {
					if _, _, err := f.complete(t.Context()); err != nil {
						t.Fatal(err)
					}
				}
				term := admitReadyTermination(t, &f)
				before := copyCodingBarrierLedger(t, f.ledger)
				after := copyCodingBarrierLedger(t, f.ledger)
				sb := after.Sandboxes[f.create.SandboxID]
				switch name {
				case "termination running":
					running, err := lifecycle.BeginOperation(term, f.now)
					if err != nil || after.UpdateOperation(running) != nil {
						t.Fatal(err)
					}
				case "termination success":
					term.State = lifecycle.OperationSucceeded
					after.Operations[term.ID] = term
					for key, r := range after.Idempotency {
						if r.Operation.ID == term.ID {
							r.Operation = term
							after.Idempotency[key] = r
						}
					}
				case "fake event":
					if _, err := after.AppendEvent(lifecycle.Event{ID: "fake-terminated", SandboxID: sb.ID, OperationID: term.ID, Generation: sb.Generation, FencingToken: term.FencingToken, Kind: "terminated", OccurredAt: f.now}); err != nil {
						t.Fatal(err)
					}
				case "bare lease":
					lease := after.Leases[sb.ID]
					lease.ExpiresAt = lease.ExpiresAt.Add(time.Minute)
					if err := after.ReplaceLease(lease, term.FencingToken); err != nil {
						t.Fatal(err)
					}
				case "idempotency removal":
					delete(after.Idempotency, sb.ProviderRevisionID+"\x00"+term.IdempotencyKey)
				case "sandbox identity":
					sb.WorkspaceID = "other-workspace"
					if err := after.UpdateSandbox(sb, sb.Generation, term.FencingToken); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.guard(before, after); err == nil {
					t.Fatal("generic side write admitted")
				}
			})
		}
	}
}

func TestCodingReadyAllowsExactRenewalAndConservativeUnknown(t *testing.T) {
	f := newReadyFixture(t)
	before := copyCodingBarrierLedger(t, f.ledger)
	unknown, err := lifecycle.MarkOutcomeUnknown(f.ledger.Operations[f.create.OperationID], f.now, lifecycle.Failure{Code: "dispatch_reply_lost", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil || f.ledger.UpdateOperation(unknown) != nil {
		t.Fatal(err)
	}
	if err := f.guard(before, f.ledger); err != nil {
		t.Fatal(err)
	}
	before = copyCodingBarrierLedger(t, f.ledger)
	if appendCodingReadyEvent(&f.ledger, f.ledger.Sandboxes[f.create.SandboxID], unknown, "outcome-unknown", "", f.now) != nil {
		t.Fatal("unknown event")
	}
	if err := f.guard(before, f.ledger); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	before = copyCodingBarrierLedger(t, f.ledger)
	sb := f.ledger.Sandboxes[f.create.SandboxID]
	req := lifecycle.LeaseRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "lease-op-1", AttemptID: "lease-attempt-1", FencingToken: f.create.Fence + 1,
		IdempotencyKey: "lease-key-1", RequestDigest: codingTestDigest("2"), Deadline: f.now.Add(time.Minute), ExpectedGeneration: sb.Generation}, ExtendSeconds: 60}
	updated, _, op, err := lifecycle.StartLeaseRenewal(sb, req, 7200, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.ledger.ReserveMutation(req.IdempotencyKey, req.RequestDigest, sb.Generation, updated, op, lifecycle.Event{ID: codingAdmissionEventID(op.ID, "lease-extended"), SandboxID: sb.ID, OperationID: op.ID, Generation: sb.Generation, FencingToken: op.FencingToken, Kind: "lease-extended", DataDigest: req.RequestDigest, OccurredAt: f.now}); err != nil {
		t.Fatal(err)
	}
	if err := f.guard(before, f.ledger); err != nil {
		t.Fatalf("exact Active renewal rejected: %v", err)
	}
}

func TestCodingAdmissionRejectsNonstandardEvent(t *testing.T) {
	for _, name := range []string{"empty digest", "wrong id", "fake expiry"} {
		t.Run(name, func(t *testing.T) {
			f := newReadyFixture(t)
			before := copyCodingBarrierLedger(t, f.ledger)
			admitReadyTermination(t, &f)
			events := f.ledger.Events[f.create.SandboxID]
			event := events[len(events)-1]
			switch name {
			case "empty digest":
				event.DataDigest = ""
			case "wrong id":
				event.ID = "arbitrary-event"
			case "fake expiry":
				event.Kind = "lease-expired"
				event.ID = codingAdmissionEventID(event.OperationID, event.Kind)
			}
			events[len(events)-1] = event
			f.ledger.Events[f.create.SandboxID] = events
			if f.guard(before, f.ledger) == nil {
				t.Fatal("nonstandard accepted event admitted")
			}
		})
	}
}
