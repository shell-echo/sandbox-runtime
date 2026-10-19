package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

// Real application coordination and PG state-transition helpers, but an
// in-process mutex and synthetic Control observer: component evidence only.
type terminationFixture struct {
	mu                                 sync.Mutex
	f                                  readyFixture
	id                                 string
	beginLost, finishLost, dispatchErr error
	recordErr                          error
	dropRecord                         bool
	dispatchResult                     *codingcontrol.CleanupDispatchResult
	cancelBegin                        context.CancelFunc
	status                             string
	begins, finishes, sends, reads     int
	readGate                           chan struct{}
}

func newTerminationFixture(t *testing.T) *terminationFixture {
	t.Helper()
	f := newReadyFixture(t)
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	op := admitReadyTermination(t, &f)
	return &terminationFixture{f: f, id: op.ID, status: codingcontrolprotocol.StatusReleased}
}
func (x *terminationFixture) service(t *testing.T) *codingcontrol.TerminationCoordinator {
	t.Helper()
	c := x.f.create
	s, err := codingcontrol.NewTerminationReconciler(x, x, x, x, codingcontrol.Expected{ProfileDigest: c.ProfileDigest, ControlPolicyDigest: c.ControlPolicyDigest, ProviderPrincipalDigest: c.PeerPrincipalDigest})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (x *terminationFixture) Now() time.Time { x.mu.Lock(); defer x.mu.Unlock(); return x.f.now }
func (x *terminationFixture) ReadTermination(ctx context.Context, id string) (lifecycle.Operation, lifecycle.Sandbox, error) {
	x.mu.Lock()
	op, sb, err := readCodingTerminationSnapshot(x.f.marker, x.f.slots, x.f.ledger, x.f.plan, codingBoundSpecs(x.f.plan), x.f.create.ControlPolicyDigest, id, x.f.now)
	x.reads++
	wait := x.readGate != nil && x.reads <= 2
	gate := x.readGate
	if wait && x.reads == 2 {
		close(gate)
	}
	x.mu.Unlock()
	if wait {
		select {
		case <-gate:
		case <-ctx.Done():
			return lifecycle.Operation{}, lifecycle.Sandbox{}, ctx.Err()
		}
	}
	return op, sb, err
}
func (x *terminationFixture) ReadBeginBinding(_ context.Context, id string) (codingcontrol.Binding, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if id != x.id || x.f.slots.Reservations[0].Status != codingidentity.Active {
		return codingcontrol.Binding{}, ErrCorrupt
	}
	return codingcontrol.Binding{Create: x.f.create, TerminationID: id}, nil
}
func (x *terminationFixture) ReadFinishBinding(_ context.Context, id string) (codingcontrol.Binding, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	f := &x.f
	c, err := readCodingCleanupEnvelope(f.slots, f.plan, f.create, id, f.create.ControlPolicyDigest, f.create.PeerPrincipalDigest, codingBoundSpecs(f.plan))
	if err != nil {
		return codingcontrol.Binding{}, err
	}
	b := f.slots.Retirements[f.create.SlotID]
	return codingcontrol.Binding{Create: f.create, Cleanup: &c, TerminationID: id, ControlRevision: b.ControlReceiptRevision, ControlStateDigest: b.ControlReceiptStateDigest}, nil
}
func (x *terminationFixture) BeginWithObservation(ctx context.Context, id string, o codingcontrol.CompletedObservation) (dockercontrol.CodingCleanupAuthority, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	f := &x.f
	if o.Validate(f.create) != nil || f.guard(f.ledger, f.ledger) != nil {
		return dockercontrol.CodingCleanupAuthority{}, ErrCorrupt
	}
	completed := dockercontrol.CodingReceipt{Authority: f.create, AuthorityDigest: f.create.Digest(), Status: dockercontrol.ReceiptCompleted, CompletionDigest: o.CompletionDigest(), CompletionEvidenceDigest: o.CompletionEvidenceDigest(), UpdatedAt: o.UpdatedAt()}
	c, _, _, _, err := beginCodingCurrentCleanup(ctx, &f.slots, &f.ledger, f.plan, codingCleanupAdmission{Create: f.create, Completed: completed, ControlRevision: o.ControlRevision(), ControlStateDigest: o.ControlStateDigest(), TerminationID: id, ControlPolicyDigest: f.create.ControlPolicyDigest, PeerPrincipalDigest: f.create.PeerPrincipalDigest, SpecBySlot: codingBoundSpecs(f.plan)}, f.now)
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	x.begins++
	if x.cancelBegin != nil {
		x.cancelBegin()
	}
	if x.beginLost != nil {
		return dockercontrol.CodingCleanupAuthority{}, x.beginLost
	}
	return c, nil
}
func (x *terminationFixture) FinishWithObservation(ctx context.Context, id string, o codingcontrol.ReleasedObservation) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	f := &x.f
	binding := f.slots.Retirements[f.create.SlotID]
	if id != x.id || o.Validate(f.create, o.CleanupAuthority(), f.now, binding.ControlReceiptRevision, binding.ControlReceiptStateDigest) != nil || f.guard(f.ledger, f.ledger) != nil {
		return ErrCorrupt
	}
	released := dockercontrol.CodingReceipt{Authority: f.create, AuthorityDigest: f.create.Digest(), Status: dockercontrol.ReceiptReleased, CleanupAuthority: o.CleanupAuthority(), CompletionDigest: o.CompletionDigest(), CompletionEvidenceDigest: o.CompletionEvidenceDigest(), AbsenceDigest: o.AbsenceDigest(), AbsenceEvidenceDigest: o.AbsenceEvidenceDigest(), UpdatedAt: o.UpdatedAt()}
	_, _, err := finishCodingCurrentCleanup(ctx, &f.slots, &f.ledger, f.plan, codingReleaseAdmission{Create: f.create, Cleanup: o.CleanupAuthority(), Released: released, ControlRevision: o.ControlRevision(), ControlStateDigest: o.ControlStateDigest(), SpecBySlot: codingBoundSpecs(f.plan), RequireDispatchAcknowledgement: true}, f.now)
	if err != nil {
		return err
	}
	if err = f.guard(f.ledger, f.ledger); err != nil {
		return err
	}
	x.finishes++
	return x.finishLost
}
func (x *terminationFixture) RecordCleanupDispatchResult(ctx context.Context, id string, result codingcontrol.CleanupDispatchResult) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.dispatchResult = &result
	if x.dropRecord {
		return x.recordErr
	}
	err := updateCodingDispatchOutcome(ctx, x.f.marker, &x.f.slots, &x.f.ledger, x.f.plan, codingBoundSpecs(x.f.plan), x.f.create.ControlPolicyDigest, id, &result, x.f.now)
	if errors.Is(err, errCodingDispatchUnchanged) {
		err = nil
	}
	return errors.Join(err, x.recordErr)
}
func (x *terminationFixture) RetainUnacknowledgedTermination(ctx context.Context, id string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	err := updateCodingDispatchOutcome(ctx, x.f.marker, &x.f.slots, &x.f.ledger, x.f.plan, codingBoundSpecs(x.f.plan), x.f.create.ControlPolicyDigest, id, nil, x.f.now)
	if errors.Is(err, errCodingDispatchUnchanged) {
		return nil
	}
	return err
}

func (x *terminationFixture) DispatchCodingCleanupAuthority(_ context.Context, create dockercontrol.CodingCreateAuthority, cleanup dockercontrol.CodingCleanupAuthority) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if create != x.f.create || cleanup.CleanupOperationID != x.id {
		return ErrCorrupt
	}
	x.sends++
	return x.dispatchErr
}
func (x *terminationFixture) Observe(_ context.Context, q codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	o := x.f.observed
	r := codingcontrolprotocol.Response{Protocol: codingcontrolprotocol.ProtocolID, Scope: codingcontrolprotocol.ScopeCoding, Action: q.Action, Status: codingcontrolprotocol.StatusCompleted, CreateAuthorityDigest: q.Create.Digest(), EffectID: q.Create.EffectID, ControlRevision: o.ControlRevision(), ControlStateDigest: o.ControlStateDigest(), CompletionDigest: o.CompletionDigest(), CompletionEvidenceDigest: o.CompletionEvidenceDigest(), UpdatedAt: o.UpdatedAt()}
	if q.Cleanup != nil {
		r.Status = x.status
		r.ControlRevision++
		r.ControlStateDigest = codingTestDigest("b")
		r.CleanupAuthorityDigest = q.Cleanup.Digest()
		r.UpdatedAt = q.Cleanup.IssuedAt
		switch r.Status {
		case codingcontrolprotocol.StatusReleased:
			r.AbsenceDigest = codingTestDigest("4")
			r.AbsenceEvidenceDigest = codingTestDigest("5")
		case codingcontrolprotocol.StatusUnknown:
			r.CleanupAuthorityDigest = ""
			r.CompletionDigest = ""
			r.CompletionEvidenceDigest = ""
		case codingcontrolprotocol.StatusNotFound:
			r.ControlRevision = 0
			r.ControlStateDigest = ""
			r.CleanupAuthorityDigest = ""
			r.CompletionDigest = ""
			r.CompletionEvidenceDigest = ""
			r.UpdatedAt = time.Time{}
		}
	}
	return r, r.Validate(q)
}

func TestCodingTerminationFreshAndHistoricalPaths(t *testing.T) {
	for _, mode := range []string{"ack", "dispatch lost", "begin commit lost", "finish commit lost", "cancel after begin", "ack commit lost", "ack not committed"} {
		t.Run(mode, func(t *testing.T) {
			x := newTerminationFixture(t)
			s := x.service(t)
			lost := errors.New("injected ambiguous response")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "dispatch lost":
				x.dispatchErr = lost
			case "begin commit lost":
				x.beginLost = lost
			case "finish commit lost":
				x.finishLost = lost
			case "cancel after begin":
				x.cancelBegin = cancel
			case "ack commit lost":
				x.recordErr = lost
			case "ack not committed":
				x.recordErr = lost
				x.dropRecord = true
			}
			op, sb, attempted, err := s.ReconcileCodingTermination(ctx, x.id)
			wantSend := mode != "begin commit lost" && mode != "cancel after begin"
			if attempted != wantSend || x.sends != map[bool]int{true: 1, false: 0}[wantSend] || x.begins != 1 {
				t.Fatalf("dispatch permission: %v %d %d %v", attempted, x.sends, x.begins, err)
			}
			if mode == "dispatch lost" || mode == "begin commit lost" || mode == "ack commit lost" || mode == "ack not committed" {
				if !errors.Is(err, lost) {
					t.Fatalf("lost error hidden: %v", err)
				}
			} else if mode == "cancel after begin" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel hidden: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			wantState := lifecycle.OperationRunning
			if mode == "dispatch lost" {
				wantState = lifecycle.OperationOutcomeUnknown
			}
			if mode != "cancel after begin" && (op.State != wantState || sb.ObservedState != lifecycle.ObservedTerminating) {
				t.Fatal("ACK published termination")
			}
			op, sb, attempted, err = s.ReconcileCodingTermination(t.Context(), x.id)
			if mode == "finish commit lost" {
				if !errors.Is(err, lost) {
					t.Fatal("finish uncertainty hidden")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			wantFinal := lifecycle.OperationSucceeded
			if mode == "dispatch lost" || mode == "begin commit lost" || mode == "cancel after begin" || mode == "ack not committed" {
				wantFinal = lifecycle.OperationOutcomeUnknown
			}
			if attempted || op.State != wantFinal || sb.ObservedState != lifecycle.ObservedTerminated || len(x.f.slots.Reservations) != 0 || x.finishes != 1 {
				t.Fatalf("typed release: %#v %#v %v", op, sb, err)
			}
			before := copyCodingBarrierLedger(t, x.f.ledger)
			sends := x.sends
			if _, _, attempted, err = s.ReconcileCodingTermination(t.Context(), x.id); err != nil || attempted || x.sends != sends || x.finishes != 1 || !reflect.DeepEqual(before, x.f.ledger) {
				t.Fatalf("terminal read wrote/replayed: %v", err)
			}
		})
	}
}

func TestCodingTerminationTwoStaleAcceptedReadersDispatchOnce(t *testing.T) {
	x := newTerminationFixture(t)
	x.readGate = make(chan struct{})
	s1, s2 := x.service(t), x.service(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, s := range []*codingcontrol.TerminationCoordinator{s1, s2} {
		wg.Add(1)
		go func(s *codingcontrol.TerminationCoordinator) {
			defer wg.Done()
			_, _, _, _ = s.ReconcileCodingTermination(ctx, x.id)
		}(s)
	}
	wg.Wait()
	if x.begins != 1 || x.sends != 1 || x.finishes != 0 {
		t.Fatalf("stale Accepted replay: begin=%d send=%d finish=%d", x.begins, x.sends, x.finishes)
	}
	if _, _, sent, err := s1.ReconcileCodingTermination(t.Context(), x.id); err != nil || sent || x.sends != 1 || x.finishes != 1 {
		t.Fatalf("recovery: %v", err)
	}
}

func TestCodingTerminationUncertainStatusNeverReleasesOrRetries(t *testing.T) {
	for _, status := range []string{codingcontrolprotocol.StatusCleanupPending, codingcontrolprotocol.StatusUnknown, codingcontrolprotocol.StatusNotFound} {
		t.Run(status, func(t *testing.T) {
			x := newTerminationFixture(t)
			s := x.service(t)
			if _, _, _, err := s.ReconcileCodingTermination(t.Context(), x.id); err != nil {
				t.Fatal(err)
			}
			x.status = status
			before := copyCodingBarrierLedger(t, x.f.ledger)
			slots := x.f.slots.Clone()
			for range 2 {
				if _, _, sent, err := s.ReconcileCodingTermination(t.Context(), x.id); err == nil || sent {
					t.Fatal("uncertainty accepted/retried")
				}
			}
			if x.sends != 1 || x.finishes != 0 || !reflect.DeepEqual(before, x.f.ledger) || !reflect.DeepEqual(slots, x.f.slots) {
				t.Fatal("uncertain observation mutated state")
			}
		})
	}
}

func TestCodingTerminationLateCancelledAndUnknownStayUnknown(t *testing.T) {
	for _, mode := range []string{"late", "cancelled", "historical unknown"} {
		t.Run(mode, func(t *testing.T) {
			x := newTerminationFixture(t)
			s := x.service(t)
			if _, _, _, err := s.ReconcileCodingTermination(t.Context(), x.id); err != nil {
				t.Fatal(err)
			}
			op := x.f.ledger.Operations[x.id]
			switch mode {
			case "late":
				x.f.now = op.Deadline
			case "cancelled":
				op.CancelRequested = true
				if err := x.f.ledger.UpdateOperation(op); err != nil {
					t.Fatal(err)
				}
			case "historical unknown":
				var err error
				op, err = lifecycle.MarkOutcomeUnknown(op, x.f.now, lifecycle.Failure{Code: "lost_reply", Retryable: true, Outcome: lifecycle.FailureUnknown})
				if err != nil || x.f.ledger.UpdateOperation(op) != nil {
					t.Fatal(err)
				}
			}
			got, sb, sent, err := s.ReconcileCodingTermination(t.Context(), x.id)
			if err != nil || sent || got.State != lifecycle.OperationOutcomeUnknown || sb.ObservedState != lifecycle.ObservedTerminated || len(x.f.slots.Reservations) != 0 {
				t.Fatalf("late/unknown release: %#v %v", got, err)
			}
			if mode == "historical unknown" && !reflect.DeepEqual(got, op) {
				t.Fatal("historical Unknown rewritten")
			}
			if _, _, sent, err = s.ReconcileCodingTermination(t.Context(), x.id); err != nil || sent || x.finishes != 1 {
				t.Fatalf("Unknown terminal replay: %v", err)
			}
		})
	}
}

func TestCodingTerminationSnapshotRejectsDriftAndReadsOldReleasedAllocation(t *testing.T) {
	for _, mode := range []string{"missing original", "wrong fence", "idempotency missing", "unproved success", "bad marker", "wrong policy", "wrong spec"} {
		t.Run(mode, func(t *testing.T) {
			x := newTerminationFixture(t)
			specs := codingBoundSpecs(x.f.plan)
			policy := x.f.create.ControlPolicyDigest
			switch mode {
			case "missing original":
				delete(x.f.slots.OriginalCreates, x.f.create.AllocationID)
			case "wrong fence":
				x.f.ledger.Fencing[x.f.create.ProviderRevisionID+"\x00"+x.f.create.SandboxID]++
			case "idempotency missing":
				for k, v := range x.f.ledger.Idempotency {
					if v.Operation.ID == x.id {
						delete(x.f.ledger.Idempotency, k)
					}
				}
			case "unproved success":
				op := x.f.ledger.Operations[x.id]
				op.State = lifecycle.OperationSucceeded
				_ = x.f.ledger.UpdateOperation(op)
			case "bad marker":
				x.f.marker.AuthorityMode = ""
			case "wrong policy":
				policy = codingTestDigest("0")
			case "wrong spec":
				specs[x.f.create.SlotID] = codingTestDigest("0")
			}
			if _, _, err := readCodingTerminationSnapshot(x.f.marker, x.f.slots, x.f.ledger, x.f.plan, specs, policy, x.id, x.f.now); err == nil {
				t.Fatal("bad snapshot admitted")
			}
		})
	}
	x := newTerminationFixture(t)
	s := x.service(t)
	for range 2 {
		if _, _, _, err := s.ReconcileCodingTermination(t.Context(), x.id); err != nil {
			t.Fatal(err)
		}
	}
	x.f.now = x.f.now.Add(time.Second)
	extra := testCodingAcceptedCreate(t, x.f.now, "revision-2", "tenant-2", "sandbox-2", "operation-2")
	for _, record := range extra.Idempotency {
		if _, err := x.f.ledger.ReserveCreate(record.Key, record.RequestDigest, extra.Sandboxes["sandbox-2"], record.Operation); err != nil {
			t.Fatal(err)
		}
	}
	_, _, _, fresh, err := beginCodingFirstCreateWithAuthority(t.Context(), &x.f.slots, &x.f.ledger, x.f.plan, "operation-2", codingBoundSpecs(x.f.plan), x.f.create.ControlPolicyDigest, x.f.now)
	if err != nil || fresh.SlotID != x.f.create.SlotID {
		t.Fatal(err)
	}
	before := x.f.slots.Clone()
	got, sb, sent, err := s.ReconcileCodingTermination(t.Context(), x.id)
	if err != nil || sent || got.ID != x.id || sb.ID != x.f.create.SandboxID || !reflect.DeepEqual(before, x.f.slots) || x.sends != 1 {
		t.Fatalf("old release touched new occupant: %v", err)
	}
	x.f.ledger.Events[sb.ID] = nil
	if _, _, _, err := s.ReconcileCodingTermination(t.Context(), x.id); err == nil {
		t.Fatal("unproved terminal projection admitted")
	}
}

func TestCodingUnacknowledgedRecoveryPersistsUnknownBeforeObservation(t *testing.T) {
	for _, status := range []string{codingcontrolprotocol.StatusCleanupPending, codingcontrolprotocol.StatusUnknown, codingcontrolprotocol.StatusNotFound} {
		t.Run(status, func(t *testing.T) {
			x := newTerminationFixture(t)
			x.beginLost = errors.New("lost Begin response before send")
			s := x.service(t)
			if _, _, sent, err := s.ReconcileCodingTermination(t.Context(), x.id); err == nil || sent {
				t.Fatal("missing original failure")
			}
			x.status = status
			got, sb, sent, err := s.ReconcileCodingTermination(t.Context(), x.id)
			if err == nil || sent || got.State != lifecycle.OperationOutcomeUnknown || sb.ObservedState != lifecycle.ObservedTerminating || x.sends != 0 || x.finishes != 0 || len(x.f.slots.Retirements) != 1 {
				t.Fatalf("lost process recovery: %#v %v", got, err)
			}
			old := copyCodingBarrierLedger(t, x.f.ledger)
			if _, _, _, err = s.ReconcileCodingTermination(t.Context(), x.id); err == nil || !reflect.DeepEqual(old, x.f.ledger) {
				t.Fatal("repeated unknown recovery changed history")
			}
		})
	}
}

func TestCodingLateAcknowledgementCannotUpgradeUnknownOrReleased(t *testing.T) {
	for _, releasedFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovery before ACK", true: "release before ACK"}[releasedFirst], func(t *testing.T) {
			x := newTerminationFixture(t)
			x.dropRecord = true
			x.recordErr = errors.New("ACK record did not commit")
			s := x.service(t)
			if _, _, sent, err := s.ReconcileCodingTermination(t.Context(), x.id); err == nil || !sent || x.dispatchResult == nil || !x.dispatchResult.Acknowledged() {
				t.Fatal("missing confirmed transport result")
			}
			if releasedFirst {
				c := x.f.create
				raw, err := codingcontrol.New(x, x, x, codingcontrol.Expected{ProfileDigest: c.ProfileDigest, ControlPolicyDigest: c.ControlPolicyDigest, ProviderPrincipalDigest: c.PeerPrincipalDigest})
				if err != nil {
					t.Fatal(err)
				}
				if err := raw.Finish(t.Context(), x.id); err != nil {
					t.Fatal(err)
				}
			} else {
				x.status = codingcontrolprotocol.StatusCleanupPending
				if _, _, _, err := s.ReconcileCodingTermination(t.Context(), x.id); err == nil {
					t.Fatal("pending release accepted")
				}
			}
			if x.f.ledger.Operations[x.id].State != lifecycle.OperationOutcomeUnknown {
				t.Fatal("unacknowledged result became success")
			}
			before, slots := copyCodingBarrierLedger(t, x.f.ledger), x.f.slots.Clone()
			err := updateCodingDispatchOutcome(t.Context(), x.f.marker, &x.f.slots, &x.f.ledger, x.f.plan, codingBoundSpecs(x.f.plan), x.f.create.ControlPolicyDigest, x.id, x.dispatchResult, x.f.now)
			if err == nil || !reflect.DeepEqual(before, x.f.ledger) || !reflect.DeepEqual(slots, x.f.slots) {
				t.Fatal("late ACK upgraded/mutated frozen result")
			}
		})
	}
}

func TestCodingDispatchResultRejectsForgeryAndUnknownEventCollision(t *testing.T) {
	x := newTerminationFixture(t)
	x.beginLost = errors.New("lost Begin reply")
	s := x.service(t)
	_, _, _, _ = s.ReconcileCodingTermination(t.Context(), x.id)
	zero := codingcontrol.CleanupDispatchResult{}
	before, slots := copyCodingBarrierLedger(t, x.f.ledger), x.f.slots.Clone()
	if err := updateCodingDispatchOutcome(t.Context(), x.f.marker, &x.f.slots, &x.f.ledger, x.f.plan, codingBoundSpecs(x.f.plan), x.f.create.ControlPolicyDigest, x.id, &zero, x.f.now); err == nil || !reflect.DeepEqual(before, x.f.ledger) || !reflect.DeepEqual(slots, x.f.slots) {
		t.Fatal("forged dispatch result admitted")
	}
	op := x.f.ledger.Operations[x.id]
	sum := sha256.Sum256([]byte(op.ID + "\x00" + string(lifecycle.OperationOutcomeUnknown) + "\x00outcome-unknown"))
	sb := x.f.ledger.Sandboxes[op.SandboxID]
	if _, err := x.f.ledger.AppendEvent(lifecycle.Event{ID: "event-" + hex.EncodeToString(sum[:]), SandboxID: sb.ID, OperationID: op.ID, Generation: sb.Generation, FencingToken: op.FencingToken, Kind: "conflict", OccurredAt: x.f.now}); err != nil {
		t.Fatal(err)
	}
	before = copyCodingBarrierLedger(t, x.f.ledger)
	if err := x.RetainUnacknowledgedTermination(t.Context(), x.id); err == nil || !reflect.DeepEqual(before, x.f.ledger) || !reflect.DeepEqual(slots, x.f.slots) {
		t.Fatal("Unknown event collision partially committed")
	}
}

func TestCodingLegacyMarkerRejectsDispatchAcknowledgement(t *testing.T) {
	f, _, now := testCodingReleasePGFixture(t, lifecycle.OperationSucceeded)
	for key, b := range f.slots.Retirements {
		b.DispatchAcknowledged = true
		f.slots.Retirements[key] = b
	}
	marker := codingIdentityMarker{Initialized: true, PlanDigest: f.slots.PlanDigest}
	if err := checkCodingRetirementBarrierWithMarker(marker, f.slots, f.ledger, f.ledger, now); err == nil {
		t.Fatal("legacy marker accepted v3 ACK bit")
	}
}
