package providerpostgres

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

func readRuntimeFixture(f readyFixture) (codingcontrol.RuntimeSnapshot, error) {
	return readCodingRuntimeSnapshot(f.marker, f.slots, f.ledger, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, f.create.SandboxID, f.now)
}

func TestCodingRuntimeSnapshotNeedsCurrentCompletionNotHistoricalPermit(t *testing.T) {
	f := newReadyFixture(t)
	if _, err := readRuntimeFixture(f); err == nil {
		t.Fatal("Creating read became runtime eligibility")
	}
	// Historical create uncertainty remains distinct from independently proven
	// current runtime readiness. Neither that old operation nor its old expiry
	// is turned into another physical permit by this read.
	op := f.ledger.Operations[f.create.OperationID]
	var err error
	op, err = lifecycle.MarkOutcomeUnknown(op, f.now, lifecycle.Failure{Code: "lost_reply", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil || f.ledger.UpdateOperation(op) != nil {
		t.Fatal(err)
	}
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.now = f.create.ExpiresAt.Add(time.Second)
	before, slots := f.ledger.Export(), f.slots.Clone()
	snapshot, err := readRuntimeFixture(f)
	if err != nil || snapshot.Sandbox != f.ledger.Sandboxes[f.create.SandboxID] || snapshot.Lease != f.ledger.Leases[f.create.SandboxID] ||
		snapshot.ProfileDigest != f.plan.ProfileDigest || snapshot.ControlPolicyDigest != f.create.ControlPolicyDigest || snapshot.ProviderPrincipalDigest != f.plan.OwnerPrincipalDigest || !snapshot.ObservedAt.Equal(f.now) {
		t.Fatalf("current snapshot: %#v %v", snapshot, err)
	}
	if !reflect.DeepEqual(before, f.ledger.Export()) || !reflect.DeepEqual(slots, f.slots) || f.ledger.Operations[op.ID].State != lifecycle.OperationOutcomeUnknown {
		t.Fatal("read mutated historical operation, lifecycle or allocation")
	}
}

func TestCodingRuntimeSnapshotRejectsDriftAndRetiredAllocation(t *testing.T) {
	for _, name := range []string{"marker", "legacy mode", "missing lease", "lease generation", "lease fence", "lease expiry", "expired", "future sandbox", "missing original", "completion authority", "completion allocation", "future completion", "no completion", "no live allocation", "creating", "retirement", "different tenant", "observed generation", "generation overflow", "zero clock"} {
		t.Run(name, func(t *testing.T) {
			f := newReadyFixture(t)
			if _, _, err := f.complete(t.Context()); err != nil {
				t.Fatal(err)
			}
			sb, lease := f.ledger.Sandboxes[f.create.SandboxID], f.ledger.Leases[f.create.SandboxID]
			switch name {
			case "marker":
				f.marker.ControlPolicyDigest = codingTestDigest("0")
			case "legacy mode":
				f.marker.AuthorityMode = ""
			case "lease generation":
				lease.Generation++
			case "lease fence":
				lease.FencingToken++
			case "lease expiry":
				lease.ExpiresAt = lease.ExpiresAt.Add(time.Second)
			case "expired":
				f.now = lease.ExpiresAt
			case "future sandbox":
				sb.UpdatedAt = f.now.Add(time.Second)
			case "missing original":
				delete(f.slots.OriginalCreates, f.create.AllocationID)
			case "completion authority", "completion allocation", "future completion":
				b := f.slots.CreateCompletions[f.create.AllocationID]
				if name == "completion authority" {
					b.AuthorityDigest = codingTestDigest("0")
				} else if name == "completion allocation" {
					b.AllocationID = "other-allocation"
				} else {
					b.UpdatedAt = f.now.Add(time.Second)
				}
				f.slots.CreateCompletions[f.create.AllocationID] = b
			case "no completion":
				delete(f.slots.CreateCompletions, f.create.AllocationID)
			case "no live allocation":
				f.slots.Reservations = []codingidentity.Reservation{}
			case "creating":
				f.slots.Reservations[0].Status = codingidentity.Creating
			case "retirement":
				f.slots.Retirements = map[string]codingidentity.RetirementBinding{f.create.SlotID: {}}
			case "different tenant":
				sb.TenantID = "other-tenant"
			case "observed generation":
				sb.ObservedGeneration = 0
			case "generation overflow":
				sb.Generation, sb.ObservedGeneration, lease.Generation = math.MaxUint64, math.MaxUint64, math.MaxUint64
			case "zero clock":
				f.now = time.Time{}
			}
			f.ledger.Sandboxes[sb.ID], f.ledger.Leases[sb.ID] = sb, lease
			if name == "missing lease" {
				delete(f.ledger.Leases, sb.ID)
			}
			before, slots := f.ledger.Export(), f.slots.Clone()
			if snapshot, err := readRuntimeFixture(f); err == nil || snapshot != (codingcontrol.RuntimeSnapshot{}) {
				t.Fatalf("unsafe runtime state exposed: %#v %v", snapshot, err)
			}
			if !reflect.DeepEqual(before, f.ledger.Export()) || !reflect.DeepEqual(slots, f.slots) {
				t.Fatal("rejected read mutated state")
			}
		})
	}
}

func TestCodingRuntimeSnapshotClosesOnTerminateAdmissionBeforeCleanup(t *testing.T) {
	f := newReadyFixture(t)
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	sb := f.ledger.Sandboxes[f.create.SandboxID]
	r := lifecycle.TerminateRequest{MutationRequest: lifecycle.MutationRequest{OperationID: "preflight-terminate", AttemptID: "preflight-terminate-attempt", IdempotencyKey: "preflight-terminate-key", RequestDigest: codingTestDigest("3"), ExpectedGeneration: sb.Generation, FencingToken: f.create.Fence, Deadline: f.now.Add(time.Minute)}, Reason: "close runtime eligibility before cleanup"}
	updated, op, err := lifecycle.StartTerminate(sb, r, f.now)
	if err != nil {
		t.Fatal(err)
	}
	event := lifecycle.Event{ID: codingAdmissionEventID(op.ID, "termination-requested"), SandboxID: sb.ID, OperationID: op.ID, Generation: updated.Generation, FencingToken: op.FencingToken, Kind: "termination-requested", DataDigest: r.RequestDigest, OccurredAt: f.now}
	if _, err := f.ledger.ReserveMutation(r.IdempotencyKey, r.RequestDigest, r.ExpectedGeneration, updated, op, event); err != nil {
		t.Fatal(err)
	}
	if f.slots.Reservations[0].Status != codingidentity.Active || f.ledger.Sandboxes[sb.ID].ObservedState != lifecycle.ObservedReady || len(f.slots.Retirements) != 0 {
		t.Fatal("fixture must be accepted termination before cleanup")
	}
	if _, err := readRuntimeFixture(f); err == nil {
		t.Fatal("termination admission left preflight eligible")
	}
}

func TestCodingRuntimeSnapshotRejectsReadyWithUnfinishedCreate(t *testing.T) {
	f := newReadyFixture(t)
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Coherent per-operation/idempotency data, but a cross-document state no
	// legal Completed-to-Ready transaction can produce. Existing generic
	// guards alone do not establish that this immutable completion was atomic.
	op := f.ledger.Operations[f.create.OperationID]
	op.State = lifecycle.OperationRunning
	f.ledger.Operations[op.ID] = op
	record, ok := f.ledger.IdempotencyForOperation(op.ID)
	if !ok || op.Validate() != nil {
		t.Fatal("invalid corruption fixture")
	}
	record.Operation = op
	f.ledger.Idempotency[record.Scope] = record
	if err := f.guard(f.ledger, f.ledger); err != nil {
		t.Fatalf("fixture must isolate the missing current-read check: %v", err)
	}
	if _, err := readRuntimeFixture(f); err == nil {
		t.Fatal("Ready plus unfinished original operation became eligible")
	}
}
