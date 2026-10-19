package providerpostgres

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

func execFenceFixture(t *testing.T) (readyFixture, codingExecIntentState, codingExecFenceState, providerexec.Request) {
	t.Helper()
	f, intents, request := execIntentFixture(t)
	f.marker.ExecFenceMode = codingExecFenceMode
	if _, err := reserveIntentFixture(f, &intents, request); err != nil {
		t.Fatal(err)
	}
	return f, intents, codingExecFenceState{Version: 1, Mode: codingExecFenceMode, PlanDigest: f.marker.PlanDigest, Records: []codingExecFenceRecord{}}, request
}

func reserveFenceFixture(f *readyFixture, intents codingExecIntentState, fences *codingExecFenceState, request providerexec.Request) (codingcontrol.ExecFenceReceipt, error) {
	return reserveCodingExecFence(f.marker, f.slots, &f.ledger, intents, fences, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, request, f.now)
}

func TestCodingExecFenceOnlyChangesTwoFieldsAndRetainsHistoricalReceipt(t *testing.T) {
	f, intents, fences, request := execFenceFixture(t)
	before := copyCodingBarrierLedger(t, f.ledger)
	slots, intentBytes := f.slots.Clone(), isolationStored(t, intents)
	receipt, err := reserveFenceFixture(&f, intents, &fences, request)
	if err != nil || receipt.Replayed || receipt.FencingToken != uint64(request.FencingToken) || receipt.ReservationDigest == "" || !receipt.RecordedAt.Equal(f.now) {
		t.Fatalf("reserve: %#v %v", receipt, err)
	}
	expected := copyCodingBarrierLedger(t, before)
	lease := expected.Leases[request.SandboxID]
	lease.FencingToken = uint64(request.FencingToken)
	expected.Leases[request.SandboxID] = lease
	expected.Fencing[f.create.ProviderRevisionID+"\x00"+request.SandboxID] = uint64(request.FencingToken)
	if !reflect.DeepEqual(expected.Export(), f.ledger.Export()) || !reflect.DeepEqual(slots, f.slots) || string(intentBytes) != string(isolationStored(t, intents)) {
		t.Fatal("reservation changed more than two fence fields")
	}
	if err := f.guard(before, f.ledger); err == nil {
		t.Fatal("generic readiness barrier now permits bare fence changes")
	}
	// The lower fence is rejected by the real typed lease path; equal and
	// higher future mutations still work because this is no physical exec hold.
	low := nextLeaseAdmission(t, f, "lease-below-fence", f.create.Fence)
	if _, err := low.reserve(t.Context()); err == nil {
		t.Fatal("reservation did not fence out stale lease")
	}
	f.now = f.now.Add(time.Second)
	high := nextLeaseAdmission(t, f, "lease-above-fence", uint64(request.FencingToken)+1)
	if _, err := high.reserve(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.ledger = high.ledger
	raw, _ := json.Marshal(fences)
	var reopened codingExecFenceState
	if err := importCodingExecFences(&reopened, raw); err != nil {
		t.Fatal(err)
	}
	before = copyCodingBarrierLedger(t, f.ledger)
	replay, err := reserveFenceFixture(&f, intents, &reopened, request)
	receipt.Replayed = true
	if err != nil || replay != receipt || !reflect.DeepEqual(before.Export(), f.ledger.Export()) || !reflect.DeepEqual(reopened, fences) {
		t.Fatalf("historical replay: %#v %v", replay, err)
	}
	// History remains valid past the request's deadline. Admission does not.
	f.now = request.Deadline.Add(time.Second)
	if err := fences.validate(f.marker, f.slots, f.ledger, intents, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, f.now); err != nil {
		t.Fatal(err)
	}
	if got, err := reserveFenceFixture(&f, intents, &fences, request); err == nil || got != (codingcontrol.ExecFenceReceipt{}) {
		t.Fatal("expired POST refreshed history")
	}
}

func TestCodingExecFenceRejectsStaleTupleAndIncompleteBindingWithoutMutation(t *testing.T) {
	for _, change := range []string{"missing intent", "argv", "deadline", "attempt", "capture", "fence", "generation", "operation", "key", "workdir", "retention", "environment", "lease advanced", "fence advanced", "terminated", "expired request", "expired lease", "missing completion", "retiring", "creating", "disabled mode", "different allocation", "future intent"} {
		t.Run(change, func(t *testing.T) {
			f, intents, fences, request := execFenceFixture(t)
			switch change {
			case "missing intent":
				intents.Records = []codingExecIntentRecord{}
			case "argv":
				request.Command[1] = "different"
			case "deadline":
				request.Deadline = request.Deadline.Add(time.Second)
			case "attempt":
				request.AttemptID += "-different"
			case "capture":
				request.CaptureStdout = true
			case "fence":
				request.FencingToken++
			case "generation":
				request.ExpectedGeneration++
			case "operation":
				request.OperationID += "-different"
			case "key":
				request.IdempotencyKey += "-different"
			case "workdir":
				request.WorkingDirectory = "/tmp"
			case "retention":
				request.ResultRetention += time.Second
			case "environment":
				request.Environment = map[string]string{"K": "envref:value"}
			case "lease advanced":
				lease := nextLeaseAdmission(t, f, "lease-before-fence", f.create.Fence+1)
				if _, err := lease.reserve(t.Context()); err != nil {
					t.Fatal(err)
				}
				f.ledger = lease.ledger
			case "fence advanced":
				lease := f.ledger.Leases[request.SandboxID]
				lease.FencingToken++
				f.ledger.Leases[request.SandboxID] = lease
				f.ledger.Fencing[f.create.ProviderRevisionID+"\x00"+request.SandboxID]++
			case "terminated":
				admitReadyTermination(t, &f)
			case "expired request":
				f.now = request.Deadline
			case "expired lease":
				f.now = f.ledger.Leases[request.SandboxID].ExpiresAt
			case "missing completion":
				delete(f.slots.CreateCompletions, f.create.AllocationID)
			case "retiring":
				f.slots.Retirements = map[string]codingidentity.RetirementBinding{f.create.SlotID: {}}
			case "creating":
				f.slots.Reservations[0].Status = codingidentity.Creating
			case "disabled mode":
				f.marker.ExecFenceMode = ""
			case "different allocation":
				intents.Records[0].AllocationID = "other-allocation"
			case "future intent":
				intents.Records[0].Snapshot.ObservedAt = f.now.Add(time.Second)
			}
			ledger, oldFences := f.ledger.Export(), isolationStored(t, fences)
			if got, err := reserveFenceFixture(&f, intents, &fences, request); err == nil || got != (codingcontrol.ExecFenceReceipt{}) {
				t.Fatalf("unsafe %s: %#v %v", change, got, err)
			}
			if !reflect.DeepEqual(ledger, f.ledger.Export()) || string(oldFences) != string(isolationStored(t, fences)) {
				t.Fatal("failure changed state")
			}
		})
	}
}

func TestCodingExecFenceIsolationRejectsHistoryCorruptionAndRollback(t *testing.T) {
	for _, change := range []string{"missing", "null", "noncanonical", "orphan", "plan", "payload", "allocation", "original", "completion", "snapshot", "future", "duplicate", "unknown intent", "scope floor", "lease floor"} {
		t.Run(change, func(t *testing.T) {
			f, intents, fences, request := execFenceFixture(t)
			if _, err := reserveFenceFixture(&f, intents, &fences, request); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "orphan":
				f.marker.ExecFenceMode = ""
			case "plan":
				fences.PlanDigest = codingTestDigest("0")
			case "payload":
				fences.Records[0].PayloadDigest = codingTestDigest("0")
			case "allocation":
				fences.Records[0].AllocationID = "other-allocation"
			case "original":
				fences.Records[0].OriginalDigest = codingTestDigest("0")
			case "completion":
				fences.Records[0].Completion.ControlRevision++
			case "snapshot":
				fences.Records[0].Snapshot.Lease.FencingToken++
			case "future":
				fences.Records[0].Snapshot.ObservedAt = f.now.Add(time.Second)
			case "duplicate":
				fences.Records = append(fences.Records, fences.Records[0])
			case "unknown intent":
				fences.Records[0].OperationID = "unknown-intent"
			case "scope floor":
				f.ledger.Fencing[f.create.ProviderRevisionID+"\x00"+request.SandboxID] = f.create.Fence
			case "lease floor":
				lease := f.ledger.Leases[request.SandboxID]
				lease.FencingToken = f.create.Fence
				f.ledger.Leases[request.SandboxID] = lease
			}
			raw := isolationStored(t, fences)
			switch change {
			case "missing":
				raw = nil
			case "null":
				raw = []byte("null")
			case "noncanonical":
				encoded, _ := json.Marshal(fences)
				raw, _ = json.Marshal(append(encoded, ' '))
			}
			if _, err := decodeCodingExecIsolation(isolationStored(t, f.marker), isolationStored(t, intents), nil, isolationStored(t, f.ledger.Export()), isolationStored(t, f.slots), raw, f.now); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("corrupt history %s: %v", change, err)
			}
		})
	}
	f, intents, fences, request := execFenceFixture(t)
	if _, err := reserveFenceFixture(&f, intents, &fences, request); err != nil {
		t.Fatal(err)
	}
	g, err := decodeCodingExecIsolation(isolationStored(t, f.marker), isolationStored(t, intents), nil, isolationStored(t, f.ledger.Export()), isolationStored(t, f.slots), isolationStored(t, fences), f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.checkWrites(map[string][]byte{codingExecFenceDocument: isolationStored(t, fences)}); err == nil {
		t.Fatal("generic writer can rewrite fence history")
	}
	lease := f.ledger.Leases[request.SandboxID]
	lease.FencingToken = f.create.Fence
	f.ledger.Leases[request.SandboxID] = lease
	f.ledger.Fencing[f.create.ProviderRevisionID+"\x00"+request.SandboxID] = f.create.Fence
	if err := g.checkWrites(map[string][]byte{lifecycleDocument: isolationStored(t, f.ledger.Export())}); err == nil {
		t.Fatal("generic writer can roll back reserved fence")
	}
}

func TestCodingExecFenceBootstrapCannotUpgradeUsedStateOrMarker(t *testing.T) {
	f, intents, _, _ := execFenceFixture(t)
	f.marker.ExecFenceMode = ""
	g := &codingExecIsolation{marker: f.marker, slots: f.slots, ledger: f.ledger, intents: intents}
	if _, _, err := initializeCodingExecFenceState(g, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, f.now); err == nil {
		t.Fatal("populated intent state upgraded")
	}
	for _, marker := range []codingIdentityMarker{{ExecFenceMode: codingExecFenceMode}, {Initialized: true, PlanDigest: f.marker.PlanDigest, ExecFenceMode: codingExecFenceMode}, {Initialized: true, PlanDigest: f.marker.PlanDigest, AuthorityMode: codingAtomicOriginalMode, ControlPolicyDigest: f.create.ControlPolicyDigest, ExecIntentMode: codingExecIntentMode, ExecFenceMode: "future"}} {
		if marker.validate() == nil {
			t.Fatal("unsupported marker admitted")
		}
	}
}
