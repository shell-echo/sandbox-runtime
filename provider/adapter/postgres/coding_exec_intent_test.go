package providerpostgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

func execIntentFixture(t *testing.T) (readyFixture, codingExecIntentState, providerexec.Request) {
	t.Helper()
	f := newReadyFixture(t)
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.marker.ExecIntentMode = codingExecIntentMode
	state := codingExecIntentState{Version: 1, Mode: codingExecIntentMode, PlanDigest: f.slots.PlanDigest, Records: []codingExecIntentRecord{}}
	request := providerexec.Request{SandboxID: f.create.SandboxID, OperationID: "intent-1", AttemptID: "intent-attempt-1", IdempotencyKey: "intent-key-1", RequestDigest: codingTestDigest("3"),
		ExpectedGeneration: int64(f.create.CreationGeneration), FencingToken: int64(f.create.Fence) + 100, Deadline: f.now.Add(time.Minute), Command: []string{"/bin/echo", "bounded"}, WorkingDirectory: "/workspace", ResultRetention: time.Minute}
	return f, state, request
}

func reserveIntentFixture(f readyFixture, state *codingExecIntentState, request providerexec.Request) (codingcontrol.ExecIntentReceipt, error) {
	return reserveCodingExecIntent(f.marker, f.slots, f.ledger, state, f.plan, codingBoundSpecs(f.plan), f.create.ControlPolicyDigest, request, f.now)
}

func TestCodingExecIntentIsDurableFullRequestWithoutPermitOrFence(t *testing.T) {
	f, state, request := execIntentFixture(t)
	ledger, slots := f.ledger.Export(), f.slots.Clone()
	receipt, err := reserveIntentFixture(f, &state, request)
	if err != nil || receipt.Replayed || receipt.OperationID != request.OperationID || receipt.PayloadDigest == request.RequestDigest || !receipt.RecordedAt.Equal(f.now) {
		t.Fatalf("record: %#v %v", receipt, err)
	}
	// Caller ownership ends at admission. Changing argv cannot rewrite history.
	request.Command[1] = "mutated"
	if state.Records[0].Request.Command[1] != "bounded" {
		t.Fatal("request aliased retained bytes")
	}
	request.Command[1] = "bounded"
	raw, _ := json.Marshal(state)
	var reopened codingExecIntentState
	if err := importCodingExecIntents(&reopened, raw); err != nil {
		t.Fatal(err)
	}
	replay, err := reserveIntentFixture(f, &reopened, request)
	if err != nil || !replay.Replayed || replay.PayloadDigest != receipt.PayloadDigest || !replay.RecordedAt.Equal(receipt.RecordedAt) {
		t.Fatalf("replay: %#v %v", replay, err)
	}
	after, _ := json.Marshal(reopened)
	if !reflect.DeepEqual(ledger, f.ledger.Export()) || !reflect.DeepEqual(slots, f.slots) || string(raw) != string(after) {
		t.Fatal("no-permit admission changed lifecycle, slot, fence, or replay history")
	}
	// Termination using the lower current fence is still valid: the prospective
	// exec fence was never dispatch authority. Only old receipts can be replayed.
	admitReadyTermination(t, &f)
	if got, err := reserveIntentFixture(f, &state, request); err != nil || !got.Replayed {
		t.Fatalf("historical terminated replay: %#v %v", got, err)
	}
	request.OperationID, request.IdempotencyKey = "intent-new", "intent-new-key"
	if _, err := reserveIntentFixture(f, &state, request); err == nil {
		t.Fatal("new intent accepted after termination")
	}
}

func TestCodingExecIntentReplayRejectsEveryChangedPayloadField(t *testing.T) {
	for _, name := range []string{"argv", "workdir", "capture stdout", "capture stderr", "capture max", "deadline", "generation", "fence", "retention", "attempt", "sandbox", "digest", "key", "operation", "environment", "secret", "grant", "grant digest", "stdin"} {
		t.Run(name, func(t *testing.T) {
			f, state, request := execIntentFixture(t)
			if _, err := reserveIntentFixture(f, &state, request); err != nil {
				t.Fatal(err)
			}
			before, _ := json.Marshal(state)
			change := request.Clone()
			switch name {
			case "argv":
				change.Command[1] = "different"
			case "workdir":
				change.WorkingDirectory = "/tmp"
			case "capture stdout":
				change.CaptureStdout = true
			case "capture stderr":
				change.CaptureStderr = true
			case "capture max":
				change.CaptureMaxBytes = 1
			case "deadline":
				change.Deadline = change.Deadline.Add(time.Second)
			case "generation":
				change.ExpectedGeneration++
			case "fence":
				change.FencingToken++
			case "retention":
				change.ResultRetention += time.Second
			case "attempt":
				change.AttemptID += "-other"
			case "sandbox":
				change.SandboxID += "-other"
			case "digest":
				change.RequestDigest = codingTestDigest("4")
			case "key":
				change.IdempotencyKey += "-other"
			case "operation":
				change.OperationID += "-other"
			case "environment":
				change.Environment = map[string]string{"KEY": "envref:test"}
			case "secret":
				change.SecretReferenceIDs = []string{"ref:test"}
			case "grant":
				change.SecretGrantID = "grant:test"
			case "grant digest":
				change.SecretGrantDigest = codingTestDigest("5")
			case "stdin":
				change.StdinReference = "ref:test"
			}
			if got, err := reserveIntentFixture(f, &state, change); err == nil || got != (codingcontrol.ExecIntentReceipt{}) {
				t.Fatalf("changed full request replayed: %#v %v", got, err)
			}
			after, _ := json.Marshal(state)
			if string(before) != string(after) {
				t.Fatal("rejected replay changed ledger")
			}
		})
	}
}

func TestCodingExecIntentRejectsCorruptBindingsAndExpiredRequests(t *testing.T) {
	for _, name := range []string{"mode", "marker", "snapshot lease", "snapshot tenant", "snapshot profile", "snapshot peer", "snapshot network", "allocation", "completion", "payload", "expired", "old fence", "operation collision"} {
		t.Run(name, func(t *testing.T) {
			f, state, request := execIntentFixture(t)
			if _, err := reserveIntentFixture(f, &state, request); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "mode":
				state.Mode = "future"
			case "marker":
				f.marker.ExecIntentMode = ""
			case "snapshot lease":
				state.Records[0].Snapshot.Lease.Generation++
			case "snapshot tenant":
				state.Records[0].Snapshot.Sandbox.TenantID = "another-tenant"
			case "snapshot profile":
				state.Records[0].Snapshot.ProfileDigest = codingTestDigest("0")
			case "snapshot peer":
				state.Records[0].Snapshot.ProviderPrincipalDigest = codingTestDigest("0")
			case "snapshot network":
				state.Records[0].Snapshot.Sandbox.Network.Mode = "bridge"
			case "allocation":
				state.Records[0].AllocationID = "other"
			case "completion":
				state.Records[0].Completion.EvidenceDigest = codingTestDigest("0")
			case "payload":
				state.Records[0].PayloadDigest = codingTestDigest("0")
			case "expired":
				f.now = request.Deadline
			case "old fence":
				request.OperationID, request.IdempotencyKey = "new-op", "new-key"
				request.FencingToken = int64(f.create.Fence) - 1
			case "operation collision":
				request.OperationID, request.IdempotencyKey = f.create.OperationID, "new-key"
			}
			before, _ := json.Marshal(state)
			if _, err := reserveIntentFixture(f, &state, request); err == nil {
				t.Fatal("unsafe binding accepted")
			}
			after, _ := json.Marshal(state)
			if string(before) != string(after) {
				t.Fatal("rejection mutated intent state")
			}
		})
	}
}

func TestCodingExecIntentBoundedDocumentAndRequest(t *testing.T) {
	f, state, request := execIntentFixture(t)
	// Construct retained history directly so this test checks capacity once,
	// rather than repeatedly revalidating every prefix of the same history.
	if _, err := reserveIntentFixture(f, &state, request); err != nil {
		t.Fatal(err)
	}
	template := state.Records[0]
	state.Records = nil
	for i := range maxCodingExecIntents {
		record := template
		record.Request = template.Request.Clone()
		record.Request.OperationID = fmt.Sprintf("bounded-%d", i)
		record.Request.IdempotencyKey = record.Request.OperationID
		_, _, record.PayloadDigest, _ = codingExecRequest(record.Request, f.now)
		state.Records = append(state.Records, record)
	}
	before, _ := json.Marshal(state)
	if _, err := reserveIntentFixture(f, &state, request); !errors.Is(err, codingcontrol.ErrExecIntentCapacity) {
		t.Fatal(err)
	}
	after, _ := json.Marshal(state)
	if string(before) != string(after) {
		t.Fatal("capacity changed retained history")
	}
	request.Command = make([]string, 64)
	for i := range request.Command {
		request.Command[i] = strings.Repeat("界", 4096)
	}
	if request.Validate(f.now) != nil {
		t.Fatal("fixture must isolate encoded-byte limit")
	}
	if _, _, _, err := codingExecRequest(request, f.now); err == nil {
		t.Fatal("oversized canonical internal request accepted")
	}
	// A structurally valid canonical document cannot bypass byte/count limits,
	// unknown/duplicate-member checks or the explicit mode/version lock.
	for _, raw := range [][]byte{[]byte(`{"version":1,"version":1}`), []byte(`{"version":1,"authority":"permit"}`), append(before, ' '), []byte(strings.Repeat(" ", maxCodingExecIntentBytes+1))} {
		var got codingExecIntentState
		if importCodingExecIntents(&got, raw) == nil {
			t.Fatal("malformed ledger imported")
		}
	}
}

func TestCodingExecIntentInitializationDoesNotUpgradeExistingHistory(t *testing.T) {
	f, _, _ := execIntentFixture(t)
	slots, err := codingidentity.NewState(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	marker := f.marker
	marker.ExecIntentMode = ""
	for _, name := range []string{"empty", "accepted create before slot", "existing slot", "existing intents", "legacy exec", "legacy marker", "initialized mode"} {
		t.Run(name, func(t *testing.T) {
			current, identity, ledger := marker, slots, newLifecycleState()
			switch name {
			case "accepted create before slot":
				ledger = testCodingAcceptedCreate(t, f.now, "revision-1", "tenant-1", "sandbox-1", "pending-create")
			case "existing slot":
				identity = f.slots
			case "legacy marker":
				current.AuthorityMode, current.ControlPolicyDigest = "", ""
			case "initialized mode":
				current.ExecIntentMode = codingExecIntentMode
			}
			got, state, err := initializeCodingExecIntentState(current, identity, ledger, f.plan, f.create.ControlPolicyDigest, name == "existing intents", name == "legacy exec")
			if name == "empty" {
				if err != nil || got.ExecIntentMode != codingExecIntentMode || len(state.Records) != 0 {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("initialized over existing or legacy history")
			}
		})
	}
}

func TestCodingExecIntentAggregateByteLimitDoesNotDiscardHistory(t *testing.T) {
	f, state, request := execIntentFixture(t)
	request.Command = make([]string, 40)
	for i := range request.Command {
		request.Command[i] = strings.Repeat("x", 4096)
	}
	if _, err := reserveIntentFixture(f, &state, request); err != nil {
		t.Fatal(err)
	}
	template := state.Records[0]
	for i := 1; ; i++ {
		record := template
		record.Request = template.Request.Clone()
		record.Request.OperationID = fmt.Sprintf("large-%d", i)
		record.Request.IdempotencyKey = record.Request.OperationID
		_, _, record.PayloadDigest, _ = codingExecRequest(record.Request, f.now)
		next := state
		next.Records = append(append([]codingExecIntentRecord{}, state.Records...), record)
		raw, _ := json.Marshal(next)
		if len(raw) > maxCodingExecIntentBytes {
			request = record.Request
			break
		}
		state = next
	}
	before, _ := json.Marshal(state)
	if len(state.Records) >= maxCodingExecIntents {
		t.Fatal("fixture must isolate aggregate bytes")
	}
	if _, err := reserveIntentFixture(f, &state, request); !errors.Is(err, codingcontrol.ErrExecIntentCapacity) {
		t.Fatal(err)
	}
	after, _ := json.Marshal(state)
	if string(before) != string(after) {
		t.Fatal("byte capacity changed history")
	}
}

func TestCodingExecIntentMissingIsNotPresentJSONNull(t *testing.T) {
	if _, exists, err := decodeCodingExecDocument(nil); err != nil || exists {
		t.Fatal("absent key not recognized")
	}
	if _, _, err := decodeCodingExecDocument([]byte("null")); err == nil {
		t.Fatal("present null lost corruption evidence")
	}
}

func TestCodingExecIntentReplayRejectsUnfinishedOrLaterOriginalCompletion(t *testing.T) {
	for _, name := range []string{"running original", "completion after admission"} {
		t.Run(name, func(t *testing.T) {
			f, state, request := execIntentFixture(t)
			if _, err := reserveIntentFixture(f, &state, request); err != nil {
				t.Fatal(err)
			}
			op := f.ledger.Operations[f.create.OperationID]
			if name == "running original" {
				op.State = lifecycle.OperationRunning
			} else {
				op.ObservedAt = f.now.Add(time.Second)
				f.now = f.now.Add(2 * time.Second)
			}
			f.ledger.Operations[op.ID] = op
			retained, exists := f.ledger.IdempotencyForOperation(op.ID)
			if !exists || op.Validate() != nil {
				t.Fatal("invalid original-operation corruption fixture")
			}
			retained.Operation = op
			f.ledger.Idempotency[retained.Scope] = retained
			if err := f.guard(f.ledger, f.ledger); err != nil {
				t.Fatalf("fixture must isolate cross-document historical completion gap: %v", err)
			}
			before, _ := json.Marshal(state)
			if receipt, err := reserveIntentFixture(f, &state, request); err == nil || receipt != (codingcontrol.ExecIntentReceipt{}) {
				t.Fatalf("corrupt original completion replayed: %#v %v", receipt, err)
			}
			after, _ := json.Marshal(state)
			if string(before) != string(after) {
				t.Fatal("rejected history was modified")
			}
		})
	}
}

func TestCodingExecIntentPreservesLegitimateUnknownOriginal(t *testing.T) {
	f := newReadyFixture(t)
	op := f.ledger.Operations[f.create.OperationID]
	var err error
	op, err = lifecycle.MarkOutcomeUnknown(op, f.now, lifecycle.Failure{Code: "lost_reply", Retryable: true, Outcome: lifecycle.FailureUnknown})
	if err != nil || f.ledger.UpdateOperation(op) != nil {
		t.Fatal(err)
	}
	if _, _, err := f.complete(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.marker.ExecIntentMode = codingExecIntentMode
	state := codingExecIntentState{Version: 1, Mode: codingExecIntentMode, PlanDigest: f.slots.PlanDigest, Records: []codingExecIntentRecord{}}
	_, _, request := execIntentFixture(t)
	request.SandboxID = f.create.SandboxID
	if _, err := reserveIntentFixture(f, &state, request); err != nil {
		t.Fatal(err)
	}
	if receipt, err := reserveIntentFixture(f, &state, request); err != nil || !receipt.Replayed {
		t.Fatalf("legitimate Unknown original lost history: %#v %v", receipt, err)
	}
	if f.ledger.Operations[op.ID].State != lifecycle.OperationOutcomeUnknown {
		t.Fatal("exec history promoted original Unknown")
	}
}
