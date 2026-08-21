package repository

import (
	"errors"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

var stateTestTime = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func validExecution() (providerexec.Request, providerexec.Dispatch) {
	request := providerexec.Request{
		SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, ExpectedGeneration: 1,
		IdempotencyKey: "exec-key-1", RequestDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline: stateTestTime.Add(time.Minute), Command: []string{"printf", "hello"}, WorkingDirectory: "/workspace",
		ResultRetention: time.Hour,
	}
	return request, providerexec.Dispatch{ExecutionReference: "ref:exec/receipt-1", AcceptedAt: stateTestTime}
}

func validCancellation() providerexec.CancellationIntent {
	return providerexec.CancellationIntent{
		SandboxID: "sandbox-1", OperationID: "cancel-1", AttemptID: "cancel-attempt-1", FencingToken: 2, ExpectedGeneration: 1,
		IdempotencyKey: "cancel-key-1", RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Deadline: stateTestTime.Add(time.Minute), TargetOperationID: "operation-1", TargetAttemptID: "attempt-1", Reason: providerexec.CancellationCallerRequested,
	}
}

func resultFor(request providerexec.Request, status providerexec.ResultStatus) providerexec.Result {
	result, err := providerexec.NewResult(request, stateTestTime, stateTestTime.Add(time.Second), providerexec.ResultOutcome{Status: status})
	if err != nil {
		panic(err)
	}
	return result
}

func TestStateExecutionIdempotencyAndCancellationBinding(t *testing.T) {
	state := NewState()
	request, dispatch := validExecution()
	first, err := state.ReserveExecution(request, dispatch)
	if err != nil || first.Replayed {
		t.Fatalf("first reservation = %#v, %v", first, err)
	}
	replay, err := state.ReserveExecution(request, providerexec.Dispatch{ExecutionReference: "ref:other", AcceptedAt: stateTestTime.Add(time.Second)})
	if err != nil || !replay.Replayed || replay.Execution.Dispatch.ExecutionReference != dispatch.ExecutionReference {
		t.Fatalf("replay reservation = %#v, %v", replay, err)
	}
	substituted := request
	substituted.RequestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := state.ReserveExecution(substituted, dispatch); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest substitution error = %v", err)
	}
	intent := validCancellation()
	reserved, err := state.ReserveCancellation(intent, stateTestTime)
	if err != nil || reserved.Replayed {
		t.Fatalf("cancel reservation = %#v, %v", reserved, err)
	}
	cancelReplay, err := state.ReserveCancellation(intent, stateTestTime)
	if err != nil || !cancelReplay.Replayed {
		t.Fatalf("cancel replay = %#v, %v", cancelReplay, err)
	}
	if _, err := state.ReserveCancellation(func() providerexec.CancellationIntent {
		bad := intent
		bad.TargetAttemptID = "attempt-other"
		bad.OperationID = "cancel-2"
		bad.IdempotencyKey = "cancel-key-2"
		return bad
	}(), stateTestTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("target mismatch error = %v", err)
	}
	if _, err := state.ReserveCancellation(func() providerexec.CancellationIntent {
		bad := intent
		bad.ExpectedGeneration = 2
		bad.OperationID = "cancel-3"
		bad.IdempotencyKey = "cancel-key-3"
		return bad
	}(), stateTestTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("generation mismatch error = %v", err)
	}
}

func TestStateResultWriteIsBoundedIdempotentAndExpiresToTombstone(t *testing.T) {
	state := NewState()
	request, dispatch := validExecution()
	if _, err := state.ReserveExecution(request, dispatch); err != nil {
		t.Fatal(err)
	}
	if _, err, changed := state.ReadResult(request.OperationID, stateTestTime); !errors.Is(err, ErrPending) || changed {
		t.Fatalf("pending result = %v", err)
	}
	result := resultFor(request, providerexec.ResultCompleted)
	if err := state.StoreResult(result); err != nil {
		t.Fatal(err)
	}
	if err := state.StoreResult(result); err != nil {
		t.Fatalf("same result replay = %v", err)
	}
	changed := result
	changed.Status = providerexec.ResultFailed
	if err := state.StoreResult(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("result substitution error = %v", err)
	}
	if _, err, changedState := state.ReadResult(request.OperationID, result.RetainedUntil.Add(-time.Nanosecond)); err != nil || changedState {
		t.Fatalf("result before expiry = %v, changed=%t", err, changedState)
	}
	if _, err, changedState := state.ReadResult(request.OperationID, result.RetainedUntil); !errors.Is(err, ErrExpired) || !changedState {
		t.Fatalf("result expiry = %v, changed=%t", err, changedState)
	}
	if _, err, changedState := state.ReadResult(request.OperationID, result.RetainedUntil.Add(time.Second)); !errors.Is(err, ErrExpired) || changedState {
		t.Fatalf("tombstone read = %v, changed=%t", err, changedState)
	}
	if err := state.StoreResult(result); !errors.Is(err, ErrExpired) {
		t.Fatalf("write after expiry = %v", err)
	}
}

func TestStateImportRejectsBrokenReferences(t *testing.T) {
	state := NewState()
	request, dispatch := validExecution()
	if _, err := state.ReserveExecution(request, dispatch); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Export()
	snapshot.ExecutionIdempotency[request.IdempotencyKey] = IdempotencyRecord{Key: request.IdempotencyKey, RequestDigest: request.RequestDigest, OperationID: "missing"}
	broken := NewState()
	if err := broken.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("broken idempotency import = %v", err)
	}
	snapshot = state.Export()
	delete(snapshot.ExecutionIdempotency, request.IdempotencyKey)
	if err := broken.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing execution idempotency import = %v", err)
	}
	intent := validCancellation()
	if _, err := state.ReserveCancellation(intent, stateTestTime); err != nil {
		t.Fatal(err)
	}
	snapshot = state.Export()
	delete(snapshot.CancellationIdempotency, intent.IdempotencyKey)
	if err := broken.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing cancellation idempotency import = %v", err)
	}
}
