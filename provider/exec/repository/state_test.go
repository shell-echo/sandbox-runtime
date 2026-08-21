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

func attachmentFor(request providerexec.Request, reference providerexec.ExecutionReference) providerexec.ExecutionAttachment {
	return providerexec.ExecutionAttachment{
		OperationID: request.OperationID, AttemptID: request.AttemptID, SandboxID: request.SandboxID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{ExecutionReference: reference, AcceptedAt: stateTestTime.Add(2 * time.Second)},
	}
}

func TestStateReservesBeforeAttachAndBindsIdentityIdempotently(t *testing.T) {
	state := NewState()
	request, _ := validExecution()
	attachment := attachmentFor(request, "ref:exec/receipt-attached")
	if _, err := state.AttachExecution(attachment); !errors.Is(err, ErrNotFound) {
		t.Fatalf("attach before reserve = %v, want ErrNotFound", err)
	}
	reserved, err := state.ReserveExecutionAt(request, stateTestTime)
	if err != nil || reserved.Replayed || reserved.Execution.Attached || !reserved.Execution.ReservedAt.Equal(stateTestTime) {
		t.Fatalf("durable reservation = %#v, %v", reserved, err)
	}
	if err := state.StoreResult(resultFor(request, providerexec.ResultCompleted)); !errors.Is(err, ErrConflict) {
		t.Fatalf("result before attach = %v, want ErrConflict", err)
	}
	attached, err := state.AttachExecution(attachment)
	if err != nil || attached.Replayed || !attached.Execution.Attached || attached.Execution.Dispatch.ExecutionReference != attachment.Dispatch.ExecutionReference {
		t.Fatalf("first attach = %#v, %v", attached, err)
	}
	replayAttachment := attachment
	replayAttachment.Dispatch.AcceptedAt = attachment.Dispatch.AcceptedAt.Add(time.Minute)
	replay, err := state.AttachExecution(replayAttachment)
	if err != nil || !replay.Replayed || replay.Execution.Dispatch.ExecutionReference != attachment.Dispatch.ExecutionReference {
		t.Fatalf("same receipt replay = %#v, %v", replay, err)
	}
	differentReceipt := attachmentFor(request, "ref:exec/other-receipt")
	if _, err := state.AttachExecution(differentReceipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("different receipt = %v, want ErrConflict", err)
	}
	differentIdentity := attachment
	differentIdentity.ExpectedGeneration++
	if _, err := state.AttachExecution(differentIdentity); !errors.Is(err, ErrConflict) {
		t.Fatalf("different identity = %v, want ErrConflict", err)
	}
}

func TestStateRejectsReceiptReuseAcrossReservationsAndPreservesDeepCopy(t *testing.T) {
	state := NewState()
	request, _ := validExecution()
	if _, err := state.ReserveExecutionAt(request, stateTestTime); err != nil {
		t.Fatal(err)
	}
	first := attachmentFor(request, "ref:exec/shared-receipt")
	if _, err := state.AttachExecution(first); err != nil {
		t.Fatal(err)
	}
	second := request.Clone()
	second.OperationID = "operation-2"
	second.AttemptID = "attempt-2"
	second.IdempotencyKey = "exec-key-2"
	if _, err := state.ReserveExecutionAt(second, stateTestTime); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AttachExecution(providerexec.ExecutionAttachment{
		OperationID: second.OperationID, AttemptID: second.AttemptID, SandboxID: second.SandboxID,
		FencingToken: second.FencingToken, ExpectedGeneration: second.ExpectedGeneration,
		Dispatch: first.Dispatch,
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("receipt reuse = %v, want ErrConflict", err)
	}
	third := second.Clone()
	third.OperationID = "operation-3"
	third.AttemptID = "attempt-3"
	third.IdempotencyKey = "exec-key-3"
	if _, err := state.ReserveExecution(third, first.Dispatch); !errors.Is(err, ErrConflict) {
		t.Fatalf("combined reserve receipt reuse = %v, want ErrConflict", err)
	}
	got, err := state.GetExecution(request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	got.Request.Command[0] = "mutated"
	gotAgain, err := state.GetExecution(request.OperationID)
	if err != nil || gotAgain.Request.Command[0] != "printf" {
		t.Fatalf("deep copy after attach = %#v, %v", gotAgain, err)
	}
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
	queried, err := state.GetCancellation(intent.OperationID)
	if err != nil || queried != intent {
		t.Fatalf("cancellation query = %#v, %v", queried, err)
	}
	if _, err := state.GetCancellation("missing-cancel"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing cancellation query = %v", err)
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
