package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
)

var fileTestTime = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func fileExecution() (providerexec.Request, providerexec.Dispatch) {
	request := providerexec.Request{
		SandboxID: "sandbox-file", OperationID: "operation-file", AttemptID: "attempt-file", FencingToken: 1, ExpectedGeneration: 1,
		IdempotencyKey: "file-key", RequestDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline: time.Now().UTC().Add(time.Hour), Command: []string{"true"}, WorkingDirectory: "/workspace", ResultRetention: time.Hour,
	}
	return request, providerexec.Dispatch{ExecutionReference: "ref:file/1", AcceptedAt: fileTestTime}
}

func TestRepositoryPersistsResultCancellationAndTombstoneAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "exec.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	request, dispatch := fileExecution()
	if _, err := r.ReserveExecution(context.Background(), request, dispatch); err != nil {
		t.Fatal(err)
	}
	intent := providerexec.CancellationIntent{
		SandboxID: request.SandboxID, OperationID: "cancel-file", AttemptID: "cancel-attempt", FencingToken: 2, ExpectedGeneration: 1,
		IdempotencyKey: "cancel-file-key", RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		Deadline: time.Now().UTC().Add(time.Hour), TargetOperationID: request.OperationID, TargetAttemptID: request.AttemptID, Reason: providerexec.CancellationShutdown,
	}
	if _, err := r.ReserveCancellation(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	queriedIntent, err := r.GetCancellation(context.Background(), intent.OperationID)
	if err != nil || queriedIntent != intent {
		t.Fatalf("cancellation query = %#v, %v", queriedIntent, err)
	}
	result, err := providerexec.NewResult(request, fileTestTime, fileTestTime.Add(time.Second), providerexec.ResultOutcome{Status: providerexec.ResultCompleted})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.StoreResult(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	queriedIntent, err = r.GetCancellation(context.Background(), intent.OperationID)
	if err != nil || queriedIntent != intent {
		t.Fatalf("cancellation query after restart = %#v, %v", queriedIntent, err)
	}
	if _, err := r.GetResult(context.Background(), request.OperationID, result.RetainedUntil.Add(-time.Second)); err != nil {
		t.Fatalf("result after restart = %v", err)
	}
	if _, err := NewRepository(path); err == nil {
		t.Fatal("second controller opened repository")
	}
	if _, err := r.GetResult(context.Background(), request.OperationID, result.RetainedUntil); !errors.Is(err, repository.ErrExpired) {
		t.Fatalf("expiry = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.GetResult(context.Background(), request.OperationID, fileTestTime); !errors.Is(err, repository.ErrExpired) {
		t.Fatalf("tombstone after restart = %v", err)
	}
}

func TestRepositoryRejectsCorruptSnapshotAndCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exec.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(path); !errors.Is(err, repository.ErrCorrupt) {
		t.Fatalf("corrupt snapshot error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path = filepath.Join(t.TempDir(), "canceled.json")
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	request, dispatch := fileExecution()
	if _, err := r.ReserveExecution(ctx, request, dispatch); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reserve = %v", err)
	}
}

func TestRepositoryPersistsReservationBeforeAttachAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exec.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := fileExecution()
	reserved, err := r.ReserveExecution(context.Background(), request)
	if err != nil || reserved.Execution.Attached {
		t.Fatalf("reservation = %#v, %v", reserved, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetExecution(context.Background(), request.OperationID)
	if err != nil || got.Attached {
		t.Fatalf("unattached record after restart = %#v, %v", got, err)
	}
	attachment := providerexec.ExecutionAttachment{
		OperationID: request.OperationID, AttemptID: request.AttemptID, SandboxID: request.SandboxID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{ExecutionReference: "ref:file/attached", AcceptedAt: fileTestTime.Add(time.Second)},
	}
	if _, err := r.AttachExecution(context.Background(), attachment); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err = r.GetExecution(context.Background(), request.OperationID)
	if err != nil || !got.Attached || got.Dispatch.ExecutionReference != attachment.Dispatch.ExecutionReference {
		t.Fatalf("attached record after restart = %#v, %v", got, err)
	}
}

func TestRepositoryAttachHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exec.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	request, _ := fileExecution()
	if _, err := r.ReserveExecution(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attachment := providerexec.ExecutionAttachment{
		OperationID: request.OperationID, AttemptID: request.AttemptID, SandboxID: request.SandboxID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		Dispatch: providerexec.Dispatch{ExecutionReference: "ref:file/canceled", AcceptedAt: fileTestTime.Add(time.Second)},
	}
	if _, err := r.AttachExecution(ctx, attachment); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled attach = %v", err)
	}
}
