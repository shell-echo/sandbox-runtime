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
		Deadline: fileTestTime.Add(time.Minute), Command: []string{"true"}, WorkingDirectory: "/workspace", ResultRetention: time.Hour,
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
		Deadline: fileTestTime.Add(time.Minute), TargetOperationID: request.OperationID, TargetAttemptID: request.AttemptID, Reason: providerexec.CancellationShutdown,
	}
	if _, err := r.ReserveCancellation(context.Background(), intent); err != nil {
		t.Fatal(err)
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
