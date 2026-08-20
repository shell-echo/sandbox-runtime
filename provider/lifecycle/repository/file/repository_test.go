package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func TestRepositoryPersistsAcrossRestartAndRejectsSecondController(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "lifecycle.json")
	r, err := NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	sandbox, operation := fileRecords(t)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := r.ReserveCreate(context.Background(), "file-key-1", digest, sandbox, operation); err != nil {
		t.Fatal(err)
	}
	event := lifecycle.Event{ID: "event-file-1", SandboxID: sandbox.ID, OperationID: operation.ID, Generation: 1, FencingToken: 1, Kind: "sandbox.requested", OccurredAt: fileTestTime}
	if got, err := r.AppendEvent(context.Background(), event); err != nil || got.Sequence != 1 {
		t.Fatalf("append event = %#v, %v", got, err)
	}
	if _, err := NewRepository(path); err == nil {
		t.Fatal("second controller opened the repository")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	r, err = NewRepository(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got, err := r.GetSandbox(context.Background(), sandbox.ID); err != nil || got.ID != sandbox.ID {
		t.Fatalf("reloaded sandbox = %#v, %v", got, err)
	}
	events, err := r.ListEvents(context.Background(), sandbox.ID, 0, 10)
	if err != nil || len(events) != 1 || events[0].Sequence != 1 {
		t.Fatalf("reloaded events = %#v, %v", events, err)
	}
}

func TestRepositoryRejectsCorruptSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lifecycle.json")
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
}

func TestRepositoryHonorsCanceledContext(t *testing.T) {
	r, err := NewRepository(filepath.Join(t.TempDir(), "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sandbox, operation := fileRecords(t)
	if _, err := r.ReserveCreate(ctx, "file-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reserve = %v", err)
	}
}

var fileTestTime = time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

func fileRecords(t *testing.T) (lifecycle.Sandbox, lifecycle.Operation) {
	t.Helper()
	request := lifecycle.CreateRequest{
		OperationID:    "operation-file-1",
		AttemptID:      "attempt-file-1",
		FencingToken:   1,
		IdempotencyKey: "file-key-1",
		RequestDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:       fileTestTime.Add(5 * time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID:          "sandbox-file-1",
			TenantID:           "tenant-1",
			WorkOrderID:        "work-order-1",
			WorkspaceID:        "workspace-1",
			ProviderRevisionID: "provider-revision-1",
			RuntimeProfile:     "profile-1",
			SandboxSlotKey:     "primary-code",
			LeaseExpiresAt:     fileTestTime.Add(time.Hour),
		},
	}
	sandbox, operation, err := lifecycle.StartCreate(request, fileTestTime)
	if err != nil {
		t.Fatal(err)
	}
	return sandbox, operation
}
