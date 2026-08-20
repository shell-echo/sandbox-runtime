package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

func TestRepositoryHonorsContextAndClose(t *testing.T) {
	r := NewRepository()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sandbox, operation := memoryRecords(t)
	if _, err := r.ReserveCreate(ctx, "key", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reserve = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetSandbox(context.Background(), sandbox.ID); !errors.Is(err, repository.ErrClosed) {
		t.Fatalf("closed get = %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func memoryRecords(t *testing.T) (lifecycle.Sandbox, lifecycle.Operation) {
	t.Helper()
	request := lifecycle.CreateRequest{
		OperationID:    "operation-memory-1",
		AttemptID:      "attempt-memory-1",
		FencingToken:   1,
		IdempotencyKey: "memory-key-1",
		RequestDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:       repositoryTestTime().Add(5 * time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID:          "sandbox-memory-1",
			TenantID:           "tenant-1",
			WorkOrderID:        "work-order-1",
			WorkspaceID:        "workspace-1",
			ProviderRevisionID: "provider-revision-1",
			RuntimeProfile:     "profile-1",
			SandboxSlotKey:     "primary-code",
			LeaseExpiresAt:     repositoryTestTime().Add(time.Hour),
		},
	}
	sandbox, operation, err := lifecycle.StartCreate(request, repositoryTestTime())
	if err != nil {
		t.Fatal(err)
	}
	return sandbox, operation
}

func repositoryTestTime() time.Time { return time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC) }
