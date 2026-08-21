package application

import (
	"context"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/fake"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/memory"
)

func TestApplicationAcceptsAndRecoversCreate(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	repo := memory.NewRepository()
	app, err := New(repo, fake.New(), coordinator.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	request := lifecycle.CreateRequest{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
		IdempotencyKey: "key-1", RequestDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline: now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
			ProviderRevisionID: "revision-1", RuntimeProfile: "profile-1", SandboxSlotKey: "primary", LeaseExpiresAt: now.Add(time.Hour),
		},
	}
	accepted, err := app.AcceptCreate(context.Background(), request)
	if err != nil || accepted.Operation.State != lifecycle.OperationAccepted {
		t.Fatalf("AcceptCreate() = %#v, %v", accepted, err)
	}
	if err := app.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	operation, err := app.GetOperation(context.Background(), request.OperationID)
	if err != nil || operation.State != lifecycle.OperationSucceeded {
		t.Fatalf("GetOperation() = %#v, %v", operation, err)
	}
}
