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

func TestApplicationAcceptsAndDispatchesCreate(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	repo := memory.NewRepository()
	app, err := New(repo, fake.New(), coordinator.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
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
	waitOperationState(t, app, request.OperationID, lifecycle.OperationSucceeded)
}

func TestApplicationDispatchesLifecycleControlsAndReadsEvents(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	repo := memory.NewRepository()
	app, err := New(repo, fake.New(), coordinator.ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	create := lifecycle.CreateRequest{
		OperationID: "operation-create", AttemptID: "attempt-create", FencingToken: 1,
		IdempotencyKey: "key-create", RequestDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Deadline: now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-control", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
			ProviderRevisionID: "revision-1", RuntimeProfile: "profile-1", SandboxSlotKey: "primary", LeaseExpiresAt: now.Add(time.Hour),
		},
	}
	if _, err := app.AcceptCreate(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	waitOperationState(t, app, create.OperationID, lifecycle.OperationSucceeded)

	suspend := lifecycle.DesiredStateRequest{
		MutationRequest: lifecycle.MutationRequest{
			OperationID: "operation-suspend", AttemptID: "attempt-suspend", FencingToken: 2,
			IdempotencyKey: "key-suspend", RequestDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			Deadline: now.Add(time.Minute), ExpectedGeneration: 1,
		},
		DesiredState: lifecycle.DesiredSuspended,
	}
	if _, err := app.AcceptDesiredState(context.Background(), create.Spec.SandboxID, suspend); err != nil {
		t.Fatal(err)
	}
	waitOperationState(t, app, suspend.OperationID, lifecycle.OperationSucceeded)
	sandbox, err := app.GetSandbox(context.Background(), create.Spec.SandboxID)
	if err != nil || sandbox.ObservedState != lifecycle.ObservedSuspended || sandbox.Generation != 2 {
		t.Fatalf("suspended sandbox = %#v, %v", sandbox, err)
	}

	lease := lifecycle.LeaseRequest{
		MutationRequest: lifecycle.MutationRequest{
			OperationID: "operation-lease", AttemptID: "attempt-lease", FencingToken: 3,
			IdempotencyKey: "key-lease", RequestDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			Deadline: now.Add(time.Minute), ExpectedGeneration: 2,
		},
		ExtendSeconds: 60,
	}
	if _, err := app.AcceptLease(context.Background(), create.Spec.SandboxID, lease, 7200); err != nil {
		t.Fatal(err)
	}
	waitOperationState(t, app, lease.OperationID, lifecycle.OperationSucceeded)

	terminate := lifecycle.TerminateRequest{
		MutationRequest: lifecycle.MutationRequest{
			OperationID: "operation-terminate", AttemptID: "attempt-terminate", FencingToken: 4,
			IdempotencyKey: "key-terminate", RequestDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444",
			Deadline: now.Add(time.Minute), ExpectedGeneration: 2,
		},
		Reason: "complete",
	}
	if _, err := app.AcceptTerminate(context.Background(), create.Spec.SandboxID, terminate); err != nil {
		t.Fatal(err)
	}
	waitOperationState(t, app, terminate.OperationID, lifecycle.OperationSucceeded)
	page, err := app.ReadEvents(context.Background(), create.Spec.SandboxID, 0)
	if err != nil || len(page.Events) == 0 || page.NextSequence != page.LatestSequence {
		t.Fatalf("ReadEvents() = %#v, %v", page, err)
	}
}

func waitOperationState(t *testing.T, app *Application, operationID string, want lifecycle.OperationState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		operation, err := app.GetOperation(context.Background(), operationID)
		if err == nil && operation.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("GetOperation(%q) = %#v, %v; want state %q", operationID, operation, err, want)
		}
		time.Sleep(time.Millisecond)
	}
}
