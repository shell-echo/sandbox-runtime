package codingcontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type staticClock struct{ now time.Time }

func (c staticClock) Now() time.Time { return c.now }

type testRepository struct {
	binding         Binding
	issued          dockercontrol.CodingCleanupAuthority
	begun, finished int
}

func (r *testRepository) ReadBeginBinding(context.Context, string) (Binding, error) {
	return r.binding, nil
}
func (r *testRepository) ReadFinishBinding(context.Context, string) (Binding, error) {
	return r.binding, nil
}
func (r *testRepository) BeginWithObservation(_ context.Context, _ string, o CompletedObservation) (dockercontrol.CodingCleanupAuthority, error) {
	if o.Validate(r.binding.Create) != nil {
		return dockercontrol.CodingCleanupAuthority{}, ErrObservation
	}
	r.begun++
	return r.issued, nil
}
func (r *testRepository) FinishWithObservation(_ context.Context, _ string, o ReleasedObservation) error {
	if r.binding.Cleanup == nil || o.Validate(r.binding.Create, *r.binding.Cleanup,
		r.binding.Cleanup.ExpiresAt.Add(time.Minute), r.binding.ControlRevision, r.binding.ControlStateDigest) != nil {
		return ErrObservation
	}
	r.finished++
	return nil
}

type testObserver struct {
	response codingcontrolprotocol.Response
	calls    int
	cancel   bool
}

func (o *testObserver) Observe(ctx context.Context, _ codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	o.calls++
	if o.cancel {
		<-ctx.Done()
		return codingcontrolprotocol.Response{}, ctx.Err()
	}
	return o.response, nil
}
func testDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func testAuthorities(t *testing.T) (dockercontrol.CodingCreateAuthority, dockercontrol.CodingCleanupAuthority, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: testDigest("a"), OwnerDeployment: "provider-runtime", OwnerPrincipalDigest: testDigest("b"),
		Namespace: "provider-coding", ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: testDigest("c"), ImageDigest: testDigest("d"), ImageConfigDigest: testDigest("e"), NetworkMode: "none",
		Limits: codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64}, Capacity: codingidentity.LocalCandidateCapacity,
		Slots: []codingidentity.Slot{{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
			InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace", OutputsVolume: "coding-0001-outputs"}}}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	request := lifecycle.CreateRequest{OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 7,
		IdempotencyKey: "key-1", RequestDigest: testDigest("f"), Deadline: now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1",
			WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1", RuntimeProfile: "sandbox-runtime-coding-shell-v1",
			Network: lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}, SandboxSlotKey: "coding/slot-1",
			LeaseExpiresAt: now.Add(time.Hour)}}
	sandbox, operation, err := lifecycle.StartCreate(request, now)
	if err != nil {
		t.Fatal(err)
	}
	operation.State = lifecycle.OperationRunning
	allocation, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID, sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	ticket := codingidentity.Reservation{PlanDigest: planDigest, Slot: plan.Slots[0], SpecDigest: testDigest("0"),
		Claim: codingidentity.Claim{TenantDigest: tenant, SandboxID: sandbox.ID, AllocationID: allocation,
			OperationID: operation.ID, AttemptID: operation.AttemptID, RequestDigest: request.RequestDigest,
			Generation: sandbox.Generation, Fence: operation.FencingToken}, Status: codingidentity.Creating}
	create, err := dockercontrol.NewCodingCreateAuthority(t.Context(), ticket, operation, sandbox, plan,
		testDigest("1"), plan.OwnerPrincipalDigest, now)
	if err != nil {
		t.Fatal(err)
	}
	ticket.Status = codingidentity.Cleaning
	sandbox.DesiredState = lifecycle.DesiredTerminated
	sandbox.Generation++
	sandbox.UpdatedAt = now.Add(time.Second)
	termination := lifecycle.Operation{ID: "termination-1", AttemptID: "termination-attempt-1", FencingToken: 8,
		SandboxID: sandbox.ID, Type: lifecycle.OperationTerminate, State: lifecycle.OperationRunning,
		Deadline: now.Add(time.Minute), ObservedAt: now.Add(time.Second), IdempotencyKey: "termination-key",
		RequestDigest: testDigest("2")}
	cleanup, err := dockercontrol.NewCodingCleanupAuthority(t.Context(), create, ticket, termination, sandbox,
		plan, testDigest("1"), plan.OwnerPrincipalDigest, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return create, cleanup, now
}

func testResponse(create dockercontrol.CodingCreateAuthority, cleanup dockercontrol.CodingCleanupAuthority,
	status string, now time.Time) codingcontrolprotocol.Response {
	r := codingcontrolprotocol.Response{Protocol: codingcontrolprotocol.ProtocolID, Scope: codingcontrolprotocol.ScopeCoding,
		Action: codingcontrolprotocol.ActionStatus, Status: status, CreateAuthorityDigest: create.Digest(), EffectID: create.EffectID,
		ControlRevision: 4, ControlStateDigest: testDigest("3"), CompletionDigest: testDigest("4"),
		CompletionEvidenceDigest: testDigest("5"), UpdatedAt: now.Add(time.Second)}
	if status == codingcontrolprotocol.StatusCleanupPending || status == codingcontrolprotocol.StatusReleased {
		r.CleanupAuthorityDigest = cleanup.Digest()
	}
	if status == codingcontrolprotocol.StatusReleased {
		r.AbsenceDigest = testDigest("6")
		r.AbsenceEvidenceDigest = testDigest("7")
	}
	return r
}

func TestCoordinatorKeepsCompletedAndReleasedSeparate(t *testing.T) {
	create, cleanup, now := testAuthorities(t)
	expected := Expected{ProfileDigest: create.ProfileDigest, ControlPolicyDigest: create.ControlPolicyDigest,
		ProviderPrincipalDigest: create.PeerPrincipalDigest}
	repo := &testRepository{binding: Binding{Create: create, TerminationID: cleanup.CleanupOperationID}, issued: cleanup}
	observer := &testObserver{response: testResponse(create, cleanup, codingcontrolprotocol.StatusCompleted, now)}
	coordinator, err := New(repo, observer, staticClock{now.Add(2 * time.Second)}, expected)
	permit, beginErr := coordinator.Begin(t.Context(), cleanup.CleanupOperationID)
	if err != nil || beginErr != nil || permit != cleanup || repo.begun != 1 {
		t.Fatalf("Completed observation: %v", err)
	}
	observer.response = testResponse(create, cleanup, codingcontrolprotocol.StatusCleanupPending, now)
	if _, err := coordinator.Begin(t.Context(), cleanup.CleanupOperationID); !errors.Is(err, ErrObservation) || repo.begun != 1 {
		t.Fatalf("pending cleanup became Completed: %v", err)
	}
	repo.binding.Cleanup = &cleanup
	repo.binding.ControlRevision = 3
	repo.binding.ControlStateDigest = testDigest("8")
	observer.response = testResponse(create, cleanup, codingcontrolprotocol.StatusReleased, now)
	if err := coordinator.Finish(t.Context(), cleanup.CleanupOperationID); err != nil || repo.finished != 1 {
		t.Fatalf("Released observation: %v", err)
	}
	observer.response = testResponse(create, cleanup, codingcontrolprotocol.StatusCleanupPending, now)
	if err := coordinator.Finish(t.Context(), cleanup.CleanupOperationID); !errors.Is(err, ErrObservation) || repo.finished != 1 {
		t.Fatalf("pending cleanup became Released: %v", err)
	}
	observer.response = testResponse(create, cleanup, codingcontrolprotocol.StatusReleased, now)
	observer.response.ControlRevision = repo.binding.ControlRevision
	if err := coordinator.Finish(t.Context(), cleanup.CleanupOperationID); !errors.Is(err, ErrObservation) {
		t.Fatalf("stale PG revision floor accepted: %v", err)
	}
}

func TestCoordinatorRejectsWrongProfileAndCancellationBeforeCommit(t *testing.T) {
	create, cleanup, now := testAuthorities(t)
	repo := &testRepository{binding: Binding{Create: create, TerminationID: cleanup.CleanupOperationID}}
	observer := &testObserver{response: testResponse(create, cleanup, codingcontrolprotocol.StatusCompleted, now)}
	wrong := Expected{ProfileDigest: testDigest("9"), ControlPolicyDigest: create.ControlPolicyDigest,
		ProviderPrincipalDigest: create.PeerPrincipalDigest}
	coordinator, err := New(repo, observer, staticClock{now.Add(2 * time.Second)}, wrong)
	_, beginErr := coordinator.Begin(t.Context(), cleanup.CleanupOperationID)
	if err != nil || !errors.Is(beginErr, ErrObservation) || observer.calls != 0 {
		t.Fatal("wrong frozen profile reached Control")
	}
	coordinator, err = New(repo, observer, staticClock{now.Add(2 * time.Second)}, Expected{
		ProfileDigest: create.ProfileDigest, ControlPolicyDigest: create.ControlPolicyDigest,
		ProviderPrincipalDigest: create.PeerPrincipalDigest})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := coordinator.Begin(ctx, cleanup.CleanupOperationID); err == nil || repo.begun != 0 {
		t.Fatal("canceled observation produced permit")
	}
}
