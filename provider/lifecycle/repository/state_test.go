package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

var repositoryTestTime = time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)

func validRecords(t *testing.T) (lifecycle.Sandbox, lifecycle.Operation) {
	t.Helper()
	request := lifecycle.CreateRequest{
		OperationID:    "operation-create-1",
		AttemptID:      "attempt-create-1",
		FencingToken:   1,
		IdempotencyKey: "create-key-1",
		RequestDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:       repositoryTestTime.Add(5 * time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID:          "sandbox-1",
			TenantID:           "tenant-1",
			WorkOrderID:        "work-order-1",
			WorkspaceID:        "workspace-1",
			ProviderRevisionID: "provider-revision-1",
			RuntimeProfile:     "profile-1",
			SandboxSlotKey:     "primary-code",
			LeaseExpiresAt:     repositoryTestTime.Add(time.Hour),
		},
	}
	sandbox, operation, err := lifecycle.StartCreate(request, repositoryTestTime)
	if err != nil {
		t.Fatal(err)
	}
	return sandbox, operation
}

func TestStateReserveCreateIsIdempotentAndFenced(t *testing.T) {
	state := NewState()
	sandbox, operation := validRecords(t)
	result, err := state.ReserveCreate("create-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation)
	if err != nil || result.Replayed || result.Operation.ID != operation.ID {
		t.Fatalf("first reservation = %#v, %v", result, err)
	}
	replay, err := state.ReserveCreate("create-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation)
	if err != nil || !replay.Replayed || replay.Operation.ID != operation.ID {
		t.Fatalf("replay reservation = %#v, %v", replay, err)
	}
	if _, err := state.ReserveCreate("create-key-1", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", sandbox, operation); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest substitution error = %v", err)
	}
	_, newer := validRecords(t)
	newer.ID = "operation-create-2"
	newer.AttemptID = "attempt-create-2"
	newer.FencingToken = 1
	if _, err := state.ReserveCreate("create-key-2", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", sandbox, newer); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate sandbox error = %v", err)
	}
}

func TestStateUpdatesRequireExpectedGenerationAndCurrentFencing(t *testing.T) {
	state := NewState()
	sandbox, operation := validRecords(t)
	if _, err := state.ReserveCreate("create-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation); err != nil {
		t.Fatal(err)
	}
	updated, err := lifecycle.RequestDesiredState(sandbox, lifecycle.DesiredSuspended, 1, repositoryTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateSandbox(updated, 1, 1); err != nil {
		t.Fatalf("generation bump update = %v", err)
	}
	if err := state.UpdateSandbox(updated, 1, 1); !errors.Is(err, lifecycle.ErrGenerationConflict) {
		t.Fatalf("stale expected generation = %v", err)
	}
	lease, err := state.GetLease(sandbox.ID)
	if err != nil || lease.Generation != 2 {
		t.Fatalf("generation-synchronized lease = %#v, %v", lease, err)
	}
	updated.UpdatedAt = repositoryTestTime.Add(2 * time.Second)
	if err := state.UpdateSandbox(updated, 2, 0); !errors.Is(err, lifecycle.ErrStaleFencingToken) {
		t.Fatalf("zero fencing update = %v", err)
	}
	operation, err = lifecycle.BeginOperation(operation, repositoryTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	operation.FencingToken = 2
	if err := state.UpdateOperation(operation); !errors.Is(err, lifecycle.ErrStaleFencingToken) {
		t.Fatalf("operation from old attempt after generation update = %v", err)
	}
}

func TestStateRejectsNetworkPolicyMutation(t *testing.T) {
	state := NewState()
	sandbox, operation := validRecords(t)
	sandbox.RuntimeProfile = lifecycle.BrowserRuntimeProfile
	sandbox.Network = lifecycle.NetworkPolicy{Mode: lifecycle.NetworkRestricted, PolicyReference: "browser-egress-policy-1", EgressGatewayRequired: true}
	if _, err := state.ReserveCreate("create-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation); err != nil {
		t.Fatal(err)
	}
	sandbox.Network.PolicyReference = "browser-egress-policy-2"
	if err := state.UpdateSandbox(sandbox, sandbox.Generation, operation.FencingToken); !errors.Is(err, ErrConflict) {
		t.Fatalf("network mutation error = %v", err)
	}
}

func TestStateEventsAreMonotonicAndReplaySafe(t *testing.T) {
	state := NewState()
	sandbox, operation := validRecords(t)
	if _, err := state.ReserveCreate("create-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation); err != nil {
		t.Fatal(err)
	}
	first := lifecycle.Event{ID: "event-1", SandboxID: sandbox.ID, OperationID: operation.ID, Generation: 1, FencingToken: 1, Kind: "sandbox.requested", OccurredAt: repositoryTestTime}
	second := first
	second.ID = "event-2"
	second.Kind = "sandbox.provisioning"
	second.OccurredAt = repositoryTestTime.Add(time.Second)
	gotFirst, err := state.AppendEvent(first)
	if err != nil || gotFirst.Sequence != 1 {
		t.Fatalf("first event = %#v, %v", gotFirst, err)
	}
	gotReplay, err := state.AppendEvent(first)
	if err != nil || gotReplay.Sequence != 1 {
		t.Fatalf("event replay = %#v, %v", gotReplay, err)
	}
	if _, err := state.AppendEvent(second); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AppendEvent(lifecycle.Event{ID: "event-2", SandboxID: sandbox.ID, OperationID: operation.ID, Generation: 1, FencingToken: 1, Kind: "different", OccurredAt: second.OccurredAt}); !errors.Is(err, ErrConflict) {
		t.Fatalf("event substitution error = %v", err)
	}
	events, err := state.ListEvents(sandbox.ID, 0, 10)
	if err != nil || len(events) != 2 || events[0].Sequence != 1 || events[1].Sequence != 2 {
		t.Fatalf("event list = %#v, %v", events, err)
	}
	if _, err := state.ListEvents(sandbox.ID, 2, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := state.ListEvents(sandbox.ID, 3, 10); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("invalid cursor = %v", err)
	}
}

func TestStateExportImportRejectsCorruption(t *testing.T) {
	state := NewState()
	sandbox, operation := validRecords(t)
	if _, err := state.ReserveCreate("create-key-1", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", sandbox, operation); err != nil {
		t.Fatal(err)
	}
	copyState := NewState()
	if err := copyState.Import(state.Export()); err != nil {
		t.Fatalf("round-trip import = %v", err)
	}
	snapshot := state.Export()
	snapshot.Leases = nil
	if err := copyState.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing lease corruption = %v", err)
	}
	snapshot = state.Export()
	snapshot.Events = append(snapshot.Events, lifecycle.Event{ID: "event-1", SandboxID: sandbox.ID, OperationID: operation.ID, Sequence: 2, Generation: 1, FencingToken: 1, Kind: "sandbox.requested", OccurredAt: repositoryTestTime})
	if err := copyState.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("event sequence corruption = %v", err)
	}
}
