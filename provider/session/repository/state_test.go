package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

var stateTestTime = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func validAuthority() session.SandboxAuthority {
	return session.SandboxAuthority{
		SandboxID:           "sandbox-1",
		ProviderRevisionID:  "provider-revision-1",
		Ready:               true,
		Generation:          1,
		LeaseExpiresAt:      stateTestTime.Add(time.Hour),
		FencingToken:        1,
		CapabilityProfileID: "terminal-v1",
	}
}

func validOpen() session.OpenRequest {
	return session.OpenRequest{
		SandboxID:           "sandbox-1",
		ProviderRevisionID:  "provider-revision-1",
		OperationID:         "operation-1",
		AttemptID:           "attempt-1",
		FencingToken:        1,
		IdempotencyKey:      "session-key-1",
		RequestDigest:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:            stateTestTime.Add(30 * time.Minute),
		ExpectedGeneration:  1,
		RuntimeSessionID:    "session-1",
		RuntimeType:         session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1",
		ExpiresAt:           stateTestTime.Add(10 * time.Minute),
	}
}

func allocationFor(request session.OpenRequest, reference string, allocatedAt time.Time) session.AllocationReceipt {
	return session.AllocationReceipt{
		Reference: reference, SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		ConnectionGeneration: 1, AllocatedAt: allocatedAt, ExpiresAt: request.ExpiresAt,
	}
}

func newStateWithAuthority(t *testing.T) State {
	t.Helper()
	state := NewState()
	if err := state.PutSandboxAuthority(validAuthority()); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestStateReserveOpenChecksAuthorityAndReplaysIdempotently(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*session.SandboxAuthority, *session.OpenRequest)
		want   error
	}{
		{name: "not ready", mutate: func(a *session.SandboxAuthority, _ *session.OpenRequest) { a.Ready = false }, want: session.ErrSandboxNotReady},
		{name: "revision", mutate: func(_ *session.SandboxAuthority, r *session.OpenRequest) {
			r.ProviderRevisionID = "provider-revision-2"
		}, want: session.ErrProviderRevisionConflict},
		{name: "generation", mutate: func(_ *session.SandboxAuthority, r *session.OpenRequest) { r.ExpectedGeneration = 2 }, want: session.ErrGenerationConflict},
		{name: "lease", mutate: func(a *session.SandboxAuthority, _ *session.OpenRequest) {
			a.LeaseExpiresAt = stateTestTime.Add(5 * time.Minute)
		}, want: session.ErrLeaseExpired},
		{name: "fencing", mutate: func(_ *session.SandboxAuthority, r *session.OpenRequest) { r.FencingToken = 2 }, want: session.ErrStaleFencingToken},
		{name: "capability", mutate: func(_ *session.SandboxAuthority, r *session.OpenRequest) { r.CapabilityProfileID = "terminal-v2" }, want: session.ErrCapabilityUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := NewState()
			authority := validAuthority()
			request := validOpen()
			test.mutate(&authority, &request)
			if err := state.PutSandboxAuthority(authority); err != nil {
				t.Fatal(err)
			}
			if _, err := state.ReserveOpenAt(request, stateTestTime); !errors.Is(err, test.want) {
				t.Fatalf("reserve error = %v, want %v", err, test.want)
			}
		})
	}

	state := newStateWithAuthority(t)
	request := validOpen()
	first, err := state.ReserveOpenAt(request, stateTestTime)
	if err != nil || first.Replayed {
		t.Fatalf("first reserve = %#v, %v", first, err)
	}
	replay, err := state.ReserveOpenAt(request, stateTestTime.Add(time.Second))
	if err != nil || !replay.Replayed || replay.Record != first.Record {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	differentDigest := request
	differentDigest.RequestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := state.ReserveOpenAt(differentDigest, stateTestTime); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest substitution = %v", err)
	}
	differentOperation := request
	differentOperation.OperationID = "operation-2"
	if _, err := state.ReserveOpenAt(differentOperation, stateTestTime); !errors.Is(err, ErrConflict) {
		t.Fatalf("identity substitution = %v", err)
	}
	got, err := state.GetOpenAt(request.OperationID, stateTestTime.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	got.Request.OperationID = "mutated"
	again, err := state.GetOpenAt(request.OperationID, stateTestTime.Add(time.Second))
	if err != nil || again.Request.OperationID != request.OperationID {
		t.Fatalf("deep copy = %#v, %v", again, err)
	}
}

func TestStateSuccessfulUpdateRechecksAuthorityAtomically(t *testing.T) {
	state := newStateWithAuthority(t)
	request := validOpen()
	_, err := state.ReserveOpenAt(request, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	attached, err := state.AttachAllocation(allocationFor(request, "ref:terminal/11111111111111111111111111111111", stateTestTime.Add(time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	running := attached.Record
	evidence := &session.EndpointEvidence{InternalEndpointReference: "ref:session:opaque-1", ConnectionGeneration: 1}
	succeeded, err := session.Transition(running, session.StatusSucceeded, stateTestTime.Add(2*time.Second), evidence)
	if err != nil {
		t.Fatal(err)
	}
	stale := validAuthority()
	stale.Ready = false
	if err := state.ReplaceSandboxAuthority(stale, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(succeeded, session.StatusRunning, stateTestTime.Add(2*time.Second)); !errors.Is(err, session.ErrSandboxNotReady) {
		t.Fatalf("success with stale authority = %v", err)
	}
	current, err := state.GetOpenAt(request.OperationID, stateTestTime.Add(2*time.Second))
	if err != nil || current.Status != session.StatusRunning {
		t.Fatalf("record after rejected success = %#v, %v", current, err)
	}
	ready := validAuthority()
	if err := state.ReplaceSandboxAuthority(ready, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(succeeded, session.StatusRunning, stateTestTime.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := state.GetOpenAt(request.OperationID, stateTestTime.Add(3*time.Second))
	if err != nil || got.Status != session.StatusSucceeded || got.Handoff == nil {
		t.Fatalf("successful record = %#v, %v", got, err)
	}
}

func TestStateExpiryAndOutcomeUnknownCannotReopen(t *testing.T) {
	state := newStateWithAuthority(t)
	request := validOpen()
	reserved, err := state.ReserveOpenAt(request, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := session.Transition(reserved.Record, session.StatusOutcomeUnknown, stateTestTime.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(unknown, session.StatusAccepted, stateTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := state.GetOpenAt(request.OperationID, stateTestTime.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Transition(unknown, session.StatusSucceeded, stateTestTime.Add(3*time.Second), &session.EndpointEvidence{InternalEndpointReference: "ref:session:opaque-2", ConnectionGeneration: 1}); !errors.Is(err, session.ErrTerminalOperation) {
		t.Fatalf("outcome unknown reopen = %v", err)
	}

	expiring := request
	expiring.OperationID = "operation-2"
	expiring.AttemptID = "attempt-2"
	expiring.RuntimeSessionID = "session-2"
	expiring.IdempotencyKey = "session-key-2"
	expiring.ExpiresAt = stateTestTime.Add(5 * time.Minute)
	_, err = state.ReserveOpenAt(expiring, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	attached, err := state.AttachAllocation(allocationFor(expiring, "ref:terminal/22222222222222222222222222222222", stateTestTime.Add(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	running := attached.Record
	succeeded, err := session.Transition(running, session.StatusSucceeded, stateTestTime.Add(time.Minute), &session.EndpointEvidence{InternalEndpointReference: "ref:session:opaque-3", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(succeeded, session.StatusRunning, stateTestTime.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := state.GetOpenAt(expiring.OperationID, expiring.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired handoff = %v", err)
	}
}

func TestStateAuthorityCompareAndSet(t *testing.T) {
	state := newStateWithAuthority(t)
	authority := validAuthority()
	authority.Ready = false
	if err := state.ReplaceSandboxAuthority(authority, 2, 1); !errors.Is(err, session.ErrGenerationConflict) {
		t.Fatalf("stale generation = %v", err)
	}
	if err := state.ReplaceSandboxAuthority(authority, 1, 2); !errors.Is(err, session.ErrStaleFencingToken) {
		t.Fatalf("stale fence = %v", err)
	}
	authority.Generation = 2
	authority.FencingToken = 2
	if err := state.ReplaceSandboxAuthority(authority, 1, 1); err != nil {
		t.Fatal(err)
	}
	got, err := state.GetSandboxAuthority(authority.SandboxID)
	if err != nil || got.Generation != 2 || got.FencingToken != 2 {
		t.Fatalf("updated authority = %#v, %v", got, err)
	}
}

func TestStateImportRejectsBrokenReferences(t *testing.T) {
	state := newStateWithAuthority(t)
	request := validOpen()
	if _, err := state.ReserveOpenAt(request, stateTestTime); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Export()
	snapshot.Idempotency[0].OperationID = "missing"
	var broken State
	if err := broken.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("broken idempotency import = %v", err)
	}
	snapshot = state.Export()
	snapshot.Authorities[0].ProviderRevisionID = "provider-revision-2"
	if err := broken.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("broken authority import = %v", err)
	}
}

func TestStateSynchronizesTrustedAuthorityMonotonically(t *testing.T) {
	state := NewState()
	authority := validAuthority()
	if err := state.SynchronizeSandboxAuthority(authority); err != nil {
		t.Fatal(err)
	}
	newer := authority
	newer.Generation = 3
	newer.FencingToken = 2
	newer.Ready = false
	if err := state.SynchronizeSandboxAuthority(newer); err != nil {
		t.Fatal(err)
	}
	staleGeneration := newer
	staleGeneration.Generation = 2
	if err := state.SynchronizeSandboxAuthority(staleGeneration); !errors.Is(err, session.ErrGenerationConflict) {
		t.Fatalf("stale generation = %v", err)
	}
	staleFence := newer
	staleFence.FencingToken = 1
	if err := state.SynchronizeSandboxAuthority(staleFence); !errors.Is(err, session.ErrStaleFencingToken) {
		t.Fatalf("stale fence = %v", err)
	}
	wrongRevision := newer
	wrongRevision.ProviderRevisionID = "provider-revision-2"
	if err := state.SynchronizeSandboxAuthority(wrongRevision); !errors.Is(err, session.ErrProviderRevisionConflict) {
		t.Fatalf("revision replacement = %v", err)
	}
	wrongCapability := newer
	wrongCapability.CapabilityProfileID = "terminal-v2"
	if err := state.SynchronizeSandboxAuthority(wrongCapability); !errors.Is(err, session.ErrCapabilityUnsupported) {
		t.Fatalf("capability replacement = %v", err)
	}
}

func TestStateAllocationAttachmentAndObservationAreDurableAndUnique(t *testing.T) {
	state := newStateWithAuthority(t)
	first := validOpen()
	if _, err := state.ReserveOpenAt(first, stateTestTime); err != nil {
		t.Fatal(err)
	}
	receipt := allocationFor(first, "ref:terminal/55555555555555555555555555555555", stateTestTime.Add(time.Second))
	attached, err := state.AttachAllocation(receipt)
	if err != nil || attached.Record.Status != session.StatusRunning || attached.Replayed {
		t.Fatalf("AttachAllocation() = %#v, %v", attached, err)
	}
	replay, err := state.AttachAllocation(receipt)
	if err != nil || !replay.Replayed {
		t.Fatalf("AttachAllocation replay = %#v, %v", replay, err)
	}
	observed, err := state.ObserveAllocation(first.OperationID, session.AllocationEvidence{
		Receipt: receipt, State: session.AllocationOutcomeUnknown, ObservedAt: stateTestTime.Add(2 * time.Second),
	})
	if err != nil || observed.Status != session.StatusOutcomeUnknown {
		t.Fatalf("ObserveAllocation() = %#v, %v", observed, err)
	}

	second := first
	second.OperationID, second.AttemptID, second.RuntimeSessionID, second.IdempotencyKey = "operation-2", "attempt-2", "session-2", "session-key-2"
	second.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := state.ReserveOpenAt(second, stateTestTime); err != nil {
		t.Fatal(err)
	}
	colliding := allocationFor(second, receipt.Reference, stateTestTime.Add(3*time.Second))
	if _, err := state.AttachAllocation(colliding); !errors.Is(err, session.ErrAllocationConflict) {
		t.Fatalf("cross-session receipt collision = %v", err)
	}

	listed := state.ListOpen()
	if len(listed) != 2 || listed[0].Request.OperationID != first.OperationID || listed[1].Request.OperationID != second.OperationID {
		t.Fatalf("ListOpen() = %#v", listed)
	}
	listed[0].Request.OperationID = "mutated"
	stored, err := state.GetOpenAt(first.OperationID, stateTestTime.Add(3*time.Second))
	if err != nil || stored.Request.OperationID != first.OperationID {
		t.Fatalf("ListOpen deep copy = %#v, %v", stored, err)
	}
}

func TestStateMigratesVersionOneWithoutLosingAcceptedOrHandoffEvidence(t *testing.T) {
	state := newStateWithAuthority(t)
	acceptedRequest := validOpen()
	if _, err := state.ReserveOpenAt(acceptedRequest, stateTestTime); err != nil {
		t.Fatal(err)
	}
	runningRequest := acceptedRequest
	runningRequest.OperationID, runningRequest.AttemptID, runningRequest.RuntimeSessionID, runningRequest.IdempotencyKey = "operation-running", "attempt-running", "session-running", "key-running"
	runningRequest.RequestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	runningReservation, err := state.ReserveOpenAt(runningRequest, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	legacyRunning, err := session.Transition(runningReservation.Record, session.StatusRunning, stateTestTime.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	successRequest := acceptedRequest
	successRequest.OperationID, successRequest.AttemptID, successRequest.RuntimeSessionID, successRequest.IdempotencyKey = "operation-success", "attempt-success", "session-success", "key-success"
	successRequest.RequestDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	successReservation, err := state.ReserveOpenAt(successRequest, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	legacySuccess, err := session.Transition(successReservation.Record, session.StatusRunning, stateTestTime.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	legacySuccess, err = session.Transition(legacySuccess, session.StatusSucceeded, stateTestTime.Add(2*time.Second), &session.EndpointEvidence{
		InternalEndpointReference: "ref:session:legacy", ConnectionGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	snapshot := state.Export()
	snapshot.Version = legacySnapshotVersion
	for index := range snapshot.Sessions {
		switch snapshot.Sessions[index].Request.OperationID {
		case runningRequest.OperationID:
			snapshot.Sessions[index] = legacyRunning
		case successRequest.OperationID:
			snapshot.Sessions[index] = legacySuccess
		}
	}
	imported := NewState()
	if err := imported.Import(snapshot); err != nil {
		t.Fatal(err)
	}
	accepted, err := imported.GetOpenAt(acceptedRequest.OperationID, stateTestTime.Add(3*time.Second))
	if err != nil || accepted.Status != session.StatusAccepted || accepted.Allocation != nil {
		t.Fatalf("migrated accepted = %#v, %v", accepted, err)
	}
	running, err := imported.GetOpenAt(runningRequest.OperationID, stateTestTime.Add(3*time.Second))
	if err != nil || running.Status != session.StatusOutcomeUnknown || running.Allocation != nil {
		t.Fatalf("migrated running = %#v, %v", running, err)
	}
	succeeded, err := imported.GetOpenAt(successRequest.OperationID, stateTestTime.Add(3*time.Second))
	if err != nil || succeeded.Status != session.StatusSucceeded || succeeded.Handoff == nil || succeeded.Handoff.InternalEndpointReference != "ref:session:legacy" {
		t.Fatalf("migrated success = %#v, %v", succeeded, err)
	}
	if imported.Export().Version != snapshotVersion {
		t.Fatalf("exported version = %d", imported.Export().Version)
	}
}

func TestStateRejectsVersionTwoAllocationCorruption(t *testing.T) {
	state := newStateWithAuthority(t)
	request := validOpen()
	if _, err := state.ReserveOpenAt(request, stateTestTime); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AttachAllocation(allocationFor(request, "ref:terminal/66666666666666666666666666666666", stateTestTime.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Export()
	snapshot.Sessions[0].Allocation = nil
	var imported State
	if err := imported.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("running without receipt = %v", err)
	}

	snapshot = state.Export()
	snapshot.Version = legacySnapshotVersion
	if err := imported.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("version 1 allocation evidence = %v", err)
	}

	second := request
	second.OperationID, second.AttemptID, second.RuntimeSessionID, second.IdempotencyKey = "operation-2", "attempt-2", "session-2", "key-2"
	second.RequestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := state.ReserveOpenAt(second, stateTestTime); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AttachAllocation(allocationFor(second, "ref:terminal/77777777777777777777777777777777", stateTestTime.Add(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	snapshot = state.Export()
	firstReference := snapshot.Sessions[0].Allocation.Receipt.Reference
	snapshot.Sessions[1].Allocation.Receipt.Reference = firstReference
	if err := imported.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate allocation reference = %v", err)
	}
}
