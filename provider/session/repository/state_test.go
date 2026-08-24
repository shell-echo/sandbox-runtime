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
	reserved, err := state.ReserveOpenAt(request, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err := session.Transition(reserved.Record, session.StatusRunning, stateTestTime.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(running, session.StatusAccepted, stateTestTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
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
	reserved, err = state.ReserveOpenAt(expiring, stateTestTime)
	if err != nil {
		t.Fatal(err)
	}
	running, err := session.Transition(reserved.Record, session.StatusRunning, stateTestTime.Add(30*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	succeeded, err := session.Transition(running, session.StatusSucceeded, stateTestTime.Add(time.Minute), &session.EndpointEvidence{InternalEndpointReference: "ref:session:opaque-3", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(running, session.StatusAccepted, stateTestTime.Add(30*time.Second)); err != nil {
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
