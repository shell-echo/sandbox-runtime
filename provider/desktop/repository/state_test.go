package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

var stateTestNow = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

func stateAuthority() desktop.SandboxAuthority {
	return desktop.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: stateTestNow.Add(2 * time.Hour), FencingToken: 3,
		CapabilityProfileID: desktop.CapabilityProfileID, NetworkPolicyReference: "desktop-egress-policy-1",
	}
}

func stateOpen() desktop.OpenRequest {
	return desktop.OpenRequest{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "open-operation-1",
		AttemptID: "open-attempt-1", FencingToken: 3, IdempotencyKey: "desktop-open-1",
		RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline:      stateTestNow.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1",
		CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: stateTestNow.Add(30 * time.Minute),
	}
}

func stateReceipt(request desktop.OpenRequest) desktop.AllocationReceipt {
	return desktop.AllocationReceipt{
		Reference: "ref:desktop/00000000000000000000000000000001", SandboxID: request.SandboxID,
		DesktopSessionID: request.DesktopSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration, ConnectionGeneration: 1,
		AllocatedAt: stateTestNow.Add(time.Second), ExpiresAt: request.ExpiresAt,
	}
}

func stateClose(request desktop.OpenRequest) desktop.CloseRequest {
	return desktop.CloseRequest{
		SandboxID: request.SandboxID, ProviderRevisionID: request.ProviderRevisionID, OperationID: "close-operation-1",
		AttemptID: "close-attempt-1", FencingToken: request.FencingToken, IdempotencyKey: "desktop-close-1",
		RequestDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Deadline:      stateTestNow.Add(time.Hour), ExpectedGeneration: request.ExpectedGeneration,
		DesktopSessionID: request.DesktopSessionID, ConnectionGeneration: 1, Reason: "caller_complete",
	}
}

func makeActive(t *testing.T, state *State) desktop.Record {
	t.Helper()
	request := stateOpen()
	reservation, err := state.ReserveOpenAt(request, stateTestNow)
	if err != nil {
		t.Fatal(err)
	}
	opening, err := desktop.Transition(reservation.Record, desktop.StatusRunning, stateTestNow.Add(time.Second), nil)
	if err != nil || state.UpdateOpenAt(opening, desktop.StatusAccepted, opening.ObservedAt) != nil {
		t.Fatalf("begin open = %#v, %v", opening, err)
	}
	attached, err := state.AttachAllocation(stateReceipt(request))
	if err != nil {
		t.Fatal(err)
	}
	active, err := desktop.Transition(attached.Record, desktop.StatusSucceeded, stateTestNow.Add(2*time.Second), &desktop.EndpointEvidence{InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(active, desktop.StatusRunning, active.ObservedAt); err != nil {
		t.Fatal(err)
	}
	return active
}

func TestStateFenceReplayAndIdempotencyMatrix(t *testing.T) {
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	request := stateOpen()
	first, err := state.ReserveOpenAt(request, stateTestNow)
	if err != nil || first.Replayed {
		t.Fatalf("first = %#v, %v", first, err)
	}
	replay, err := state.ReserveOpenAt(request, stateTestNow.Add(time.Second))
	if err != nil || !replay.Replayed || replay.Record.Request != first.Record.Request {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	conflict := request
	conflict.RequestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := state.ReserveOpenAt(conflict, stateTestNow); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest conflict = %v", err)
	}
	for name, test := range map[string]struct {
		mutate func(*desktop.OpenRequest)
		want   error
	}{
		"generation": {func(r *desktop.OpenRequest) { r.ExpectedGeneration++ }, desktop.ErrGenerationConflict},
		"fence":      {func(r *desktop.OpenRequest) { r.FencingToken++ }, desktop.ErrStaleFencingToken},
		"revision":   {func(r *desktop.OpenRequest) { r.ProviderRevisionID = "revision-2" }, desktop.ErrProviderRevisionConflict},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.OperationID += "-" + name
			candidate.AttemptID += "-" + name
			candidate.IdempotencyKey += "-" + name
			test.mutate(&candidate)
			if _, err := state.ReserveOpenAt(candidate, stateTestNow); !errors.Is(err, test.want) {
				t.Fatalf("ReserveOpenAt() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestStateCloseRevocationAbsenceAndTerminalReplay(t *testing.T) {
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	source := makeActive(t, &state)
	request := stateClose(source.Request)
	reservation, err := state.ReserveCloseAt(request, stateTestNow.Add(3*time.Second), false)
	if err != nil || reservation.Replayed {
		t.Fatalf("reserve close = %#v, %v", reservation, err)
	}
	revoked := state.Sessions[source.Request.OperationID]
	if revoked.RevokedAt == nil || revoked.SessionState() != desktop.SessionClosing {
		t.Fatalf("source was not durably revoked = %#v", revoked)
	}
	running, err := desktop.TransitionClose(reservation.Record, desktop.StatusRunning, stateTestNow.Add(4*time.Second))
	if err != nil || state.UpdateClose(running, desktop.StatusAccepted, revoked) != nil {
		t.Fatalf("running close = %#v, %v", running, err)
	}
	unknown, err := desktop.TransitionClose(running, desktop.StatusOutcomeUnknown, stateTestNow.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	unknownSource, err := desktop.MarkCloseUnknown(revoked, unknown.ObservedAt)
	if err != nil || state.UpdateClose(unknown, desktop.StatusRunning, unknownSource) != nil {
		t.Fatalf("unknown close = %#v / %#v, %v", unknown, unknownSource, err)
	}
	succeeded, err := desktop.TransitionClose(unknown, desktop.StatusSucceeded, stateTestNow.Add(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := desktop.CompleteClose(unknownSource, succeeded.ObservedAt, false)
	if err != nil || state.UpdateClose(succeeded, desktop.StatusOutcomeUnknown, closed) != nil {
		t.Fatalf("complete close = %#v / %#v, %v", succeeded, closed, err)
	}
	if state.Sessions[source.Request.OperationID].SessionState() != desktop.SessionClosed {
		t.Fatalf("session state = %s", state.Sessions[source.Request.OperationID].SessionState())
	}
	replay, err := state.ReserveCloseAt(request, stateTestNow.Add(7*time.Second), false)
	if err != nil || !replay.Replayed || replay.Record.Status != desktop.StatusSucceeded {
		t.Fatalf("terminal replay = %#v, %v", replay, err)
	}
	other := request
	other.OperationID = "close-operation-2"
	other.AttemptID = "close-attempt-2"
	other.IdempotencyKey = "desktop-close-2"
	other.RequestDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, err := state.ReserveCloseAt(other, stateTestNow.Add(8*time.Second), false); !errors.Is(err, desktop.ErrHandoffUnavailable) {
		t.Fatalf("terminal resurrection = %v", err)
	}
}

func TestStateSnapshotRoundTripIncludesCloseAuthority(t *testing.T) {
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	source := makeActive(t, &state)
	if _, err := state.ReserveCloseAt(stateClose(source.Request), stateTestNow.Add(3*time.Second), true); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Export()
	var restored State
	if err := restored.Import(snapshot); err != nil {
		t.Fatal(err)
	}
	if len(restored.Sessions) != 1 || len(restored.Closes) != 1 || len(restored.CloseIdempotency) != 1 {
		t.Fatalf("restored = %#v", restored.Export())
	}
	snapshot.CloseIdempotency = nil
	if err := restored.Import(snapshot); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing close idempotency = %v", err)
	}
}
