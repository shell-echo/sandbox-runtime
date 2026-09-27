package repository

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

func desktopIdentityTicket(request desktop.OpenRequest) sandboxidentity.Reservation {
	return sandboxidentity.Reservation{
		PlanDigest: "sha256:" + strings.Repeat("c", 64),
		Slot: sandboxidentity.Slot{ID: "desktop-0000", WorkloadUID: 21000, WorkloadGID: 31000,
			GatewayUID: 21001, GatewayGID: 31001},
		Claim: sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.DesktopSessionID,
			OperationID: request.OperationID, AttemptID: request.AttemptID,
			RequestDigest: request.RequestDigest, Generation: request.ExpectedGeneration,
			Fence: request.FencingToken},
		SpecDigest: "sha256:" + strings.Repeat("d", 64), Status: sandboxidentity.Cleaning,
	}
}

func TestDesktopIdentityNeverDispatchedRetirementIsDurableAndFenced(t *testing.T) {
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	request := stateOpen()
	reserved, err := state.ReserveOpenAt(request, stateTestNow)
	if err != nil {
		t.Fatal(err)
	}
	running, err := desktop.Transition(reserved.Record, desktop.StatusRunning, stateTestNow.Add(time.Second), nil)
	if err != nil || state.UpdateOpenAt(running, desktop.StatusAccepted, running.ObservedAt) != nil {
		t.Fatalf("begin Desktop Open = %v", err)
	}
	allocation := desktop.Allocation{Request: desktop.AllocationRequest{
		SandboxID: request.SandboxID, DesktopSessionID: request.DesktopSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		RequestDigest: request.RequestDigest, NetworkPolicyReference: stateAuthority().NetworkPolicyReference,
		ExpiresAt: request.ExpiresAt}, AllocatedAt: reserved.Record.AcceptedAt}
	if err := state.AuthorizeIdentityCreate(allocation, stateTestNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	failed, err := desktop.Transition(running, desktop.StatusFailed, stateTestNow.Add(2*time.Second), nil)
	if err != nil || state.UpdateOpenAt(failed, desktop.StatusRunning, failed.ObservedAt) != nil {
		t.Fatalf("terminal Desktop Open = %v", err)
	}
	ticket := desktopIdentityTicket(request)
	if err := state.RetireIdentityNeverDispatched(ticket); err != nil {
		t.Fatal(err)
	}
	if err := state.AuthorizeIdentityCreate(allocation, stateTestNow.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired Desktop claim recreated: %v", err)
	}
	if err := state.RetireIdentityNeverDispatched(ticket); err != nil {
		t.Fatalf("exact never-dispatched replay: %v", err)
	}
	var reopened State
	if err := reopened.Import(state.Export()); err != nil || !reopened.Retirements[request.OperationID].NeverDispatched {
		t.Fatalf("persisted Desktop retirement: %v", err)
	}
	corrupt := state.Export()
	corrupt.Retirements[0].Released = false
	if err := reopened.Import(corrupt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unreleased never-dispatched retirement imported: %v", err)
	}
}

func TestDesktopCloseRetiresOnlySourceOpenAllocation(t *testing.T) {
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(stateAuthority()); err != nil {
		t.Fatal(err)
	}
	source := makeActive(t, &state)
	closeRequest := stateClose(source.Request)
	closeRequest.FencingToken = source.Request.FencingToken
	closeRequest.Deadline = stateTestNow.Add(time.Hour)
	closed, err := state.ReserveCloseAt(closeRequest, stateTestNow.Add(3*time.Second), false)
	if err != nil || closed.Record.SourceOpenOperationID != source.Request.OperationID {
		t.Fatalf("Desktop Close source = %+v, %v", closed, err)
	}
	ticket := desktopIdentityTicket(source.Request)
	if err := state.RetireIdentity(ticket, source.Allocation.Receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := state.CompletedIdentityRetirement(source.Allocation.Receipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("unreleased Desktop identity completed: %v", err)
	}
	if err := state.ReleaseIdentity(ticket); err != nil {
		t.Fatal(err)
	}
	var reopened State
	if err := reopened.Import(state.Export()); err != nil {
		t.Fatal(err)
	}
	if completed, err := reopened.CompletedIdentityRetirement(source.Allocation.Receipt); err != nil || completed != ticket {
		t.Fatalf("released Desktop source Open identity = %+v, %v", completed, err)
	}
	drifted := source.Allocation.Receipt
	drifted.ConnectionGeneration++
	if _, err := reopened.CompletedIdentityRetirement(drifted); !errors.Is(err, ErrConflict) {
		t.Fatalf("drifted Desktop receipt released: %v", err)
	}
}
