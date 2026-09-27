package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

func TestIdentityRetirementRejectsExactReplayButAllowsNewSession(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(browser.SandboxAuthority{
		SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1,
		CapabilityProfileID: browser.CapabilityProfileID, NetworkPolicyReference: "policy-1"}); err != nil {
		t.Fatal(err)
	}
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1",
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
		IdempotencyKey: "key-1", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Deadline: now.Add(time.Hour), ExpectedGeneration: 1, BrowserSessionID: "browser-1",
		CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute)}
	if _, err := state.ReserveOpenAt(request, now); err != nil {
		t.Fatal(err)
	}
	allocation := browser.Allocation{Request: browser.AllocationRequest{
		SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		RequestDigest: request.RequestDigest, NetworkPolicyReference: "policy-1", ExpiresAt: request.ExpiresAt},
		AllocatedAt: now}
	if err := state.AuthorizeIdentityCreate(allocation, now); err != nil {
		t.Fatal(err)
	}
	if err := state.AuthorizeIdentityRecovery(allocation, now); err != nil {
		t.Fatal(err)
	}
	claim := sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.BrowserSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID, RequestDigest: request.RequestDigest,
		Generation: request.ExpectedGeneration, Fence: request.FencingToken}
	ticket := sandboxidentity.Reservation{PlanDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Slot: sandboxidentity.Slot{ID: "browser-0000", WorkloadUID: 20000, WorkloadGID: 30000,
			GatewayUID: 20001, GatewayGID: 30001}, Claim: claim,
		SpecDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Status:     sandboxidentity.Cleaning}
	receipt := browser.AllocationReceipt{Reference: "ref:browser/11111111111111111111111111111111",
		SandboxID: claim.SandboxID, BrowserSessionID: claim.SessionID, OperationID: claim.OperationID,
		AttemptID: claim.AttemptID, FencingToken: claim.Fence, ExpectedGeneration: claim.Generation,
		ConnectionGeneration: 1, AllocatedAt: now, ExpiresAt: request.ExpiresAt}
	if err := state.RetireIdentity(ticket, receipt); err != nil {
		t.Fatal(err)
	}
	if err := state.AuthorizeIdentityCreate(allocation, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired create = %v", err)
	}
	if err := state.AuthorizeIdentityRecovery(allocation, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired recovery = %v", err)
	}
	if err := state.RetireIdentity(ticket, receipt); err != nil {
		t.Fatalf("exact retirement retry = %v", err)
	}
	wrong := claim
	wrong.Fence++
	wrongTicket := ticket
	wrongTicket.Claim = wrong
	if err := state.RetireIdentity(wrongTicket, receipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("drifted retirement = %v", err)
	}
	if _, err := state.CompletedIdentityRetirement(receipt); !errors.Is(err, ErrConflict) {
		t.Fatalf("unreleased retirement was completed: %v", err)
	}
	terminal, err := browser.Transition(state.Sessions[request.OperationID], browser.StatusFailed, now.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpdateOpenAt(terminal, browser.StatusAccepted, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := state.ReleaseIdentity(ticket); err != nil {
		t.Fatal(err)
	}
	var restored State
	if err := restored.Import(state.Export()); err != nil || !restored.IdentityRetired(ticket) {
		t.Fatalf("durable retirement = %v, %v", restored.Retirements, err)
	}
	if completed, err := restored.CompletedIdentityRetirement(receipt); err != nil || completed != ticket {
		t.Fatalf("durable released retirement = %+v, %v", completed, err)
	}
	if completed, exactReceipt, err := restored.CompletedTerminalIdentityRetirement(terminal); err != nil ||
		completed != ticket || exactReceipt != receipt {
		t.Fatalf("terminal released proof = %+v, %+v, %v", completed, exactReceipt, err)
	}
	request.OperationID = "operation-2"
	request.BrowserSessionID = "browser-2"
	request.IdempotencyKey = "key-2"
	request.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	secondOpen, err := restored.ReserveOpenAt(request, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	allocation.Request.OperationID = request.OperationID
	allocation.Request.BrowserSessionID = request.BrowserSessionID
	allocation.Request.RequestDigest = request.RequestDigest
	allocation.AllocatedAt = now.Add(time.Second)
	if err := restored.AuthorizeIdentityCreate(allocation, now.Add(time.Second)); err != nil {
		t.Fatalf("new exact session in same sandbox/generation = %v", err)
	}
	failed, err := browser.Transition(secondOpen.Record, browser.StatusFailed, now.Add(2*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.UpdateOpenAt(failed, browser.StatusAccepted, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	neverDispatched := ticket
	neverDispatched.Claim.OperationID = request.OperationID
	neverDispatched.Claim.SessionID = request.BrowserSessionID
	neverDispatched.Claim.RequestDigest = request.RequestDigest
	if err := restored.RetireIdentityNeverDispatched(neverDispatched); err != nil {
		t.Fatal(err)
	}
	if err := restored.RetireIdentityNeverDispatched(neverDispatched); err != nil {
		t.Fatalf("exact never-dispatched replay: %v", err)
	}
	if err := restored.AuthorizeIdentityCreate(allocation, now.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired undispatched claim created: %v", err)
	}
	var reopened State
	if err := reopened.Import(restored.Export()); err != nil || !reopened.Retirements[request.OperationID].NeverDispatched {
		t.Fatalf("durable never-dispatched proof: %v", err)
	}
	corrupt := restored.Export()
	for index := range corrupt.Retirements {
		if corrupt.Retirements[index].NeverDispatched {
			corrupt.Retirements[index].Released = false
		}
	}
	if err := reopened.Import(corrupt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unreleased never-dispatched proof imported: %v", err)
	}
}

func TestStateRoundTripRequiresIdempotencyAndAuthority(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: now.Add(time.Minute), ExpectedGeneration: 1, BrowserSessionID: "browser-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Second)}
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(browser.SandboxAuthority{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1, LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: browser.CapabilityProfileID, NetworkPolicyReference: "browser-egress-policy-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := state.ReserveOpenAt(request, now); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Export()
	var restored State
	if err := restored.Import(snapshot); err != nil {
		t.Fatal(err)
	}
	reservation, err := restored.ReserveOpenAt(request, now.Add(time.Second))
	if err != nil || !reservation.Replayed {
		t.Fatalf("replay = %#v, %v", reservation, err)
	}
	snapshot.Idempotency = nil
	if err := restored.Import(snapshot); err == nil {
		t.Fatal("Import without idempotency succeeded")
	}
}

func TestUpdateOpenCannotBypassAttachAllocation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: now.Add(time.Minute), ExpectedGeneration: 1, BrowserSessionID: "browser-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Second)}
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(browser.SandboxAuthority{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1, LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: browser.CapabilityProfileID, NetworkPolicyReference: "browser-egress-policy-1"}); err != nil {
		t.Fatal(err)
	}
	reservation, err := state.ReserveOpenAt(request, now)
	if err != nil {
		t.Fatal(err)
	}
	invalid := reservation.Record.Clone()
	invalid.Status = browser.StatusRunning
	invalid.ObservedAt = now.Add(time.Second)
	if err := state.UpdateOpenAt(invalid, browser.StatusAccepted, invalid.ObservedAt); !errors.Is(err, browser.ErrInvalidAllocation) {
		t.Fatalf("UpdateOpenAt() = %v", err)
	}
}

func TestSandboxAuthorityRejectsNetworkPolicyMutation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := NewState()
	authority := browser.SandboxAuthority{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1, LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: browser.CapabilityProfileID, NetworkPolicyReference: "browser-egress-policy-1"}
	if err := state.SynchronizeSandboxAuthority(authority); err != nil {
		t.Fatal(err)
	}
	authority.NetworkPolicyReference = "browser-egress-policy-2"
	if err := state.SynchronizeSandboxAuthority(authority); !errors.Is(err, browser.ErrNetworkPolicyConflict) {
		t.Fatalf("policy mutation error = %v", err)
	}
}
