package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

func TestStateRoundTripRequiresIdempotencyAndAuthority(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: now.Add(time.Minute), ExpectedGeneration: 1, BrowserSessionID: "browser-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Second)}
	state := NewState()
	if err := state.SynchronizeSandboxAuthority(browser.SandboxAuthority{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1, LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: browser.CapabilityProfileID}); err != nil {
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
	if err := state.SynchronizeSandboxAuthority(browser.SandboxAuthority{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", Ready: true, Generation: 1, LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: browser.CapabilityProfileID}); err != nil {
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
