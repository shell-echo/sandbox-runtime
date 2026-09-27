package repository

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

func connectionFixture(t *testing.T) (State, browserhandoffv2.OpenRequest, browser.Record, browser.SandboxAuthority, time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	expires := now.Add(30 * time.Minute)
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1",
		AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64),
		Deadline: now.Add(time.Hour), ExpectedGeneration: 1, BrowserSessionID: "browser-1",
		CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: expires}
	running, err := browser.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt := browser.AllocationReceipt{Reference: "ref:browser/11111111111111111111111111111111", SandboxID: request.SandboxID,
		BrowserSessionID: request.BrowserSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(time.Second), ExpiresAt: expires}
	running, err = browser.AttachAllocation(running, receipt)
	if err != nil {
		t.Fatal(err)
	}
	referenceID := "ref:browser-session:" + strings.Repeat("1", 32)
	digest := browserbinding.Prefix + strings.Repeat("b", 64)
	ref, err := reference.NewRecordWithTenantBinding(referenceID, running, digest, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	source, err := browser.Transition(running, browser.StatusSucceeded, now.Add(3*time.Second),
		&browser.EndpointEvidence{InternalEndpointReference: referenceID, ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	authority := browser.SandboxAuthority{SandboxID: request.SandboxID, ProviderRevisionID: request.ProviderRevisionID,
		Ready: true, Generation: 1, FencingToken: 1, LeaseExpiresAt: expires.Add(time.Minute),
		CapabilityProfileID: browser.CapabilityProfileID, NetworkPolicyReference: "browser-egress-policy-1"}
	state := NewState()
	if err := state.Create(ref); err != nil {
		t.Fatal(err)
	}
	open := browserhandoffv2.OpenRequest{BindingVersion: browserhandoffv2.BindingVersion,
		BindingIssuer: browserhandoffv2.BindingIssuer, Protocol: browserhandoffv2.ProtocolID,
		RequestID: "private-request-1", Resource: browserhandoffv2.ResourceBrowser, TenantBindingDigest: digest,
		ProviderRevisionID: request.ProviderRevisionID, SandboxID: request.SandboxID,
		BrowserSessionID: request.BrowserSessionID, CapabilityProfileID: browser.CapabilityProfileID,
		MediaProfileID: browserhandoffv2.MediaProfileID, ControlProfileID: browserhandoffv2.ControlProfileID,
		HandoffReference: referenceID, HandoffDigest: browserhandoffv2.ReferenceDigest(referenceID),
		ConnectionGeneration: 1, ConnectionEpoch: "epoch-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 1, AuthorityExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt: expires.Format(time.RFC3339Nano)}
	open.AuthorityDigest = browserhandoffv2.AuthorityDigest(open)
	open.RequestDigest = browserhandoffv2.RequestDigest(open)
	return state, open, source, authority, now.Add(4 * time.Second)
}

func executorForPrivate(t *testing.T, private browserhandoffv2.OpenRequest, requestID string) executorprotocol.Open {
	t.Helper()
	fence, err := browserhandoffv2.ExecutorFence(private.AuthorityDigest)
	if err != nil {
		t.Fatal(err)
	}
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser,
		RequestID: requestID, TenantBindingDigest: private.TenantBindingDigest,
		ProviderRevisionID: private.ProviderRevisionID, SandboxID: private.SandboxID,
		RuntimeSessionID: private.BrowserSessionID, CapabilityProfileID: private.CapabilityProfileID,
		MediaProfileID: private.MediaProfileID, ControlProfileID: private.ControlProfileID,
		HandoffReference: private.HandoffReference, HandoffDigest: private.HandoffDigest,
		ConnectionGeneration: private.ConnectionGeneration, ConnectionEpoch: private.ConnectionEpoch,
		Fence: fence, AuthorityExpiresAt: private.AuthorityExpiresAt, HandoffExpiresAt: private.HandoffExpiresAt,
		Codec: "application/json"}
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	return open
}

func TestBrowserConnectionExactOneUseAndClosedReplay(t *testing.T) {
	state, private, source, authority, now := connectionFixture(t)
	created, err := state.BindConnectionWithOwnership(private, source, authority, now)
	if err != nil || !created {
		t.Fatalf("initial claim ownership=%v err=%v", created, err)
	}
	created, err = state.BindConnectionWithOwnership(private, source, authority, now)
	if err != nil || created {
		t.Fatalf("duplicate claim ownership=%v err=%v", created, err)
	}
	executor := executorForPrivate(t, private, "executor-request-1")
	if err := state.ReserveExecutor(executor, source, authority, now); err != nil {
		t.Fatal(err)
	}
	if err := state.ReserveExecutor(executor, source, authority, now); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("second reservation = %v", err)
	}
	if err := state.ClaimExecutorV2(executor, source, authority, now); err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimExecutorV2(executor, source, authority, now); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("executor replay = %v", err)
	}
	if err := state.CloseConnection(private.HandoffReference, private.ConnectionEpoch, private.AuthorityDigest); err != nil {
		t.Fatal(err)
	}
	if err := state.CloseConnection(private.HandoffReference, private.ConnectionEpoch, private.AuthorityDigest); err != nil {
		t.Fatalf("idempotent close = %v", err)
	}
	if err := state.ReserveExecutor(executorForPrivate(t, private, "executor-request-2"), source, authority, now); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("closed connection revived = %v", err)
	}
	stored, err := state.Get(private.HandoffReference)
	if err != nil || stored.ConnectionClaims[private.ConnectionEpoch].Status != reference.ConnectionClosed ||
		len(stored.ExecutorReplayClaims) != 1 {
		t.Fatalf("close lost one-use evidence: %#v, %v", stored, err)
	}
	corrupt := stored.Clone()
	delete(corrupt.ExecutorReplayClaims, executor.RequestID)
	if corrupt.Validate() == nil {
		t.Fatal("closed consumed connection without durable replay evidence accepted")
	}
}

func TestBrowserConnectionConflictLeavesStateUntouched(t *testing.T) {
	state, private, source, authority, now := connectionFixture(t)
	if err := state.BindConnection(private, source, authority, now); err != nil {
		t.Fatal(err)
	}
	conflict := private
	conflict.ControlFence++
	conflict.AuthorityDigest = browserhandoffv2.AuthorityDigest(conflict)
	conflict.RequestDigest = browserhandoffv2.RequestDigest(conflict)
	if err := state.BindConnection(conflict, source, authority, now); !errors.Is(err, reference.ErrConflict) {
		t.Fatalf("same epoch changed tuple = %v", err)
	}
	next := private
	next.ConnectionEpoch = "epoch-2"
	next.RequestID = "private-request-2"
	next.AuthorityDigest = browserhandoffv2.AuthorityDigest(next)
	next.RequestDigest = browserhandoffv2.RequestDigest(next)
	if err := state.BindConnection(next, source, authority, now); !errors.Is(err, reference.ErrConflict) {
		t.Fatalf("parallel writer = %v", err)
	}
	stored, _ := state.Get(private.HandoffReference)
	if len(stored.ConnectionClaims) != 1 || stored.ConnectionClaims[private.ConnectionEpoch].Status != reference.ConnectionPending {
		t.Fatal("failed conflict changed durable state")
	}
	if err := state.CloseConnection(private.HandoffReference, private.ConnectionEpoch, private.AuthorityDigest); err != nil {
		t.Fatal(err)
	}
	if err := state.BindConnection(next, source, authority, now); err != nil {
		t.Fatalf("closed epoch prevented exact replacement: %v", err)
	}
	stored, _ = state.Get(private.HandoffReference)
	if len(stored.ConnectionClaims) != 2 || stored.ConnectionClaims[private.ConnectionEpoch].Status != reference.ConnectionClosed ||
		stored.ConnectionClaims[next.ConnectionEpoch].Status != reference.ConnectionPending {
		t.Fatal("replacement did not retain old replay history")
	}
}

func TestBrowserConnectionRejectsDriftBeforeReservation(t *testing.T) {
	state, private, source, authority, now := connectionFixture(t)
	if err := state.BindConnection(private, source, authority, now); err != nil {
		t.Fatal(err)
	}
	executor := executorForPrivate(t, private, "executor-request-1")
	for _, test := range []struct {
		name      string
		open      executorprotocol.Open
		source    browser.Record
		authority browser.SandboxAuthority
		at        time.Time
	}{
		{"wrong epoch", func() executorprotocol.Open {
			v := executor
			v.ConnectionEpoch = "epoch-2"
			v.AuthorityDigest = v.CalculateAuthorityDigest()
			v.RequestDigest = v.CalculateRequestDigest()
			return v
		}(), source, authority, now},
		{"wrong tenant", func() executorprotocol.Open {
			v := executor
			v.TenantBindingDigest = browserbinding.Prefix + strings.Repeat("d", 64)
			v.AuthorityDigest = v.CalculateAuthorityDigest()
			v.RequestDigest = v.CalculateRequestDigest()
			return v
		}(), source, authority, now},
		{"fence drift", func() executorprotocol.Open {
			v := executor
			v.Fence = strings.Repeat("d", 64)
			v.AuthorityDigest = v.CalculateAuthorityDigest()
			v.RequestDigest = v.CalculateRequestDigest()
			return v
		}(), source, authority, now},
		{"authority drift", executor, source, func() browser.SandboxAuthority { v := authority; v.FencingToken++; return v }(), now},
		{"expired", executor, source, authority, now.Add(11 * time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := state.ReserveExecutor(test.open, test.source, test.authority, test.at); !errors.Is(err, reference.ErrStale) {
				t.Fatalf("drift reservation = %v", err)
			}
		})
	}
	stored, _ := state.Get(private.HandoffReference)
	if stored.ConnectionClaims[private.ConnectionEpoch].Status != reference.ConnectionPending || len(stored.ExecutorReplayClaims) != 0 {
		t.Fatal("failed reservation mutated stored state")
	}
}
