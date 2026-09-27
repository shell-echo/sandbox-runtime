package reference_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference/repository/memory"
)

type refClock struct{ now time.Time }

func (c refClock) Now() time.Time { return c.now }

type refStream struct{}

func (refStream) Read(context.Context, []byte) (int, error)  { return 0, io.EOF }
func (refStream) Write(context.Context, []byte) (int, error) { return 0, nil }
func (refStream) Close() error                               { return nil }

type refAttacher struct{ calls int }

func (a *refAttacher) Attach(context.Context, browser.AllocationReceipt) (browser.Stream, error) {
	a.calls++
	return refStream{}, nil
}

type connectionAttacher struct {
	refAttacher
	connectionCalls int
}

func (a *connectionAttacher) AttachConnection(_ context.Context, _ reference.Record, _ string) (browser.Stream, error) {
	a.connectionCalls++
	return refStream{}, nil
}

func runningRecord(t *testing.T, now time.Time) (browser.Record, browser.AllocationReceipt) {
	t.Helper()
	request := browser.OpenRequest{SandboxID: "sandbox-1", ProviderRevisionID: "revision-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, IdempotencyKey: "key-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(time.Hour), ExpectedGeneration: 1, BrowserSessionID: "browser-session-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute)}
	record, err := browser.NewRecord(request, now)
	if err != nil {
		t.Fatal(err)
	}
	receipt := browser.AllocationReceipt{Reference: "ref:browser/11111111111111111111111111111111", SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1, AllocatedAt: now.Add(time.Second), ExpiresAt: request.ExpiresAt}
	record, err = browser.AttachAllocation(record, receipt)
	if err != nil {
		t.Fatal(err)
	}
	return record, receipt
}

func TestBrowserReferenceAcceptsV2TenantBindingWithoutReinterpretingV1(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	source, _ := runningRecord(t, now)
	referenceID := "ref:browser-session:" + strings.Repeat("1", 32)
	createdAt := now.Add(2 * time.Second)
	for _, digest := range []string{
		"sha256:v1:" + strings.Repeat("a", 64),
		"hmac-sha256:v2:" + strings.Repeat("b", 64),
	} {
		record, err := reference.NewRecordWithTenantBinding(referenceID, source, digest, createdAt)
		if err != nil || record.TenantBindingDigest != digest {
			t.Fatalf("reference binding %q = %#v, %v", digest, record, err)
		}
	}
	if _, err := reference.NewRecordWithTenantBinding(referenceID, source, "hmac-sha256:v2:"+strings.Repeat("B", 64), createdAt); err == nil {
		t.Fatal("noncanonical Browser v2 binding accepted")
	}
}

func TestConnectionResolverUsesExactStoredPrivateClaim(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	running, _ := runningRecord(t, now)
	referenceID := "ref:browser-session:" + strings.Repeat("4", 32)
	tenantDigest := browserbinding.Prefix + strings.Repeat("b", 64)
	record, err := reference.NewRecordWithTenantBinding(referenceID, running, tenantDigest, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	private := browserhandoffv2.OpenRequest{BindingVersion: browserhandoffv2.BindingVersion,
		BindingIssuer: browserhandoffv2.BindingIssuer, Protocol: browserhandoffv2.ProtocolID,
		RequestID: "private-1", Resource: browserhandoffv2.ResourceBrowser,
		TenantBindingDigest: tenantDigest, ProviderRevisionID: running.Request.ProviderRevisionID,
		SandboxID: running.Request.SandboxID, BrowserSessionID: running.Request.BrowserSessionID,
		CapabilityProfileID: browser.CapabilityProfileID, MediaProfileID: browserhandoffv2.MediaProfileID,
		ControlProfileID: browserhandoffv2.ControlProfileID, HandoffReference: referenceID,
		HandoffDigest: browserhandoffv2.ReferenceDigest(referenceID), ConnectionGeneration: 1,
		ConnectionEpoch: "epoch-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 1, AuthorityExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt: record.ExpiresAt.Format(time.RFC3339Nano)}
	private.AuthorityDigest = browserhandoffv2.AuthorityDigest(private)
	private.RequestDigest = browserhandoffv2.RequestDigest(private)
	claim, err := reference.ConnectionFromOpen(private, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	record.ConnectionClaims = map[string]reference.ConnectionClaim{private.ConnectionEpoch: claim}
	registry := memory.NewRegistry()
	if err := registry.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	attacher := &connectionAttacher{}
	resolver, err := reference.NewResolver(registry, authorityReader{record: succeededRecord(t, running, referenceID, now.Add(3*time.Second))},
		attacher, refClock{now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolver.ResolveConnection(context.Background(), private)
	if err != nil {
		t.Fatal(err)
	}
	if stream, err := endpoint.Dial(context.Background()); err != nil || stream == nil || attacher.connectionCalls != 1 || attacher.calls != 0 {
		t.Fatalf("exact v2 connection attach: stream=%v err=%v calls=%d legacy=%d", stream, err, attacher.connectionCalls, attacher.calls)
	}
	drift := private
	drift.ConnectionEpoch = "epoch-2"
	drift.AuthorityDigest = browserhandoffv2.AuthorityDigest(drift)
	drift.RequestDigest = browserhandoffv2.RequestDigest(drift)
	if _, err := resolver.ResolveConnection(context.Background(), drift); err == nil {
		t.Fatal("unpersisted epoch resolved")
	}
	if err := registry.Revoke(context.Background(), referenceID, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Dial(context.Background()); err == nil {
		t.Fatal("revoked reference remained dialable")
	}
}

func succeededRecord(t *testing.T, running browser.Record, reference string, now time.Time) browser.Record {
	t.Helper()
	record, err := browser.Transition(running, browser.StatusSucceeded, now, &browser.EndpointEvidence{InternalEndpointReference: reference, ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestRegistrarResolverRequiresCommittedHandoffAndRechecksOnDial(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	running, _ := runningRecord(t, now)
	registry := memory.NewRegistry()
	registrar, err := reference.NewRegistrar(registry, refClock{now: now.Add(2 * time.Second)}, func() (string, error) { return "ref:browser-session:11111111111111111111111111111111", nil })
	if err != nil {
		t.Fatal(err)
	}
	registration, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	pendingResolver, err := reference.NewResolver(registry, authorityReader{record: running}, &refAttacher{}, refClock{now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pendingResolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("uncommitted resolve = %v", err)
	}
	committed := succeededRecord(t, running, registration.Record.Reference, now.Add(3*time.Second))
	reader := authorityReader{record: committed}
	attacher := &refAttacher{}
	resolver, err := reference.NewResolver(registry, reader, attacher, refClock{now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := resolver.Resolve(context.Background(), registration.Record.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.BrowserSessionID != "browser-session-1" {
		t.Fatalf("endpoint = %#v", endpoint)
	}
	if _, err := endpoint.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	if attacher.calls != 1 {
		t.Fatalf("attach calls = %d", attacher.calls)
	}
	if err := registry.Revoke(context.Background(), registration.Record.Reference, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Dial(context.Background()); !errors.Is(err, reference.ErrRevoked) {
		t.Fatalf("dial after revoke = %v", err)
	}
	if attacher.calls != 1 {
		t.Fatalf("attach calls after revoke = %d", attacher.calls)
	}
}

type authorityReader struct{ record browser.Record }

func (r authorityReader) GetOpen(context.Context, string) (browser.Record, error) {
	return r.record.Clone(), nil
}

type fencedAuthorityReader struct {
	authorityReader
	authority browser.SandboxAuthority
}

func (r fencedAuthorityReader) GetSandboxAuthority(context.Context, string) (browser.SandboxAuthority, error) {
	return r.authority.Clone(), nil
}

func TestResolverRejectsCurrentAuthorityDrift(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	running, _ := runningRecord(t, now)
	registry := memory.NewRegistry()
	registrar, err := reference.NewRegistrar(registry, refClock{now: now.Add(2 * time.Second)}, func() (string, error) {
		return "ref:browser-session:33333333333333333333333333333333", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	registration, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	succeeded := succeededRecord(t, running, registration.Record.Reference, now.Add(3*time.Second))
	authority := browser.SandboxAuthority{SandboxID: running.Request.SandboxID, ProviderRevisionID: running.Request.ProviderRevisionID,
		Ready: true, Generation: 1, FencingToken: 1, LeaseExpiresAt: now.Add(time.Hour), CapabilityProfileID: browser.CapabilityProfileID,
		NetworkPolicyReference: "browser-egress-policy-1"}
	reader := fencedAuthorityReader{authorityReader: authorityReader{record: succeeded}, authority: authority}
	resolver, err := reference.NewResolver(registry, reader, &refAttacher{}, refClock{now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), registration.Record.Reference); err != nil {
		t.Fatalf("current authority rejected: %v", err)
	}
	reader.authority.FencingToken = 2
	resolver, err = reference.NewResolver(registry, reader, &refAttacher{}, refClock{now: now.Add(4 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), registration.Record.Reference); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("fenced authority retained Browser handoff: %v", err)
	}
}

func TestRegistrarReplayAndRevocationFailClosed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	running, _ := runningRecord(t, now)
	registry := memory.NewRegistry()
	registrar, err := reference.NewRegistrar(registry, refClock{now: now.Add(time.Second)}, func() (string, error) { return "ref:browser-session:22222222222222222222222222222222", nil })
	if err != nil {
		t.Fatal(err)
	}
	first, err := registrar.Register(context.Background(), running)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registrar.Register(context.Background(), running)
	if err != nil || second.Record.Reference != first.Record.Reference {
		t.Fatalf("replay = %#v, %v", second, err)
	}
	if err := registry.Revoke(context.Background(), first.Record.Reference, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	resolver, err := reference.NewResolver(registry, authorityReader{record: succeededRecord(t, running, first.Record.Reference, now.Add(2*time.Second))}, &refAttacher{}, refClock{now: now.Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), first.Record.Reference); !errors.Is(err, reference.ErrRevoked) {
		t.Fatalf("revoked resolve = %v", err)
	}
}
