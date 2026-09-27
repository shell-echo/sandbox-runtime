package cdpfence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

type fencedResolverFunc func(context.Context, string, gateway.DownstreamFenceSubject, gateway.DownstreamFence) (gateway.Endpoint, error)

func (f fencedResolverFunc) ResolveFenced(ctx context.Context, reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (gateway.Endpoint, error) {
	return f(ctx, reference, subject, fence)
}

func TestNetworkHandlerPassesExactClaimToFencedResolverInsideIngress(t *testing.T) {
	subject := testSubject("browser-fenced")
	subject.ExpiresAt = subject.ExpiresAt.Round(0)
	fence := testFence(t, "exact-claim")
	reference := "ref:browser-session:00000000000000000000000000000001"
	checks := make(chan struct{}, 1)
	ingress := newTestIngress(t, Options{Authority: authorityFunc(func(_ context.Context, got gateway.DownstreamFenceSubject, claim gateway.DownstreamFence, _ time.Duration) (gateway.DownstreamFenceDecision, error) {
		if got != subject || claim.Opaque() != fence.Opaque() {
			t.Error("action authority did not receive exact subject and claim")
		}
		checks <- struct{}{}
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	})})
	downstream := newBlockingStream()
	handler, err := NewNetworkHandler(NetworkOptions{Ingress: ingress, AllowInsecureHTTPForTests: true,
		FencedResolver: fencedResolverFunc(func(_ context.Context, gotRef string, got gateway.DownstreamFenceSubject, claim gateway.DownstreamFence) (gateway.Endpoint, error) {
			if gotRef != reference || got != subject || claim.Opaque() != fence.Opaque() {
				t.Error("fenced resolver did not receive exact admitted subject and claim")
			}
			select {
			case <-checks:
			default:
				t.Error("fenced resolver ran before ingress action admission")
			}
			return gateway.Endpoint{Reference: reference, SandboxID: subject.SandboxID, BrowserSessionID: subject.BrowserSessionID,
				CapabilityProfileID: subject.CapabilityProfileID, ConnectionGeneration: subject.ConnectionGeneration,
				ExpiresAt: subject.ExpiresAt, Dial: func(context.Context) (gateway.Stream, error) { return downstream, nil }}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	headers := http.Header{}
	headers.Set("Authorization", "Downstream "+fence.Opaque())
	headers.Set(privateBrowserReferenceHeader, reference)
	headers.Set(privateBrowserTenantHeader, subject.TenantID)
	headers.Set(privateBrowserSandboxHeader, subject.SandboxID)
	headers.Set(privateBrowserSessionHeader, subject.BrowserSessionID)
	headers.Set(privateBrowserProfileHeader, subject.CapabilityProfileID)
	headers.Set(privateBrowserGenerationHeader, strconv.FormatInt(subject.ConnectionGeneration, 10))
	headers.Set(privateBrowserExpiryHeader, subject.ExpiresAt.Format(time.RFC3339Nano))
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"), &websocket.DialOptions{
		HTTPHeader: headers, Subprotocols: []string{PrivateBrowserSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	connection.CloseNow()
	select {
	case <-downstream.closed:
	case <-time.After(time.Second):
		t.Fatal("network ingress did not close the unique downstream")
	}
}

func TestNetworkHandlerRejectsAmbiguousResolverSelection(t *testing.T) {
	ingress := newTestIngress(t, Options{Authority: authorityFunc(func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence, time.Duration) (gateway.DownstreamFenceDecision, error) {
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	})})
	resolver := fencedResolverFunc(func(context.Context, string, gateway.DownstreamFenceSubject, gateway.DownstreamFence) (gateway.Endpoint, error) {
		return gateway.Endpoint{}, nil
	})
	if handler, err := NewNetworkHandler(NetworkOptions{Ingress: ingress, FencedResolver: resolver, Resolver: legacyResolverSpy{}, AllowInsecureHTTPForTests: true}); handler != nil || err == nil {
		t.Fatalf("ambiguous resolver selection = %#v, %v", handler, err)
	}
}

type legacyResolverSpy struct{}

func (legacyResolverSpy) Resolve(context.Context, string) (gateway.Endpoint, error) {
	return gateway.Endpoint{}, nil
}
