package productgateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/browseringress"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func TestPrivateBrowserV2ResolverSendsOnlyCommittedProjectionToActionIngress(t *testing.T) {
	binding := ingressBindingFixture()
	receivedCh := make(chan browseringress.Open, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != cdpfence.BrowserActionV2Path || request.Header.Get("Authorization") != "" {
			http.Error(writer, "bad private route", http.StatusForbidden)
			return
		}
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{browseringress.ProtocolID}})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		kind, document, err := connection.Read(request.Context())
		if err != nil || kind != websocket.MessageText {
			return
		}
		received, err := browseringress.DecodeOpen(document, time.Now().UTC())
		if err != nil {
			return
		}
		receivedCh <- received
		response, _ := handoff.Encode(browseringress.AcceptedResponse(received.RequestID))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		_, _, _ = connection.Read(request.Context())
	}))
	defer server.Close()
	resolver, err := NewPrivateBrowserV2Resolver(PrivateBrowserV2ResolverOptions{
		Origin:     "wss" + strings.TrimPrefix(server.URL, "https") + cdpfence.BrowserActionV2Path,
		HTTPClient: server.Client(), Binding: binding,
	})
	if err != nil {
		t.Fatal(err)
	}
	fence, err := gateway.NewDownstreamFence("v1.opaque-capacity-claim")
	if err != nil {
		t.Fatal(err)
	}
	subject := gateway.DownstreamFenceSubject{TenantID: binding.TenantID, SandboxID: binding.SandboxID,
		BrowserSessionID: binding.SessionID, CapabilityProfileID: browserhandoffv2.CapabilityProfileID,
		ConnectionGeneration: binding.ConnectionGeneration, ExpiresAt: binding.ExpiresAt}
	endpoint, err := resolver.ResolveFenced(context.Background(), binding.HandoffReference, subject, fence)
	if err != nil || endpoint.Dial == nil || endpoint.CapabilityProfileID != browserhandoffv2.CapabilityProfileID {
		t.Fatalf("v2 endpoint: %+v, %v", endpoint, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := endpoint.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	received := <-receivedCh
	if received.TenantBindingDigest != binding.BrowserTenantBindingDigest ||
		received.ProviderAudience != binding.BrowserProviderAudience ||
		received.CapacityClaim != fence.Opaque() ||
		received.ControlLeaseDigest == "" || received.ControlLeaseDigest == binding.ControlLeaseID {
		t.Fatal("Gateway did not send the exact private projection")
	}
	staleSubject := subject
	staleSubject.ConnectionGeneration++
	if _, err := resolver.ResolveFenced(context.Background(), binding.HandoffReference, staleSubject, fence); !errors.Is(err, gateway.ErrDownstreamUnavailable) {
		t.Fatalf("stale generation admitted: %v", err)
	}
}

func TestPrivateBrowserV2ResolverRejectsNonV2AndInsecureProductionOrigin(t *testing.T) {
	binding := ingressBindingFixture()
	for _, origin := range []string{"ws://127.0.0.1:1234" + cdpfence.BrowserActionV2Path,
		"wss://browser.example.test/private/browser", "wss://browser.example.test/browser/action?bypass=1"} {
		if _, err := NewPrivateBrowserV2Resolver(PrivateBrowserV2ResolverOptions{Origin: origin,
			HTTPClient: &http.Client{}, Binding: binding}); err == nil {
			t.Fatalf("unsafe Browser ingress origin accepted: %q", origin)
		}
	}
}
