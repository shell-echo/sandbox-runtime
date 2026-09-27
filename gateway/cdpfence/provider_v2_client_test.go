package cdpfence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func TestV2ProviderClientSendsCanonicalOpenAndBridgesCDP(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	private, err := admittedProviderOpen(v2IngressOpenFixture(now), now)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan browserhandoffv2.OpenRequest, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != browserhandoffv2.PrivatePath || request.Header.Get("Authorization") != "" {
			http.Error(writer, "wrong private route", http.StatusForbidden)
			return
		}
		conn, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{browserhandoffv2.ProtocolID}})
		if err != nil {
			return
		}
		defer conn.CloseNow()
		kind, document, err := conn.Read(request.Context())
		if err != nil || kind != websocket.MessageText {
			return
		}
		open, err := browserhandoffv2.DecodeOpen(document, time.Now().UTC())
		if err != nil {
			return
		}
		received <- open
		response, _ := handoff.Encode(browserhandoffv2.AcceptedResponse(open.RequestID))
		if conn.Write(request.Context(), websocket.MessageText, response) != nil {
			return
		}
		kind, payload, err := conn.Read(request.Context())
		if err == nil && kind == websocket.MessageText {
			_ = conn.Write(request.Context(), websocket.MessageText, payload)
		}
	}))
	defer server.Close()
	client, err := NewV2ProviderClient(V2ProviderClientOptions{
		Origin:     "wss" + strings.TrimPrefix(server.URL, "https") + browserhandoffv2.PrivatePath,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Open(ctx, private)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close(context.Background())
	if err := stream.Send(ctx, gateway.Frame{Type: gateway.TextFrame, Payload: []byte(`{"id":1,"method":"Browser.getVersion"}`)}); err != nil {
		t.Fatal(err)
	}
	frame, err := stream.Receive(ctx)
	if err != nil || string(frame.Payload) != `{"id":1,"method":"Browser.getVersion"}` {
		t.Fatalf("CDP frame=%s err=%v", frame.Payload, err)
	}
	if actual := <-received; actual != private {
		t.Fatal("Provider received a different authority tuple")
	}
	for _, origin := range []string{"ws://127.0.0.1:1234" + browserhandoffv2.PrivatePath,
		"wss://provider.example.test/browser/action", "wss://provider.example.test/private/browser?bypass=1"} {
		if _, err := NewV2ProviderClient(V2ProviderClientOptions{Origin: origin, HTTPClient: &http.Client{}}); err == nil {
			t.Fatalf("unsafe Provider private origin accepted: %q", origin)
		}
	}
}
