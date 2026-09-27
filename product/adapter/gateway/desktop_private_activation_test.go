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
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/product"
)

func activationTestSource(t *testing.T, server *httptest.Server) *PrivateDesktopMediaSource {
	t.Helper()
	source, err := NewPrivateDesktopMediaSource(PrivateDesktopMediaOptions{
		Origin:     strings.Replace(server.URL, "http://", "ws://", 1),
		HTTPClient: server.Client(), AllowHTTPForTests: true,
		ExpectedProviderID: "provider-desktop-revision", OpenTimeout: 2 * time.Second,
		TenantBindingDigest: func(context.Context, product.GatewayBinding) (string, error) {
			return handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), nil
		},
		ControllerFence: func(context.Context, product.GatewayBinding) (string, error) {
			return strings.Repeat("b", handoff.MinFenceBytes), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func activationTestServer(t *testing.T, afterPrepared func(*websocket.Conn, desktophandoffv2.OpenRequest)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
			Subprotocols:    []string{desktophandoffv2.ProtocolID},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			t.Errorf("accept Desktop v2: %v", err)
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		kind, document, err := connection.Read(ctx)
		var open desktophandoffv2.OpenRequest
		if err != nil || kind != websocket.MessageText || desktophandoffv2.Decode(document, &open) != nil || open.Validate(time.Now().UTC()) != nil {
			t.Errorf("invalid Desktop v2 open: %v", err)
			return
		}
		prepared, _ := handoff.Encode(desktophandoffv2.PreparedResponse(open))
		if err := connection.Write(ctx, websocket.MessageText, prepared); err != nil {
			t.Errorf("write Desktop v2 prepare: %v", err)
			return
		}
		afterPrepared(connection, open)
	}))
}

func TestPrivateDesktopV2ActivationGatesCommandsAndPackets(t *testing.T) {
	server := activationTestServer(t, func(connection *websocket.Conn, open desktophandoffv2.OpenRequest) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		kind, document, err := connection.Read(ctx)
		var start desktophandoffv2.Start
		if err != nil || kind != websocket.MessageText || desktophandoffv2.Decode(document, &start) != nil || start.Validate(open) != nil {
			t.Errorf("invalid Desktop v2 start: %v", err)
			return
		}
		started, _ := handoff.Encode(desktophandoffv2.StartedResponse(start))
		if err := connection.Write(ctx, websocket.MessageText, started); err != nil {
			t.Errorf("write Desktop v2 started: %v", err)
			return
		}
		if err := connection.Write(ctx, websocket.MessageBinary, []byte{1, 0x80, 0x01}); err != nil {
			t.Errorf("write Desktop v2 frame: %v", err)
			return
		}
		_, _, _ = connection.Read(ctx)
	})
	defer server.Close()
	source := activationTestSource(t, server)
	session, err := source.Open(context.Background(), privateDesktopTestBinding(time.Now().Add(time.Minute)), privateDesktopTestPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.Resynchronize(context.Background()); !errors.Is(err, product.ErrControlStale) {
		t.Fatalf("pre-start control admitted: %v", err)
	}
	activator, ok := session.(DesktopLiveMediaActivator)
	if !ok {
		t.Fatal("v2 session has no activation barrier")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := activator.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := activator.Activate(ctx); err != nil {
		t.Fatalf("idempotent local activation: %v", err)
	}
	packet, err := session.ReadVideoRTP(ctx)
	if err != nil || string(packet) != string([]byte{0x80, 0x01}) {
		t.Fatalf("post-start packet=%x err=%v", packet, err)
	}
}

func TestPrivateDesktopV2RejectsBadStartAckAndPreStartMedia(t *testing.T) {
	for _, scenario := range []string{"bad_ack", "early_frame"} {
		t.Run(scenario, func(t *testing.T) {
			server := activationTestServer(t, func(connection *websocket.Conn, open desktophandoffv2.OpenRequest) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if scenario == "early_frame" {
					_ = connection.Write(ctx, websocket.MessageBinary, []byte{1, 0x80, 0x01})
				} else {
					_, document, err := connection.Read(ctx)
					var start desktophandoffv2.Start
					if err != nil || desktophandoffv2.Decode(document, &start) != nil || start.Validate(open) != nil {
						t.Errorf("invalid Desktop v2 start: %v", err)
						return
					}
					started := desktophandoffv2.StartedResponse(start)
					started.StartDigest = "sha256:" + strings.Repeat("0", 64)
					document, _ = handoff.Encode(started)
					_ = connection.Write(ctx, websocket.MessageText, document)
				}
				_, _, _ = connection.Read(ctx)
			})
			defer server.Close()
			source := activationTestSource(t, server)
			session, err := source.Open(context.Background(), privateDesktopTestBinding(time.Now().Add(time.Minute)), privateDesktopTestPolicy())
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := session.(DesktopLiveMediaActivator).Activate(ctx); err == nil {
				t.Fatal("invalid activation response admitted")
			}
			if _, err := session.ReadVideoRTP(ctx); err == nil {
				t.Fatal("media delivered after invalid activation")
			}
		})
	}
}
