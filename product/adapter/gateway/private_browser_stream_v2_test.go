package productgateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
)

func TestPrivateBrowserV2StreamUnknownWriteOutcomeIsTerminal(t *testing.T) {
	for name, closeCode := range map[string]websocket.StatusCode{
		"normal close with pending action": websocket.StatusNormalClosure,
		"witness unavailable":              cdpfence.BrowserActionUnavailableCloseCode,
		"fence lost":                       cdpfence.BrowserActionFenceLostCloseCode,
	} {
		t.Run(name, func(t *testing.T) {
			stream, cleanup := browserV2StreamFixture(t, func(conn *websocket.Conn, ctx context.Context) {
				_, _, _ = conn.Read(ctx)
				_ = conn.Close(closeCode, "closed")
			})
			defer cleanup()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := stream.Send(ctx, gateway.Frame{Type: gateway.TextFrame, Payload: []byte(`{"id":1,"method":"Runtime.evaluate"}`)}); err != nil {
				t.Fatal(err)
			}
			_, err := stream.Receive(ctx)
			want := gateway.ErrDownstreamUnavailable
			if closeCode == cdpfence.BrowserActionFenceLostCloseCode {
				want = gateway.ErrDownstreamFenceLost
			}
			if !errors.Is(err, want) {
				t.Fatalf("unknown write was reconnectable: %v", err)
			}
		})
	}
}

func TestPrivateBrowserV2StreamReconnectsOnlyAfterConfirmedIdleClose(t *testing.T) {
	stream, cleanup := browserV2StreamFixture(t, func(conn *websocket.Conn, ctx context.Context) {
		_ = conn.Close(websocket.StatusNormalClosure, "idle")
	})
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := stream.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("confirmed idle close not reconnectable: %v", err)
	}
	completed, stop := browserV2StreamFixture(t, func(conn *websocket.Conn, ctx context.Context) {
		_, _, _ = conn.Read(ctx)
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"id":1,"result":{"result":{"value":"done"}}}`))
		_ = conn.Close(websocket.StatusNormalClosure, "completed")
	})
	defer stop()
	if err := completed.Send(ctx, gateway.Frame{Type: gateway.TextFrame, Payload: []byte(`{"id":1,"method":"Runtime.evaluate"}`)}); err != nil {
		t.Fatal(err)
	}
	if frame, err := completed.Receive(ctx); err != nil || !strings.Contains(string(frame.Payload), `"done"`) {
		t.Fatalf("completed response=%s err=%v", frame.Payload, err)
	}
	if _, err := completed.Receive(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("completed close not reconnectable: %v", err)
	}
}

func browserV2StreamFixture(t *testing.T, serve func(*websocket.Conn, context.Context)) (*privateBrowserV2Stream, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		conn, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		serve(conn, request.Context())
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, _, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(server.URL, "https"),
		&websocket.DialOptions{HTTPClient: server.Client()})
	cancel()
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return newPrivateBrowserV2Stream(conn, defaultAutomationMessageSize), func() {
		_ = conn.CloseNow()
		server.Close()
	}
}
