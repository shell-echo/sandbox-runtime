package browsergateway

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoff"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

type testStream struct {
	input  chan []byte
	output chan []byte
	closed chan struct{}
}

func newTestStream() *testStream {
	return &testStream{input: make(chan []byte, 2), output: make(chan []byte, 2), closed: make(chan struct{})}
}
func (s *testStream) Read(ctx context.Context, payload []byte) (int, error) {
	select {
	case value := <-s.output:
		copy(payload, value)
		return len(value), nil
	case <-s.closed:
		return 0, io.EOF
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (s *testStream) Write(_ context.Context, payload []byte) (int, error) {
	s.input <- append([]byte(nil), payload...)
	return len(payload), nil
}
func (s *testStream) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

type testResolver struct {
	stream  *testStream
	expires time.Time
}

func (r testResolver) Resolve(_ context.Context, value string) (reference.Endpoint, error) {
	return reference.Endpoint{Reference: value, SandboxID: "sandbox-1", BrowserSessionID: "browser-1", CapabilityProfileID: "browser-v1", ConnectionGeneration: 2, ExpiresAt: r.expires, TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), Dial: func(context.Context) (providerbrowser.Stream, error) { return r.stream, nil }}, nil
}

type testBinding struct{}

func (testBinding) AuthorizeHandoff(_ context.Context, request browserhandoff.OpenRequest) error {
	if request.TenantBindingDigest == "" {
		return errors.New("missing binding")
	}
	return nil
}

func TestPrivateBrowserHandlerRoundTrip(t *testing.T) {
	stream := newTestStream()
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Nanosecond)
	handler, err := New(Options{Resolver: testResolver{stream: stream, expires: expires}, BindingAuthorizer: testBinding{}, AllowInsecureHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	connection, _, err := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")+"/private", &websocket.DialOptions{HTTPClient: server.Client(), Subprotocols: []string{browserhandoff.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	request := browserhandoff.OpenRequest{Protocol: browserhandoff.ProtocolID, RequestID: "request-1", Resource: browserhandoff.ResourceBrowser,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), SandboxID: "sandbox-1", BrowserSessionID: "browser-1", CapabilityProfileID: "browser-v1", HandoffReference: "ref:browser-session:opaque", ConnectionGeneration: 2, ExpiresAt: expires.Format(time.RFC3339Nano), Fence: strings.Repeat("b", handoff.MinFenceBytes)}
	document, _ := handoff.Encode(request)
	if err := connection.Write(context.Background(), websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, responseDocument, err := connection.Read(context.Background())
	if err != nil || kind != websocket.MessageText {
		t.Fatalf("response kind=%v err=%v", kind, err)
	}
	var response browserhandoff.OpenResponse
	if err := handoff.Decode(responseDocument, &response); err != nil || response.Validate() != nil || response.Status != browserhandoff.StatusAccepted {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"method":"Page.enable"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-stream.input:
		if string(value) != `{"method":"Page.enable"}` {
			t.Fatalf("input=%q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("Provider stream did not receive Browser frame")
	}
	stream.output <- []byte(`{"result":{}}`)
	_, output, err := connection.Read(context.Background())
	if err != nil || string(output) != `{"result":{}}` {
		t.Fatalf("output=%q err=%v", output, err)
	}
}
