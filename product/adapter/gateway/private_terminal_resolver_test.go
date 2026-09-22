package productgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
	terminalgateway "github.com/shell-echo/sandbox-runtime/provider/terminal/gateway"
)

type privateTerminalTestStream struct {
	readCh  chan []byte
	writes  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

func newPrivateTerminalTestStream() *privateTerminalTestStream {
	return &privateTerminalTestStream{readCh: make(chan []byte, 2), writes: make(chan []byte, 2), closeCh: make(chan struct{})}
}

func (s *privateTerminalTestStream) Read(ctx context.Context, payload []byte) (int, error) {
	select {
	case value := <-s.readCh:
		copy(payload, value)
		return len(value), nil
	case <-s.closeCh:
		return 0, io.EOF
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (s *privateTerminalTestStream) Write(_ context.Context, payload []byte) (int, error) {
	s.writes <- append([]byte(nil), payload...)
	return len(payload), nil
}

func (s *privateTerminalTestStream) Close() error {
	s.once.Do(func() { close(s.closeCh) })
	return nil
}

type privateTerminalTestResolver struct {
	stream  *privateTerminalTestStream
	expires time.Time
}

func (r privateTerminalTestResolver) Resolve(_ context.Context, value string) (reference.Endpoint, error) {
	return reference.Endpoint{Reference: value, SandboxID: "sandbox-1", RuntimeSessionID: "session-1", CapabilityProfileID: "terminal-v1", ConnectionGeneration: 3, ExpiresAt: r.expires, TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("b", 64), Dial: func(context.Context) (terminal.Stream, error) { return r.stream, nil }}, nil
}

type privateTerminalTestTenant struct{}

func (privateTerminalTestTenant) AuthorizeHandoff(_ context.Context, request handoff.OpenRequest) error {
	if request.TenantID != "tenant-1" || request.Fence == "" {
		return errors.New("invalid tenant binding")
	}
	return nil
}

func TestPrivateTerminalResolverRoundTripsOpaqueAttach(t *testing.T) {
	stream := newPrivateTerminalTestStream()
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Nanosecond)
	handler, err := terminalgateway.New(terminalgateway.Options{Resolver: privateTerminalTestResolver{stream: stream, expires: expires}, TenantAuthorizer: privateTerminalTestTenant{}, AllowInsecureHTTPForTests: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	resolver, err := NewPrivateTerminalResolver(PrivateTerminalResolverOptions{Origin: strings.Replace(server.URL, "http://", "ws://", 1) + "/handoff", HTTPClient: server.Client(), AllowHTTPForTests: true,
		TenantBindingDigest: func(context.Context, gateway.Grant) (string, error) {
			return handoff.TenantBindingDigestPrefix + strings.Repeat("b", 64), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := gateway.Grant{GrantID: "grant-1", CallerID: "caller-1", TenantID: "tenant-1", SandboxID: "sandbox-1", RuntimeSessionID: "session-1", CapabilityProfileID: "terminal-v1", HandoffReference: "ref:session:opaque", ConnectionGeneration: 3, ExpiresAt: expires}
	endpoint, err := resolver.ResolveBound(context.Background(), grant)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := endpoint.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Send(context.Background(), gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("input")}); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-stream.writes:
		if string(value) != "input" {
			t.Fatalf("Provider received %q", value)
		}
	case <-time.After(time.Second):
		t.Fatal("Provider did not receive terminal input")
	}
	stream.readCh <- []byte("output")
	frame, err := backend.Receive(context.Background())
	if err != nil || string(frame.Payload) != "output" || frame.Type != gateway.BinaryFrame {
		t.Fatalf("terminal output=%#v err=%v", frame, err)
	}
	_ = backend.Close(context.Background())
}

func TestPrivateTerminalHandlerRequiresTenantAuthority(t *testing.T) {
	if _, err := terminalgateway.New(terminalgateway.Options{Resolver: privateTerminalTestResolver{stream: newPrivateTerminalTestStream()}, AllowInsecureHTTPForTests: true}); err == nil {
		t.Fatal("private terminal handler accepted missing tenant authority")
	}
}

func TestRandomTokenAlwaysSatisfiesPrivateHandoffGrammar(t *testing.T) {
	now := time.Now().UTC()
	for iteration := 0; iteration < 10_000; iteration++ {
		requestID, err := randomRequestID()
		if err != nil {
			t.Fatal(err)
		}
		fence, err := randomToken(32)
		if err != nil {
			t.Fatal(err)
		}
		request := handoff.OpenRequest{
			Protocol: handoff.ProtocolID, RequestID: requestID, Resource: handoff.ResourceTerminal,
			TenantID: "tenant-1", SandboxID: "sandbox-1", RuntimeSessionID: "session-1",
			CapabilityProfileID: "terminal-v1", HandoffReference: "ref:session:opaque",
			ConnectionGeneration: 3, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Fence: fence,
		}
		if err := request.Validate(now); err != nil {
			t.Fatalf("iteration %d request_id=%q fence=%q: %v", iteration, requestID, fence, err)
		}
	}
}

func TestRequestIDPrefixesBase64URLBoundaryBytesWithoutLosingEntropy(t *testing.T) {
	now := time.Now().UTC()
	for name, first := range map[string]byte{"dash": 0xf8, "underscore": 0xfc} {
		t.Run(name, func(t *testing.T) {
			random := make([]byte, 16)
			random[0] = first
			raw := base64.RawURLEncoding.EncodeToString(random)
			if raw[0] != map[string]byte{"dash": '-', "underscore": '_'}[name] {
				t.Fatalf("test vector encoded as %q", raw)
			}
			requestID := requestIDFromRandom(random)
			if len(requestID) != 23 || requestID[0] != 'r' {
				t.Fatalf("request ID=%q length=%d", requestID, len(requestID))
			}
			decoded, err := base64.RawURLEncoding.DecodeString(requestID[1:])
			if err != nil || !bytes.Equal(decoded, random) {
				t.Fatalf("request ID lost random bytes: decoded=%x err=%v", decoded, err)
			}
			request := handoff.OpenRequest{
				Protocol: handoff.ProtocolID, RequestID: requestID, Resource: handoff.ResourceTerminal,
				TenantID: "tenant-1", SandboxID: "sandbox-1", RuntimeSessionID: "session-1",
				CapabilityProfileID: "terminal-v1", HandoffReference: "ref:session:opaque",
				ConnectionGeneration: 3, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
				Fence: strings.Repeat("a", handoff.MinFenceBytes),
			}
			if err := request.Validate(now); err != nil {
				t.Fatal(err)
			}
		})
	}
}
