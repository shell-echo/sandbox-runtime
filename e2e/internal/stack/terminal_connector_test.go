package stack

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

type terminalHandoffReaderStub struct {
	handoff sessionapplication.Handoff
	err     error
}

func (s terminalHandoffReaderStub) GetHandoff(context.Context, string) (sessionapplication.Handoff, error) {
	return s.handoff, s.err
}

type terminalEndpointResolverStub struct {
	endpoint sessionreference.Endpoint
	err      error
}

func (s terminalEndpointResolverStub) Resolve(context.Context, string) (sessionreference.Endpoint, error) {
	return s.endpoint, s.err
}

type terminalStreamStub struct{}

func (terminalStreamStub) Read(context.Context, []byte) (int, error)  { return 0, io.EOF }
func (terminalStreamStub) Write(context.Context, []byte) (int, error) { return 0, nil }
func (terminalStreamStub) Close() error                               { return nil }

func TestTerminalConnectorRevalidatesRetainedHandoffAndEndpoint(t *testing.T) {
	now := time.Date(2026, 9, 18, 7, 0, 0, 0, time.UTC)
	handoff := sessionapplication.Handoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 7, SandboxID: "sandbox-1",
		RuntimeSessionID: "runtime-session-1", RuntimeType: session.RuntimeTerminal,
		CapabilityProfileID: "terminal-v1", Protocol: session.ProtocolWebSocket,
		InternalEndpointReference: "ref:session:0123456789abcdef0123456789abcdef",
		ConnectionGeneration:      2, ExpiresAt: now.Add(time.Minute),
	}
	stream := terminalStreamStub{}
	endpoint := sessionreference.Endpoint{
		Reference: handoff.InternalEndpointReference, SandboxID: handoff.SandboxID,
		RuntimeSessionID: handoff.RuntimeSessionID, CapabilityProfileID: handoff.CapabilityProfileID,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: handoff.ExpiresAt,
		Dial: func(context.Context) (terminal.Stream, error) { return stream, nil },
	}
	connector := terminalConnector{
		sessions: terminalHandoffReaderStub{handoff: handoff},
		resolver: terminalEndpointResolverStub{endpoint: endpoint},
	}
	connected, err := connector.ConnectRuntimeSession(context.Background(), handoff)
	if err != nil || connected != stream {
		t.Fatalf("ConnectRuntimeSession() = (%T, %v), want retained stream", connected, err)
	}

	stale := handoff
	stale.ConnectionGeneration++
	if _, err := connector.ConnectRuntimeSession(context.Background(), stale); !errors.Is(err, providerapi.ErrRuntimeSessionConnectConflict) {
		t.Fatalf("stale ConnectRuntimeSession() error = %v", err)
	}

	connector.resolver = terminalEndpointResolverStub{err: sessionreference.ErrRevoked}
	if _, err := connector.ConnectRuntimeSession(context.Background(), handoff); !errors.Is(err, providerapi.ErrRuntimeSessionConnectGone) {
		t.Fatalf("revoked ConnectRuntimeSession() error = %v", err)
	}
}
