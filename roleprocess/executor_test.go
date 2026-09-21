package roleprocess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

type executorTestSession struct {
	input  chan []byte
	output chan []byte
	closed chan struct{}
}

func newExecutorTestSession() *executorTestSession {
	return &executorTestSession{input: make(chan []byte, 2), output: make(chan []byte, 2), closed: make(chan struct{})}
}
func (s *executorTestSession) Read(ctx context.Context) (websocket.MessageType, []byte, error) {
	select {
	case payload := <-s.output:
		return websocket.MessageText, payload, nil
	case <-s.closed:
		return websocket.MessageText, nil, io.EOF
	case <-ctx.Done():
		return websocket.MessageText, nil, ctx.Err()
	}
}
func (s *executorTestSession) Write(_ context.Context, _ websocket.MessageType, payload []byte) error {
	s.input <- append([]byte(nil), payload...)
	return nil
}
func (s *executorTestSession) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

type executorTestBackend struct{ session *executorTestSession }

func (b executorTestBackend) Ready(context.Context) error { return nil }
func (b executorTestBackend) Open(context.Context, executorprotocol.Open) (ExecutorSession, error) {
	return b.session, nil
}

func executorTestOpen() executorprotocol.Open {
	now := time.Now().UTC()
	reference := "ref:desktop-session:" + strings.Repeat("a", 32)
	digest := sha256.Sum256([]byte(reference))
	policy := &desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	value := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleDesktop, RequestID: "request-1", TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("b", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", RuntimeSessionID: "desktop-session-1", CapabilityProfileID: "desktop-v1", MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1", AllocationReference: "ref:desktop/11111111111111111111111111111111", MediaPolicy: policy, MediaPolicyDigest: executorprotocol.PolicyDigest(*policy), HandoffReference: reference, HandoffDigest: fmt.Sprintf("sha256:%x", digest[:]), ConnectionGeneration: 2, ConnectionEpoch: "epoch-1", Fence: strings.Repeat("c", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), Codec: "video/VP8"}
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	value.AuthorityDigest = value.CalculateAuthorityDigest()
	value.RequestDigest = value.CalculateRequestDigest()
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: "provider-desktop-v2", ExecutorRole: executorprotocol.RoleDesktop, ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: value.ProviderRevisionID, TenantBindingDigest: value.TenantBindingDigest, SandboxID: value.SandboxID, RuntimeSessionID: value.RuntimeSessionID, HandoffReferenceDigest: value.HandoffDigest, AllocationReference: value.AllocationReference, MediaPolicy: *value.MediaPolicy, ConnectionGeneration: value.ConnectionGeneration, ConnectionEpoch: value.ConnectionEpoch, Fence: value.Fence, AuthorityExpiresAt: value.AuthorityExpiresAt, HandoffExpiresAt: value.HandoffExpiresAt, NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: value.AuthorityDigest, ExecutorRequestDigest: value.RequestDigest, Nonce: "nonce-abcdefghijklmnopqrstuvwxyz123456"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	envelope, _ := desktopbridge.Sign(statement, privateKey)
	value.Bridge = &envelope
	return value
}

func TestExecutorHandlerRequiresClosedAuthorityAndRelaysFrames(t *testing.T) {
	session := newExecutorTestSession()
	handler, err := NewExecutorHandler(ExecutorHandlerOptions{Role: executorprotocol.RoleDesktop, Backend: executorTestBackend{session: session}, OperationTimeout: time.Second, MaxSessions: 2})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	connection, _, err := websocket.Dial(context.Background(), "wss"+strings.TrimPrefix(server.URL, "https"), &websocket.DialOptions{HTTPClient: server.Client(), Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	open := executorTestOpen()
	document, err := executorprotocol.Encode(open)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(context.Background(), websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, responseDocument, err := connection.Read(context.Background())
	if err != nil || kind != websocket.MessageText {
		t.Fatalf("response kind=%v err=%v", kind, err)
	}
	var response executorprotocol.Response
	if err := executorprotocol.Decode(responseDocument, &response); err != nil || response.Validate() != nil || response.Status != executorprotocol.StatusAccepted {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if err := connection.Write(context.Background(), websocket.MessageText, []byte(`{"method":"stream.configure"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-session.input:
		if string(payload) != `{"method":"stream.configure"}` {
			t.Fatalf("backend payload=%q", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("executor backend did not receive frame")
	}
	session.output <- []byte(`{"ok":true}`)
	_, payload, err := connection.Read(context.Background())
	if err != nil || string(payload) != `{"ok":true}` {
		t.Fatalf("executor response=%q err=%v", payload, err)
	}
}
