package providerapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type runtimeSessionConnectorSpy struct {
	mu        sync.Mutex
	calls     int
	requested sessionapplication.Handoff
	stream    terminal.Stream
	err       error
}

func (s *runtimeSessionConnectorSpy) ConnectRuntimeSession(_ context.Context, requested sessionapplication.Handoff) (terminal.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.requested = requested
	return s.stream, s.err
}

func (s *runtimeSessionConnectorSpy) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type inertTerminalStream struct{ closed bool }

func (*inertTerminalStream) Read(context.Context, []byte) (int, error)  { return 0, io.EOF }
func (*inertTerminalStream) Write(context.Context, []byte) (int, error) { return 0, io.ErrClosedPipe }
func (s *inertTerminalStream) Close() error                             { s.closed = true; return nil }

func TestProtectedRuntimeSessionConnectAdmitsDescriptorBeforeResolution(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stream := &inertTerminalStream{}
	connector := &runtimeSessionConnectorSpy{stream: stream}
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{}), SessionConnector: connector,
		Now: func() time.Time { return releaseGateTestTime() }, capabilitySnapshot: terminalConnectSnapshotForTest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	document := runtimeSessionConnectDocumentForTest(t)
	request := newRuntimeSessionConnectRequest(t, material.client, privateKey, document)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if connector.Calls() != 1 {
		t.Fatalf("connector calls = %d, want 1; response=%d %s", connector.Calls(), response.Code, response.Body.String())
	}
	if connector.requested.InternalEndpointReference != "ref:session:0123456789abcdef0123456789abcdef" ||
		connector.requested.RuntimeSessionID != "session-1" || !stream.closed {
		t.Fatalf("connector request=%#v stream_closed=%t", connector.requested, stream.closed)
	}
}

func TestProtectedRuntimeSessionConnectRejectsMalformedCarrierBeforeResolution(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	connector := &runtimeSessionConnectorSpy{stream: &inertTerminalStream{}}
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{}), SessionConnector: connector,
		Now: func() time.Time { return releaseGateTestTime() }, capabilitySnapshot: terminalConnectSnapshotForTest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := newRuntimeSessionConnectRequest(t, material.client, privateKey, runtimeSessionConnectDocumentForTest(t))
	request.Header.Set(runtimeSessionHandoffHeader, "not+base64")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || connector.Calls() != 0 {
		t.Fatalf("response=%d connector_calls=%d body=%s", response.Code, connector.Calls(), response.Body.String())
	}
}

func TestProtectedRuntimeSessionConnectAdvertisementMatchesComposition(t *testing.T) {
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gate := newTestProtectedGateWithPublicKey(t, publicKey, &testAdmissionGuard{})
	if _, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: gate, SessionConnector: &runtimeSessionConnectorSpy{stream: &inertTerminalStream{}},
	}); err == nil {
		t.Fatal("connector without terminal-connect advertisement was accepted")
	}
	if _, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: gate, capabilitySnapshot: terminalConnectSnapshotForTest(),
	}); err == nil {
		t.Fatal("terminal-connect advertisement without connector was accepted")
	}
}

func TestRuntimeSessionConnectDescriptorRequiresBoundedAuthority(t *testing.T) {
	document := runtimeSessionConnectDocumentForTest(t)
	admitted := newProtectedReleaseContext(protectedReleaseRoute{
		method: http.MethodGet, path: "/v1/runtime-sessions:connect", operation: admission.OperationConnectRuntimeSession,
	})
	admitted.DeadlineAt = releaseGateTestTime().Add(4 * time.Minute).Format(time.RFC3339Nano)
	if _, err := decodeRuntimeSessionConnectDescriptor(document, admitted, releaseGateTestTime()); err == nil {
		t.Fatal("descriptor accepted an admission deadline after handoff expiry")
	}
	admitted.DeadlineAt = releaseGateTestTime().Add(2 * time.Minute).Format(time.RFC3339Nano)
	admitted.SandboxID = "other-sandbox"
	if _, err := decodeRuntimeSessionConnectDescriptor(document, admitted, releaseGateTestTime()); err == nil {
		t.Fatal("descriptor accepted a sandbox binding mismatch")
	}
}

func runtimeSessionConnectDocumentForTest(t *testing.T) []byte {
	t.Helper()
	document, err := json.Marshal(providerv1.RuntimeSessionHandoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		RuntimeSessionID: "session-1", RuntimeType: providerv1.TerminalRuntimeTerminal,
		CapabilityProfileID: "terminal-v1", Protocol: providerv1.TerminalProtocolWebSocket,
		InternalEndpointReference: "ref:session:0123456789abcdef0123456789abcdef", ConnectionGeneration: 1,
		ExpiresAt: releaseGateTestTime().Add(3 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func newRuntimeSessionConnectRequest(t *testing.T, certificate tls.Certificate, privateKey ed25519.PrivateKey, document []byte) *http.Request {
	t.Helper()
	path := "/v1/runtime-sessions:connect"
	request := httptest.NewRequest(http.MethodGet, "https://provider.test"+path, nil)
	contextValue := newProtectedReleaseContext(protectedReleaseRoute{
		method: http.MethodGet, path: path, operation: admission.OperationConnectRuntimeSession,
	})
	contextValue.RequestContractID = "urn:shell-echo:sandbox-runtime:descriptor:runtime-session-connect:v1"
	contextValue.RequestDigestProfile = admission.DigestProfileFullDocument
	contextValue.RequestDigest = releaseFullDocumentDigest(t, document)
	contextValue.DeadlineAt = releaseGateTestTime().Add(2 * time.Minute).Format(time.RFC3339Nano)
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	state := verifiedState(t, certificate)
	request.TLS = &state
	claims := admissionTokenClaimsForTest(contextValue)
	claims["exp"] = releaseGateTestTime().Add(90 * time.Second).Unix()
	request.Header.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))
	request.Header.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	request.Header.Set(runtimeSessionHandoffHeader, base64.RawURLEncoding.EncodeToString(document))
	request.Header.Set("Sec-WebSocket-Protocol", runtimeSessionWebSocketProtocol)
	return request
}

func TestProtectedRuntimeSessionConnectRoundTripsBinaryBytes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		payload := make([]byte, maxRuntimeSessionWebSocketMessageBytes)
		for {
			read, err := client.Read(payload)
			if read != 0 {
				_, _ = client.Write(payload[:read])
			}
			if err != nil {
				return
			}
		}
	}()
	stream := &pipeTerminalStream{connection: server}
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	gate, err := admission.NewProtectedOperationGate(
		mustTestTrustedKeySource(t, publicKey), mustTestAdmissionAuthority(t), testAdmissionClock{now: now}, &testAdmissionGuard{},
	)
	if err != nil {
		t.Fatal(err)
	}
	connector := &runtimeSessionConnectorSpy{stream: stream}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: gate, SessionConnector: connector, Now: func() time.Time { return now }, capabilitySnapshot: terminalConnectSnapshotForTest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	verified := verifiedState(t, material.client)
	webSocketServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		request.TLS = &verified
		handler.ServeHTTP(response, request)
	}))
	defer webSocketServer.Close()
	document, err := json.Marshal(providerv1.RuntimeSessionHandoff{
		OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1",
		RuntimeSessionID: "session-1", RuntimeType: providerv1.TerminalRuntimeTerminal,
		CapabilityProfileID: "terminal-v1", Protocol: providerv1.TerminalProtocolWebSocket,
		InternalEndpointReference: "ref:session:0123456789abcdef0123456789abcdef", ConnectionGeneration: 1,
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	contextValue := newProtectedReleaseContext(protectedReleaseRoute{
		method: http.MethodGet, path: "/v1/runtime-sessions:connect", operation: admission.OperationConnectRuntimeSession,
	})
	contextValue.PolicyDecidedAt = now.Add(-time.Second).Format(time.RFC3339Nano)
	contextValue.DeadlineAt = now.Add(30 * time.Second).Format(time.RFC3339Nano)
	contextValue.RequestContractID = "urn:shell-echo:sandbox-runtime:descriptor:runtime-session-connect:v1"
	contextValue.RequestDigestProfile = admission.DigestProfileFullDocument
	contextValue.RequestDigest = releaseFullDocumentDigest(t, document)
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	claims := admissionTokenClaimsForTest(contextValue)
	claims["iat"] = now.Add(-time.Second).Unix()
	claims["nbf"] = now.Add(-time.Second).Unix()
	claims["exp"] = now.Add(20 * time.Second).Unix()
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+signTestAdmissionToken(t, privateKey, claims))
	headers.Set(admission.AdmissionContextHeader, encodeTestAdmissionContext(t, contextValue))
	headers.Set(runtimeSessionHandoffHeader, base64.RawURLEncoding.EncodeToString(document))
	dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := "ws" + strings.TrimPrefix(webSocketServer.URL, "http") + "/v1/runtime-sessions:connect"
	connection, _, err := websocket.Dial(dialContext, url, &websocket.DialOptions{
		HTTPHeader: headers, Subprotocols: []string{runtimeSessionWebSocketProtocol},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	payload := []byte{0, 1, 2, 127, 255}
	if err := connection.Write(dialContext, websocket.MessageBinary, payload); err != nil {
		t.Fatal(err)
	}
	messageType, echoed, err := connection.Read(dialContext)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageBinary || !bytes.Equal(echoed, payload) {
		t.Fatalf("echo type=%v payload=%v", messageType, echoed)
	}
	if connector.Calls() != 1 || connection.Subprotocol() != runtimeSessionWebSocketProtocol {
		t.Fatalf("connector_calls=%d subprotocol=%q", connector.Calls(), connection.Subprotocol())
	}
}

type pipeTerminalStream struct{ connection net.Conn }

func (s *pipeTerminalStream) Read(ctx context.Context, payload []byte) (int, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.connection.SetReadDeadline(deadline)
	}
	return s.connection.Read(payload)
}
func (s *pipeTerminalStream) Write(ctx context.Context, payload []byte) (int, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.connection.SetWriteDeadline(deadline)
	}
	return s.connection.Write(payload)
}
func (s *pipeTerminalStream) Close() error { return s.connection.Close() }

func terminalConnectSnapshotForTest() provider.CapabilitySnapshot {
	return provider.CapabilitySnapshot{
		ProviderRevisionID: "provider-revision-1", APIVersion: provider.APIVersionV1,
		Capabilities: []provider.Capability{
			{ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}},
			{ID: "sandbox.terminal-connect", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-connect-v1"}},
		},
		RuntimeProfiles: []provider.RuntimeProfile{{
			ID: "sandbox-runtime-terminal-connect-v1", IsolationClass: "container",
			CapabilityProfileIDs: []string{"terminal-v1", "terminal-connect-v1"},
		}},
	}
}
