package executorbackend

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	providerremote "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/remote"
)

func TestDesktopBackendBridgesSignedBrokerSession(t *testing.T) {
	socket := testBrokerSocket(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	open, publicKey, privateKey := testDesktopOpen(t)
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- serveFakeV2Broker(listener, publicKey, *open.MediaPolicy) }()

	directory := t.TempDir()
	material := writeTLSMaterial(t, directory)
	backend, err := NewDesktop(DesktopConfig{Role: executorprotocol.RoleDesktop, ListenAddress: freeListenerAddress(t), BrokerSocketPath: socket, ExecutorIdentity: "executor-desktop-1", ServerCertificateFile: material.serverCertificate, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.ca, AllowedClientIdentities: []string{"spiffe://sandbox-runtime/browser-role"}, MaxSessions: 2, OperationTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- backend.Serve(ctx) }()
	waitListener(t, backend.config.ListenAddress)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.pool, Certificates: []tls.Certificate{material.client}, ServerName: "127.0.0.1"}}}
	connection, _, err := websocket.Dial(ctx, "wss://"+backend.config.ListenAddress+"/executor", &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, responseDocument, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageText {
		t.Fatalf("Desktop authority response kind=%v err=%v", kind, err)
	}
	var response executorprotocol.Response
	if err := executorprotocol.Decode(responseDocument, &response); err != nil || response.Status != executorprotocol.StatusAccepted {
		t.Fatalf("Desktop authority response=%#v err=%v", response, err)
	}
	kind, frame, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || len(frame) < 12 || frame[0]>>6 != 2 {
		t.Fatalf("Desktop RTP kind=%v len=%d err=%v", kind, len(frame), err)
	}
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 10, Y: 20, ControlLeaseID: "lease-1", ControlFence: 1}
	command := fmt.Sprintf(`{"protocol":%q,"method":"input","sequence":1,"value":%s}`, executorprotocol.ProtocolID, mustJSON(t, input))
	if err := connection.Write(ctx, websocket.MessageText, []byte(command)); err != nil {
		t.Fatal(err)
	}
	for {
		kind, result, err := connection.Read(ctx)
		if err != nil {
			t.Fatalf("Desktop input result read: %v", err)
		}
		if kind == websocket.MessageText && strings.Contains(string(result), `"type":"result"`) {
			break
		}
		if kind != websocket.MessageBinary {
			t.Fatalf("Desktop input result kind=%v result=%s", kind, result)
		}
	}
	_ = connection.CloseNow()
	cancel()
	select {
	case <-serveErr:
	case <-time.After(time.Second):
		t.Fatal("Desktop backend did not stop")
	}
	if err := <-brokerDone; err != nil && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("fake broker error: %v", err)
	}
	_ = privateKey
}

func TestDesktopRemoteDriverDemultiplexesMediaAndInput(t *testing.T) {
	socket := testBrokerSocket(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	fixture, publicKey, privateKey := testDesktopOpen(t)
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- serveFakeV2Broker(listener, publicKey, *fixture.MediaPolicy) }()

	directory := t.TempDir()
	material := writeTLSMaterial(t, directory)
	backend, err := NewDesktop(DesktopConfig{Role: executorprotocol.RoleDesktop, ListenAddress: freeListenerAddress(t), BrokerSocketPath: socket, ExecutorIdentity: "executor-desktop-1", ServerCertificateFile: material.serverCertificate, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.ca, AllowedClientIdentities: []string{"spiffe://sandbox-runtime/browser-role"}, MaxSessions: 2, OperationTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- backend.Serve(ctx) }()
	waitListener(t, backend.config.ListenAddress)
	defer func() {
		cancel()
		select {
		case <-serveErr:
		case <-time.After(time.Second):
			t.Fatal("Desktop backend did not stop")
		}
	}()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: material.pool, Certificates: []tls.Certificate{material.client}, ServerName: "127.0.0.1"}}}
	driver, err := providerremote.New(providerremote.Options{URL: "wss://" + backend.config.ListenAddress + "/executor", HTTPClient: client, OperationTimeout: 5 * time.Second, BridgeKeyID: "provider-desktop-v2", ExecutorIdentity: "executor-desktop-1", BridgePrivateKey: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	authority := providerdesktop.MediaAuthority{TenantBindingDigest: fixture.TenantBindingDigest, ProviderRevisionID: fixture.ProviderRevisionID, SandboxID: fixture.SandboxID, DesktopSessionID: fixture.RuntimeSessionID, HandoffReference: fixture.HandoffReference, HandoffReferenceDigest: fixture.HandoffDigest, AllocationReference: fixture.AllocationReference, ConnectionGeneration: fixture.ConnectionGeneration, ConnectionEpoch: fixture.ConnectionEpoch, ControllerFence: fixture.Fence, MediaProfileID: fixture.MediaProfileID, ControlProfileID: fixture.ControlProfileID, AuthorityExpiresAt: time.Now().UTC().Add(time.Minute), HandoffExpiresAt: time.Now().UTC().Add(2 * time.Minute)}
	attachment := providerdesktop.Attachment{DesktopSessionID: fixture.RuntimeSessionID, ConnectionGeneration: fixture.ConnectionGeneration, MediaProfileID: fixture.MediaProfileID, ControlProfileID: fixture.ControlProfileID}
	session, err := driver.OpenMedia(ctx, authority, attachment, *fixture.MediaPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	first, err := session.ReadVideoRTP(ctx)
	if err != nil || len(first) < 12 {
		t.Fatalf("first Desktop RTP len=%d err=%v", len(first), err)
	}
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 10, Y: 20, ControlLeaseID: "lease-1", ControlFence: 1}
	result, err := session.HandleInput(ctx, input)
	if err != nil || result.Text != "input accepted" {
		t.Fatalf("Desktop input result=%#v err=%v", result, err)
	}
	second, err := session.ReadVideoRTP(ctx)
	if err != nil || len(second) < 12 {
		t.Fatalf("second Desktop RTP len=%d err=%v", len(second), err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-brokerDone; err != nil && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("fake broker error: %v", err)
	}
}

func TestDesktopBackendReadinessRequiresV2BrokerProbe(t *testing.T) {
	socket := testBrokerSocket(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	probeDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			probeDone <- acceptErr
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadBytes('\n')
		var request desktopbroker.Request
		if readErr != nil || desktopbroker.DecodeSession(line, &request) != nil || request.Method != desktopbroker.BridgeProbeMethod {
			probeDone <- errors.New("backend did not issue the v2 broker probe")
			return
		}
		response, _ := desktopbroker.EncodeSession(desktopbroker.Response{Protocol: desktopbroker.ProtocolID, RequestID: request.RequestID, Status: "ok", Descriptor: func() *desktopbroker.Descriptor { value := desktopbroker.ReadyDescriptor(); return &value }()})
		_, writeErr := connection.Write(response)
		probeDone <- writeErr
	}()
	material := writeTLSMaterial(t, t.TempDir())
	backend, err := NewDesktop(DesktopConfig{Role: executorprotocol.RoleDesktop, ListenAddress: freeListenerAddress(t), BrokerSocketPath: socket, ExecutorIdentity: "executor-desktop-1", ServerCertificateFile: material.serverCertificate, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.ca, AllowedClientIdentities: []string{"spiffe://sandbox-runtime/browser-role"}, MaxSessions: 2, OperationTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-probeDone; err != nil {
		t.Fatal(err)
	}
}

func serveFakeV2Broker(listener *net.UnixListener, publicKey ed25519.PublicKey, policy desktopmedia.MediaPolicy) error {
	connection, err := listener.AcceptUnix()
	if err != nil {
		return err
	}
	defer connection.Close()
	reader := bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	var open desktopbroker.SessionOpen
	if desktopbroker.DecodeSession(line, &open) != nil || open.ValidateV2(time.Now().UTC(), map[string]ed25519.PublicKey{"provider-desktop-v2": publicKey}) != nil || open.MediaPolicy != policy {
		return fmt.Errorf("invalid fake broker open")
	}
	accepted, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionAcceptedType, RequestID: open.RequestID, OK: true})
	if _, err := connection.Write(accepted); err != nil {
		return err
	}
	frame := append([]byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte("frame")...)
	encoded, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionFrameType, Sequence: 1, Timestamp: time.Now().UnixNano(), Payload: base64.StdEncoding.EncodeToString(frame)})
	if _, err := connection.Write(encoded); err != nil {
		return err
	}
	line, err = reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	var command desktopbroker.SessionCommand
	if desktopbroker.DecodeSession(line, &command) != nil || command.ValidateFor(policy, 0, desktopbroker.SessionProtocolV2ID) != nil {
		return fmt.Errorf("invalid fake broker command")
	}
	frame[len(frame)-1]++
	encoded, _ = desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionFrameType, Sequence: 2, Timestamp: time.Now().UnixNano(), Payload: base64.StdEncoding.EncodeToString(frame)})
	if _, err := connection.Write(encoded); err != nil {
		return err
	}
	result, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionResultType, RequestID: command.RequestID, Sequence: command.Sequence, OK: true, Text: "input accepted"})
	if _, err = connection.Write(result); err != nil {
		return err
	}
	_, err = reader.ReadBytes('\n')
	return err
}

func testDesktopOpen(t *testing.T) (executorprotocol.Open, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	now := time.Now().UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := &desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 640, Height: 480, MaxFPS: 30, MaxVideoBitrateKbps: 1000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleDesktop, RequestID: "request-desktop-1", TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", RuntimeSessionID: "desktop-session-1", CapabilityProfileID: "desktop-v1", MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1", AllocationReference: "ref:desktop/11111111111111111111111111111111", MediaPolicy: policy, MediaPolicyDigest: executorprotocol.PolicyDigest(*policy), HandoffReference: "ref:desktop-session:opaque-1", HandoffDigest: executorprotocol.ReferenceDigest("ref:desktop-session:opaque-1"), ConnectionGeneration: 1, ConnectionEpoch: "epoch-1", Fence: strings.Repeat("b", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), Codec: policy.VideoCodec}
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: "provider-desktop-v2", ExecutorRole: executorprotocol.RoleDesktop, ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: open.ProviderRevisionID, TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID, RuntimeSessionID: open.RuntimeSessionID, HandoffReferenceDigest: open.HandoffDigest, AllocationReference: open.AllocationReference, MediaPolicy: *policy, ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.Fence, AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt, NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: open.AuthorityDigest, ExecutorRequestDigest: open.RequestDigest, Nonce: "nonce-abcdefghijklmnopqrstuvwxyz123456"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	open.Bridge = &bridge
	return open, publicKey, privateKey
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(document)
}

func testBrokerSocket(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-desktop-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, fmt.Sprintf("desktop-broker-%x.sock", value))
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}
