package docker

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
)

type terminalMuxTestStream struct {
	terminal   chan sessiontermination.Record
	closeWrite func()
}

func (s *terminalMuxTestStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *terminalMuxTestStream) Write(value []byte) (int, error) {
	return len(value), nil
}
func (s *terminalMuxTestStream) Close() error { return nil }
func (s *terminalMuxTestStream) CloseWrite() error {
	if s.closeWrite != nil {
		s.closeWrite()
	}
	return nil
}
func (s *terminalMuxTestStream) Terminal() <-chan sessiontermination.Record { return s.terminal }

type muxTestEngine struct {
	*fakeEngine
	publicKey ed25519.PublicKey
	mu        sync.Mutex
	opens     int
	serve     func(net.Conn) error
}

func (e *muxTestEngine) openSession(context.Context, string) (io.ReadWriteCloser, error) {
	e.mu.Lock()
	e.opens++
	serve := e.serve
	e.mu.Unlock()
	if serve == nil {
		return nil, errors.New("session unavailable")
	}
	provider, broker := net.Pipe()
	go func() {
		defer broker.Close()
		_ = serve(broker)
	}()
	return provider, nil
}

func (e *muxTestEngine) openCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.opens
}

type muxTestAuthority struct {
	mu        sync.Mutex
	err       error
	template  desktopbroker.SessionOpen
	authorize int
}

func (a *muxTestAuthority) Authorize(_ context.Context, open desktopbroker.SessionOpen) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.authorize++
	if a.err != nil {
		return a.err
	}
	if a.template.HandoffReference != "" && open.HandoffReference != a.template.HandoffReference {
		return errors.New("authority mismatch")
	}
	return nil
}

func (a *muxTestAuthority) Probe(context.Context) (desktopbroker.SessionOpen, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return desktopbroker.SessionOpen{}, a.err
	}
	return a.template, nil
}

func TestBrokerMuxForwardsOnlyAuthorizedOwnedCandidateSession(t *testing.T) {
	fixture := newMuxFixture(t)
	fixture.engine.serve = serveMuxBroker(fixture.publicKey, true)
	mux, socket, cancel, done := startMux(t, fixture.driver, fixture.authority, 2)
	_ = mux
	defer stopMux(t, socket, cancel, done)

	connection := dialMux(t, socket)
	defer connection.Close()
	openDocument, _ := desktopbroker.EncodeSession(fixture.open)
	if _, err := connection.Write(openDocument); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument)
	accepted := readMuxTestMessage(t, reader)
	if accepted.Type != desktopbroker.SessionAcceptedType || accepted.RequestID != fixture.open.RequestID {
		t.Fatalf("accepted = %#v", accepted)
	}
	frame := readMuxTestMessage(t, reader)
	if frame.Type != desktopbroker.SessionFrameType {
		t.Fatalf("frame = %#v", frame)
	}
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 10, Y: 20, ControlLeaseID: "lease-1", ControlFence: 1}
	command := desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolV2ID, Type: "input", RequestID: "input-1", Sequence: 1, Input: &input}
	document, _ := desktopbroker.EncodeSession(command)
	if _, err := connection.Write(document); err != nil {
		t.Fatal(err)
	}
	result := readMuxTestMessage(t, reader)
	if result.Type != desktopbroker.SessionResultType || result.RequestID != command.RequestID || !result.OK {
		t.Fatalf("result = %#v", result)
	}
	closeCommand := desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolV2ID, Type: "close", RequestID: "close-2", Sequence: 2}
	document, _ = desktopbroker.EncodeSession(closeCommand)
	if _, err := connection.Write(document); err != nil {
		t.Fatal(err)
	}
	if closed := readMuxTestMessage(t, reader); closed.Type != desktopbroker.SessionClosedType {
		t.Fatalf("closed = %#v", closed)
	}
	if fixture.engine.openCount() != 1 {
		t.Fatalf("broker exec opens = %d", fixture.engine.openCount())
	}
}

func TestBrokerMuxProbeTraversesSignedCandidateBroker(t *testing.T) {
	fixture := newMuxFixture(t)
	fixture.engine.serve = serveMuxBroker(fixture.publicKey, false)
	_, socket, cancel, done := startMux(t, fixture.driver, fixture.authority, 2)
	defer stopMux(t, socket, cancel, done)
	connection := dialMux(t, socket)
	defer connection.Close()
	request := desktopbroker.Request{Protocol: desktopbroker.ProtocolID, RequestID: "probe-1", Method: desktopbroker.BridgeProbeMethod}
	document, _ := desktopbroker.EncodeSession(request)
	if _, err := connection.Write(document); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var response desktopbroker.Response
	if desktopbroker.DecodeSession(line, &response) != nil || response.Validate() != nil || response.RequestID != request.RequestID || response.Status != "ok" {
		t.Fatalf("probe response = %#v", response)
	}
}

func TestBrokerMuxRejectsAuthorityAllocationAndRuntimeDrift(t *testing.T) {
	tests := map[string]func(*muxFixture){
		"authority": func(f *muxFixture) { f.authority.err = errors.New("revoked") },
		"allocation": func(f *muxFixture) {
			f.open.AllocationReference = "ref:desktop/22222222222222222222222222222222"
			resignMuxOpen(t, f)
		},
		"container labels": func(f *muxFixture) { f.engine.container.labels[ownerLabel] = "other-owner" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newMuxFixture(t)
			fixture.engine.serve = serveMuxBroker(fixture.publicKey, false)
			mutate(fixture)
			_, socket, cancel, done := startMux(t, fixture.driver, fixture.authority, 1)
			defer stopMux(t, socket, cancel, done)
			connection := dialMux(t, socket)
			document, _ := desktopbroker.EncodeSession(fixture.open)
			_, _ = connection.Write(document)
			_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := bufio.NewReader(connection).ReadByte(); err == nil {
				t.Fatal("unsafe session was accepted")
			}
			_ = connection.Close()
			if name == "authority" && fixture.engine.openCount() != 0 {
				t.Fatal("broker exec opened before authority validation")
			}
		})
	}
}

func TestBrokerMuxRejectsUnsafeSocketAndCleansExactOwnedSocket(t *testing.T) {
	fixture := newMuxFixture(t)
	directory := shortMuxDirectory(t)
	socket := filepath.Join(directory, "desktop-broker-11111111111111111111111111111111.sock")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, socket); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBrokerMux(fixture.driver, BrokerMuxOptions{SocketPath: socket, MaxSessions: 1, OperationTimeout: time.Second, Authority: fixture.authority}); err != nil {
		t.Fatalf("constructor should defer socket-node validation: %v", err)
	}
	_ = os.Remove(socket)
	mux, err := NewBrokerMux(fixture.driver, BrokerMuxOptions{SocketPath: socket, MaxSessions: 1, OperationTimeout: time.Second, Authority: fixture.authority})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mux.Startup(ctx) }()
	waitMuxSocket(t, socket)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("mux did not stop")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket was not cleaned: %v", err)
	}
}

type muxFixture struct {
	driver     *Driver
	engine     *muxTestEngine
	authority  *muxTestAuthority
	open       desktopbroker.SessionOpen
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func newMuxFixture(t *testing.T) *muxFixture {
	t.Helper()
	now := time.Now().UTC()
	clock := &fakeClock{now: now}
	root := t.TempDir()
	options := validOptions(t, root, clock)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options.BridgeKeyID = "provider-desktop-v2"
	options.BridgePublicKey = publicKey
	sourceRoot, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("9", 64)
	candidate, err := desktopcandidate.New(sourceRoot, "linux/amd64", digest, digest)
	if err != nil {
		t.Fatal(err)
	}
	options.Image = digest
	options.PullPolicy = PullNever
	base := &fakeEngine{image: validImageInfo(t)}
	base.image.id = digest
	base.image.repositoryDigests = nil
	base.image.descriptorDigest = ""
	base.image.labels["org.opencontainers.image.revision"] = candidate.SourceRevision
	engine := &muxTestEngine{fakeEngine: base, publicKey: publicKey}
	driver, err := newCandidateDriver(context.Background(), engine, options, candidate, newFakeNetwork())
	if err != nil {
		t.Fatal(err)
	}
	allocation := allocation(now)
	receipt, err := driver.Allocate(context.Background(), allocation)
	if err != nil {
		t.Fatal(err)
	}
	open := signedMuxOpen(t, now, receipt, privateKey)
	authority := &muxTestAuthority{template: open}
	return &muxFixture{driver: driver, engine: engine, authority: authority, open: open, publicKey: publicKey, privateKey: privateKey}
}

func signedMuxOpen(t *testing.T, now time.Time, receipt providerdesktop.AllocationReceipt, privateKey ed25519.PrivateKey) desktopbroker.SessionOpen {
	t.Helper()
	policy := desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	reference := "ref:desktop-session:11111111111111111111111111111111"
	referenceSum := sha256.Sum256([]byte(reference))
	open := desktopbroker.SessionOpen{BindingVersion: desktopbroker.SessionBindingV2, BindingIssuer: desktopbroker.SessionBindingIssuerV2, Protocol: desktopbroker.SessionProtocolV2ID, RequestID: "mux-open-1", Method: desktopbroker.SessionMethod,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: receipt.SandboxID, DesktopSessionID: receipt.DesktopSessionID,
		CapabilityProfileID: providerdesktop.CapabilityProfileID, MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID,
		HandoffReferenceDigest: fmt.Sprintf("sha256:%x", referenceSum[:]), AllocationReference: receipt.Reference, ConnectionGeneration: receipt.ConnectionGeneration,
		ConnectionEpoch: "epoch-1", Fence: strings.Repeat("b", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: receipt.ExpiresAt.Format(time.RFC3339Nano),
		AuthorityDigest: "sha256:" + strings.Repeat("c", 64), RequestDigest: "sha256:" + strings.Repeat("d", 64), HandoffReference: reference, MediaPolicy: policy}
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: "provider-desktop-v2", ExecutorRole: "desktop", ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: open.ProviderRevisionID,
		TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID, RuntimeSessionID: open.DesktopSessionID, HandoffReferenceDigest: open.HandoffReferenceDigest, AllocationReference: open.AllocationReference,
		MediaPolicy: policy, ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.Fence, AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt,
		NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: open.AuthorityDigest, ExecutorRequestDigest: open.RequestDigest, Nonce: "nonce-mux-abcdefghijklmnopqrstuvwxyz123456"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	open.Bridge = &bridge
	return open
}

func resignMuxOpen(t *testing.T, fixture *muxFixture) {
	t.Helper()
	statement := fixture.open.Bridge.Statement
	statement.AllocationReference = fixture.open.AllocationReference
	statement.Nonce = "nonce-drift-abcdefghijklmnopqrstuvwxyz1234"
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, fixture.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fixture.open.Bridge = &bridge
}

func serveMuxBroker(publicKey ed25519.PublicKey, sendFrame bool) func(net.Conn) error {
	return func(connection net.Conn) error {
		reader := bufio.NewReaderSize(connection, desktopbroker.SessionMaxDocument)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return err
		}
		var open desktopbroker.SessionOpen
		if desktopbroker.DecodeSession(line, &open) != nil || open.ValidateV2(time.Now().UTC(), map[string]ed25519.PublicKey{"provider-desktop-v2": publicKey}) != nil {
			return errors.New("invalid mux broker open")
		}
		accepted, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionAcceptedType, RequestID: open.RequestID, OK: true})
		if _, err := connection.Write(accepted); err != nil {
			return err
		}
		if sendFrame {
			frame := append([]byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte("frame")...)
			document, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionFrameType, Sequence: 1, Timestamp: time.Now().UnixNano(), Payload: base64.StdEncoding.EncodeToString(frame)})
			if _, err := connection.Write(document); err != nil {
				return err
			}
		}
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return err
			}
			var command desktopbroker.SessionCommand
			if desktopbroker.DecodeSession(line, &command) != nil {
				return errors.New("invalid mux broker command")
			}
			if command.Type == "close" {
				closed, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionClosedType})
				_, err = connection.Write(closed)
				return err
			}
			result, _ := desktopbroker.EncodeSession(desktopbroker.SessionMessage{Protocol: desktopbroker.SessionProtocolV2ID, Type: desktopbroker.SessionResultType, RequestID: command.RequestID, Sequence: command.Sequence, OK: true})
			if _, err := connection.Write(result); err != nil {
				return err
			}
		}
	}
}

func startMux(t *testing.T, driver *Driver, authority BrokerMuxAuthority, capacity int) (*BrokerMux, string, context.CancelFunc, <-chan error) {
	t.Helper()
	directory := shortMuxDirectory(t)
	socket := filepath.Join(directory, "desktop-broker-11111111111111111111111111111111.sock")
	mux, err := NewBrokerMux(driver, BrokerMuxOptions{SocketPath: socket, MaxSessions: capacity, OperationTimeout: 2 * time.Second, Authority: authority})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mux.Startup(ctx) }()
	waitMuxSocket(t, socket)
	return mux, socket, cancel, done
}

func stopMux(t *testing.T, socket string, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("mux stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mux did not stop")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mux socket cleanup: %v", err)
	}
}

func shortMuxDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-mux-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func waitMuxSocket(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("unix", socket, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		runtime.Gosched()
	}
	t.Fatal("mux socket was not created")
}

func TestMuxTerminationArbitrationPrefersBoundTypedCause(t *testing.T) {
	first := sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseTransportClosed}
	want := sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseInputTimeout}
	for _, test := range []struct {
		name  string
		delay time.Duration
	}{
		{name: "typed already available"},
		{name: "generic arrives before typed", delay: 10 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := &terminalMuxTestStream{terminal: make(chan sessiontermination.Record, 1)}
			stream.closeWrite = func() {
				go func() {
					time.Sleep(test.delay)
					stream.terminal <- want
				}()
			}
			if got := arbitrateMuxTermination(context.Background(), 100*time.Millisecond, first, stream); got != want {
				t.Fatalf("arbitrated record = %#v, want %#v", got, want)
			}
		})
	}
}

func TestMuxTerminationArbitrationIsBoundedAndSessionLocal(t *testing.T) {
	first := sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseTransportClosed}
	other := &terminalMuxTestStream{terminal: make(chan sessiontermination.Record, 1)}
	other.terminal <- sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseInputNonzeroExit}
	stream := &terminalMuxTestStream{terminal: make(chan sessiontermination.Record, 1)}
	started := time.Now()
	if got := arbitrateMuxTermination(context.Background(), 20*time.Millisecond, first, stream); got != first {
		t.Fatalf("cross-session or absent terminal replaced first cause: %#v", got)
	}
	if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("bounded arbitration elapsed=%s", elapsed)
	}
	stream.terminal <- sessiontermination.Record{Stage: "forged", Cause: sessiontermination.CauseInputTimeout}
	if got := arbitrateMuxTermination(context.Background(), 20*time.Millisecond, first, stream); got != first {
		t.Fatalf("forged terminal replaced first cause: %#v", got)
	}
}

func TestMuxTerminationArbitrationPreservesPolicyPriority(t *testing.T) {
	first := sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseTransportClosed}
	for name, makeContext := range map[string]func() (context.Context, context.CancelFunc, sessiontermination.Cause){
		"caller cancel": func() (context.Context, context.CancelFunc, sessiontermination.Cause) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}, sessiontermination.CauseCallerCancel
		},
		"expiry": func() (context.Context, context.CancelFunc, sessiontermination.Cause) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			return ctx, cancel, sessiontermination.CauseExpiry
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel, cause := makeContext()
			defer cancel()
			stream := &terminalMuxTestStream{terminal: make(chan sessiontermination.Record, 1)}
			stream.terminal <- sessiontermination.Record{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseInputTimeout}
			got := arbitrateMuxTermination(ctx, 100*time.Millisecond, first, stream)
			if got.Cause != cause {
				t.Fatalf("policy cause = %#v, want %q", got, cause)
			}
		})
	}
}

func TestMuxTerminationPriorityIsClosed(t *testing.T) {
	ordered := []sessiontermination.Record{
		{Stage: sessiontermination.StageCloseOrdering, Cause: sessiontermination.CauseCleanClose},
		{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseTransportClosed},
		{Stage: sessiontermination.StageCloseOrdering, Cause: sessiontermination.CauseCallerCancel},
		{Stage: sessiontermination.StageBrokerRuntime, Cause: sessiontermination.CauseRuntimeFailure},
		{Stage: sessiontermination.StageInputWriter, Cause: sessiontermination.CauseInputNonzeroExit},
		{Stage: sessiontermination.StageAuthorityWatcher, Cause: sessiontermination.CauseExpiry},
	}
	for index := 1; index < len(ordered); index++ {
		if muxTerminationPriority(ordered[index]) <= muxTerminationPriority(ordered[index-1]) {
			t.Fatalf("priority did not increase at %d", index)
		}
	}
	if muxTerminationPriority(sessiontermination.Record{Stage: "forged", Cause: sessiontermination.CauseExpiry}) != -1 {
		t.Fatal("invalid record acquired priority")
	}
}

func dialMux(t *testing.T, socket string) *net.UnixConn {
	t.Helper()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func readMuxTestMessage(t *testing.T, reader *bufio.Reader) desktopbroker.SessionMessage {
	t.Helper()
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var message desktopbroker.SessionMessage
	if desktopbroker.DecodeSession(line, &message) != nil || message.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil {
		t.Fatalf("invalid mux message: %s", line)
	}
	return message
}
