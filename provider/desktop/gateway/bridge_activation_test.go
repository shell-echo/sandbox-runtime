package desktopgateway

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/rtp"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

type activationFixture struct {
	open         desktophandoffv2.OpenRequest
	allocation   atomic.Value
	attachCount  atomic.Int32
	openedCount  atomic.Int32
	closedCount  atomic.Int32
	resolveCount atomic.Int32
	openEntered  chan struct{}
	releaseOpen  chan struct{}
	openError    atomic.Bool
}

func newActivationFixture() *activationFixture {
	now := time.Now().UTC()
	legacy := desktophandoff.OpenRequest{BindingVersion: desktophandoff.BindingVersion,
		BindingIssuer: desktophandoff.BindingIssuer, Protocol: desktophandoffv2.ProtocolID,
		RequestID: "activation-request-1", Resource: desktophandoff.ResourceDesktop,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64),
		ProviderRevisionID:  "provider-revision-1", SandboxID: "sandbox-1",
		DesktopSessionID: "desktop-1", CapabilityProfileID: "desktop-v1",
		MediaProfileID: desktophandoff.MediaProfileID, ControlProfileID: desktophandoff.ControlProfileID,
		HandoffReference:     "ref:desktop-session:opaque",
		HandoffDigest:        desktophandoff.ReferenceDigest("ref:desktop-session:opaque"),
		ConnectionGeneration: 2, ConnectionEpoch: "connection-1",
		AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt:   now.Add(2 * time.Minute).Format(time.RFC3339Nano),
		ControllerFence:    strings.Repeat("b", handoff.MinFenceBytes),
		MediaPolicy: desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 640, Height: 480,
			MaxFPS: 30, MaxVideoBitrateKbps: 1000,
			MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames,
			MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs,
			MaxInputBytes:   desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}}
	legacy.AuthorityDigest = desktophandoff.AuthorityDigest(legacy)
	legacy.RequestDigest = desktophandoff.RequestDigest(legacy)
	open := desktophandoffv2.OpenRequest{OpenRequest: legacy}
	open.TransportDigest = desktophandoffv2.TransportDigest(open)
	fixture := &activationFixture{open: open}
	fixture.allocation.Store("ref:desktop/11111111111111111111111111111111")
	return fixture
}

func (f *activationFixture) Resolve(_ context.Context, reference string) (desktopreference.Endpoint, error) {
	f.resolveCount.Add(1)
	if reference != f.open.HandoffReference {
		return desktopreference.Endpoint{}, providerdesktop.ErrDesktopNotFound
	}
	expires, _ := time.Parse(time.RFC3339Nano, f.open.HandoffExpiresAt)
	binding := f.open.Binding()
	return desktopreference.Endpoint{Reference: reference,
		ProviderRevisionID: f.open.ProviderRevisionID, SandboxID: f.open.SandboxID,
		DesktopSessionID: f.open.DesktopSessionID, CapabilityProfileID: f.open.CapabilityProfileID,
		ConnectionGeneration: f.open.ConnectionGeneration,
		TenantBindingDigest:  f.open.TenantBindingDigest, ExpiresAt: expires,
		AllocationReference: f.allocation.Load().(string), Binding: &binding,
		Attach: func(context.Context) (providerdesktop.Attachment, error) {
			f.attachCount.Add(1)
			return providerdesktop.Attachment{DesktopSessionID: f.open.DesktopSessionID,
				ConnectionGeneration: f.open.ConnectionGeneration}, nil
		}}, nil
}

func (*activationFixture) BindHandoff(context.Context, desktophandoff.Binding) error { return nil }

func (f *activationFixture) OpenBound(_ context.Context, open desktophandoff.OpenRequest,
	_ desktopreference.Endpoint, _ providerdesktop.Attachment) (Session, error) {
	if open.Protocol != desktophandoff.ProtocolID {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	f.openedCount.Add(1)
	if f.openError.Load() {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	if f.openEntered != nil {
		close(f.openEntered)
		<-f.releaseOpen
	}
	return &activationSession{fixture: f}, nil
}

type activationSession struct {
	fixture *activationFixture
	sent    atomic.Bool
	closed  atomic.Bool
}

func (s *activationSession) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	if s.sent.CompareAndSwap(false, true) {
		return (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96,
			SequenceNumber: 1, Timestamp: 3000, SSRC: 1, Marker: true},
			Payload: []byte{0x10, 0x00, 0x01}}).Marshal()
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (s *activationSession) ReadAudioRTP(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (*activationSession) HandleInput(context.Context, Input) (InputResult, error) {
	return InputResult{}, nil
}
func (*activationSession) UpdateStream(context.Context, DisplayPolicy, string) error { return nil }
func (*activationSession) Resynchronize(context.Context) error                       { return nil }
func (*activationSession) RequestKeyframe(context.Context) error                     { return nil }
func (s *activationSession) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.fixture.closedCount.Add(1)
	}
	return nil
}

func activationServer(t *testing.T, fixture *activationFixture, setupTimeout time.Duration) (*Handler, *httptest.Server) {
	t.Helper()
	handler, err := New(Options{Resolver: fixture, BoundMedia: fixture, BindingRegistrar: fixture,
		MaxSessions: 1, MaxSessionsPerDesktop: 1, AuthorityPollInterval: 20 * time.Millisecond,
		OperationTimeout: setupTimeout, AllowInsecureHTTPForTests: true, RequireActivationV2: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return handler, server
}

func dialPrepared(t *testing.T, server *httptest.Server, open desktophandoffv2.OpenRequest) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{Subprotocols: []string{ActivationSubprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.CloseNow() })
	document, _ := handoff.Encode(open)
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, document, err := connection.Read(ctx)
	var prepared desktophandoffv2.Prepared
	if err != nil || kind != websocket.MessageText || desktophandoffv2.Decode(document, &prepared) != nil || prepared.Validate(open) != nil {
		t.Fatalf("prepare response = %#v, %v", prepared, err)
	}
	return connection
}

func waitActivation(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !predicate() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !predicate() {
		t.Fatal("activation cleanup did not converge")
	}
}

func TestActivationPrepareDoesNotOpenMediaThenStartsOnce(t *testing.T) {
	fixture := newActivationFixture()
	handler, server := activationServer(t, fixture, 3*time.Second)
	connection := dialPrepared(t, server, fixture.open)
	time.Sleep(750 * time.Millisecond) // longer than a 32-frame/20ms preconnection overflow
	if fixture.attachCount.Load() != 0 || fixture.openedCount.Load() != 0 {
		t.Fatal("prepare opened the executor or media before start")
	}
	start := desktophandoffv2.NewStart(fixture.open)
	document, _ := handoff.Encode(start)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	kind, document, err := connection.Read(ctx)
	var started desktophandoffv2.Started
	if err != nil || kind != websocket.MessageText || desktophandoffv2.Decode(document, &started) != nil || started.Validate(start) != nil {
		t.Fatalf("started response = %#v, %v", started, err)
	}
	kind, document, err = connection.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || len(document) < 2 || document[0] != videoPacket {
		t.Fatalf("first video frame = %x, %v", document, err)
	}
	if fixture.attachCount.Load() != 1 || fixture.openedCount.Load() != 1 {
		t.Fatalf("media opens=%d attaches=%d", fixture.openedCount.Load(), fixture.attachCount.Load())
	}
	_ = connection.CloseNow()
	waitActivation(t, func() bool {
		handler.mu.Lock()
		active := handler.active
		handler.mu.Unlock()
		return fixture.closedCount.Load() == 1 && active == 0
	})
}

func TestActivationRejectsOldEpochAndNoStartTimeout(t *testing.T) {
	fixture := newActivationFixture()
	handler, server := activationServer(t, fixture, 250*time.Millisecond)
	connection := dialPrepared(t, server, fixture.open)
	wrong := desktophandoffv2.NewStart(fixture.open)
	wrong.ConnectionEpoch = "old-epoch"
	wrong.StartDigest = desktophandoffv2.StartDigest(wrong)
	document, _ := handoff.Encode(wrong)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("stale epoch start returned an acknowledgement")
	}
	waitActivation(t, func() bool {
		handler.mu.Lock()
		active := handler.active
		handler.mu.Unlock()
		return active == 0
	})
	if fixture.attachCount.Load() != 0 || fixture.openedCount.Load() != 0 {
		t.Fatal("stale epoch opened media")
	}
	fixture.open.RequestID = "activation-request-2"
	fixture.open.TransportDigest = desktophandoffv2.TransportDigest(fixture.open)
	connection = dialPrepared(t, server, fixture.open)
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("missing start remained prepared past setup deadline")
	}
	waitActivation(t, func() bool {
		handler.mu.Lock()
		active := handler.active
		handler.mu.Unlock()
		return active == 0
	})
	if fixture.openedCount.Load() != 0 {
		t.Fatal("missing start opened media")
	}
	fixture.open.RequestID = "activation-request-3"
	fixture.open.TransportDigest = desktophandoffv2.TransportDigest(fixture.open)
	connection = dialPrepared(t, server, fixture.open)
	command, _ := handoff.Encode(desktopmedia.Command{Type: "stream.resync", RequestID: 1})
	if err := connection.Write(ctx, websocket.MessageText, command); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(ctx); err == nil || fixture.openedCount.Load() != 0 {
		t.Fatalf("pre-start command admitted: %v", err)
	}
}

func TestActivationRequiredHandlerRejectsV1StreamingTransport(t *testing.T) {
	fixture := newActivationFixture()
	_, server := activationServer(t, fixture, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"),
		&websocket.DialOptions{Subprotocols: []string{ClosedSubprotocol}})
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if connection != nil {
		_ = connection.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != 400 {
		t.Fatalf("v1 transport admitted by v2-only handler: response=%v err=%v", response, err)
	}
	if fixture.attachCount.Load() != 0 || fixture.openedCount.Load() != 0 {
		t.Fatal("v1 transport touched runtime")
	}
}

func TestActivationCancelDuringRuntimeOpenClosesLateSession(t *testing.T) {
	fixture := newActivationFixture()
	fixture.openEntered = make(chan struct{})
	fixture.releaseOpen = make(chan struct{})
	handler, server := activationServer(t, fixture, time.Second)
	connection := dialPrepared(t, server, fixture.open)
	start := desktophandoffv2.NewStart(fixture.open)
	document, _ := handoff.Encode(start)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fixture.openEntered:
	case <-ctx.Done():
		t.Fatal("runtime open was not reached")
	}
	_ = connection.CloseNow()
	close(fixture.releaseOpen)
	waitActivation(t, func() bool {
		handler.mu.Lock()
		active := handler.active
		handler.mu.Unlock()
		return fixture.closedCount.Load() == 1 && active == 0
	})
}

func TestActivationPrepareHoldsCapacityAndRejectsReplay(t *testing.T) {
	fixture := newActivationFixture()
	handler, server := activationServer(t, fixture, time.Second)
	first := dialPrepared(t, server, fixture.open)
	attempt := func(open desktophandoffv2.OpenRequest) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"),
			&websocket.DialOptions{Subprotocols: []string{ActivationSubprotocol}})
		if err != nil {
			t.Fatal(err)
		}
		defer connection.CloseNow()
		document, _ := handoff.Encode(open)
		if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
			t.Fatal(err)
		}
		if _, _, err := connection.Read(ctx); err == nil {
			t.Fatal("replay or over-capacity prepare was admitted")
		}
	}
	attempt(fixture.open)
	other := fixture.open
	other.RequestID = "other-request-1"
	other.TransportDigest = desktophandoffv2.TransportDigest(other)
	attempt(other)
	if fixture.attachCount.Load() != 0 || fixture.openedCount.Load() != 0 {
		t.Fatal("replay or capacity check opened runtime")
	}
	_ = first.CloseNow()
	waitActivation(t, func() bool {
		handler.mu.Lock()
		active := handler.active
		handler.mu.Unlock()
		return active == 0
	})
}

func TestActivationBrokerLossAfterStartReleasesReservation(t *testing.T) {
	fixture := newActivationFixture()
	fixture.openError.Store(true)
	handler, server := activationServer(t, fixture, time.Second)
	connection := dialPrepared(t, server, fixture.open)
	start := desktophandoffv2.NewStart(fixture.open)
	document, _ := handoff.Encode(start)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("broker loss returned a started acknowledgement")
	}
	waitActivation(t, func() bool {
		handler.mu.Lock()
		active := handler.active
		handler.mu.Unlock()
		return active == 0
	})
	if fixture.openedCount.Load() != 1 || fixture.closedCount.Load() != 0 {
		t.Fatalf("broker loss opens=%d closes=%d", fixture.openedCount.Load(), fixture.closedCount.Load())
	}
}

func TestActivationRejectsDriftBeforeOpeningMedia(t *testing.T) {
	for _, scenario := range []string{"allocation", "generation", "fence", "epoch"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newActivationFixture()
			handler, server := activationServer(t, fixture, time.Second)
			connection := dialPrepared(t, server, fixture.open)
			start := desktophandoffv2.NewStart(fixture.open)
			switch scenario {
			case "allocation":
				fixture.allocation.Store("ref:desktop/22222222222222222222222222222222")
			case "generation":
				start.ConnectionGeneration++
			case "fence":
				start.ControllerFence = strings.Repeat("c", handoff.MinFenceBytes)
			case "epoch":
				start.ConnectionEpoch = "stale-epoch"
			}
			start.StartDigest = desktophandoffv2.StartDigest(start)
			document, _ := handoff.Encode(start)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
				t.Fatal(err)
			}
			if _, _, err := connection.Read(ctx); err == nil {
				t.Fatal("drifted start returned an acknowledgement")
			}
			waitActivation(t, func() bool {
				handler.mu.Lock()
				active := handler.active
				handler.mu.Unlock()
				return active == 0
			})
			if fixture.attachCount.Load() != 0 || fixture.openedCount.Load() != 0 {
				t.Fatalf("drift opened runtime: attaches=%d opens=%d", fixture.attachCount.Load(), fixture.openedCount.Load())
			}
		})
	}
}
