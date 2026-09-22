package productgateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopgateway "github.com/shell-echo/sandbox-runtime/provider/desktop/gateway"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

func TestPrivateDesktopMediaBridgeRoundTripAndContinuousRevocation(t *testing.T) {
	now := time.Now().UTC()
	binding := privateDesktopTestBinding(now.Add(time.Minute))
	resolver := &privateDesktopTestResolver{binding: binding}
	media := newPrivateDesktopTestSource()
	closeRelease := make(chan struct{})
	media.closeGate = closeRelease
	var releaseOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(closeRelease) }) }
	defer releaseClose()
	handler, err := desktopgateway.New(desktopgateway.Options{
		Resolver: resolver, Media: media, MaxSessions: 2, MaxSessionsPerDesktop: 1,
		AuthorityPollInterval: 10 * time.Millisecond, OperationTimeout: time.Second, AllowInsecureHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	source := newPrivateDesktopTestClient(t, server, binding.ProviderRevisionID)
	session, err := source.Open(context.Background(), binding, privateDesktopTestPolicy())
	if err != nil {
		t.Fatal(err)
	}
	opened := <-media.opened
	opened.video <- []byte{0x80, 0x01}
	opened.audio <- []byte{0x90, 0x02}
	if packet, err := session.ReadVideoRTP(context.Background()); err != nil || string(packet) != string([]byte{0x80, 0x01}) {
		t.Fatalf("video packet=%x err=%v", packet, err)
	}
	if packet, err := session.ReadAudioRTP(context.Background()); err != nil || string(packet) != string([]byte{0x90, 0x02}) {
		t.Fatalf("audio packet=%x err=%v", packet, err)
	}
	input := DesktopLiveInput{Sequence: 1, Kind: "clipboard.read", ControlLeaseID: "ctl-private-desktop", ControlFence: 7}
	result, err := session.HandleInput(context.Background(), input)
	if err != nil || result.Text != "private clipboard" {
		t.Fatalf("input result=%#v err=%v", result, err)
	}
	if err := session.UpdateStream(context.Background(), DesktopLiveDisplayPolicy{Width: 640, Height: 480, MaxFPS: 24}, "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := session.Resynchronize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.RequestKeyframe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := opened.commandCount.Load(); got != 4 {
		t.Fatalf("private command count=%d", got)
	}
	resolver.revoked.Store(true)
	readDone := make(chan error, 1)
	go func() {
		readCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, readErr := session.ReadVideoRTP(readCtx)
		readDone <- readErr
	}()
	select {
	case <-opened.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Provider media close did not start after handoff revocation")
	}
	select {
	case err := <-readDone:
		t.Fatalf("bridge termination became observable before Provider close completed: %v", err)
	default:
	}
	releaseClose()
	var readErr error
	select {
	case readErr = <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Desktop bridge did not terminate after Provider close completed")
	}
	if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, product.ErrStoreUnavailable) {
		t.Fatalf("read after Provider revocation err=%v", readErr)
	}
	select {
	case <-opened.closeFinished:
	case <-time.After(time.Second):
		t.Fatal("Provider media close completion was not published")
	}
	if calls := opened.closeCalls.Load(); calls != 1 {
		t.Fatalf("Provider media close calls=%d, want=1", calls)
	}
	if !opened.closed.Load() {
		t.Fatal("Provider media session remained open after handoff revocation")
	}
}

func TestPrivateDesktopMediaBridgeRejectsSubstitutionAndRecoversCapacity(t *testing.T) {
	binding := privateDesktopTestBinding(time.Now().UTC().Add(time.Minute))
	resolver := &privateDesktopTestResolver{binding: binding}
	media := newPrivateDesktopTestSource()
	handler, err := desktopgateway.New(desktopgateway.Options{
		Resolver: resolver, Media: media, MaxSessions: 1, MaxSessionsPerDesktop: 1,
		AuthorityPollInterval: 20 * time.Millisecond, OperationTimeout: time.Second, AllowInsecureHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	source := newPrivateDesktopTestClient(t, server, binding.ProviderRevisionID)

	tampered := binding
	tampered.SandboxID = "sandbox-substituted"
	if _, err := source.Open(context.Background(), tampered, privateDesktopTestPolicy()); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("sandbox substitution err=%v", err)
	}
	tampered = binding
	tampered.ConnectionGeneration++
	if _, err := source.Open(context.Background(), tampered, privateDesktopTestPolicy()); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("generation substitution err=%v", err)
	}

	first, err := source.Open(context.Background(), binding, privateDesktopTestPolicy())
	if err != nil {
		t.Fatal(err)
	}
	<-media.opened
	if _, err := source.Open(context.Background(), binding, privateDesktopTestPolicy()); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("capacity admission err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recovered, openErr := source.Open(context.Background(), binding, privateDesktopTestPolicy())
		if openErr == nil {
			<-media.opened
			_ = recovered.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("private Desktop capacity did not recover after close")
}

func TestPrivateDesktopMediaSourceFailsClosed(t *testing.T) {
	client := &http.Client{}
	for _, options := range []PrivateDesktopMediaOptions{
		{Origin: "ws://127.0.0.1/private", HTTPClient: client, ExpectedProviderID: "provider"},
		{Origin: "wss://127.0.0.1/private", HTTPClient: nil, ExpectedProviderID: "provider"},
		{Origin: "wss://127.0.0.1/private", HTTPClient: client},
	} {
		if _, err := NewPrivateDesktopMediaSource(options); !errors.Is(err, product.ErrInvalid) {
			t.Fatalf("options=%#v err=%v", options, err)
		}
	}
	if _, err := desktopgateway.New(desktopgateway.Options{Resolver: (*privateDesktopTestResolver)(nil), Media: newPrivateDesktopTestSource(), AllowInsecureHTTPForTests: true}); err == nil {
		t.Fatal("typed-nil private resolver accepted")
	}
}

func newPrivateDesktopTestClient(t *testing.T, server *httptest.Server, providerID string) *PrivateDesktopMediaSource {
	t.Helper()
	source, err := NewPrivateDesktopMediaSource(PrivateDesktopMediaOptions{
		Origin: strings.Replace(server.URL, "http://", "ws://", 1), HTTPClient: server.Client(),
		AllowHTTPForTests: true, ExpectedProviderID: providerID, OpenTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func privateDesktopTestBinding(expires time.Time) product.GatewayBinding {
	return product.GatewayBinding{
		ConnectionID: "con-private-desktop", TenantID: "tenant-private-desktop",
		Actor:       product.ActorRef{Type: product.ActorHuman, ID: "owner-private-desktop"},
		WorkspaceID: "wsp-private-desktop", SlotKey: "desktop-main", SlotGeneration: 3,
		SessionID: "ses-private-desktop", ProtocolProfile: product.SessionProfileDesktop,
		AccessMode: product.GrantAccessControl, ControlLeaseID: "ctl-private-desktop", ControlFence: 7,
		ExpiresAt: expires, ProviderRevisionID: "provider-desktop-revision", SandboxID: "sandbox-private-desktop",
		HandoffReference: "ref:desktop-session:11111111111111111111111111111111", ConnectionGeneration: 5,
		HandoffExpiresAt: expires,
	}
}

func privateDesktopTestPolicy() DesktopLiveMediaPolicy {
	return DesktopLiveMediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30,
		MaxVideoBitrateKbps: 2000, AudioCodec: "audio/opus", MaxAudioBitrateKbps: 64}
}

type privateDesktopTestResolver struct {
	binding product.GatewayBinding
	revoked atomic.Bool
}

func (r *privateDesktopTestResolver) Resolve(_ context.Context, reference string) (desktopreference.Endpoint, error) {
	if r == nil || r.revoked.Load() || reference != r.binding.HandoffReference {
		return desktopreference.Endpoint{}, desktopreference.ErrUnavailable
	}
	return desktopreference.Endpoint{
		Reference: reference, SandboxID: r.binding.SandboxID, DesktopSessionID: r.binding.SessionID,
		CapabilityProfileID: product.DesktopCapabilityProfile, ConnectionGeneration: r.binding.ConnectionGeneration,
		ExpiresAt: r.binding.HandoffExpiresAt,
		Attach: func(context.Context) (providerdesktop.Attachment, error) {
			if r.revoked.Load() {
				return providerdesktop.Attachment{}, desktopreference.ErrRevoked
			}
			return providerdesktop.Attachment{DesktopSessionID: r.binding.SessionID, ConnectionGeneration: r.binding.ConnectionGeneration,
				MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID,
				DisplayReference: "ref:desktop-display:primary", Width: 1280, Height: 720, Depth: 24,
				PrivateInputModes: []string{"keyboard", "pointer"}, AttachedAt: time.Now().UTC()}, nil
		},
	}, nil
}

type privateDesktopTestSource struct {
	opened    chan *privateDesktopTestSession
	closeGate <-chan struct{}
}

func newPrivateDesktopTestSource() *privateDesktopTestSource {
	return &privateDesktopTestSource{opened: make(chan *privateDesktopTestSession, 8)}
}

func (s *privateDesktopTestSource) Open(_ context.Context, _ desktopreference.Endpoint, _ providerdesktop.Attachment, _ desktopgateway.MediaPolicy) (desktopgateway.Session, error) {
	session := &privateDesktopTestSession{video: make(chan []byte, 8), audio: make(chan []byte, 8), stop: make(chan struct{}), closeStarted: make(chan struct{}), closeFinished: make(chan struct{}), closeGate: s.closeGate}
	s.opened <- session
	return session, nil
}

type privateDesktopTestSession struct {
	video, audio  chan []byte
	stop          chan struct{}
	closed        atomic.Bool
	closeOnce     sync.Once
	closeCalls    atomic.Int64
	closeStarted  chan struct{}
	closeFinished chan struct{}
	closeGate     <-chan struct{}
	commandCount  atomic.Int64
}

func (s *privateDesktopTestSession) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	return s.read(ctx, s.video)
}

func (s *privateDesktopTestSession) ReadAudioRTP(ctx context.Context) ([]byte, error) {
	return s.read(ctx, s.audio)
}

func (s *privateDesktopTestSession) read(ctx context.Context, source <-chan []byte) ([]byte, error) {
	select {
	case value := <-source:
		return value, nil
	case <-s.stop:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *privateDesktopTestSession) HandleInput(context.Context, desktopgateway.Input) (desktopgateway.InputResult, error) {
	s.commandCount.Add(1)
	return desktopgateway.InputResult{Text: "private clipboard"}, nil
}

func (s *privateDesktopTestSession) UpdateStream(context.Context, desktopgateway.DisplayPolicy, string) error {
	s.commandCount.Add(1)
	return nil
}

func (s *privateDesktopTestSession) Resynchronize(context.Context) error {
	s.commandCount.Add(1)
	return nil
}

func (s *privateDesktopTestSession) RequestKeyframe(context.Context) error {
	s.commandCount.Add(1)
	return nil
}

func (s *privateDesktopTestSession) Close() error {
	s.closeCalls.Add(1)
	s.closeOnce.Do(func() {
		close(s.closeStarted)
		if s.closeGate != nil {
			<-s.closeGate
		}
		s.closed.Store(true)
		close(s.stop)
		close(s.closeFinished)
	})
	return nil
}

var (
	_ desktopgateway.Resolver    = (*privateDesktopTestResolver)(nil)
	_ desktopgateway.MediaSource = (*privateDesktopTestSource)(nil)
	_ desktopgateway.Session     = (*privateDesktopTestSession)(nil)
)
