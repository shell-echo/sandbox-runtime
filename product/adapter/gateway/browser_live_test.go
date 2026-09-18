package productgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestBrowserLiveHandlerCarriesBoundedMediaAndFencedInput(t *testing.T) {
	for _, test := range []struct {
		name       string
		accessMode string
		control    bool
	}{
		{name: "viewer", accessMode: product.GrantAccessView},
		{name: "controller", accessMode: product.GrantAccessControl, control: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := testBrowserLiveBinding(test.accessMode)
			store := &grantStoreSpy{ticket: strings.Repeat(string(test.name[0]), 43), binding: binding, active: true}
			source := &browserLiveMediaSourceSpy{opened: make(chan struct{}), session: newBrowserLiveMediaSessionSpy()}
			handler := mustBrowserLiveHandler(t, store, source)
			server := httptest.NewTLSServer(handler)
			defer server.Close()

			clientPeer, dataChannel, offer := newBrowserLiveClientOffer(t, test.control)
			defer clientPeer.Close()
			trackPackets := make(chan *rtp.Packet, 1)
			clientPeer.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
				packet, _, err := track.ReadRTP()
				if err == nil {
					trackPackets <- packet
				}
			})
			response := postBrowserLiveOffer(t, server, store.ticket, offer, test.control)
			if response.ConnectionID != binding.ConnectionID || response.AccessMode != test.accessMode || response.Answer.Type != "answer" {
				t.Fatalf("response=%#v", response)
			}
			if err := clientPeer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: response.Answer.SDP}); err != nil {
				t.Fatal(err)
			}
			waitForPeerState(t, clientPeer, webrtc.PeerConnectionStateConnected)

			packet := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: 1, Timestamp: 3000, SSRC: 1234, Marker: true}, Payload: []byte{0x10, 0x00, 0x00, 0x00}}
			encoded, err := packet.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			source.session.rtp <- encoded
			select {
			case received := <-trackPackets:
				if received.SequenceNumber != packet.SequenceNumber || !bytes.Equal(received.Payload, packet.Payload) {
					t.Fatalf("received=%#v", received)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("RTP was not received")
			}

			if test.control {
				opened := make(chan struct{})
				dataChannel.OnOpen(func() { close(opened) })
				select {
				case <-opened:
				case <-time.After(3 * time.Second):
					t.Fatal("control data channel did not open")
				}
				results := make(chan webrtc.DataChannelMessage, 1)
				dataChannel.OnMessage(func(message webrtc.DataChannelMessage) { results <- message })
				if err := dataChannel.SendText(`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":20,"y":30,"button":0,"delta_x":0,"delta_y":0,"user_activation":true}}`); err != nil {
					t.Fatal(err)
				}
				select {
				case input := <-source.session.inputs:
					if input.Action.Kind != product.BrowserActionPointer || input.X != 20 || input.Y != 30 || input.ControlLeaseID != binding.ControlLeaseID || input.ControlFence != binding.ControlFence {
						t.Fatalf("input=%#v", input)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("fenced input was not forwarded")
				}
				select {
				case result := <-results:
					if !result.IsString || string(result.Data) != `{"type":"input.result","sequence":1,"ok":true}` {
						t.Fatalf("input result=%s", result.Data)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("input result was not returned")
				}
			}
			if source.policy.Codec != "video/VP8" || source.policy.Width != 640 || source.policy.Height != 480 {
				t.Fatalf("policy=%#v", source.policy)
			}
		})
	}
}

func TestBrowserLiveHandlerAuthenticatesBeforeOpeningPeer(t *testing.T) {
	store := &grantStoreSpy{ticket: strings.Repeat("a", 43), binding: testBrowserLiveBinding(product.GrantAccessView), active: true}
	source := &browserLiveMediaSourceSpy{opened: make(chan struct{}), session: newBrowserLiveMediaSessionSpy()}
	handler := mustBrowserLiveHandler(t, store, source)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	peer, _, offer := newBrowserLiveClientOffer(t, false)
	defer peer.Close()
	payload := encodeBrowserLiveOffer(t, offer, false)

	for _, test := range []struct {
		name, origin, ticket string
		status               int
	}{
		{name: "missing origin", ticket: store.ticket, status: http.StatusForbidden},
		{name: "wrong origin", origin: "https://evil.example", ticket: store.ticket, status: http.StatusForbidden},
		{name: "missing ticket", origin: "https://app.example", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.ticket != "" {
				request.Header.Set("Authorization", "Ticket "+test.ticket)
			}
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status=%d", response.StatusCode)
			}
		})
	}
	store.mu.Lock()
	consumed := store.consumed
	store.mu.Unlock()
	if consumed {
		t.Fatal("unauthenticated request consumed the one-use grant")
	}
	select {
	case <-source.opened:
		t.Fatal("unauthenticated request opened media")
	default:
	}

	plain := httptest.NewServer(handler)
	defer plain.Close()
	request, _ := http.NewRequest(http.MethodPost, plain.URL, bytes.NewReader(payload))
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Authorization", "Ticket "+store.ticket)
	response, err := plain.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("insecure status=%d", response.StatusCode)
	}
}

func TestBrowserLiveHandlerRejectsUnsupportedNegotiationAndViewerControl(t *testing.T) {
	valid := browserLiveSignalRequest{
		Offer: browserLiveDescription{Type: "offer", SDP: "v=0"},
		Video: BrowserLiveVideoPolicy{Codec: "video/VP8", Width: 640, Height: 480, MaxFPS: 30, MaxBitrateKbps: 1000},
	}
	invalid := []browserLiveSignalRequest{valid, valid, valid}
	invalid[0].Video.Codec = "video/H264"
	invalid[1].Video.Width = 4096
	invalid[2].Video.MaxBitrateKbps = 10000
	for _, signal := range invalid {
		encoded, err := json.Marshal(signal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeBrowserLiveSignal(bytes.NewReader(encoded), int64(len(encoded))); err == nil {
			t.Fatalf("invalid negotiation accepted: %#v", signal.Video)
		}
	}

	store := &grantStoreSpy{ticket: strings.Repeat("v", 43), binding: testBrowserLiveBinding(product.GrantAccessView), active: true}
	source := &browserLiveMediaSourceSpy{opened: make(chan struct{}), session: newBrowserLiveMediaSessionSpy()}
	handler := mustBrowserLiveHandler(t, store, source)
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	peer, _, offer := newBrowserLiveClientOffer(t, true)
	defer peer.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(encodeBrowserLiveOffer(t, offer, true)))
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Authorization", "Ticket "+store.ticket)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("viewer control status=%d", response.StatusCode)
	}
	select {
	case <-source.opened:
		t.Fatal("viewer control opened media")
	default:
	}
}

func TestBrowserLiveMediaQueueClosesSlowConsumer(t *testing.T) {
	binding := testBrowserLiveBinding(product.GrantAccessView)
	store := &grantStoreSpy{binding: binding, active: true}
	source := newBrowserLiveMediaSessionSpy()
	handler := &BrowserLiveHandler{grants: store, media: &browserLiveMediaSourceSpy{}, maxRTPQueue: 1, maxInputQueue: 1, pollInterval: time.Second, connectionTimeout: time.Second, sessions: map[string]int{binding.SessionID: 1}, peers: 1}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	state := newBrowserLivePeer(handler, peer, source, binding, BrowserLiveVideoPolicy{MaxBitrateKbps: 4000}, testGatewayBrowserPolicy())
	writer := &blockingRTPWriter{entered: make(chan struct{}), release: make(chan struct{})}
	go state.mediaLoop(writer)
	packet, _ := (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96}}).Marshal()
	source.rtp <- packet
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("writer did not block")
	}
	source.rtp <- packet
	source.rtp <- packet
	select {
	case <-state.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("slow media consumer was not closed")
	}
	close(writer.release)
}

func TestBrowserLiveProductionRequiresEncryptedRelay(t *testing.T) {
	base := BrowserLiveOptions{Grants: &grantStoreSpy{}, Media: &browserLiveMediaSourceSpy{}, Policy: &browserPolicySourceSpy{policy: testGatewayBrowserPolicy()}, Transfers: denyBrowserTransferAuthority{}, AllowedOrigins: []string{"https://app.example"}}
	if _, err := NewBrowserLiveHandler(base); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("missing relay err=%v", err)
	}
	base.ICEServers = []webrtc.ICEServer{{URLs: []string{"turn:relay.example:3478"}, Username: "user", Credential: "password", CredentialType: webrtc.ICECredentialTypePassword}}
	if _, err := NewBrowserLiveHandler(base); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("unencrypted relay err=%v", err)
	}
	base.ICEServers[0].URLs[0] = "turns:relay.example:5349"
	if _, err := NewBrowserLiveHandler(base); err != nil {
		t.Fatalf("encrypted relay err=%v", err)
	}
}

func mustBrowserLiveHandler(t *testing.T, store product.ConnectionGrantStore, source BrowserLiveMediaSource) *BrowserLiveHandler {
	t.Helper()
	handler, err := NewBrowserLiveHandler(BrowserLiveOptions{
		Grants: store, Media: source, Policy: &browserPolicySourceSpy{policy: testGatewayBrowserPolicy()}, Transfers: denyBrowserTransferAuthority{}, AllowedOrigins: []string{"https://app.example"},
		AllowHostCandidatesForTests: true, AuthorityPollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func testGatewayBrowserPolicy() product.BrowserPolicy {
	return product.BrowserPolicy{
		Revision:  1,
		Input:     product.BrowserInputPolicy{Keyboard: true, Pointer: true, Touch: true},
		Clipboard: product.BrowserClipboardPolicy{MaxBytes: product.MaxBrowserClipboardBytes},
	}
}

type browserPolicySourceSpy struct {
	mu     sync.RWMutex
	policy product.BrowserPolicy
	err    error
}

func (s *browserPolicySourceSpy) CurrentBrowserPolicy(context.Context, product.GatewayBinding) (product.BrowserPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy, s.err
}

func (s *browserPolicySourceSpy) setRevision(revision int64) {
	s.mu.Lock()
	s.policy.Revision = revision
	s.mu.Unlock()
}

func testBrowserLiveBinding(access string) product.GatewayBinding {
	now := time.Now().UTC()
	binding := product.GatewayBinding{
		ConnectionID: "con-live", TenantID: "tenant-1", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-1"},
		WorkspaceID: "wrk-1", SlotKey: "browser-main", SessionID: "ses-live", ProtocolProfile: product.SessionProfileBrowserLive,
		SlotGeneration: 1, AccessMode: access, ExpiresAt: now.Add(time.Minute), ProviderRevisionID: "provider-v1",
		SandboxID: "sandbox-live", HandoffReference: "ref:browser-session:opaque", ConnectionGeneration: 1, HandoffExpiresAt: now.Add(time.Minute),
	}
	if access == product.GrantAccessControl {
		binding.ControlLeaseID = "ctl-live"
		binding.ControlFence = 9
	}
	return binding
}

func newBrowserLiveClientOffer(t *testing.T, control bool) (*webrtc.PeerConnection, *webrtc.DataChannel, webrtc.SessionDescription) {
	t.Helper()
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	var channel *webrtc.DataChannel
	if control {
		channel, err = peer.CreateDataChannel(BrowserLiveDataChannel, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	offer, err := peer.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(peer)
	if err := peer.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gathered:
	case <-time.After(3 * time.Second):
		t.Fatal("client ICE gathering timed out")
	}
	return peer, channel, *peer.LocalDescription()
}

func encodeBrowserLiveOffer(t *testing.T, offer webrtc.SessionDescription, control bool) []byte {
	t.Helper()
	encoded, err := json.Marshal(browserLiveSignalRequest{
		Offer: browserLiveDescription{Type: "offer", SDP: offer.SDP}, ControlDataChannel: control,
		Video: BrowserLiveVideoPolicy{Codec: "video/VP8", Width: 640, Height: 480, MaxFPS: 30, MaxBitrateKbps: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func postBrowserLiveOffer(t *testing.T, server *httptest.Server, ticket string, offer webrtc.SessionDescription, control bool) browserLiveSignalResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(encodeBrowserLiveOffer(t, offer, control)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
	var signal browserLiveSignalResponse
	if err := json.NewDecoder(response.Body).Decode(&signal); err != nil {
		t.Fatal(err)
	}
	return signal
}

func waitForPeerState(t *testing.T, peer *webrtc.PeerConnection, expected webrtc.PeerConnectionState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if peer.ConnectionState() == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer state=%s", peer.ConnectionState())
}

type browserLiveMediaSourceSpy struct {
	mu      sync.Mutex
	opened  chan struct{}
	session *browserLiveMediaSessionSpy
	policy  BrowserLiveVideoPolicy
	binding product.GatewayBinding
}

func (s *browserLiveMediaSourceSpy) Open(_ context.Context, binding product.GatewayBinding, policy BrowserLiveVideoPolicy) (BrowserLiveMediaSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.binding, s.policy = binding, policy
	if s.opened != nil {
		select {
		case <-s.opened:
		default:
			close(s.opened)
		}
	}
	if s.session == nil {
		return nil, errors.New("unavailable")
	}
	return s.session, nil
}

type browserLiveMediaSessionSpy struct {
	rtp       chan []byte
	inputs    chan BrowserLiveInput
	closed    chan struct{}
	closeOnce sync.Once
}

func newBrowserLiveMediaSessionSpy() *browserLiveMediaSessionSpy {
	return &browserLiveMediaSessionSpy{rtp: make(chan []byte, 16), inputs: make(chan BrowserLiveInput, 4), closed: make(chan struct{})}
}

func (s *browserLiveMediaSessionSpy) ReadRTP(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, io.EOF
	case packet := <-s.rtp:
		return packet, nil
	}
}

func (s *browserLiveMediaSessionSpy) HandleInput(ctx context.Context, input BrowserLiveInput) (BrowserLiveInputResult, error) {
	select {
	case <-ctx.Done():
		return BrowserLiveInputResult{}, ctx.Err()
	case s.inputs <- input:
		return BrowserLiveInputResult{}, nil
	}
}

func (*browserLiveMediaSessionSpy) RequestKeyframe(context.Context) error { return nil }
func (s *browserLiveMediaSessionSpy) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type blockingRTPWriter struct {
	entered chan struct{}
	entry   sync.Once
	release chan struct{}
}

func (w *blockingRTPWriter) WriteRTP(*rtp.Packet) error {
	if w.entered != nil {
		w.entry.Do(func() { close(w.entered) })
	}
	<-w.release
	return nil
}
