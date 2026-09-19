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
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestDesktopLiveHandlerCarriesBoundedVideoAudioAndOrderedInput(t *testing.T) {
	for _, test := range []struct {
		name, access string
		control      bool
		audio        bool
	}{
		{name: "viewer", access: product.GrantAccessView},
		{name: "controller", access: product.GrantAccessControl, control: true, audio: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := testDesktopLiveBinding(test.access)
			store := &grantStoreSpy{ticket: strings.Repeat(string(test.name[0]), 43), binding: binding, active: true}
			session := newDesktopLiveMediaSessionSpy()
			source := &desktopLiveMediaSourceSpy{opened: make(chan struct{}), session: session}
			authority := &desktopPolicySourceSpy{policy: testDesktopPolicy()}
			handler := mustDesktopLiveHandler(t, store, source, authority)
			server := httptest.NewTLSServer(handler)
			defer server.Close()

			client, channel, offer := newDesktopLiveClientOffer(t, test.control, test.audio)
			defer client.Close()
			videoPackets := make(chan *rtp.Packet, 1)
			audioPackets := make(chan *rtp.Packet, 1)
			client.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
				packet, _, err := track.ReadRTP()
				if err != nil {
					return
				}
				if track.Kind() == webrtc.RTPCodecTypeAudio {
					audioPackets <- packet
				} else {
					videoPackets <- packet
				}
			})
			response, raw := postDesktopLiveOffer(t, server, store.ticket, offer, test.control, test.audio)
			if response.ConnectionID != binding.ConnectionID || response.AccessMode != test.access || response.Answer.Type != "answer" || response.RecordingMode != binding.RecordingPolicy || bytes.Contains(raw, []byte(binding.HandoffReference)) {
				t.Fatalf("response=%#v raw=%s", response, raw)
			}
			if err := client.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: response.Answer.SDP}); err != nil {
				t.Fatal(err)
			}
			waitForPeerState(t, client, webrtc.PeerConnectionStateConnected)

			video := desktopRTPPacket(t, 96, 1, 3000, 1001, []byte{0x10, 0x00, 0x00, 0x00})
			session.video <- video
			select {
			case packet := <-videoPackets:
				if packet.SequenceNumber != 1 || !bytes.Equal(packet.Payload, []byte{0x10, 0x00, 0x00, 0x00}) {
					t.Fatalf("video packet=%#v", packet)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Desktop video RTP was not received")
			}

			if test.audio {
				audio := desktopRTPPacket(t, 111, 2, 960, 1002, []byte{0xf8, 0xff, 0xfe})
				session.audio <- audio
				select {
				case packet := <-audioPackets:
					if packet.SequenceNumber != 2 || !bytes.Equal(packet.Payload, []byte{0xf8, 0xff, 0xfe}) {
						t.Fatalf("audio packet=%#v", packet)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("Desktop audio RTP was not received")
				}
			}

			if test.control {
				opened := make(chan struct{})
				channel.OnOpen(func() { close(opened) })
				select {
				case <-opened:
				case <-time.After(3 * time.Second):
					t.Fatal("Desktop control data channel did not open")
				}
				results := make(chan webrtc.DataChannelMessage, 1)
				channel.OnMessage(func(message webrtc.DataChannelMessage) { results <- message })
				if err := channel.SendText(`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":20,"y":30,"button":0,"delta_x":0,"delta_y":0}}`); err != nil {
					t.Fatal(err)
				}
				select {
				case input := <-session.inputs:
					if input.Kind != "pointer" || input.X != 20 || input.Y != 30 || input.ControlLeaseID != binding.ControlLeaseID || input.ControlFence != binding.ControlFence {
						t.Fatalf("input=%#v", input)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("fenced Desktop input was not forwarded")
				}
				select {
				case result := <-results:
					if !result.IsString || string(result.Data) != `{"type":"input.result","sequence":1,"ok":true}` {
						t.Fatalf("input result=%s", result.Data)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("Desktop input result was not returned")
				}
				if err := channel.SendText(`{"type":"stream.configure","sequence":2,"display":{"width":1024,"height":768,"max_fps":24},"audio_device":"default"}`); err != nil {
					t.Fatal(err)
				}
				select {
				case update := <-session.updates:
					if update.display.Width != 1024 || update.display.Height != 768 || update.display.MaxFPS != 24 || update.audioDevice != "default" {
						t.Fatalf("stream update=%#v", update)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("Desktop stream update was not forwarded")
				}
				select {
				case result := <-results:
					if string(result.Data) != `{"type":"stream.configure.result","sequence":2,"ok":true}` {
						t.Fatalf("stream update result=%s", result.Data)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("Desktop stream update result was not returned")
				}
				time.Sleep(defaultDesktopResyncInterval)
				if err := channel.SendText(`{"type":"stream.resync","sequence":3}`); err != nil {
					t.Fatal(err)
				}
				select {
				case result := <-results:
					if string(result.Data) != `{"type":"stream.resync.result","sequence":3,"ok":true}` {
						t.Fatalf("stream resync result=%s", result.Data)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("Desktop stream resync result was not returned")
				}
				if session.resyncs.Load() < 3 || session.keyframes.Load() < 3 {
					t.Fatalf("resyncs=%d keyframes=%d", session.resyncs.Load(), session.keyframes.Load())
				}
				if authority.calls.Load() < 2 {
					t.Fatalf("input authority calls=%d", authority.calls.Load())
				}
			}
		})
	}
}

func TestDesktopLiveReconnectWithinGraceResynchronizesAndRejectsOldEpochInput(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	store := &grantStoreSpy{binding: binding, active: true}
	media := newDesktopLiveMediaSessionSpy()
	handler := &DesktopLiveHandler{
		grants: store, policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, transfers: denyDesktopTransferAuthority{}, audit: &auditStoreSpy{},
		maxInputQueue: 2, disconnectGrace: 20 * time.Millisecond, minKeyframeInterval: time.Millisecond,
		minResyncInterval: time.Millisecond, sessions: map[string]int{binding.SessionID: 1}, peers: 1,
	}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	state := newDesktopLivePeer(handler, peer, media, nil, binding, testDesktopLiveMediaPolicy(true), testDesktopPolicy())
	state.onConnectionState(webrtc.PeerConnectionStateConnected)
	oldEpoch := state.currentStateEpoch()
	state.onConnectionState(webrtc.PeerConnectionStateDisconnected)
	state.onConnectionState(webrtc.PeerConnectionStateConnected)
	time.Sleep(2 * handler.disconnectGrace)
	select {
	case <-state.ctx.Done():
		t.Fatal("recovered Desktop connection was closed by a stale disconnect timer")
	default:
	}
	if media.resyncs.Load() != 2 || media.keyframes.Load() != 2 {
		t.Fatalf("reconnect resyncs=%d keyframes=%d", media.resyncs.Load(), media.keyframes.Load())
	}
	go state.inputLoop()
	state.inputs <- desktopLiveQueuedInput{kind: "input", sequence: 1, epoch: oldEpoch, input: DesktopLiveInput{
		Sequence: 1, Kind: product.DesktopActionPointer, Action: product.DesktopPolicyAction{Kind: product.DesktopActionPointer},
		ControlLeaseID: binding.ControlLeaseID, ControlFence: binding.ControlFence,
	}}
	select {
	case <-state.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("pre-disconnect Desktop input was not rejected after reconnect")
	}
	select {
	case input := <-media.inputs:
		t.Fatalf("stale input reached Desktop media: %#v", input)
	default:
	}
}

func TestDesktopLiveControlResyncAndResizeBounds(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	mediaPolicy := testDesktopLiveMediaPolicy(true)
	valid, err := decodeDesktopLiveControl([]byte(`{"type":"stream.configure","sequence":1,"display":{"width":800,"height":600,"max_fps":30},"audio_device":"disabled"}`), mediaPolicy, binding)
	if err != nil || valid.kind != "stream.configure" || valid.display.Width != 800 || valid.audioDevice != "disabled" {
		t.Fatalf("valid stream configuration=%#v err=%v", valid, err)
	}
	for _, document := range []string{
		`{"type":"stream.configure","sequence":1,"display":{"width":319,"height":600,"max_fps":30},"audio_device":"default"}`,
		`{"type":"stream.configure","sequence":1,"display":{"width":800,"height":600,"max_fps":61},"audio_device":"host-device-1"}`,
		`{"type":"stream.resync","sequence":1,"extra":true}`,
	} {
		if _, err := decodeDesktopLiveControl([]byte(document), mediaPolicy, binding); !errors.Is(err, product.ErrInvalid) {
			t.Fatalf("unbounded Desktop control %s err=%v", document, err)
		}
	}
	oldMedia := mediaPolicy
	oldMedia.Width = 1280
	stale := []byte(`{"type":"input","sequence":2,"action":{"kind":"pointer","event":"move","x":1100,"y":300,"button":0,"delta_x":0,"delta_y":0}}`)
	if _, err := decodeDesktopLiveInput(stale, oldMedia, binding); err != nil {
		t.Fatalf("input should fit old display: %v", err)
	}
	resized := oldMedia
	resized.Width = 800
	if _, err := decodeDesktopLiveInput(stale, resized, binding); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("pre-resize coordinates survived current-display revalidation: %v", err)
	}

	media := newDesktopLiveMediaSessionSpy()
	handler := &DesktopLiveHandler{minResyncInterval: time.Hour, minKeyframeInterval: time.Hour}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	state := newDesktopLivePeer(handler, peer, media, nil, binding, mediaPolicy, testDesktopPolicy())
	if !state.resynchronize(false) || state.resynchronize(false) {
		t.Fatal("Desktop control resynchronization limiter was not fail closed")
	}
	if media.resyncs.Load() != 1 || media.keyframes.Load() != 1 {
		t.Fatalf("bounded resyncs=%d keyframes=%d", media.resyncs.Load(), media.keyframes.Load())
	}
}

func TestDesktopLiveAuthenticatesBeforeGrantConsumptionAndMediaOpen(t *testing.T) {
	store := &grantStoreSpy{ticket: strings.Repeat("a", 43), binding: testDesktopLiveBinding(product.GrantAccessView), active: true}
	source := &desktopLiveMediaSourceSpy{opened: make(chan struct{}), session: newDesktopLiveMediaSessionSpy()}
	handler := mustDesktopLiveHandler(t, store, source, &desktopPolicySourceSpy{policy: testDesktopPolicy()})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	peer, _, offer := newDesktopLiveClientOffer(t, false, false)
	defer peer.Close()
	payload := encodeDesktopLiveOffer(t, offer, false, false)

	for _, test := range []struct {
		name, origin, ticket string
		status               int
	}{
		{name: "missing origin", ticket: store.ticket, status: http.StatusForbidden},
		{name: "wrong origin", origin: "https://evil.example", ticket: store.ticket, status: http.StatusForbidden},
		{name: "missing ticket", origin: "https://app.example", status: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(payload))
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
		t.Fatal("unauthenticated request consumed the one-use Desktop grant")
	}
	select {
	case <-source.opened:
		t.Fatal("unauthenticated request opened Desktop media")
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
		t.Fatalf("insecure signaling status=%d", response.StatusCode)
	}
}

func TestDesktopLiveRejectsUnsupportedNegotiationViewerControlAndRequiredRecording(t *testing.T) {
	valid := desktopLiveSignalRequest{
		Offer: desktopLiveDescription{Type: "offer", SDP: "v=0"},
		Media: testDesktopLiveMediaPolicy(false),
	}
	invalid := []desktopLiveSignalRequest{valid, valid, valid, valid}
	invalid[0].Media.VideoCodec = "video/H264"
	invalid[1].Media.Width = 4096
	invalid[2].Media.AudioCodec = "audio/PCMU"
	invalid[3].Media.MaxAudioBitrateKbps = 32
	for _, signal := range invalid {
		encoded, err := json.Marshal(signal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeDesktopLiveSignal(bytes.NewReader(encoded), int64(len(encoded))); err == nil {
			t.Fatalf("invalid Desktop negotiation accepted: %#v", signal.Media)
		}
	}
	peer, _, offer := newDesktopLiveClientOffer(t, false, false)
	peer.Close()
	validOffer := desktopLiveSignalRequest{Offer: desktopLiveDescription{Type: "offer", SDP: offer.SDP}, Media: testDesktopLiveMediaPolicy(false)}
	validEncoded, err := json.Marshal(validOffer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDesktopLiveSignal(bytes.NewReader(validEncoded), int64(len(validEncoded))); err != nil {
		t.Fatalf("valid receive-only Desktop offer rejected: %v", err)
	}
	unsafeOffer := validOffer
	unsafeOffer.Offer.SDP = strings.Replace(unsafeOffer.Offer.SDP, "a=recvonly", "a=sendrecv", 1)
	unsafeEncoded, err := json.Marshal(unsafeOffer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeDesktopLiveSignal(bytes.NewReader(unsafeEncoded), int64(len(unsafeEncoded))); err == nil {
		t.Fatal("Desktop offer capable of upstream camera/microphone media was accepted")
	}

	for _, test := range []struct {
		name       string
		binding    product.GatewayBinding
		control    bool
		wantStatus int
	}{
		{name: "viewer control", binding: testDesktopLiveBinding(product.GrantAccessView), control: true, wantStatus: http.StatusUnauthorized},
		{name: "required recording", binding: func() product.GatewayBinding {
			b := testDesktopLiveBinding(product.GrantAccessView)
			b.RecordingPolicy = "required"
			return b
		}(), wantStatus: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &grantStoreSpy{ticket: strings.Repeat("v", 43), binding: test.binding, active: true}
			source := &desktopLiveMediaSourceSpy{opened: make(chan struct{}), session: newDesktopLiveMediaSessionSpy()}
			handler := mustDesktopLiveHandler(t, store, source, &desktopPolicySourceSpy{policy: testDesktopPolicy()})
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			peer, _, offer := newDesktopLiveClientOffer(t, test.control, false)
			defer peer.Close()
			request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(encodeDesktopLiveOffer(t, offer, test.control, false)))
			request.Header.Set("Origin", "https://app.example")
			request.Header.Set("Authorization", "Ticket "+store.ticket)
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != test.wantStatus {
				t.Fatalf("status=%d want=%d", response.StatusCode, test.wantStatus)
			}
			select {
			case <-source.opened:
				t.Fatal("rejected Desktop negotiation opened media")
			default:
			}
		})
	}
}

func TestDesktopLiveInputDecoderIsClosedAndFenceBound(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	media := testDesktopLiveMediaPolicy(false)
	valid := []string{
		`{"type":"input","sequence":1,"action":{"kind":"keyboard","event":"down","code":"KeyA","key":"a","modifiers":["shift"]}}`,
		`{"type":"input","sequence":2,"action":{"kind":"pointer","event":"wheel","x":10,"y":20,"button":0,"delta_x":1,"delta_y":-1}}`,
		`{"type":"input","sequence":3,"action":{"kind":"touch","event":"start","points":[{"id":1,"x":10,"y":20}]}}`,
	}
	for _, document := range valid {
		input, err := decodeDesktopLiveInput([]byte(document), media, binding)
		if err != nil || input.ControlLeaseID != binding.ControlLeaseID || input.ControlFence != binding.ControlFence {
			t.Fatalf("input=%#v err=%v", input, err)
		}
	}
	invalid := []string{
		`{"type":"input","sequence":1,"action":{"kind":"clipboard.read","text":"not-allowed"}}`,
		`{"type":"input","sequence":1,"action":{"kind":"microphone"}}`,
		`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":640,"y":1,"button":0,"delta_x":0,"delta_y":0}}`,
		`{"type":"input","sequence":1,"sequence":2,"action":{"kind":"keyboard","event":"down","code":"KeyA","key":"a","modifiers":[]}}`,
	}
	for _, document := range invalid {
		if _, err := decodeDesktopLiveInput([]byte(document), media, binding); err == nil {
			t.Fatalf("invalid Desktop input accepted: %s", document)
		}
	}
	viewer := testDesktopLiveBinding(product.GrantAccessView)
	if _, err := decodeDesktopLiveInput([]byte(valid[0]), media, viewer); err == nil {
		t.Fatal("viewer input was not rejected")
	}
}

func TestDesktopLiveRejectsOutOfOrderRevokedOrDeniedInput(t *testing.T) {
	for _, test := range []struct {
		name      string
		sequence  int64
		revoked   bool
		policyErr error
	}{
		{name: "out of order", sequence: 2},
		{name: "revoked", sequence: 1, revoked: true},
		{name: "policy denied", sequence: 1, policyErr: product.ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := testDesktopLiveBinding(product.GrantAccessControl)
			store := &grantStoreSpy{binding: binding, active: !test.revoked}
			authority := &desktopPolicySourceSpy{policy: testDesktopPolicy(), err: test.policyErr}
			media := newDesktopLiveMediaSessionSpy()
			handler := &DesktopLiveHandler{grants: store, policy: authority, transfers: denyDesktopTransferAuthority{}, audit: &auditStoreSpy{}, maxInputQueue: 1, sessions: map[string]int{binding.SessionID: 1}, peers: 1}
			peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
			if err != nil {
				t.Fatal(err)
			}
			state := newDesktopLivePeer(handler, peer, media, nil, binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
			state.state = webrtc.PeerConnectionStateConnected
			go state.inputLoop()
			state.inputs <- desktopLiveQueuedInput{input: DesktopLiveInput{Sequence: test.sequence, Kind: "pointer", Action: product.DesktopPolicyAction{Kind: product.DesktopActionPointer}, ControlLeaseID: binding.ControlLeaseID, ControlFence: binding.ControlFence}}
			select {
			case <-state.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("unsafe Desktop input did not close peer")
			}
			select {
			case input := <-media.inputs:
				t.Fatalf("unsafe Desktop input reached broker: %#v", input)
			default:
			}
		})
	}
}

func TestDesktopLiveContinuousAuthorityClosesRevokedPeer(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessView)
	store := &grantStoreSpy{binding: binding, active: true}
	media := newDesktopLiveMediaSessionSpy()
	handler := &DesktopLiveHandler{grants: store, policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, audit: &auditStoreSpy{}, pollInterval: 10 * time.Millisecond, sessions: map[string]int{binding.SessionID: 1}, peers: 1}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	state := newDesktopLivePeer(handler, peer, media, nil, binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
	go state.authorityLoop()
	store.revoke()
	select {
	case <-state.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("revoked Desktop grant did not close the live peer")
	}
}

func TestDesktopLiveAllowsOnlyOneReliableOrderedControlChannel(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	handler := &DesktopLiveHandler{maxInputQueue: 1}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	state := newDesktopLivePeer(handler, peer, newDesktopLiveMediaSessionSpy(), nil, binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
	if !state.claimControlChannel() || state.claimControlChannel() {
		t.Fatal("Desktop peer did not enforce one control data channel")
	}
}

func TestDesktopLiveClosesOnInputBackpressureAndMediaSlowConsumer(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessControl)
	store := &grantStoreSpy{binding: binding, active: true}
	media := newDesktopLiveMediaSessionSpy()
	handler := &DesktopLiveHandler{
		grants: store, policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, transfers: denyDesktopTransferAuthority{}, audit: &auditStoreSpy{}, maxVideoQueue: 1, maxAudioQueue: 1, maxInputQueue: 1,
		pollInterval: time.Second, connectionTimeout: time.Second, sessions: map[string]int{binding.SessionID: 1}, peers: 1,
	}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	state := newDesktopLivePeer(handler, peer, media, nil, binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
	writer := &desktopBlockingRTPWriter{entered: make(chan struct{}), release: make(chan struct{})}
	go state.streamLoop("video.rtp", media.ReadVideoRTP, writer, 1, maxDesktopVideoRTPPacketBytes, 8000)
	packet := desktopRTPPacket(t, 96, 1, 1, 1, []byte{0x01})
	media.video <- packet
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("Desktop writer did not block")
	}
	media.video <- packet
	media.video <- packet
	select {
	case <-state.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("slow Desktop media consumer was not closed")
	}
	close(writer.release)

	peer2, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	media2 := newDesktopLiveMediaSessionSpy()
	handler2 := &DesktopLiveHandler{grants: store, policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, transfers: denyDesktopTransferAuthority{}, audit: &auditStoreSpy{}, maxInputQueue: 1, sessions: map[string]int{binding.SessionID: 1}, peers: 1}
	state2 := newDesktopLivePeer(handler2, peer2, media2, nil, binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
	state2.state = webrtc.PeerConnectionStateConnected
	if !state2.enqueueInput(desktopLiveQueuedInput{input: DesktopLiveInput{Sequence: 1}}) {
		t.Fatal("first Desktop input did not fit")
	}
	if state2.enqueueInput(desktopLiveQueuedInput{input: DesktopLiveInput{Sequence: 2}}) {
		t.Fatal("Desktop input queue exceeded its bound")
	}
	select {
	case <-state2.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("Desktop input backpressure did not close peer")
	}
}

func TestDesktopLiveRequiredRecordingFailsClosedBeforeMediaOpen(t *testing.T) {
	for _, test := range []struct {
		name     string
		recorder DesktopLiveRecorder
		consent  string
	}{
		{name: "missing recorder", consent: "consent-desktop-visible"},
		{name: "recorder unavailable", recorder: &desktopLiveRecorderSpy{err: errors.New("object store unavailable")}, consent: "consent-desktop-visible"},
		{name: "missing visible consent", recorder: &desktopLiveRecorderSpy{session: &desktopLiveRecordingSessionSpy{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := testDesktopLiveBinding(product.GrantAccessView)
			binding.RecordingPolicy = "required"
			store := &grantStoreSpy{ticket: strings.Repeat("r", 43), binding: binding, active: true}
			source := &desktopLiveMediaSourceSpy{opened: make(chan struct{}), session: newDesktopLiveMediaSessionSpy()}
			handler, err := NewDesktopLiveHandler(DesktopLiveOptions{
				Grants: store, Media: source, Policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, Transfers: denyDesktopTransferAuthority{},
				Audit: &auditStoreSpy{}, Recorder: test.recorder, AllowedOrigins: []string{"https://app.example"}, AllowHostCandidatesForTests: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			peer, _, offer := newDesktopLiveClientOffer(t, false, false)
			defer peer.Close()
			request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(encodeDesktopLiveOfferWithConsent(t, offer, false, false, test.consent)))
			request.Header.Set("Origin", "https://app.example")
			request.Header.Set("Authorization", "Ticket "+store.ticket)
			response, err := server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("status=%d", response.StatusCode)
			}
			select {
			case <-source.opened:
				t.Fatal("media opened after required recorder admission failure")
			default:
			}
		})
	}
}

func TestDesktopLiveRequiredRecordingReportsModeAndVisibleConsent(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessView)
	binding.RecordingPolicy = "required"
	store := &grantStoreSpy{ticket: strings.Repeat("v", 43), binding: binding, active: true}
	source := &desktopLiveMediaSourceSpy{session: newDesktopLiveMediaSessionSpy()}
	recording := &desktopLiveRecordingSessionSpy{closed: make(chan bool, 1)}
	recorder := &desktopLiveRecorderSpy{session: recording}
	handler, err := NewDesktopLiveHandler(DesktopLiveOptions{
		Grants: store, Media: source, Policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, Transfers: denyDesktopTransferAuthority{},
		Audit: &auditStoreSpy{}, Recorder: recorder, AllowedOrigins: []string{"https://app.example"}, AllowHostCandidatesForTests: true,
		AuthorityPollInterval: 10 * time.Millisecond, ConnectionTimeout: 2 * time.Second, DisconnectGrace: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client, _, offer := newDesktopLiveClientOffer(t, false, false)
	const consent = "consent-desktop-visible"
	request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(encodeDesktopLiveOfferWithConsent(t, offer, false, false, consent)))
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Authorization", "Ticket "+store.ticket)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var signal desktopLiveSignalResponse
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&signal) != nil || signal.RecordingMode != "required" || recorder.consent != consent {
		t.Fatalf("status=%d signal=%#v recorder consent=%q", response.StatusCode, signal, recorder.consent)
	}
	if err := client.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.Answer.SDP}); err != nil {
		t.Fatal(err)
	}
	waitForPeerState(t, client, webrtc.PeerConnectionStateConnected)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case failed := <-recording.closed:
		if failed {
			t.Fatal("healthy required Desktop recording was marked failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closed Desktop peer did not finalize required recording")
	}
}

func TestDesktopLiveRequiredRecorderLossClosesPeer(t *testing.T) {
	binding := testDesktopLiveBinding(product.GrantAccessView)
	binding.RecordingPolicy = "required"
	media := newDesktopLiveMediaSessionSpy()
	recording := &desktopLiveRecordingSessionSpy{mediaErr: errors.New("recorder lost"), closed: make(chan bool, 1)}
	handler := &DesktopLiveHandler{
		grants: &grantStoreSpy{binding: binding, active: true}, audit: &auditStoreSpy{}, maxVideoQueue: 1, maxInputQueue: 1,
		sessions: map[string]int{binding.SessionID: 1}, peers: 1,
	}
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	state := newDesktopLivePeer(handler, peer, media, recording, binding, testDesktopLiveMediaPolicy(false), testDesktopPolicy())
	release := make(chan struct{})
	defer close(release)
	go state.streamLoop("video.rtp", media.ReadVideoRTP, &desktopBlockingRTPWriter{release: release}, 1, maxDesktopVideoRTPPacketBytes, 8000)
	media.video <- desktopRTPPacket(t, 96, 1, 1, 1, []byte{0x01})
	select {
	case failed := <-recording.closed:
		if !failed {
			t.Fatal("recorder loss was finalized as successful")
		}
	case <-time.After(time.Second):
		t.Fatal("recorder loss did not close Desktop peer")
	}
}

func TestDesktopLiveProductionRequiresEncryptedRelay(t *testing.T) {
	base := DesktopLiveOptions{Grants: &grantStoreSpy{}, Media: &desktopLiveMediaSourceSpy{}, Policy: &desktopPolicySourceSpy{policy: testDesktopPolicy()}, Transfers: denyDesktopTransferAuthority{}, Audit: &auditStoreSpy{}, AllowedOrigins: []string{"https://app.example"}}
	if _, err := NewDesktopLiveHandler(base); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("missing relay err=%v", err)
	}
	base.ICEServers = []webrtc.ICEServer{{URLs: []string{"turn:relay.example:3478"}, Username: "user", Credential: "password", CredentialType: webrtc.ICECredentialTypePassword}}
	if _, err := NewDesktopLiveHandler(base); !errors.Is(err, product.ErrInvalid) {
		t.Fatalf("unencrypted relay err=%v", err)
	}
	base.ICEServers[0].URLs[0] = "turns:relay.example:5349"
	if _, err := NewDesktopLiveHandler(base); err != nil {
		t.Fatalf("encrypted relay err=%v", err)
	}
}

func mustDesktopLiveHandler(t *testing.T, store product.ConnectionGrantStore, source DesktopLiveMediaSource, policy product.DesktopPolicySource) *DesktopLiveHandler {
	t.Helper()
	handler, err := NewDesktopLiveHandler(DesktopLiveOptions{
		Grants: store, Media: source, Policy: policy, Transfers: denyDesktopTransferAuthority{}, Audit: &auditStoreSpy{}, AllowedOrigins: []string{"https://app.example"},
		AllowHostCandidatesForTests: true, AuthorityPollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func testDesktopLiveBinding(access string) product.GatewayBinding {
	now := time.Now().UTC()
	binding := product.GatewayBinding{
		ConnectionID: "con-desktop-live", TenantID: "tenant-1", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-1"},
		WorkspaceID: "wrk-1", SlotKey: "desktop-main", SessionID: "ses-desktop-live", ProtocolProfile: product.SessionProfileDesktop,
		SlotGeneration: 1, AccessMode: access, RecordingPolicy: "metadata_only", ExpiresAt: now.Add(time.Minute), ProviderRevisionID: "provider-v1",
		SandboxID: "sandbox-desktop-live", HandoffReference: "ref:desktop-session:opaque-secret", ConnectionGeneration: 1, HandoffExpiresAt: now.Add(time.Minute),
	}
	if access == product.GrantAccessControl {
		binding.ControlLeaseID = "ctl-desktop-live"
		binding.ControlFence = 9
	}
	return binding
}

func testDesktopLiveMediaPolicy(audio bool) DesktopLiveMediaPolicy {
	policy := DesktopLiveMediaPolicy{VideoCodec: "video/VP8", Width: 640, Height: 480, MaxFPS: 30, MaxVideoBitrateKbps: 1000}
	if audio {
		policy.AudioCodec = "audio/opus"
		policy.MaxAudioBitrateKbps = 64
	}
	return policy
}

func testDesktopPolicy() product.DesktopPolicy {
	transfer := product.DesktopTransferPolicy{
		Enabled: true, MaxFiles: 4, MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20,
		AllowedMediaTypes: []string{"application/json", "text/plain"}, RequireActivation: true, RequireConsent: true,
	}
	return product.DesktopPolicy{
		Revision:  1,
		Input:     product.DesktopInputPolicy{Keyboard: true, Pointer: true, Touch: true},
		Clipboard: product.DesktopClipboardPolicy{Read: true, Write: true, MaxBytes: product.MaxDesktopClipboardBytes, RequireActivation: true, RequireConsent: true},
		Upload:    transfer, Download: transfer,
	}
}

func newDesktopLiveClientOffer(t *testing.T, control, audio bool) (*webrtc.PeerConnection, *webrtc.DataChannel, webrtc.SessionDescription) {
	t.Helper()
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	if audio {
		if _, err := peer.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
			t.Fatal(err)
		}
	}
	var channel *webrtc.DataChannel
	if control {
		channel, err = peer.CreateDataChannel(DesktopLiveControlDataChannel, nil)
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
		t.Fatal("Desktop client ICE gathering timed out")
	}
	return peer, channel, *peer.LocalDescription()
}

func encodeDesktopLiveOffer(t *testing.T, offer webrtc.SessionDescription, control, audio bool) []byte {
	return encodeDesktopLiveOfferWithConsent(t, offer, control, audio, "")
}

func encodeDesktopLiveOfferWithConsent(t *testing.T, offer webrtc.SessionDescription, control, audio bool, consentReference string) []byte {
	t.Helper()
	encoded, err := json.Marshal(desktopLiveSignalRequest{
		Offer: desktopLiveDescription{Type: "offer", SDP: offer.SDP}, Media: testDesktopLiveMediaPolicy(audio), ControlDataChannel: control,
		RecordingConsentReference: consentReference,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func postDesktopLiveOffer(t *testing.T, server *httptest.Server, ticket string, offer webrtc.SessionDescription, control, audio bool) (desktopLiveSignalResponse, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(encodeDesktopLiveOffer(t, offer, control, audio)))
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
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.StatusCode, raw)
	}
	var signal desktopLiveSignalResponse
	if err := json.Unmarshal(raw, &signal); err != nil {
		t.Fatal(err)
	}
	return signal, raw
}

func desktopRTPPacket(t *testing.T, payloadType uint8, sequence uint16, timestamp, ssrc uint32, payload []byte) []byte {
	t.Helper()
	encoded, err := (&rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: payloadType, SequenceNumber: sequence, Timestamp: timestamp, SSRC: ssrc, Marker: true}, Payload: payload}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type desktopPolicySourceSpy struct {
	calls  atomic.Int32
	mu     sync.RWMutex
	policy product.DesktopPolicy
	err    error
}

func (s *desktopPolicySourceSpy) CurrentDesktopPolicy(context.Context, product.GatewayBinding) (product.DesktopPolicy, error) {
	s.calls.Add(1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.policy, s.err
}

type desktopLiveMediaSourceSpy struct {
	mu      sync.Mutex
	opened  chan struct{}
	session *desktopLiveMediaSessionSpy
	policy  DesktopLiveMediaPolicy
	binding product.GatewayBinding
}

func (s *desktopLiveMediaSourceSpy) Open(_ context.Context, binding product.GatewayBinding, policy DesktopLiveMediaPolicy) (DesktopLiveMediaSession, error) {
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
		return nil, errors.New("Desktop media unavailable")
	}
	return s.session, nil
}

type desktopLiveMediaSessionSpy struct {
	video     chan []byte
	audio     chan []byte
	inputs    chan DesktopLiveInput
	updates   chan desktopLiveStreamUpdate
	closed    chan struct{}
	closeOnce sync.Once
	keyframes atomic.Int32
	resyncs   atomic.Int32
}

type desktopLiveStreamUpdate struct {
	display     DesktopLiveDisplayPolicy
	audioDevice string
}

func newDesktopLiveMediaSessionSpy() *desktopLiveMediaSessionSpy {
	return &desktopLiveMediaSessionSpy{video: make(chan []byte, 16), audio: make(chan []byte, 16), inputs: make(chan DesktopLiveInput, 4), updates: make(chan desktopLiveStreamUpdate, 4), closed: make(chan struct{})}
}

func (s *desktopLiveMediaSessionSpy) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	return s.read(ctx, s.video)
}

func (s *desktopLiveMediaSessionSpy) ReadAudioRTP(ctx context.Context) ([]byte, error) {
	return s.read(ctx, s.audio)
}

func (s *desktopLiveMediaSessionSpy) read(ctx context.Context, stream <-chan []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, io.EOF
	case packet := <-stream:
		return packet, nil
	}
}

func (s *desktopLiveMediaSessionSpy) HandleInput(ctx context.Context, input DesktopLiveInput) (DesktopLiveInputResult, error) {
	select {
	case <-ctx.Done():
		return DesktopLiveInputResult{}, ctx.Err()
	case s.inputs <- input:
		return DesktopLiveInputResult{}, nil
	}
}

func (s *desktopLiveMediaSessionSpy) UpdateStream(ctx context.Context, display DesktopLiveDisplayPolicy, audioDevice string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case s.updates <- desktopLiveStreamUpdate{display: display, audioDevice: audioDevice}:
		return nil
	}
}

func (s *desktopLiveMediaSessionSpy) Resynchronize(context.Context) error {
	s.resyncs.Add(1)
	return nil
}

func (s *desktopLiveMediaSessionSpy) RequestKeyframe(context.Context) error {
	s.keyframes.Add(1)
	return nil
}

func (s *desktopLiveMediaSessionSpy) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type desktopBlockingRTPWriter struct {
	entered chan struct{}
	once    sync.Once
	release chan struct{}
}

type desktopLiveRecorderSpy struct {
	session DesktopLiveRecordingSession
	err     error
	consent string
}

func (s *desktopLiveRecorderSpy) Start(_ context.Context, _ product.GatewayBinding, consent string, _ DesktopLiveMediaPolicy) (DesktopLiveRecordingSession, error) {
	s.consent = consent
	return s.session, s.err
}

type desktopLiveRecordingSessionSpy struct {
	mediaErr   error
	controlErr error
	closed     chan bool
}

func (s *desktopLiveRecordingSessionSpy) RecordMedia(context.Context, time.Time, string, []byte) error {
	return s.mediaErr
}

func (s *desktopLiveRecordingSessionSpy) RecordControl(context.Context, time.Time, string, int64, DesktopLiveInput, DesktopLiveDisplayPolicy, string) error {
	return s.controlErr
}

func (s *desktopLiveRecordingSessionSpy) Close(_ context.Context, failed bool) error {
	if s.closed != nil {
		s.closed <- failed
	}
	return nil
}

func (w *desktopBlockingRTPWriter) WriteRTP(*rtp.Packet) error {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return nil
}

var _ product.DesktopPolicySource = (*desktopPolicySourceSpy)(nil)
var _ DesktopLiveMediaSource = (*desktopLiveMediaSourceSpy)(nil)
var _ DesktopLiveMediaSession = (*desktopLiveMediaSessionSpy)(nil)
