package productgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	DesktopLiveControlDataChannel   = "product-desktop-control.v1"
	defaultDesktopSignalingBytes    = int64(96 << 10)
	defaultDesktopVideoQueue        = 32
	defaultDesktopAudioQueue        = 64
	defaultDesktopInputQueue        = 16
	defaultDesktopAuthorityInterval = 250 * time.Millisecond
	defaultDesktopDisconnectGrace   = 5 * time.Second
	defaultDesktopKeyframeInterval  = 250 * time.Millisecond
	defaultDesktopResyncInterval    = 250 * time.Millisecond
	maxDesktopVideoRTPPacketBytes   = 16 << 10
	maxDesktopAudioRTPPacketBytes   = 4 << 10
	maxDesktopControlMessageBytes   = 32 << 10
	maxDesktopControlBufferedBytes  = 64 << 10
)

// DesktopLiveMediaPolicy is the complete public negotiation result for one
// Desktop connection. The first data-plane slice intentionally supports one
// interoperable video codec and optional output-only audio.
type DesktopLiveMediaPolicy struct {
	VideoCodec          string `json:"video_codec"`
	Width               int    `json:"width"`
	Height              int    `json:"height"`
	MaxFPS              int    `json:"max_fps"`
	MaxVideoBitrateKbps int    `json:"max_video_bitrate_kbps"`
	AudioCodec          string `json:"audio_codec,omitempty"`
	MaxAudioBitrateKbps int    `json:"max_audio_bitrate_kbps,omitempty"`
}

type DesktopLiveTouchPoint struct {
	ID int `json:"id"`
	X  int `json:"x"`
	Y  int `json:"y"`
}

// DesktopLiveDisplayPolicy is the mutable subset of the negotiated stream.
// Codecs and bitrate ceilings remain fixed for the lifetime of a peer.
type DesktopLiveDisplayPolicy struct {
	Width  int `json:"width"`
	Height int `json:"height"`
	MaxFPS int `json:"max_fps"`
}

// DesktopLiveInput is a closed, ordered Desktop action already bound to the
// current Product controller lease, fence, and immutable policy snapshot.
// Private broker messages are never part of this type.
type DesktopLiveInput struct {
	Sequence       int64
	Action         product.DesktopPolicyAction
	Kind           string
	Event          string
	Code           string
	Key            string
	Modifiers      []string
	X, Y           int
	Button         int
	DeltaX, DeltaY int
	Touches        []DesktopLiveTouchPoint
	ControlLeaseID string
	ControlFence   int64
}

type DesktopLiveInputResult struct {
	Text string
}

type DesktopLiveMediaSession interface {
	ReadVideoRTP(context.Context) ([]byte, error)
	ReadAudioRTP(context.Context) ([]byte, error)
	HandleInput(context.Context, DesktopLiveInput) (DesktopLiveInputResult, error)
	UpdateStream(context.Context, DesktopLiveDisplayPolicy, string) error
	Resynchronize(context.Context) error
	RequestKeyframe(context.Context) error
	Close() error
}

type DesktopLiveMediaSource interface {
	Open(context.Context, product.GatewayBinding, DesktopLiveMediaPolicy) (DesktopLiveMediaSession, error)
}

type DesktopLiveTransferAuthority interface {
	AuthorizeDesktopTransfer(context.Context, product.GatewayBinding, product.DesktopPolicyAction) error
}

type DesktopLiveRecordingSession interface {
	RecordMedia(context.Context, time.Time, string, []byte) error
	RecordControl(context.Context, time.Time, string, int64, DesktopLiveInput, DesktopLiveDisplayPolicy, string) error
	Close(context.Context, bool) error
}

type DesktopLiveRecorder interface {
	Start(context.Context, product.GatewayBinding, string, DesktopLiveMediaPolicy) (DesktopLiveRecordingSession, error)
}

type DesktopLiveOptions struct {
	Grants                      product.ConnectionGrantStore
	Media                       DesktopLiveMediaSource
	Policy                      product.DesktopPolicySource
	Transfers                   DesktopLiveTransferAuthority
	Audit                       AuditStore
	Recorder                    DesktopLiveRecorder
	AllowedOrigins              []string
	ICEServers                  []webrtc.ICEServer
	MaxSignalingBytes           int64
	MaxVideoQueue               int
	MaxAudioQueue               int
	MaxInputQueue               int
	MaxPeers                    int
	MaxPeersPerSession          int
	AuthorityPollInterval       time.Duration
	ConnectionTimeout           time.Duration
	DisconnectGrace             time.Duration
	MinKeyframeInterval         time.Duration
	MinResyncInterval           time.Duration
	AllowInsecureHTTPForTests   bool
	AllowHostCandidatesForTests bool
}

type DesktopLiveHandler struct {
	grants               product.ConnectionGrantStore
	media                DesktopLiveMediaSource
	policy               product.DesktopPolicySource
	transfers            DesktopLiveTransferAuthority
	audit                AuditStore
	recorder             DesktopLiveRecorder
	origins              map[string]struct{}
	configuration        webrtc.Configuration
	maxSignalingBytes    int64
	maxVideoQueue        int
	maxAudioQueue        int
	maxInputQueue        int
	maxPeers             int
	maxPeersPerSession   int
	pollInterval         time.Duration
	connectionTimeout    time.Duration
	disconnectGrace      time.Duration
	minKeyframeInterval  time.Duration
	minResyncInterval    time.Duration
	allowInsecureForTest bool

	mu       sync.Mutex
	peers    int
	sessions map[string]int
}

type desktopLiveSignalRequest struct {
	Offer                     desktopLiveDescription `json:"offer"`
	Media                     DesktopLiveMediaPolicy `json:"media"`
	ControlDataChannel        bool                   `json:"control_data_channel"`
	RecordingConsentReference string                 `json:"recording_consent_reference,omitempty"`
}

type desktopLiveSignalResponse struct {
	Answer        desktopLiveDescription `json:"answer"`
	ConnectionID  string                 `json:"connection_id"`
	AccessMode    string                 `json:"access_mode"`
	Media         DesktopLiveMediaPolicy `json:"media"`
	RecordingMode string                 `json:"recording_mode"`
}

type desktopLiveDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type desktopLiveControlEnvelope struct {
	Type     string          `json:"type"`
	Sequence int64           `json:"sequence"`
	Action   json.RawMessage `json:"action"`
}

type desktopLiveResyncMessage struct {
	Type     string `json:"type"`
	Sequence int64  `json:"sequence"`
}

type desktopLiveConfigureMessage struct {
	Type        string                   `json:"type"`
	Sequence    int64                    `json:"sequence"`
	Display     DesktopLiveDisplayPolicy `json:"display"`
	AudioDevice string                   `json:"audio_device"`
}

type desktopLiveInputResponse struct {
	Type     string `json:"type"`
	Sequence int64  `json:"sequence"`
	OK       bool   `json:"ok"`
	Text     string `json:"text,omitempty"`
}

type desktopLiveQueuedInput struct {
	kind        string
	sequence    int64
	input       DesktopLiveInput
	display     DesktopLiveDisplayPolicy
	audioDevice string
	payload     []byte
	epoch       uint64
	channel     *webrtc.DataChannel
}

func NewDesktopLiveHandler(options DesktopLiveOptions) (*DesktopLiveHandler, error) { //nolint:cyclop
	if nilInterface(options.Grants) || nilInterface(options.Media) || nilInterface(options.Policy) || nilInterface(options.Transfers) || nilInterface(options.Audit) || len(options.AllowedOrigins) == 0 || len(options.AllowedOrigins) > 32 {
		return nil, product.ErrInvalid
	}
	origins := make(map[string]struct{}, len(options.AllowedOrigins))
	for _, origin := range options.AllowedOrigins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || len(origin) > 255 {
			return nil, product.ErrInvalid
		}
		origins[origin] = struct{}{}
	}
	limit := options.MaxSignalingBytes
	if limit == 0 {
		limit = defaultDesktopSignalingBytes
	}
	videoQueue := options.MaxVideoQueue
	if videoQueue == 0 {
		videoQueue = defaultDesktopVideoQueue
	}
	audioQueue := options.MaxAudioQueue
	if audioQueue == 0 {
		audioQueue = defaultDesktopAudioQueue
	}
	inputQueue := options.MaxInputQueue
	if inputQueue == 0 {
		inputQueue = defaultDesktopInputQueue
	}
	maxPeers := options.MaxPeers
	if maxPeers == 0 {
		maxPeers = 100
	}
	maxPerSession := options.MaxPeersPerSession
	if maxPerSession == 0 {
		maxPerSession = 16
	}
	poll := options.AuthorityPollInterval
	if poll == 0 {
		poll = defaultDesktopAuthorityInterval
	}
	connectTimeout := options.ConnectionTimeout
	if connectTimeout == 0 {
		connectTimeout = 15 * time.Second
	}
	disconnectGrace := options.DisconnectGrace
	if disconnectGrace == 0 {
		disconnectGrace = defaultDesktopDisconnectGrace
	}
	keyframeInterval := options.MinKeyframeInterval
	if keyframeInterval == 0 {
		keyframeInterval = defaultDesktopKeyframeInterval
	}
	resyncInterval := options.MinResyncInterval
	if resyncInterval == 0 {
		resyncInterval = defaultDesktopResyncInterval
	}
	if limit < 1024 || limit > 256<<10 || videoQueue < 1 || videoQueue > 256 || audioQueue < 1 || audioQueue > 512 || inputQueue < 1 || inputQueue > 64 || maxPeers < 1 || maxPeers > 10000 || maxPerSession < 1 || maxPerSession > 64 || poll < 10*time.Millisecond || poll > 5*time.Second || connectTimeout < time.Second || connectTimeout > time.Minute || disconnectGrace < 100*time.Millisecond || disconnectGrace > 30*time.Second || keyframeInterval < 50*time.Millisecond || keyframeInterval > 5*time.Second || resyncInterval < 50*time.Millisecond || resyncInterval > 5*time.Second {
		return nil, product.ErrInvalid
	}
	configuration := webrtc.Configuration{ICEServers: append([]webrtc.ICEServer(nil), options.ICEServers...)}
	if options.AllowHostCandidatesForTests {
		configuration.ICETransportPolicy = webrtc.ICETransportPolicyAll
	} else {
		if !validDesktopRelayOnlyICE(options.ICEServers) {
			return nil, product.ErrInvalid
		}
		configuration.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	return &DesktopLiveHandler{
		grants: options.Grants, media: options.Media, policy: options.Policy, transfers: options.Transfers, audit: options.Audit,
		recorder: options.Recorder,
		origins:  origins, configuration: configuration, maxSignalingBytes: limit,
		maxVideoQueue: videoQueue, maxAudioQueue: audioQueue, maxInputQueue: inputQueue,
		maxPeers: maxPeers, maxPeersPerSession: maxPerSession, pollInterval: poll,
		connectionTimeout: connectTimeout, disconnectGrace: disconnectGrace,
		minKeyframeInterval: keyframeInterval, minResyncInterval: resyncInterval, allowInsecureForTest: options.AllowInsecureHTTPForTests,
		sessions: make(map[string]int),
	}, nil
}

func validDesktopRelayOnlyICE(servers []webrtc.ICEServer) bool {
	if len(servers) == 0 || len(servers) > 8 {
		return false
	}
	for _, server := range servers {
		if server.Username == "" || server.CredentialType != webrtc.ICECredentialTypePassword {
			return false
		}
		password, ok := server.Credential.(string)
		if !ok || password == "" || len(server.URLs) == 0 || len(server.URLs) > 8 {
			return false
		}
		for _, rawURL := range server.URLs {
			if !strings.HasPrefix(strings.ToLower(rawURL), "turns:") || len(rawURL) > 2048 {
				return false
			}
		}
	}
	return true
}

func (h *DesktopLiveHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) { //nolint:cyclop
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	if h == nil || request == nil || request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if request.TLS == nil && !h.allowInsecureForTest {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if !h.originAllowed(request.Header.Values("Origin")) {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	ticket, ok := singleTicket(request.Header.Values("Authorization"))
	request.Header.Del("Authorization")
	if !ok {
		writer.Header().Set("WWW-Authenticate", "Ticket")
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	signal, err := decodeDesktopLiveSignal(http.MaxBytesReader(writer, request.Body, h.maxSignalingBytes), h.maxSignalingBytes)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	binding, err := h.grants.ConsumeConnectionGrant(request.Context(), ticket)
	ticket = ""
	if err != nil || binding.ProtocolProfile != product.SessionProfileDesktop || (binding.AccessMode != product.GrantAccessView && binding.AccessMode != product.GrantAccessControl) ||
		(binding.AccessMode == product.GrantAccessControl && (binding.ControlLeaseID == "" || binding.ControlFence < 1 || !signal.ControlDataChannel)) ||
		(binding.AccessMode == product.GrantAccessView && (binding.ControlLeaseID != "" || binding.ControlFence != 0 || signal.ControlDataChannel)) {
		writer.Header().Set("WWW-Authenticate", "Ticket")
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if err := h.grants.CheckGatewayAuthority(request.Context(), binding); err != nil || !h.reserve(binding.SessionID) {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if binding.RecordingPolicy != "disabled" && binding.RecordingPolicy != "metadata_only" && binding.RecordingPolicy != "required" {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	policy, err := h.policy.CurrentDesktopPolicy(request.Context(), binding)
	if err != nil || policy.Validate() != nil {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	if h.recordAudit(request.Context(), binding, gateway.AuditAuthorized, "") != nil {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	var recording DesktopLiveRecordingSession
	if binding.RecordingPolicy == "required" {
		if nilInterface(h.recorder) || !validDesktopConsentReference(signal.RecordingConsentReference) {
			h.release(binding.SessionID)
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		recording, err = h.recorder.Start(request.Context(), binding, signal.RecordingConsentReference, signal.Media)
		if err != nil || nilInterface(recording) {
			h.release(binding.SessionID)
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	} else if signal.RecordingConsentReference != "" {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	media, err := h.media.Open(request.Context(), binding, signal.Media)
	if err != nil || nilInterface(media) {
		closeDesktopLiveRecording(recording, true)
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	peer, err := webrtc.NewPeerConnection(h.configuration)
	if err != nil {
		closeDesktopLiveRecording(recording, true)
		_ = media.Close()
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	state := newDesktopLivePeer(h, peer, media, recording, binding, signal.Media, policy)
	if signal.ControlDataChannel {
		state.installControlChannel()
	} else {
		peer.OnDataChannel(func(*webrtc.DataChannel) { state.stop() })
	}
	video, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, "video", "desktop")
	if err == nil {
		var sender *webrtc.RTPSender
		sender, err = peer.AddTrack(video)
		if err == nil {
			go state.readRTCP(sender)
		}
	}
	var audio *webrtc.TrackLocalStaticRTP
	if err == nil && signal.Media.AudioCodec != "" {
		audio, err = webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2}, "audio", "desktop")
		if err == nil {
			_, err = peer.AddTrack(audio)
		}
	}
	if err != nil {
		state.stop()
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	peer.OnConnectionStateChange(state.onConnectionState)
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: signal.Offer.SDP}); err != nil {
		state.stop()
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	answer, err := peer.CreateAnswer(nil)
	if err != nil {
		state.stop()
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	gathered := webrtc.GatheringCompletePromise(peer)
	if err := peer.SetLocalDescription(answer); err != nil {
		state.stop()
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	select {
	case <-request.Context().Done():
		state.stop()
		return
	case <-gathered:
	}
	local := peer.LocalDescription()
	if local == nil {
		state.stop()
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	state.start(video, audio)
	response := desktopLiveSignalResponse{
		Answer: desktopLiveDescription{Type: "answer", SDP: local.SDP}, ConnectionID: binding.ConnectionID,
		AccessMode: binding.AccessMode, Media: signal.Media, RecordingMode: binding.RecordingPolicy,
	}
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		state.stop()
	}
}

func (h *DesktopLiveHandler) originAllowed(values []string) bool {
	if len(values) != 1 {
		return false
	}
	_, ok := h.origins[values[0]]
	return ok
}

func (h *DesktopLiveHandler) reserve(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers >= h.maxPeers || h.sessions[sessionID] >= h.maxPeersPerSession {
		return false
	}
	h.peers++
	h.sessions[sessionID]++
	return true
}

func (h *DesktopLiveHandler) release(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers > 0 {
		h.peers--
	}
	if h.sessions[sessionID] <= 1 {
		delete(h.sessions, sessionID)
	} else {
		h.sessions[sessionID]--
	}
}

func (h *DesktopLiveHandler) recordAudit(ctx context.Context, binding product.GatewayBinding, eventType gateway.AuditEventType, reason string) error {
	return h.audit.RecordGatewayEvent(ctx, binding, gateway.AuditEvent{
		Type: eventType, At: time.Now().UTC(), GrantID: binding.ConnectionID, CallerID: binding.Actor.ID,
		TenantID: binding.TenantID, RuntimeSessionID: binding.SessionID, ConnectionGeneration: binding.ConnectionGeneration, Reason: reason,
	})
}

func decodeDesktopLiveSignal(reader io.Reader, limit int64) (desktopLiveSignalRequest, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(payload)) > limit || rejectDuplicateAutomationMembers(payload) != nil {
		return desktopLiveSignalRequest{}, product.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var signal desktopLiveSignalRequest
	if err := decoder.Decode(&signal); err != nil {
		return signal, product.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || signal.Offer.Type != "offer" || len(signal.Offer.SDP) < 1 || len(signal.Offer.SDP) > 80<<10 || !validDesktopLiveMediaPolicy(signal.Media) || !validDesktopLiveOffer(signal.Offer.SDP, signal.Media) {
		return signal, product.ErrInvalid
	}
	return signal, nil
}

func validDesktopLiveOffer(raw string, policy DesktopLiveMediaPolicy) bool {
	var offer sdp.SessionDescription
	if offer.UnmarshalString(raw) != nil {
		return false
	}
	video, audio := 0, 0
	for _, media := range offer.MediaDescriptions {
		switch media.MediaName.Media {
		case "video":
			video++
			if !desktopOfferReceivesOnly(&offer, media) || !desktopOfferHasCodec(media, "VP8/90000") {
				return false
			}
		case "audio":
			audio++
			if policy.AudioCodec == "" || !desktopOfferReceivesOnly(&offer, media) || !desktopOfferHasCodec(media, "opus/48000") {
				return false
			}
		case "application":
			// The optional ordered control data channel is bound separately to
			// the consumed controller grant.
		default:
			return false
		}
	}
	wantAudio := 0
	if policy.AudioCodec != "" {
		wantAudio = 1
	}
	return video == 1 && audio == wantAudio
}

func desktopOfferReceivesOnly(session *sdp.SessionDescription, media *sdp.MediaDescription) bool {
	for _, direction := range []string{"sendrecv", "sendonly", "recvonly", "inactive"} {
		if _, ok := media.Attribute(direction); ok {
			return direction == "recvonly"
		}
	}
	for _, direction := range []string{"sendrecv", "sendonly", "recvonly", "inactive"} {
		if _, ok := session.Attribute(direction); ok {
			return direction == "recvonly"
		}
	}
	return false
}

func desktopOfferHasCodec(media *sdp.MediaDescription, codec string) bool {
	for _, attribute := range media.Attributes {
		if attribute.Key == "rtpmap" && strings.Contains(strings.ToLower(attribute.Value), strings.ToLower(codec)) {
			return true
		}
	}
	return false
}

func validDesktopLiveMediaPolicy(media DesktopLiveMediaPolicy) bool {
	if media.VideoCodec != "video/VP8" || media.Width < 320 || media.Width > 2560 || media.Height < 240 || media.Height > 1440 || media.MaxFPS < 1 || media.MaxFPS > 60 || media.MaxVideoBitrateKbps < 128 || media.MaxVideoBitrateKbps > 8000 {
		return false
	}
	switch media.AudioCodec {
	case "":
		return media.MaxAudioBitrateKbps == 0
	case "audio/opus":
		return media.MaxAudioBitrateKbps >= 16 && media.MaxAudioBitrateKbps <= 128
	default:
		return false
	}
}

type desktopLivePeer struct {
	handler         *DesktopLiveHandler
	peer            *webrtc.PeerConnection
	media           DesktopLiveMediaSession
	recording       DesktopLiveRecordingSession
	binding         product.GatewayBinding
	mediaPolicy     DesktopLiveMediaPolicy
	desktopPolicy   product.DesktopPolicy
	ctx             context.Context
	cancel          context.CancelFunc
	stopOnce        sync.Once
	connected       chan struct{}
	connectedOnce   sync.Once
	inputs          chan desktopLiveQueuedInput
	stateMu         sync.RWMutex
	state           webrtc.PeerConnectionState
	stateEpoch      uint64
	mediaMu         sync.RWMutex
	keyframeMu      sync.Mutex
	nextKeyframe    time.Time
	resyncMu        sync.Mutex
	nextResync      time.Time
	controlMu       sync.Mutex
	controlClaimed  bool
	recordingMu     sync.Mutex
	recordingFailed bool
}

func newDesktopLivePeer(handler *DesktopLiveHandler, peer *webrtc.PeerConnection, media DesktopLiveMediaSession, recording DesktopLiveRecordingSession, binding product.GatewayBinding, mediaPolicy DesktopLiveMediaPolicy, desktopPolicy product.DesktopPolicy) *desktopLivePeer {
	ctx, cancel := context.WithCancel(context.Background())
	return &desktopLivePeer{handler: handler, peer: peer, media: media, recording: recording, binding: binding, mediaPolicy: mediaPolicy, desktopPolicy: desktopPolicy, ctx: ctx, cancel: cancel, connected: make(chan struct{}), inputs: make(chan desktopLiveQueuedInput, handler.maxInputQueue), state: webrtc.PeerConnectionStateNew}
}

func (p *desktopLivePeer) start(video, audio *webrtc.TrackLocalStaticRTP) {
	go p.streamLoop("video.rtp", p.media.ReadVideoRTP, video, p.handler.maxVideoQueue, maxDesktopVideoRTPPacketBytes, p.mediaPolicy.MaxVideoBitrateKbps)
	if audio != nil {
		go p.streamLoop("audio.rtp", p.media.ReadAudioRTP, audio, p.handler.maxAudioQueue, maxDesktopAudioRTPPacketBytes, p.mediaPolicy.MaxAudioBitrateKbps)
	}
	go p.inputLoop()
	go p.authorityLoop()
	go func() {
		timer := time.NewTimer(p.handler.connectionTimeout)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-p.connected:
		case <-timer.C:
			p.stop()
		}
	}()
}

type desktopLiveRTPWriter interface {
	WriteRTP(*rtp.Packet) error
}

func (p *desktopLivePeer) streamLoop(kind string, read func(context.Context) ([]byte, error), track desktopLiveRTPWriter, queueSize, maxPacketBytes, maxBitrateKbps int) {
	queue := make(chan []byte, queueSize)
	go func() {
		defer close(queue)
		for {
			packet, err := read(p.ctx)
			if err != nil || len(packet) == 0 || len(packet) > maxPacketBytes {
				p.stop()
				return
			}
			copyPacket := append([]byte(nil), packet...)
			if p.recording != nil && p.recording.RecordMedia(p.ctx, time.Now().UTC(), kind, copyPacket) != nil {
				p.markRecordingFailed()
				p.stop()
				return
			}
			select {
			case queue <- copyPacket:
			case <-p.ctx.Done():
				return
			default:
				p.stop()
				return
			}
		}
	}()
	windowStart := time.Now()
	bytesInWindow := 0
	for packet := range queue {
		now := time.Now()
		if now.Sub(windowStart) >= time.Second {
			windowStart, bytesInWindow = now, 0
		}
		bytesInWindow += len(packet)
		if bytesInWindow*8 > maxBitrateKbps*1000 {
			p.stop()
			return
		}
		var parsed rtp.Packet
		if err := parsed.Unmarshal(packet); err != nil || track.WriteRTP(&parsed) != nil {
			p.stop()
			return
		}
	}
}

func (p *desktopLivePeer) readRTCP(sender *webrtc.RTPSender) {
	for {
		packets, _, err := sender.ReadRTCP()
		if err != nil {
			return
		}
		for _, packet := range packets {
			switch packet.(type) {
			case *rtcp.PictureLossIndication, *rtcp.FullIntraRequest:
				p.requestKeyframe()
			}
		}
	}
}

func (p *desktopLivePeer) authorityLoop() {
	ticker := time.NewTicker(p.handler.pollInterval)
	defer ticker.Stop()
	deadline := minTime(p.binding.ExpiresAt, p.binding.HandoffExpiresAt)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			currentPolicy, policyErr := p.handler.policy.CurrentDesktopPolicy(p.ctx, p.binding)
			if !deadline.After(time.Now()) || p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil || policyErr != nil || currentPolicy.Revision != p.desktopPolicy.Revision {
				p.stop()
				return
			}
		}
	}
}

func (p *desktopLivePeer) installControlChannel() {
	p.peer.OnDataChannel(func(channel *webrtc.DataChannel) {
		if channel.Label() != DesktopLiveControlDataChannel || !channel.Ordered() || channel.MaxPacketLifeTime() != nil || channel.MaxRetransmits() != nil || !p.claimControlChannel() {
			p.stop()
			return
		}
		channel.OnMessage(func(message webrtc.DataChannelMessage) {
			if !message.IsString || len(message.Data) > maxDesktopControlMessageBytes || !p.isConnected() {
				p.stop()
				return
			}
			control, err := decodeDesktopLiveControl(message.Data, p.currentMediaPolicy(), p.binding)
			if err != nil {
				p.stop()
				return
			}
			control.channel = channel
			control.epoch = p.currentStateEpoch()
			p.enqueueInput(control)
		})
	})
}

func decodeDesktopLiveControl(payload []byte, media DesktopLiveMediaPolicy, binding product.GatewayBinding) (desktopLiveQueuedInput, error) {
	if len(payload) == 0 || rejectDuplicateAutomationMembers(payload) != nil {
		return desktopLiveQueuedInput{}, product.ErrInvalid
	}
	var envelope desktopLiveControlEnvelope
	if json.Unmarshal(payload, &envelope) != nil || envelope.Sequence < 1 || envelope.Sequence > maxAutomationSequence {
		return desktopLiveQueuedInput{}, product.ErrInvalid
	}
	switch envelope.Type {
	case "input":
		input, err := decodeDesktopLiveInput(payload, media, binding)
		return desktopLiveQueuedInput{kind: "input", sequence: envelope.Sequence, input: input, payload: append([]byte(nil), payload...)}, err
	case "stream.resync":
		var message desktopLiveResyncMessage
		if decodeStrictRaw(payload, &message) != nil {
			return desktopLiveQueuedInput{}, product.ErrInvalid
		}
		return desktopLiveQueuedInput{kind: envelope.Type, sequence: envelope.Sequence}, nil
	case "stream.configure":
		var message desktopLiveConfigureMessage
		if decodeStrictRaw(payload, &message) != nil || !validDesktopDisplayPolicy(message.Display) || !validDesktopAudioDevice(message.AudioDevice, media) {
			return desktopLiveQueuedInput{}, product.ErrInvalid
		}
		return desktopLiveQueuedInput{kind: envelope.Type, sequence: envelope.Sequence, display: message.Display, audioDevice: message.AudioDevice}, nil
	default:
		return desktopLiveQueuedInput{}, product.ErrInvalid
	}
}

func validDesktopDisplayPolicy(display DesktopLiveDisplayPolicy) bool {
	return display.Width >= 320 && display.Width <= 2560 && display.Height >= 240 && display.Height <= 1440 && display.MaxFPS >= 1 && display.MaxFPS <= 60
}

func validDesktopAudioDevice(device string, media DesktopLiveMediaPolicy) bool {
	if media.AudioCodec == "" {
		return device == "disabled"
	}
	return device == "default" || device == "disabled"
}

func (p *desktopLivePeer) claimControlChannel() bool {
	p.controlMu.Lock()
	defer p.controlMu.Unlock()
	if p.controlClaimed {
		return false
	}
	p.controlClaimed = true
	return true
}

func (p *desktopLivePeer) enqueueInput(input desktopLiveQueuedInput) bool {
	select {
	case p.inputs <- input:
		return true
	default:
		p.stop()
		return false
	}
}

func (p *desktopLivePeer) inputLoop() {
	lastSequence := int64(0)
	for {
		select {
		case <-p.ctx.Done():
			return
		case queued := <-p.inputs:
			currentPolicy, policyErr := p.handler.policy.CurrentDesktopPolicy(p.ctx, p.binding)
			sequence := queued.sequence
			if sequence == 0 {
				sequence = queued.input.Sequence
			}
			kind := queued.kind
			if kind == "" {
				kind = "input"
			}
			if sequence != lastSequence+1 || !p.connectedAtEpoch(queued.epoch) || p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil || policyErr != nil || currentPolicy.Revision != p.desktopPolicy.Revision {
				p.stop()
				return
			}
			response := desktopLiveInputResponse{Sequence: sequence, OK: true}
			switch kind {
			case "input":
				input := queued.input
				if len(queued.payload) != 0 {
					var err error
					input, err = decodeDesktopLiveInput(queued.payload, p.currentMediaPolicy(), p.binding)
					if err != nil {
						p.stop()
						return
					}
				}
				if p.desktopPolicy.Authorize(input.Action) != nil || ((input.Action.Kind == product.DesktopActionUpload || input.Action.Kind == product.DesktopActionDownload) && p.handler.transfers.AuthorizeDesktopTransfer(p.ctx, p.binding, input.Action) != nil) {
					p.stop()
					return
				}
				result, err := p.media.HandleInput(p.ctx, input)
				if err != nil || !validDesktopLiveInputResult(p.desktopPolicy, input.Action, result) {
					p.stop()
					return
				}
				response.Type, response.Text = "input.result", result.Text
			case "stream.resync":
				response.Type = "stream.resync.result"
				if !p.resynchronize(false) {
					p.stop()
					return
				}
			case "stream.configure":
				response.Type = "stream.configure.result"
				if p.media.UpdateStream(p.ctx, queued.display, queued.audioDevice) != nil {
					p.stop()
					return
				}
				p.mediaMu.Lock()
				p.mediaPolicy.Width, p.mediaPolicy.Height, p.mediaPolicy.MaxFPS = queued.display.Width, queued.display.Height, queued.display.MaxFPS
				p.mediaMu.Unlock()
				if !p.resynchronize(false) {
					p.stop()
					return
				}
			default:
				p.stop()
				return
			}
			if p.recording != nil && p.recording.RecordControl(p.ctx, time.Now().UTC(), kind, sequence, queued.input, queued.display, queued.audioDevice) != nil {
				p.markRecordingFailed()
				p.stop()
				return
			}
			encoded, err := json.Marshal(response)
			if err != nil || len(encoded) > maxDesktopControlMessageBytes || queued.channel == nil || queued.channel.BufferedAmount()+uint64(len(encoded)) > maxDesktopControlBufferedBytes || queued.channel.SendText(string(encoded)) != nil {
				p.stop()
				return
			}
			lastSequence = sequence
		}
	}
}

func (p *desktopLivePeer) onConnectionState(state webrtc.PeerConnectionState) {
	p.stateMu.Lock()
	p.state, p.stateEpoch = state, p.stateEpoch+1
	epoch := p.stateEpoch
	p.stateMu.Unlock()
	switch state {
	case webrtc.PeerConnectionStateConnected:
		if p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil {
			p.stop()
			return
		}
		p.connectedOnce.Do(func() { close(p.connected) })
		if p.handler.recordAudit(p.ctx, p.binding, gateway.AuditConnected, "") != nil || !p.resynchronize(true) {
			p.stop()
		}
	case webrtc.PeerConnectionStateDisconnected:
		go p.disconnectTimer(epoch)
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		p.stop()
	}
}

func (p *desktopLivePeer) disconnectTimer(epoch uint64) {
	timer := time.NewTimer(p.handler.disconnectGrace)
	defer timer.Stop()
	select {
	case <-p.ctx.Done():
		return
	case <-timer.C:
	}
	p.stateMu.RLock()
	stale := p.stateEpoch != epoch || p.state != webrtc.PeerConnectionStateDisconnected
	p.stateMu.RUnlock()
	if !stale {
		p.stop()
	}
}

func (p *desktopLivePeer) isConnected() bool {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.state == webrtc.PeerConnectionStateConnected
}

func (p *desktopLivePeer) currentStateEpoch() uint64 {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.stateEpoch
}

func (p *desktopLivePeer) connectedAtEpoch(epoch uint64) bool {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.state == webrtc.PeerConnectionStateConnected && (epoch == 0 || p.stateEpoch == epoch)
}

func (p *desktopLivePeer) currentMediaPolicy() DesktopLiveMediaPolicy {
	p.mediaMu.RLock()
	defer p.mediaMu.RUnlock()
	return p.mediaPolicy
}

func (p *desktopLivePeer) resynchronize(force bool) bool {
	if !force {
		p.resyncMu.Lock()
		now := time.Now()
		if now.Before(p.nextResync) {
			p.resyncMu.Unlock()
			return false
		}
		p.nextResync = now.Add(p.handler.minResyncInterval)
		p.resyncMu.Unlock()
	}
	if p.media.Resynchronize(p.ctx) != nil {
		return false
	}
	return p.requestKeyframeForce()
}

func (p *desktopLivePeer) requestKeyframe() bool {
	p.keyframeMu.Lock()
	now := time.Now()
	if now.Before(p.nextKeyframe) {
		p.keyframeMu.Unlock()
		return true
	}
	p.nextKeyframe = now.Add(p.handler.minKeyframeInterval)
	p.keyframeMu.Unlock()
	return p.media.RequestKeyframe(p.ctx) == nil
}

func (p *desktopLivePeer) requestKeyframeForce() bool {
	p.keyframeMu.Lock()
	p.nextKeyframe = time.Now().Add(p.handler.minKeyframeInterval)
	p.keyframeMu.Unlock()
	return p.media.RequestKeyframe(p.ctx) == nil
}

func validDesktopConsentReference(value string) bool {
	if len(value) < 1 || len(value) > 200 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._:-", character) {
			return false
		}
	}
	return true
}

func (p *desktopLivePeer) markRecordingFailed() {
	p.recordingMu.Lock()
	p.recordingFailed = true
	p.recordingMu.Unlock()
}

func (p *desktopLivePeer) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		_ = p.peer.Close()
		_ = p.media.Close()
		p.recordingMu.Lock()
		recordingFailed := p.recordingFailed
		p.recordingMu.Unlock()
		closeDesktopLiveRecording(p.recording, recordingFailed)
		if closer, ok := p.handler.grants.(product.GatewayConnectionCloser); ok {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = closer.CloseGatewayConnection(closeCtx, p.binding)
			closeCancel()
		}
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = p.handler.recordAudit(auditCtx, p.binding, gateway.AuditClientClosed, "connection closed")
		auditCancel()
		p.handler.release(p.binding.SessionID)
	})
}

func closeDesktopLiveRecording(recording DesktopLiveRecordingSession, failed bool) {
	if nilInterface(recording) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = recording.Close(ctx, failed)
}

var _ http.Handler = (*DesktopLiveHandler)(nil)
