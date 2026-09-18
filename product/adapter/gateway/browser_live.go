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
	"unicode/utf8"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	BrowserLiveDataChannel       = "product-browser-control.v1"
	defaultLiveSignalingBytes    = int64(96 << 10)
	defaultLiveRTPQueue          = 32
	defaultLiveInputQueue        = 16
	defaultLiveAuthorityInterval = 250 * time.Millisecond
	defaultLiveDisconnectGrace   = 5 * time.Second
	defaultLiveKeyframeInterval  = 250 * time.Millisecond
	maxLiveRTPPacketBytes        = 16 << 10
	maxLiveControlMessageBytes   = 96 << 10
)

type BrowserLiveVideoPolicy struct {
	Codec          string `json:"codec"`
	Width          int    `json:"width"`
	Height         int    `json:"height"`
	MaxFPS         int    `json:"max_fps"`
	MaxBitrateKbps int    `json:"max_bitrate_kbps"`
}

// BrowserLiveInput is a closed Product action already bound to the current
// controller lease and fence. Private browser protocol messages are never
// accepted at the public edge.
type BrowserLiveInput struct {
	Sequence       int64
	Action         product.BrowserPolicyAction
	Event          string
	Code           string
	Key            string
	Modifiers      []string
	X, Y           int
	Button         int
	DeltaX, DeltaY int
	Touches        []BrowserLiveTouchPoint
	ControlLeaseID string
	ControlFence   int64
}

type BrowserLiveTouchPoint struct {
	ID int `json:"id"`
	X  int `json:"x"`
	Y  int `json:"y"`
}

type BrowserLiveMediaSession interface {
	ReadRTP(context.Context) ([]byte, error)
	HandleInput(context.Context, BrowserLiveInput) (BrowserLiveInputResult, error)
	UpdateVideoPolicy(context.Context, BrowserLiveVideoPolicy) error
	RequestKeyframe(context.Context) error
	Close() error
}

type BrowserLiveInputResult struct {
	Text string
}

type BrowserLiveMediaSource interface {
	Open(context.Context, product.GatewayBinding, BrowserLiveVideoPolicy) (BrowserLiveMediaSession, error)
}

type BrowserLiveTransferAuthority interface {
	AuthorizeBrowserTransfer(context.Context, product.GatewayBinding, product.BrowserPolicyAction) error
}

type BrowserLiveRecordingSession interface {
	RecordMedia(context.Context, time.Time, []byte) error
	RecordControl(context.Context, time.Time, string, BrowserLiveInput, BrowserLiveVideoPolicy) error
	Close(context.Context, bool) error
}

type BrowserLiveRecorder interface {
	Start(context.Context, product.GatewayBinding, string, BrowserLiveVideoPolicy) (BrowserLiveRecordingSession, error)
}

type BrowserLiveOptions struct {
	Grants                      product.ConnectionGrantStore
	Media                       BrowserLiveMediaSource
	Policy                      product.BrowserPolicySource
	Transfers                   BrowserLiveTransferAuthority
	Audit                       AuditStore
	Recorder                    BrowserLiveRecorder
	AllowedOrigins              []string
	ICEServers                  []webrtc.ICEServer
	MaxSignalingBytes           int64
	MaxRTPQueue                 int
	MaxInputQueue               int
	MaxPeers                    int
	MaxPeersPerSession          int
	AuthorityPollInterval       time.Duration
	ConnectionTimeout           time.Duration
	DisconnectGrace             time.Duration
	MinKeyframeInterval         time.Duration
	AllowInsecureHTTPForTests   bool
	AllowHostCandidatesForTests bool
}

type BrowserLiveHandler struct {
	grants               product.ConnectionGrantStore
	media                BrowserLiveMediaSource
	policy               product.BrowserPolicySource
	transfers            BrowserLiveTransferAuthority
	audit                AuditStore
	recorder             BrowserLiveRecorder
	origins              map[string]struct{}
	configuration        webrtc.Configuration
	maxSignalingBytes    int64
	maxRTPQueue          int
	maxInputQueue        int
	maxPeers             int
	maxPeersPerSession   int
	pollInterval         time.Duration
	connectionTimeout    time.Duration
	disconnectGrace      time.Duration
	minKeyframeInterval  time.Duration
	allowInsecureForTest bool

	mu       sync.Mutex
	peers    int
	sessions map[string]int
}

type browserLiveSignalRequest struct {
	Offer                     browserLiveDescription `json:"offer"`
	Video                     BrowserLiveVideoPolicy `json:"video"`
	ControlDataChannel        bool                   `json:"control_data_channel"`
	RecordingConsentReference string                 `json:"recording_consent_reference,omitempty"`
}

type browserLiveSignalResponse struct {
	Answer        browserLiveDescription `json:"answer"`
	ConnectionID  string                 `json:"connection_id"`
	AccessMode    string                 `json:"access_mode"`
	Video         BrowserLiveVideoPolicy `json:"video"`
	RecordingMode string                 `json:"recording_mode"`
}

type browserLiveDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type browserLiveControlMessage struct {
	Type     string          `json:"type"`
	Sequence int64           `json:"sequence"`
	Action   json.RawMessage `json:"action"`
}

type browserLiveControlEnvelope struct {
	Type     string `json:"type"`
	Sequence int64  `json:"sequence"`
}

type browserLiveResyncMessage struct {
	Type     string `json:"type"`
	Sequence int64  `json:"sequence"`
}

type browserLiveResizeMessage struct {
	Type     string                 `json:"type"`
	Sequence int64                  `json:"sequence"`
	Video    BrowserLiveVideoPolicy `json:"video"`
}

type browserLiveInputResponse struct {
	Type     string `json:"type"`
	Sequence int64  `json:"sequence"`
	OK       bool   `json:"ok"`
	Text     string `json:"text,omitempty"`
}

type browserLiveQueuedControl struct {
	kind     string
	sequence int64
	input    BrowserLiveInput
	video    BrowserLiveVideoPolicy
	channel  *webrtc.DataChannel
}

func NewBrowserLiveHandler(options BrowserLiveOptions) (*BrowserLiveHandler, error) { //nolint:cyclop
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
		limit = defaultLiveSignalingBytes
	}
	rtpQueue := options.MaxRTPQueue
	if rtpQueue == 0 {
		rtpQueue = defaultLiveRTPQueue
	}
	inputQueue := options.MaxInputQueue
	if inputQueue == 0 {
		inputQueue = defaultLiveInputQueue
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
		poll = defaultLiveAuthorityInterval
	}
	connectTimeout := options.ConnectionTimeout
	if connectTimeout == 0 {
		connectTimeout = 15 * time.Second
	}
	disconnectGrace := options.DisconnectGrace
	if disconnectGrace == 0 {
		disconnectGrace = defaultLiveDisconnectGrace
	}
	keyframeInterval := options.MinKeyframeInterval
	if keyframeInterval == 0 {
		keyframeInterval = defaultLiveKeyframeInterval
	}
	if limit < 1024 || limit > 256<<10 || rtpQueue < 1 || rtpQueue > 256 || inputQueue < 1 || inputQueue > 64 || maxPeers < 1 || maxPeers > 10000 || maxPerSession < 1 || maxPerSession > 64 || poll < 10*time.Millisecond || poll > 5*time.Second || connectTimeout < time.Second || connectTimeout > time.Minute || disconnectGrace < 100*time.Millisecond || disconnectGrace > 30*time.Second || keyframeInterval < 50*time.Millisecond || keyframeInterval > 5*time.Second {
		return nil, product.ErrInvalid
	}
	configuration := webrtc.Configuration{ICEServers: append([]webrtc.ICEServer(nil), options.ICEServers...)}
	if options.AllowHostCandidatesForTests {
		configuration.ICETransportPolicy = webrtc.ICETransportPolicyAll
	} else {
		if !validRelayOnlyICE(options.ICEServers) {
			return nil, product.ErrInvalid
		}
		configuration.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	return &BrowserLiveHandler{
		grants: options.Grants, media: options.Media, policy: options.Policy, transfers: options.Transfers, audit: options.Audit, recorder: options.Recorder, origins: origins, configuration: configuration,
		maxSignalingBytes: limit, maxRTPQueue: rtpQueue, maxInputQueue: inputQueue,
		maxPeers: maxPeers, maxPeersPerSession: maxPerSession, pollInterval: poll,
		connectionTimeout: connectTimeout, disconnectGrace: disconnectGrace, minKeyframeInterval: keyframeInterval,
		allowInsecureForTest: options.AllowInsecureHTTPForTests,
		sessions:             make(map[string]int),
	}, nil
}

func validRelayOnlyICE(servers []webrtc.ICEServer) bool {
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

func (h *BrowserLiveHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) { //nolint:cyclop
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
	signal, err := decodeBrowserLiveSignal(http.MaxBytesReader(writer, request.Body, h.maxSignalingBytes), h.maxSignalingBytes)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	binding, err := h.grants.ConsumeConnectionGrant(request.Context(), ticket)
	ticket = ""
	if err != nil || binding.ProtocolProfile != product.SessionProfileBrowserLive || (binding.AccessMode != product.GrantAccessView && binding.AccessMode != product.GrantAccessControl) ||
		(binding.AccessMode == product.GrantAccessControl && (binding.ControlLeaseID == "" || binding.ControlFence < 1)) ||
		(binding.AccessMode == product.GrantAccessView && (binding.ControlLeaseID != "" || signal.ControlDataChannel)) {
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
	if h.recordLiveAudit(request.Context(), binding, gateway.AuditAuthorized, "") != nil {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	policy, err := h.policy.CurrentBrowserPolicy(request.Context(), binding)
	if err != nil || policy.Validate() != nil {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	var recording BrowserLiveRecordingSession
	if binding.RecordingPolicy == "required" {
		if nilInterface(h.recorder) || !validBrowserConsentReference(signal.RecordingConsentReference) {
			h.release(binding.SessionID)
			http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		recording, err = h.recorder.Start(request.Context(), binding, signal.RecordingConsentReference, signal.Video)
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
	media, err := h.media.Open(request.Context(), binding, signal.Video)
	if err != nil {
		closeBrowserLiveRecording(recording, true)
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	peer, err := webrtc.NewPeerConnection(h.configuration)
	if err != nil {
		closeBrowserLiveRecording(recording, true)
		_ = media.Close()
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	state := newBrowserLivePeer(h, peer, media, recording, binding, signal.Video, policy)
	if signal.ControlDataChannel {
		state.installControlChannel()
	} else {
		peer.OnDataChannel(func(*webrtc.DataChannel) { state.stop() })
	}
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000}, "video", "browser")
	if err == nil {
		var sender *webrtc.RTPSender
		sender, err = peer.AddTrack(track)
		if err == nil {
			go state.readRTCP(sender)
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
	state.start(track)
	response := browserLiveSignalResponse{
		Answer: browserLiveDescription{Type: "answer", SDP: local.SDP}, ConnectionID: binding.ConnectionID,
		AccessMode: binding.AccessMode, Video: signal.Video,
		RecordingMode: binding.RecordingPolicy,
	}
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		state.stop()
	}
}

func (h *BrowserLiveHandler) recordLiveAudit(ctx context.Context, binding product.GatewayBinding, eventType gateway.AuditEventType, reason string) error {
	return h.audit.RecordGatewayEvent(ctx, binding, gateway.AuditEvent{
		Type: eventType, At: time.Now().UTC(), GrantID: binding.ConnectionID, CallerID: binding.Actor.ID,
		TenantID: binding.TenantID, RuntimeSessionID: binding.SessionID, ConnectionGeneration: binding.ConnectionGeneration, Reason: reason,
	})
}

func (h *BrowserLiveHandler) originAllowed(values []string) bool {
	if len(values) != 1 {
		return false
	}
	_, ok := h.origins[values[0]]
	return ok
}

func (h *BrowserLiveHandler) reserve(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers >= h.maxPeers || h.sessions[sessionID] >= h.maxPeersPerSession {
		return false
	}
	h.peers++
	h.sessions[sessionID]++
	return true
}

func (h *BrowserLiveHandler) release(sessionID string) {
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

func decodeBrowserLiveSignal(reader io.Reader, limit int64) (browserLiveSignalRequest, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(payload)) > limit || rejectDuplicateAutomationMembers(payload) != nil {
		return browserLiveSignalRequest{}, product.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var signal browserLiveSignalRequest
	if err := decoder.Decode(&signal); err != nil {
		return signal, product.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || signal.Offer.Type != "offer" || len(signal.Offer.SDP) < 1 || len(signal.Offer.SDP) > 80<<10 || !validBrowserLiveVideoPolicy(signal.Video) {
		return signal, product.ErrInvalid
	}
	return signal, nil
}

type browserLivePeer struct {
	handler         *BrowserLiveHandler
	peer            *webrtc.PeerConnection
	media           BrowserLiveMediaSession
	recording       BrowserLiveRecordingSession
	binding         product.GatewayBinding
	video           BrowserLiveVideoPolicy
	policy          product.BrowserPolicy
	ctx             context.Context
	cancel          context.CancelFunc
	stopOnce        sync.Once
	connected       chan struct{}
	connectedOnce   sync.Once
	controls        chan browserLiveQueuedControl
	stateMu         sync.RWMutex
	state           webrtc.PeerConnectionState
	stateEpoch      uint64
	videoMu         sync.RWMutex
	keyframeMu      sync.Mutex
	nextKeyframe    time.Time
	recordingFailed bool
}

func newBrowserLivePeer(handler *BrowserLiveHandler, peer *webrtc.PeerConnection, media BrowserLiveMediaSession, recording BrowserLiveRecordingSession, binding product.GatewayBinding, video BrowserLiveVideoPolicy, policy product.BrowserPolicy) *browserLivePeer {
	ctx, cancel := context.WithCancel(context.Background())
	return &browserLivePeer{handler: handler, peer: peer, media: media, recording: recording, binding: binding, video: video, policy: policy, ctx: ctx, cancel: cancel, connected: make(chan struct{}), controls: make(chan browserLiveQueuedControl, handler.maxInputQueue), state: webrtc.PeerConnectionStateNew}
}

func (p *browserLivePeer) start(track *webrtc.TrackLocalStaticRTP) {
	go p.mediaLoop(track)
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

type browserLiveRTPWriter interface {
	WriteRTP(*rtp.Packet) error
}

func (p *browserLivePeer) mediaLoop(track browserLiveRTPWriter) {
	queue := make(chan []byte, p.handler.maxRTPQueue)
	go func() {
		defer close(queue)
		for {
			packet, err := p.media.ReadRTP(p.ctx)
			if err != nil || len(packet) == 0 || len(packet) > maxLiveRTPPacketBytes {
				p.stop()
				return
			}
			copyPacket := append([]byte(nil), packet...)
			if p.recording != nil && p.recording.RecordMedia(p.ctx, time.Now().UTC(), copyPacket) != nil {
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
		video := p.currentVideo()
		if bytesInWindow*8 > video.MaxBitrateKbps*1000 {
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

func (p *browserLivePeer) readRTCP(sender *webrtc.RTPSender) {
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

func (p *browserLivePeer) authorityLoop() {
	ticker := time.NewTicker(p.handler.pollInterval)
	defer ticker.Stop()
	deadline := minTime(p.binding.ExpiresAt, p.binding.HandoffExpiresAt)
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			currentPolicy, policyErr := p.handler.policy.CurrentBrowserPolicy(p.ctx, p.binding)
			if !deadline.After(time.Now()) || p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil || policyErr != nil || currentPolicy.Revision != p.policy.Revision {
				p.stop()
				return
			}
		}
	}
}

func (p *browserLivePeer) installControlChannel() {
	p.peer.OnDataChannel(func(channel *webrtc.DataChannel) {
		if channel.Label() != BrowserLiveDataChannel {
			p.stop()
			return
		}
		channel.OnMessage(func(message webrtc.DataChannelMessage) {
			if !message.IsString || len(message.Data) > maxLiveControlMessageBytes || !p.isConnected() {
				p.stop()
				return
			}
			control, err := decodeBrowserLiveControl(message.Data, p.currentVideo(), p.binding)
			if err != nil {
				p.stop()
				return
			}
			control.channel = channel
			select {
			case p.controls <- control:
			default:
				p.stop()
			}
		})
	})
}

func decodeBrowserLiveControl(payload []byte, video BrowserLiveVideoPolicy, binding product.GatewayBinding) (browserLiveQueuedControl, error) {
	if len(payload) == 0 || rejectDuplicateAutomationMembers(payload) != nil {
		return browserLiveQueuedControl{}, product.ErrInvalid
	}
	var envelope browserLiveControlEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.Sequence < 1 || envelope.Sequence > maxAutomationSequence {
		return browserLiveQueuedControl{}, product.ErrInvalid
	}
	switch envelope.Type {
	case "input":
		input, err := decodeBrowserLiveInput(payload, video, binding)
		return browserLiveQueuedControl{kind: envelope.Type, sequence: envelope.Sequence, input: input}, err
	case "stream.resync":
		var message browserLiveResyncMessage
		if decodeStrictRaw(payload, &message) != nil {
			return browserLiveQueuedControl{}, product.ErrInvalid
		}
		return browserLiveQueuedControl{kind: envelope.Type, sequence: envelope.Sequence}, nil
	case "stream.resize":
		var message browserLiveResizeMessage
		if decodeStrictRaw(payload, &message) != nil || !validBrowserLiveVideoPolicy(message.Video) {
			return browserLiveQueuedControl{}, product.ErrInvalid
		}
		return browserLiveQueuedControl{kind: envelope.Type, sequence: envelope.Sequence, video: message.Video}, nil
	default:
		return browserLiveQueuedControl{}, product.ErrInvalid
	}
}

func decodeBrowserLiveInput(payload []byte, video BrowserLiveVideoPolicy, binding product.GatewayBinding) (BrowserLiveInput, error) {
	if rejectDuplicateAutomationMembers(payload) != nil {
		return BrowserLiveInput{}, product.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var message browserLiveControlMessage
	if err := decoder.Decode(&message); err != nil {
		return BrowserLiveInput{}, product.ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || message.Type != "input" || message.Sequence < 1 || message.Sequence > maxAutomationSequence || len(message.Action) < 2 || binding.ControlLeaseID == "" || binding.ControlFence < 1 {
		return BrowserLiveInput{}, product.ErrInvalid
	}
	input := BrowserLiveInput{Sequence: message.Sequence, ControlLeaseID: binding.ControlLeaseID, ControlFence: binding.ControlFence}
	if err := decodeBrowserLiveAction(message.Action, video, &input); err != nil {
		return BrowserLiveInput{}, err
	}
	return input, nil
}

func (p *browserLivePeer) inputLoop() {
	lastSequence := int64(0)
	for {
		select {
		case <-p.ctx.Done():
			return
		case queued := <-p.controls:
			currentPolicy, policyErr := p.handler.policy.CurrentBrowserPolicy(p.ctx, p.binding)
			if queued.sequence != lastSequence+1 || !p.isConnected() || p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil || policyErr != nil || currentPolicy.Revision != p.policy.Revision {
				p.stop()
				return
			}
			response := browserLiveInputResponse{Sequence: queued.sequence, OK: true}
			switch queued.kind {
			case "input":
				input := queued.input
				if p.policy.Authorize(input.Action) != nil || ((input.Action.Kind == product.BrowserActionUpload || input.Action.Kind == product.BrowserActionDownload) && p.handler.transfers.AuthorizeBrowserTransfer(p.ctx, p.binding, input.Action) != nil) {
					p.stop()
					return
				}
				result, err := p.media.HandleInput(p.ctx, input)
				if err != nil || !validBrowserLiveInputResult(p.policy, input.Action, result) {
					p.stop()
					return
				}
				response.Type, response.Text = "input.result", result.Text
			case "stream.resync":
				response.Type = "stream.resync.result"
				if !p.requestKeyframe() {
					p.stop()
					return
				}
			case "stream.resize":
				response.Type = "stream.resize.result"
				if p.media.UpdateVideoPolicy(p.ctx, queued.video) != nil {
					p.stop()
					return
				}
				p.videoMu.Lock()
				p.video = queued.video
				p.videoMu.Unlock()
				p.requestKeyframe()
			default:
				p.stop()
				return
			}
			if p.recording != nil && p.recording.RecordControl(p.ctx, time.Now().UTC(), queued.kind, queued.input, queued.video) != nil {
				p.markRecordingFailed()
				p.stop()
				return
			}
			encoded, err := json.Marshal(response)
			if err != nil || len(encoded) > maxLiveControlMessageBytes || queued.channel.SendText(string(encoded)) != nil {
				p.stop()
				return
			}
			lastSequence = queued.sequence
		}
	}
}

func validBrowserLiveInputResult(policy product.BrowserPolicy, action product.BrowserPolicyAction, result BrowserLiveInputResult) bool {
	if action.Kind == product.BrowserActionClipboardRead {
		return utf8.ValidString(result.Text) && len(result.Text) <= policy.Clipboard.MaxBytes
	}
	return result.Text == ""
}

func (p *browserLivePeer) onConnectionState(state webrtc.PeerConnectionState) {
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
		if p.handler.recordLiveAudit(p.ctx, p.binding, gateway.AuditConnected, "") != nil {
			p.stop()
			return
		}
		if !p.requestKeyframe() {
			p.stop()
		}
	case webrtc.PeerConnectionStateDisconnected:
		go p.disconnectTimer(epoch)
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		p.stop()
	}
}

func (p *browserLivePeer) disconnectTimer(epoch uint64) {
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

func (p *browserLivePeer) isConnected() bool {
	p.stateMu.RLock()
	defer p.stateMu.RUnlock()
	return p.state == webrtc.PeerConnectionStateConnected
}

func (p *browserLivePeer) currentVideo() BrowserLiveVideoPolicy {
	p.videoMu.RLock()
	defer p.videoMu.RUnlock()
	return p.video
}

func (p *browserLivePeer) requestKeyframe() bool {
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

func validBrowserLiveVideoPolicy(video BrowserLiveVideoPolicy) bool {
	return video.Codec == "video/VP8" && video.Width >= 320 && video.Width <= 1920 && video.Height >= 240 && video.Height <= 1080 && video.MaxFPS >= 1 && video.MaxFPS <= 60 && video.MaxBitrateKbps >= 128 && video.MaxBitrateKbps <= 4000
}

func validBrowserConsentReference(value string) bool {
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

func (p *browserLivePeer) markRecordingFailed() {
	p.keyframeMu.Lock()
	p.recordingFailed = true
	p.keyframeMu.Unlock()
}

func (p *browserLivePeer) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		_ = p.peer.Close()
		_ = p.media.Close()
		p.keyframeMu.Lock()
		recordingFailed := p.recordingFailed
		p.keyframeMu.Unlock()
		closeBrowserLiveRecording(p.recording, recordingFailed)
		if closer, ok := p.handler.grants.(product.GatewayConnectionCloser); ok {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = closer.CloseGatewayConnection(closeCtx, p.binding)
			closeCancel()
		}
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = p.handler.recordLiveAudit(auditCtx, p.binding, gateway.AuditClientClosed, "connection closed")
		auditCancel()
		p.handler.release(p.binding.SessionID)
	})
}

func closeBrowserLiveRecording(recording BrowserLiveRecordingSession, failed bool) {
	if nilInterface(recording) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = recording.Close(ctx, failed)
}

var _ http.Handler = (*BrowserLiveHandler)(nil)
