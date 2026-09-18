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

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	BrowserLiveDataChannel       = "product-browser-control.v1"
	defaultLiveSignalingBytes    = int64(96 << 10)
	defaultLiveRTPQueue          = 32
	defaultLiveInputQueue        = 16
	defaultLiveAuthorityInterval = 250 * time.Millisecond
	maxLiveRTPPacketBytes        = 16 << 10
	maxLiveControlMessageBytes   = 4 << 10
)

type BrowserLiveVideoPolicy struct {
	Codec          string `json:"codec"`
	Width          int    `json:"width"`
	Height         int    `json:"height"`
	MaxFPS         int    `json:"max_fps"`
	MaxBitrateKbps int    `json:"max_bitrate_kbps"`
}

// BrowserLiveInput is already bound to the Product controller lease and fence.
// Later policy slices may expand the closed set of input kinds without exposing
// a private browser protocol at the public edge.
type BrowserLiveInput struct {
	Sequence       int64
	Kind           string
	X, Y           int
	ControlLeaseID string
	ControlFence   int64
}

type BrowserLiveMediaSession interface {
	ReadRTP(context.Context) ([]byte, error)
	HandleInput(context.Context, BrowserLiveInput) error
	RequestKeyframe(context.Context) error
	Close() error
}

type BrowserLiveMediaSource interface {
	Open(context.Context, product.GatewayBinding, BrowserLiveVideoPolicy) (BrowserLiveMediaSession, error)
}

type BrowserLiveOptions struct {
	Grants                      product.ConnectionGrantStore
	Media                       BrowserLiveMediaSource
	AllowedOrigins              []string
	ICEServers                  []webrtc.ICEServer
	MaxSignalingBytes           int64
	MaxRTPQueue                 int
	MaxInputQueue               int
	MaxPeers                    int
	MaxPeersPerSession          int
	AuthorityPollInterval       time.Duration
	ConnectionTimeout           time.Duration
	AllowInsecureHTTPForTests   bool
	AllowHostCandidatesForTests bool
}

type BrowserLiveHandler struct {
	grants               product.ConnectionGrantStore
	media                BrowserLiveMediaSource
	origins              map[string]struct{}
	configuration        webrtc.Configuration
	maxSignalingBytes    int64
	maxRTPQueue          int
	maxInputQueue        int
	maxPeers             int
	maxPeersPerSession   int
	pollInterval         time.Duration
	connectionTimeout    time.Duration
	allowInsecureForTest bool

	mu       sync.Mutex
	peers    int
	sessions map[string]int
}

type browserLiveSignalRequest struct {
	Offer              browserLiveDescription `json:"offer"`
	Video              BrowserLiveVideoPolicy `json:"video"`
	ControlDataChannel bool                   `json:"control_data_channel"`
}

type browserLiveSignalResponse struct {
	Answer       browserLiveDescription `json:"answer"`
	ConnectionID string                 `json:"connection_id"`
	AccessMode   string                 `json:"access_mode"`
	Video        BrowserLiveVideoPolicy `json:"video"`
}

type browserLiveDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type browserLiveControlMessage struct {
	Type     string `json:"type"`
	Sequence int64  `json:"sequence"`
	X        int    `json:"x"`
	Y        int    `json:"y"`
}

func NewBrowserLiveHandler(options BrowserLiveOptions) (*BrowserLiveHandler, error) { //nolint:cyclop
	if nilInterface(options.Grants) || nilInterface(options.Media) || len(options.AllowedOrigins) == 0 || len(options.AllowedOrigins) > 32 {
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
	if limit < 1024 || limit > 256<<10 || rtpQueue < 1 || rtpQueue > 256 || inputQueue < 1 || inputQueue > 64 || maxPeers < 1 || maxPeers > 10000 || maxPerSession < 1 || maxPerSession > 64 || poll < 10*time.Millisecond || poll > 5*time.Second || connectTimeout < time.Second || connectTimeout > time.Minute {
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
		grants: options.Grants, media: options.Media, origins: origins, configuration: configuration,
		maxSignalingBytes: limit, maxRTPQueue: rtpQueue, maxInputQueue: inputQueue,
		maxPeers: maxPeers, maxPeersPerSession: maxPerSession, pollInterval: poll,
		connectionTimeout: connectTimeout, allowInsecureForTest: options.AllowInsecureHTTPForTests,
		sessions: make(map[string]int),
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
	media, err := h.media.Open(request.Context(), binding, signal.Video)
	if err != nil {
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	peer, err := webrtc.NewPeerConnection(h.configuration)
	if err != nil {
		_ = media.Close()
		h.release(binding.SessionID)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	state := newBrowserLivePeer(h, peer, media, binding, signal.Video)
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
	}
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		state.stop()
	}
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
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || signal.Offer.Type != "offer" || len(signal.Offer.SDP) < 1 || len(signal.Offer.SDP) > 80<<10 || signal.Video.Codec != "video/VP8" || signal.Video.Width < 320 || signal.Video.Width > 1920 || signal.Video.Height < 240 || signal.Video.Height > 1080 || signal.Video.MaxFPS < 1 || signal.Video.MaxFPS > 60 || signal.Video.MaxBitrateKbps < 128 || signal.Video.MaxBitrateKbps > 4000 {
		return signal, product.ErrInvalid
	}
	return signal, nil
}

type browserLivePeer struct {
	handler       *BrowserLiveHandler
	peer          *webrtc.PeerConnection
	media         BrowserLiveMediaSession
	binding       product.GatewayBinding
	video         BrowserLiveVideoPolicy
	ctx           context.Context
	cancel        context.CancelFunc
	stopOnce      sync.Once
	connected     chan struct{}
	connectedOnce sync.Once
	inputs        chan BrowserLiveInput
}

func newBrowserLivePeer(handler *BrowserLiveHandler, peer *webrtc.PeerConnection, media BrowserLiveMediaSession, binding product.GatewayBinding, video BrowserLiveVideoPolicy) *browserLivePeer {
	ctx, cancel := context.WithCancel(context.Background())
	return &browserLivePeer{handler: handler, peer: peer, media: media, binding: binding, video: video, ctx: ctx, cancel: cancel, connected: make(chan struct{}), inputs: make(chan BrowserLiveInput, handler.maxInputQueue)}
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
		if bytesInWindow*8 > p.video.MaxBitrateKbps*1000 {
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
		if _, _, err := sender.ReadRTCP(); err != nil {
			return
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
			if !deadline.After(time.Now()) || p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil {
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
			if !message.IsString || len(message.Data) > maxLiveControlMessageBytes {
				p.stop()
				return
			}
			input, err := decodeBrowserLiveInput(message.Data, p.video, p.binding)
			if err != nil {
				p.stop()
				return
			}
			select {
			case p.inputs <- input:
			default:
				p.stop()
			}
		})
	})
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
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || message.Type != "pointer.move" || message.Sequence < 1 || message.Sequence > maxAutomationSequence || message.X < 0 || message.X >= video.Width || message.Y < 0 || message.Y >= video.Height || binding.ControlLeaseID == "" || binding.ControlFence < 1 {
		return BrowserLiveInput{}, product.ErrInvalid
	}
	return BrowserLiveInput{Sequence: message.Sequence, Kind: message.Type, X: message.X, Y: message.Y, ControlLeaseID: binding.ControlLeaseID, ControlFence: binding.ControlFence}, nil
}

func (p *browserLivePeer) inputLoop() {
	lastSequence := int64(0)
	for {
		select {
		case <-p.ctx.Done():
			return
		case input := <-p.inputs:
			if input.Sequence != lastSequence+1 || p.handler.grants.CheckGatewayAuthority(p.ctx, p.binding) != nil || p.media.HandleInput(p.ctx, input) != nil {
				p.stop()
				return
			}
			lastSequence = input.Sequence
		}
	}
}

func (p *browserLivePeer) onConnectionState(state webrtc.PeerConnectionState) {
	switch state {
	case webrtc.PeerConnectionStateConnected:
		p.connectedOnce.Do(func() { close(p.connected) })
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		p.stop()
	}
}

func (p *browserLivePeer) stop() {
	p.stopOnce.Do(func() {
		p.cancel()
		_ = p.peer.Close()
		_ = p.media.Close()
		p.handler.release(p.binding.SessionID)
	})
}

var _ http.Handler = (*BrowserLiveHandler)(nil)
