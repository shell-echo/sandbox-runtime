// Package desktopgateway implements the private Provider-to-Product-Gateway
// Desktop media and control bridge. It is not a public signaling endpoint and
// never authenticates end users; callers must restrict it to the trusted
// Product Gateway identity.
package desktopgateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

const (
	PrivateSubprotocol = desktopmedia.Subprotocol
	ClosedSubprotocol  = desktophandoff.ProtocolID

	referenceHeader  = "X-Sandbox-Desktop-Reference"
	sandboxHeader    = "X-Sandbox-ID"
	sessionHeader    = "X-Sandbox-Desktop-Session"
	profileHeader    = "X-Sandbox-Desktop-Profile"
	generationHeader = "X-Sandbox-Connection-Generation"
	expiryHeader     = "X-Sandbox-Authority-Expires-At"
	policyHeader     = "X-Sandbox-Desktop-Media-Policy"

	videoPacket = desktopmedia.VideoPacket
	audioPacket = desktopmedia.AudioPacket

	defaultMessageBytes     = int64(64 << 10)
	maxMessageBytes         = int64(256 << 10)
	defaultAuthorityPoll    = 250 * time.Millisecond
	defaultOperationTimeout = 5 * time.Second
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

// Resolver is the durable Provider handoff authority. Resolve must recheck
// revocation, expiry, source operation, receipt, and connection generation.
type Resolver interface {
	Resolve(context.Context, string) (desktopreference.Endpoint, error)
}

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, tls.ConnectionState) error
}

type PeerAuthorizerFunc func(context.Context, tls.ConnectionState) error

func (f PeerAuthorizerFunc) AuthorizePeer(ctx context.Context, state tls.ConnectionState) error {
	return f(ctx, state)
}

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type MediaPolicy = desktopmedia.MediaPolicy
type DisplayPolicy = desktopmedia.DisplayPolicy
type TouchPoint = desktopmedia.TouchPoint
type TransferFile = desktopmedia.TransferFile
type Input = desktopmedia.Input
type InputResult = desktopmedia.InputResult

type Session interface {
	ReadVideoRTP(context.Context) ([]byte, error)
	ReadAudioRTP(context.Context) ([]byte, error)
	HandleInput(context.Context, Input) (InputResult, error)
	UpdateStream(context.Context, DisplayPolicy, string) error
	Resynchronize(context.Context) error
	RequestKeyframe(context.Context) error
	Close() error
}

type MediaSource interface {
	Open(context.Context, desktopreference.Endpoint, providerdesktop.Attachment, MediaPolicy) (Session, error)
}

type BoundMediaSource interface {
	OpenBound(context.Context, desktophandoff.OpenRequest, desktopreference.Endpoint, providerdesktop.Attachment) (Session, error)
}

type BindingRegistrar interface {
	BindHandoff(context.Context, desktophandoff.Binding) error
}

type Options struct {
	Resolver                  Resolver
	Media                     MediaSource
	BoundMedia                BoundMediaSource
	BindingRegistrar          BindingRegistrar
	PeerAuthorizer            PeerAuthorizer
	MaxMessageBytes           int64
	MaxSessions               int
	MaxSessionsPerDesktop     int
	AuthorityPollInterval     time.Duration
	OperationTimeout          time.Duration
	Clock                     Clock
	AllowInsecureHTTPForTests bool
}

type Handler struct {
	resolver         Resolver
	media            MediaSource
	boundMedia       BoundMediaSource
	bindingRegistrar BindingRegistrar
	peerAuthorizer   PeerAuthorizer
	maxMessageBytes  int64
	maxSessions      int
	maxPerDesktop    int
	authorityPoll    time.Duration
	operationTimeout time.Duration
	clock            Clock
	insecureTests    bool

	mu       sync.Mutex
	active   int
	sessions map[string]int
	replayMu sync.Mutex
	replayed map[string]time.Time
	clockMu  sync.Mutex
	lastNow  time.Time
}

func New(options Options) (*Handler, error) {
	messageLimit := options.MaxMessageBytes
	if messageLimit == 0 {
		messageLimit = defaultMessageBytes
	}
	maxSessions := options.MaxSessions
	if maxSessions == 0 {
		maxSessions = 100
	}
	maxPerDesktop := options.MaxSessionsPerDesktop
	if maxPerDesktop == 0 {
		maxPerDesktop = 16
	}
	poll := options.AuthorityPollInterval
	if poll == 0 {
		poll = defaultAuthorityPoll
	}
	operationTimeout := options.OperationTimeout
	if operationTimeout == 0 {
		operationTimeout = defaultOperationTimeout
	}
	clock := options.Clock
	if clock == nil {
		clock = ClockFunc(func() time.Time { return time.Now().UTC() })
	}
	if nilDependency(options.Resolver) || (nilDependency(options.Media) && nilDependency(options.BoundMedia)) ||
		(!options.AllowInsecureHTTPForTests && nilDependency(options.PeerAuthorizer)) ||
		messageLimit < 1024 || messageLimit > maxMessageBytes || maxSessions < 1 || maxSessions > 10000 ||
		maxPerDesktop < 1 || maxPerDesktop > 64 || poll < 10*time.Millisecond || poll > 5*time.Second ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 30*time.Second {
		return nil, providerdesktop.ErrDesktopUnsupported
	}
	return &Handler{resolver: options.Resolver, media: options.Media, boundMedia: options.BoundMedia, bindingRegistrar: options.BindingRegistrar, peerAuthorizer: options.PeerAuthorizer, clock: clock,
		maxMessageBytes: messageLimit, maxSessions: maxSessions, maxPerDesktop: maxPerDesktop,
		authorityPoll: poll, operationTimeout: operationTimeout, insecureTests: options.AllowInsecureHTTPForTests,
		sessions: make(map[string]int), replayed: make(map[string]time.Time)}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) { //nolint:cyclop
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet ||
		(!h.insecureTests && request.TLS == nil) || (request.Header.Get("Sec-WebSocket-Protocol") != PrivateSubprotocol && request.Header.Get("Sec-WebSocket-Protocol") != ClosedSubprotocol) {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if !h.insecureTests && (h.peerAuthorizer == nil || h.peerAuthorizer.AuthorizePeer(request.Context(), *request.TLS) != nil) {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	if request.Header.Get("Sec-WebSocket-Protocol") == ClosedSubprotocol {
		h.serveClosed(writer, request)
		return
	}
	authority, ok := decodeAuthority(request)
	if !ok {
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	resolveCtx, resolveCancel := context.WithTimeout(request.Context(), h.operationTimeout)
	endpoint, attachment, err := h.resolve(resolveCtx, authority)
	resolveCancel()
	if err != nil || !h.acquire(authority.sessionID) {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer h.release(authority.sessionID)
	for _, header := range []string{referenceHeader, sandboxHeader, sessionHeader, profileHeader, generationHeader, expiryHeader, policyHeader} {
		request.Header.Del(header)
	}
	operationCtx, operationCancel := context.WithTimeout(request.Context(), h.operationTimeout)
	session, err := h.media.Open(operationCtx, endpoint, attachment, authority.policy)
	operationCancel()
	if err != nil || nilDependency(session) {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer session.Close()
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{PrivateSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	connection.SetReadLimit(h.maxMessageBytes)
	defer connection.CloseNow()
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	bridge := &connectionBridge{connection: connection, session: session, authority: authority, handler: h}
	bridge.run(ctx)
	// Close the Provider media session before ServeHTTP returns and its deferred
	// WebSocket close becomes observable to the Product Gateway. Keeping the
	// defer above still covers handshake failures after Media.Open.
	_ = session.Close()
}

func (h *Handler) serveClosed(writer http.ResponseWriter, request *http.Request) {
	if h.boundMedia == nil || h.bindingRegistrar == nil {
		http.Error(writer, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{ClosedSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(h.maxMessageBytes)
	kind, document, err := connection.Read(request.Context())
	if err != nil || kind != websocket.MessageText || int64(len(document)) > handoff.MaxDocumentBytes {
		return
	}
	var open desktophandoff.OpenRequest
	now, trusted := h.now()
	if handoff.Decode(document, &open) != nil || !trusted || open.Validate(now) != nil {
		return
	}
	if !h.claim(open.RequestID, now, mustExpiry(open.AuthorityExpiresAt)) {
		response, _ := handoff.Encode(desktophandoff.RejectResponse(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	if err := h.bindingRegistrar.BindHandoff(request.Context(), open.Binding()); err != nil {
		response, _ := handoff.Encode(desktophandoff.RejectResponse(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	resolveCtx, cancel := context.WithTimeout(request.Context(), h.operationTimeout)
	endpoint, attachment, err := h.resolveClosed(resolveCtx, open)
	cancel()
	if err != nil {
		response, _ := handoff.Encode(desktophandoff.RejectResponse(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	if !h.acquire(open.DesktopSessionID) {
		response, _ := handoff.Encode(desktophandoff.RejectResponse(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	defer h.release(open.DesktopSessionID)
	operationCtx, operationCancel := context.WithTimeout(request.Context(), h.operationTimeout)
	session, err := h.boundMedia.OpenBound(operationCtx, open, endpoint, attachment)
	operationCancel()
	if err != nil || nilDependency(session) {
		response, _ := handoff.Encode(desktophandoff.RejectResponse(open.RequestID, "unavailable"))
		_ = connection.Write(request.Context(), websocket.MessageText, response)
		return
	}
	defer session.Close()
	response, _ := handoff.Encode(desktophandoff.AcceptedResponse(open.RequestID))
	if err := connection.Write(request.Context(), websocket.MessageText, response); err != nil {
		return
	}
	authorityExpiry, _ := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	ctx, cancelBridge := context.WithDeadline(request.Context(), authorityExpiry)
	defer cancelBridge()
	handoffExpiry, _ := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	binding := open.Binding()
	bridge := &connectionBridge{connection: connection, session: session, authority: requestAuthority{reference: open.HandoffReference, providerRevision: open.ProviderRevisionID, tenantDigest: open.TenantBindingDigest, allocationReference: endpoint.AllocationReference, sandboxID: open.SandboxID, sessionID: open.DesktopSessionID, profileID: open.CapabilityProfileID, generation: open.ConnectionGeneration, connectionEpoch: open.ConnectionEpoch, expiresAt: authorityExpiry, handoffExpiresAt: handoffExpiry, policy: open.MediaPolicy, binding: &binding}, handler: h}
	bridge.run(ctx)
	_ = session.Close()
}

func (h *Handler) resolveClosed(ctx context.Context, open desktophandoff.OpenRequest) (desktopreference.Endpoint, providerdesktop.Attachment, error) {
	endpoint, err := h.resolver.Resolve(ctx, open.HandoffReference)
	if err != nil {
		return desktopreference.Endpoint{}, providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	handoffExpires, handoffErr := time.Parse(time.RFC3339Nano, open.HandoffExpiresAt)
	if handoffErr != nil || endpoint.Binding == nil || *endpoint.Binding != open.Binding() || endpoint.Reference != open.HandoffReference || endpoint.ProviderRevisionID != open.ProviderRevisionID || endpoint.SandboxID != open.SandboxID || endpoint.DesktopSessionID != open.DesktopSessionID || endpoint.CapabilityProfileID != open.CapabilityProfileID || endpoint.ConnectionGeneration != open.ConnectionGeneration || endpoint.TenantBindingDigest != open.TenantBindingDigest || !endpoint.ExpiresAt.Equal(handoffExpires) || endpoint.AllocationReference == "" || endpoint.Attach == nil {
		return desktopreference.Endpoint{}, providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	attachment, err := endpoint.Attach(ctx)
	if err != nil {
		return desktopreference.Endpoint{}, providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	if attachment.DesktopSessionID != open.DesktopSessionID || attachment.ConnectionGeneration != open.ConnectionGeneration {
		return desktopreference.Endpoint{}, providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	return endpoint, attachment, nil
}

func mustExpiry(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

type requestAuthority struct {
	reference, providerRevision, tenantDigest, allocationReference string
	sandboxID, sessionID, profileID, connectionEpoch               string
	generation                                                     int64
	expiresAt, handoffExpiresAt                                    time.Time
	policy                                                         MediaPolicy
	binding                                                        *desktophandoff.Binding
}

func decodeAuthority(request *http.Request) (requestAuthority, bool) {
	values := make(map[string]string, 7)
	for _, name := range []string{referenceHeader, sandboxHeader, sessionHeader, profileHeader, generationHeader, expiryHeader, policyHeader} {
		headers := request.Header.Values(name)
		if len(headers) != 1 || headers[0] == "" || strings.ContainsAny(headers[0], "\r\n\x00") {
			return requestAuthority{}, false
		}
		values[name] = headers[0]
	}
	generation, err := strconv.ParseInt(values[generationHeader], 10, 64)
	if err != nil || generation < 1 {
		return requestAuthority{}, false
	}
	expires, err := time.Parse(time.RFC3339Nano, values[expiryHeader])
	// The caller must supply a strict closed authority; the legacy header path
	// remains only for older component tests and is never used by production
	// composition.
	now := time.Now().UTC()
	if err != nil || !expires.After(now) || expires.After(now.Add(24*time.Hour)) {
		return requestAuthority{}, false
	}
	var policy MediaPolicy
	decoder := json.NewDecoder(strings.NewReader(values[policyHeader]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil || decoder.Decode(&struct{}{}) != io.EOF || !policy.Validate() {
		return requestAuthority{}, false
	}
	authority := requestAuthority{reference: values[referenceHeader], sandboxID: values[sandboxHeader], sessionID: values[sessionHeader],
		profileID: values[profileHeader], generation: generation, expiresAt: expires.UTC(), handoffExpiresAt: expires.UTC(), policy: policy}
	if !strings.HasPrefix(authority.reference, "ref:desktop-session:") || len(authority.reference) > 256 || strings.ContainsAny(authority.reference, " \r\n\t") ||
		!identifierPattern.MatchString(authority.sandboxID) || !identifierPattern.MatchString(authority.sessionID) || authority.profileID != providerdesktop.CapabilityProfileID {
		return requestAuthority{}, false
	}
	return authority, true
}

func (h *Handler) resolve(ctx context.Context, authority requestAuthority) (desktopreference.Endpoint, providerdesktop.Attachment, error) {
	endpoint, err := h.resolver.Resolve(ctx, authority.reference)
	if err != nil || endpoint.Reference != authority.reference || endpoint.SandboxID != authority.sandboxID ||
		endpoint.DesktopSessionID != authority.sessionID || endpoint.CapabilityProfileID != authority.profileID ||
		endpoint.ConnectionGeneration != authority.generation || !endpoint.ExpiresAt.Equal(authority.expiresAt) || endpoint.Attach == nil {
		return desktopreference.Endpoint{}, providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	attachment, err := endpoint.Attach(ctx)
	if err != nil || attachment.DesktopSessionID != authority.sessionID || attachment.ConnectionGeneration != authority.generation {
		return desktopreference.Endpoint{}, providerdesktop.Attachment{}, providerdesktop.ErrDesktopNotFound
	}
	return endpoint, attachment, nil
}

func (h *Handler) check(ctx context.Context, authority requestAuthority) error {
	endpoint, err := h.resolver.Resolve(ctx, authority.reference)
	if err != nil || endpoint.Reference != authority.reference || endpoint.SandboxID != authority.sandboxID ||
		endpoint.DesktopSessionID != authority.sessionID || endpoint.CapabilityProfileID != authority.profileID ||
		endpoint.ConnectionGeneration != authority.generation || !endpoint.ExpiresAt.Equal(authority.handoffExpiresAt) ||
		(authority.providerRevision != "" && endpoint.ProviderRevisionID != authority.providerRevision) ||
		(authority.tenantDigest != "" && endpoint.TenantBindingDigest != authority.tenantDigest) ||
		(authority.allocationReference != "" && endpoint.AllocationReference != authority.allocationReference) ||
		(authority.binding != nil && (endpoint.Binding == nil || *endpoint.Binding != *authority.binding)) {
		return providerdesktop.ErrDesktopNotFound
	}
	return nil
}

func (h *Handler) now() (time.Time, bool) {
	if h == nil || h.clock == nil {
		return time.Time{}, false
	}
	now := h.clock.Now().UTC()
	if now.IsZero() {
		return time.Time{}, false
	}
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	if !h.lastNow.IsZero() && now.Before(h.lastNow) {
		return time.Time{}, false
	}
	h.lastNow = now
	return now, true
}

func (h *Handler) claim(requestID string, now, expires time.Time) bool {
	if requestID == "" || now.IsZero() || expires.IsZero() || !expires.After(now) {
		return false
	}
	h.replayMu.Lock()
	defer h.replayMu.Unlock()
	for id, until := range h.replayed {
		if !until.After(now) {
			delete(h.replayed, id)
		}
	}
	if _, exists := h.replayed[requestID]; exists {
		return false
	}
	h.replayed[requestID] = expires
	return true
}

func (h *Handler) acquire(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active >= h.maxSessions || h.sessions[sessionID] >= h.maxPerDesktop {
		return false
	}
	h.active++
	h.sessions[sessionID]++
	return true
}

func (h *Handler) release(sessionID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.active--
	h.sessions[sessionID]--
	if h.sessions[sessionID] == 0 {
		delete(h.sessions, sessionID)
	}
}

type command = desktopmedia.Command
type result = desktopmedia.Result

type connectionBridge struct {
	connection *websocket.Conn
	session    Session
	authority  requestAuthority
	handler    *Handler
	writeMu    sync.Mutex
}

func (b *connectionBridge) run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{}, 4)
	go func() { defer func() { done <- struct{}{} }(); b.stream(ctx, videoPacket, b.session.ReadVideoRTP) }()
	if b.authority.policy.AudioCodec != "" {
		go func() { defer func() { done <- struct{}{} }(); b.stream(ctx, audioPacket, b.session.ReadAudioRTP) }()
	}
	go func() { defer func() { done <- struct{}{} }(); b.readCommands(ctx) }()
	go func() { defer func() { done <- struct{}{} }(); b.watchAuthority(ctx) }()
	<-done
	cancel()
}

func (b *connectionBridge) stream(ctx context.Context, packetType byte, read func(context.Context) ([]byte, error)) {
	packetLimit := 16 << 10
	if packetType == audioPacket {
		packetLimit = 4 << 10
	}
	for {
		packet, err := read(ctx)
		if err != nil || len(packet) == 0 || len(packet) > packetLimit || int64(len(packet)+1) > b.handler.maxMessageBytes {
			return
		}
		payload := make([]byte, len(packet)+1)
		payload[0] = packetType
		copy(payload[1:], packet)
		if b.write(ctx, websocket.MessageBinary, payload) != nil {
			return
		}
	}
}

func (b *connectionBridge) readCommands(ctx context.Context) {
	for {
		kind, payload, err := b.connection.Read(ctx)
		if err != nil || kind != websocket.MessageText || int64(len(payload)) > b.handler.maxMessageBytes {
			return
		}
		var command command
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&command) != nil || decoder.Decode(&struct{}{}) != io.EOF || command.RequestID < 1 || b.handler.check(ctx, b.authority) != nil {
			return
		}
		response := result{Type: "result", RequestID: command.RequestID, OK: true}
		operationCtx, cancel := context.WithTimeout(ctx, b.handler.operationTimeout)
		switch command.Type {
		case "input":
			if command.Input == nil || command.Display != nil || command.AudioDevice != "" || !desktopmedia.ValidInput(*command.Input, b.authority.policy) {
				cancel()
				return
			}
			inputResult, inputErr := b.session.HandleInput(operationCtx, *command.Input)
			response.Text, err = inputResult.Text, inputErr
		case "stream.configure":
			if command.Input != nil || command.Display == nil || command.Display.Width < 320 || command.Display.Width > b.authority.policy.Width || command.Display.Height < 240 || command.Display.Height > b.authority.policy.Height || command.Display.MaxFPS < 1 || command.Display.MaxFPS > b.authority.policy.MaxFPS || len(command.AudioDevice) > 64 {
				cancel()
				return
			}
			err = b.session.UpdateStream(operationCtx, *command.Display, command.AudioDevice)
		case "stream.resync":
			if command.Input != nil || command.Display != nil || command.AudioDevice != "" {
				cancel()
				return
			}
			err = b.session.Resynchronize(operationCtx)
		case "keyframe":
			if command.Input != nil || command.Display != nil || command.AudioDevice != "" {
				cancel()
				return
			}
			err = b.session.RequestKeyframe(operationCtx)
		default:
			cancel()
			return
		}
		cancel()
		if err != nil {
			return
		}
		if b.writeJSON(ctx, response) != nil {
			return
		}
	}
}

func (b *connectionBridge) watchAuthority(ctx context.Context) {
	ticker := time.NewTicker(b.handler.authorityPoll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, b.handler.operationTimeout)
			err := b.handler.check(checkCtx, b.authority)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (b *connectionBridge) writeJSON(ctx context.Context, value any) error {
	payload, err := json.Marshal(value)
	if err != nil || int64(len(payload)) > b.handler.maxMessageBytes {
		return providerdesktop.ErrDesktopUnsupported
	}
	return b.write(ctx, websocket.MessageText, payload)
}

func (b *connectionBridge) write(ctx context.Context, kind websocket.MessageType, payload []byte) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	return b.connection.Write(ctx, kind, payload)
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ http.Handler = (*Handler)(nil)
