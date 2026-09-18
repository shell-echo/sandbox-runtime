package guestagent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type Identity struct {
	TenantID, WorkspaceID, SlotKey, GuestID string
	BindingGeneration                       int64
	ProtocolVersion                         string
	Capabilities                            []string
	ClientNonce                             string
	ExpiresAt                               time.Time
}

type Authenticator interface {
	Authenticate(context.Context, AuthRequest) (Identity, error)
	CheckAuthority(context.Context, Identity) error
	Disconnected(context.Context, Identity) error
}

type HubOptions struct {
	Authenticator       Authenticator
	Clock               func() time.Time
	HandshakeTimeout    time.Duration
	AuthorityPollPeriod time.Duration
}

type Hub struct {
	auth      Authenticator
	clock     func() time.Time
	handshake time.Duration
	poll      time.Duration
	mu        sync.RWMutex
	peers     map[peerKey]*peer
}

type peerKey struct{ tenant, workspace, slot string }

func NewHub(options HubOptions) (*Hub, error) {
	if options.Authenticator == nil {
		return nil, ErrInvalid
	}
	clock := options.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	handshake := options.HandshakeTimeout
	if handshake == 0 {
		handshake = 10 * time.Second
	}
	poll := options.AuthorityPollPeriod
	if poll == 0 {
		poll = time.Second
	}
	if handshake < time.Second || handshake > 30*time.Second || poll < 10*time.Millisecond || poll > 30*time.Second {
		return nil, ErrInvalid
	}
	return &Hub{auth: options.Authenticator, clock: clock, handshake: handshake, poll: poll, peers: make(map[peerKey]*peer)}, nil
}

func (h *Hub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request.Method != http.MethodGet || request.Header.Get("Origin") != "" || !exactSubprotocol(request.Header.Values("Sec-WebSocket-Protocol")) {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	connection.SetReadLimit(MaxMessageBytes)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	identity, err := h.handshakeGuest(ctx, connection)
	if err != nil {
		_ = connection.Close(websocket.StatusPolicyViolation, "guest authentication failed")
		return
	}
	p := newPeer(connection, identity)
	key := peerKey{identity.TenantID, identity.WorkspaceID, identity.SlotKey}
	if !h.install(key, p) {
		_ = connection.Close(websocket.StatusPolicyViolation, "guest already connected")
		return
	}
	defer h.remove(key, p)
	go h.monitorAuthority(ctx, p)
	p.readLoop(ctx)
}

func (h *Hub) Call(ctx context.Context, tenantID, workspaceID, slotKey, operation string, payload any) (json.RawMessage, error) {
	if h == nil || ctx == nil || !validID(tenantID) || !validID(workspaceID) || !validID(slotKey) || !validID(operation) {
		return nil, ErrInvalid
	}
	h.mu.RLock()
	p := h.peers[peerKey{tenantID, workspaceID, slotKey}]
	h.mu.RUnlock()
	if p == nil {
		return nil, ErrUnavailable
	}
	if !p.hasCapability(operation) {
		return nil, ErrCapabilityMissing
	}
	return p.call(ctx, operation, payload)
}

// Disconnect terminates only the current transport. Product authority remains
// unchanged, so an authorized outbound Guest may reconnect with a fresh nonce.
func (h *Hub) Disconnect(tenantID, workspaceID, slotKey string) {
	if h == nil {
		return
	}
	h.mu.RLock()
	p := h.peers[peerKey{tenantID, workspaceID, slotKey}]
	h.mu.RUnlock()
	if p != nil {
		p.close(ErrUnavailable)
	}
}

func (h *Hub) handshakeGuest(parent context.Context, connection *websocket.Conn) (Identity, error) {
	ctx, cancel := context.WithTimeout(parent, h.handshake)
	defer cancel()
	nonce, err := randomNonce()
	if err != nil {
		return Identity{}, ErrUnavailable
	}
	challenge := Challenge{Type: "challenge", Nonce: nonce, ExpiresAt: h.clock().Add(h.handshake).UTC().Format(time.RFC3339Nano)}
	if err := writeJSON(ctx, connection, challenge); err != nil {
		return Identity{}, ErrUnavailable
	}
	var hello Hello
	if err := readJSON(ctx, connection, &hello); err != nil {
		return Identity{}, err
	}
	request := AuthRequest{Hello: hello, Challenge: challenge}
	if err := request.Validate(); err != nil {
		return Identity{}, err
	}
	if hello.ProtocolVersion != ProtocolVersion {
		return Identity{}, ErrIncompatible
	}
	identity, err := h.auth.Authenticate(ctx, request)
	if err != nil || identity.ProtocolVersion != ProtocolVersion || identity.GuestID != hello.GuestID ||
		identity.BindingGeneration != hello.BindingGeneration || !uniqueCapabilities(identity.Capabilities) || !subset(identity.Capabilities, hello.Capabilities) || !identity.ExpiresAt.After(h.clock()) {
		return Identity{}, ErrUnauthorized
	}
	welcome := Welcome{Type: "welcome", ProtocolVersion: ProtocolVersion, Capabilities: append([]string(nil), identity.Capabilities...), BindingGeneration: identity.BindingGeneration}
	if err := writeJSON(ctx, connection, welcome); err != nil {
		return Identity{}, ErrUnavailable
	}
	return identity, nil
}

func (h *Hub) install(key peerKey, candidate *peer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if current := h.peers[key]; current != nil {
		return false
	}
	h.peers[key] = candidate
	return true
}

func (h *Hub) remove(key peerKey, candidate *peer) {
	h.mu.Lock()
	if h.peers[key] == candidate {
		delete(h.peers, key)
	}
	h.mu.Unlock()
	candidate.close(ErrUnavailable)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = h.auth.Disconnected(ctx, candidate.identity)
}

func (h *Hub) monitorAuthority(ctx context.Context, p *peer) {
	ticker := time.NewTicker(h.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.done:
			return
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, h.poll)
			err := h.auth.CheckAuthority(checkCtx, p.identity)
			cancel()
			if err != nil {
				p.close(ErrUnauthorized)
				return
			}
		}
	}
}

type peer struct {
	connection *websocket.Conn
	identity   Identity
	writeMu    sync.Mutex
	mu         sync.Mutex
	pending    map[string]chan Response
	sem        chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
	closeErr   error
}

func newPeer(connection *websocket.Conn, identity Identity) *peer {
	return &peer{connection: connection, identity: identity, pending: make(map[string]chan Response), sem: make(chan struct{}, MaxInFlight), done: make(chan struct{})}
}

func (p *peer) call(ctx context.Context, operation string, payload any) (json.RawMessage, error) {
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-p.done:
		return nil, ErrUnavailable
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(time.Now().Add(30*time.Second)) {
		return nil, ErrInvalid
	}
	document, err := encodeMessage(payload)
	if err != nil {
		return nil, err
	}
	requestID, err := randomID()
	if err != nil {
		return nil, ErrUnavailable
	}
	response := make(chan Response, 1)
	p.mu.Lock()
	p.pending[requestID] = response
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.pending, requestID); p.mu.Unlock() }()
	request := Request{Type: "request", RequestID: requestID, Operation: operation, DeadlineAt: deadline.UTC().Format(time.RFC3339Nano), Payload: document}
	if err := p.write(ctx, request); err != nil {
		return nil, ErrUnavailable
	}
	select {
	case result := <-response:
		if !result.OK {
			return nil, errors.Join(ErrRemote, errors.New(result.ErrorCode))
		}
		return append(json.RawMessage(nil), result.Payload...), nil
	case <-p.done:
		return nil, ErrUnavailable
	case <-ctx.Done():
		cancelCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = p.write(cancelCtx, Cancel{Type: "cancel", RequestID: requestID})
		cancel()
		return nil, ctx.Err()
	}
}

func (p *peer) readLoop(ctx context.Context) {
	for {
		var response Response
		if err := readJSON(ctx, p.connection, &response); err != nil {
			p.close(err)
			return
		}
		if response.Type != "response" || !validID(response.RequestID) || response.OK == (response.ErrorCode != "") {
			p.close(ErrInvalid)
			return
		}
		p.mu.Lock()
		waiter := p.pending[response.RequestID]
		p.mu.Unlock()
		if waiter != nil {
			select {
			case waiter <- response:
			default:
			}
		}
	}
}

func (p *peer) write(ctx context.Context, value any) error {
	document, err := encodeMessage(value)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.connection.Write(ctx, websocket.MessageText, document)
}

func (p *peer) close(err error) {
	p.closeOnce.Do(func() {
		p.closeErr = err
		close(p.done)
		_ = p.connection.CloseNow()
	})
}

func (p *peer) hasCapability(operation string) bool {
	for _, capability := range p.identity.Capabilities {
		if capability == operation {
			return true
		}
	}
	return false
}

func readJSON(ctx context.Context, connection *websocket.Conn, value any) error {
	messageType, document, err := connection.Read(ctx)
	if err != nil {
		return err
	}
	if messageType != websocket.MessageText {
		return ErrInvalid
	}
	return DecodeStrict(document, value)
}

func writeJSON(ctx context.Context, connection *websocket.Conn, value any) error {
	document, err := encodeMessage(value)
	if err != nil {
		return err
	}
	return connection.Write(ctx, websocket.MessageText, document)
}

func randomNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "greq-" + base64.RawURLEncoding.EncodeToString(value), nil
}

func exactSubprotocol(values []string) bool {
	return len(values) == 1 && strings.TrimSpace(values[0]) == Subprotocol && !strings.Contains(values[0], ",")
}

func subset(selected, offered []string) bool {
	set := make(map[string]struct{}, len(offered))
	for _, value := range offered {
		set[value] = struct{}{}
	}
	for _, value := range selected {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

var _ http.Handler = (*Hub)(nil)
