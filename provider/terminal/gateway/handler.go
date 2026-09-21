// Package terminalgateway exposes the Provider-local private terminal handoff
// bridge. It accepts only the internal handoff protocol and never serves the
// Provider Contract or a public endpoint.
package terminalgateway

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

var (
	ErrInvalidOptions = errors.New("invalid private terminal gateway options")
	ErrUnauthorized   = errors.New("private terminal peer is unauthorized")
)

type Resolver interface {
	Resolve(context.Context, string) (reference.Endpoint, error)
}

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, tls.ConnectionState) error
}

type TenantAuthorizer interface {
	AuthorizeHandoff(context.Context, handoff.OpenRequest) error
}

type Options struct {
	Resolver                  Resolver
	PeerAuthorizer            PeerAuthorizer
	TenantAuthorizer          TenantAuthorizer
	MaxMessageBytes           int64
	OperationTimeout          time.Duration
	AllowInsecureHTTPForTests bool
}

type Handler struct {
	resolver      Resolver
	peer          PeerAuthorizer
	tenant        TenantAuthorizer
	maxBytes      int64
	operation     time.Duration
	insecureTests bool
	replayMu      sync.Mutex
	replayed      map[string]time.Time
}

func New(options Options) (*Handler, error) {
	maxBytes := options.MaxMessageBytes
	if maxBytes == 0 {
		maxBytes = handoff.MaxFrameBytes
	}
	operation := options.OperationTimeout
	if operation == 0 {
		operation = 5 * time.Second
	}
	if options.Resolver == nil || options.TenantAuthorizer == nil ||
		(!options.AllowInsecureHTTPForTests && options.PeerAuthorizer == nil) ||
		maxBytes < 1024 || maxBytes > 256<<10 || operation < 100*time.Millisecond || operation > 30*time.Second {
		return nil, ErrInvalidOptions
	}
	return &Handler{resolver: options.Resolver, peer: options.PeerAuthorizer, tenant: options.TenantAuthorizer,
		maxBytes: maxBytes, operation: operation, insecureTests: options.AllowInsecureHTTPForTests, replayed: make(map[string]time.Time)}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet ||
		(!h.insecureTests && request.TLS == nil) || request.Header.Get("Sec-WebSocket-Protocol") != handoff.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if !h.insecureTests && (h.peer == nil || request.TLS == nil || h.peer.AuthorizePeer(request.Context(), *request.TLS) != nil) {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{handoff.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(h.maxBytes)
	messageType, document, err := connection.Read(request.Context())
	if err != nil || messageType != websocket.MessageText || len(document) > handoff.MaxDocumentBytes {
		return
	}
	var open handoff.OpenRequest
	if handoff.Decode(document, &open) != nil || open.Validate(time.Now().UTC()) != nil {
		h.writeReject(connection, request.Context(), open.RequestID, "invalid_request")
		return
	}
	if !h.claim(open.RequestID, time.Now().UTC(), mustExpiry(open.ExpiresAt)) {
		h.writeReject(connection, request.Context(), open.RequestID, "replayed_request")
		return
	}
	if err := h.tenant.AuthorizeHandoff(request.Context(), open); err != nil {
		h.writeReject(connection, request.Context(), open.RequestID, "unauthorized")
		return
	}
	resolveContext, cancelResolve := context.WithTimeout(request.Context(), h.operation)
	endpoint, err := h.resolver.Resolve(resolveContext, open.HandoffReference)
	cancelResolve()
	expires, _ := handoff.AuthorityExpiry(open.ExpiresAt)
	if err != nil || endpoint.Reference != open.HandoffReference || endpoint.SandboxID != open.SandboxID ||
		endpoint.RuntimeSessionID != open.RuntimeSessionID || endpoint.CapabilityProfileID != open.CapabilityProfileID ||
		endpoint.ConnectionGeneration != open.ConnectionGeneration || endpoint.TenantBindingDigest != open.TenantBindingDigest ||
		!endpoint.ExpiresAt.Equal(expires) || endpoint.Dial == nil {
		h.writeReject(connection, request.Context(), open.RequestID, "unavailable")
		return
	}
	attachContext, cancelAttach := context.WithTimeout(request.Context(), h.operation)
	stream, err := endpoint.Dial(attachContext)
	cancelAttach()
	if err != nil || stream == nil {
		h.writeReject(connection, request.Context(), open.RequestID, "unavailable")
		return
	}
	defer stream.Close()
	response, _ := handoff.Encode(handoff.AcceptedResponse(open.RequestID))
	if err := connection.Write(request.Context(), websocket.MessageText, response); err != nil {
		return
	}
	bridgeCtx, cancel := context.WithDeadline(request.Context(), expires)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- copyWebSocketToTerminal(bridgeCtx, connection, stream, h.maxBytes) }()
	go func() { results <- copyTerminalToWebSocket(bridgeCtx, stream, connection, h.maxBytes) }()
	<-results
	cancel()
	_ = stream.Close()
	<-results
}

func (h *Handler) writeReject(connection *websocket.Conn, ctx context.Context, requestID, code string) {
	response, err := handoff.Encode(handoff.RejectResponse(requestID, code))
	if err == nil {
		_ = connection.Write(ctx, websocket.MessageText, response)
	}
}

func (h *Handler) claim(requestID string, now, expires time.Time) bool {
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

func mustExpiry(value string) time.Time {
	expires, _ := handoff.AuthorityExpiry(value)
	return expires
}

func copyWebSocketToTerminal(ctx context.Context, connection *websocket.Conn, stream terminal.Stream, maxBytes int64) error {
	for {
		kind, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if kind != websocket.MessageBinary || int64(len(payload)) > maxBytes {
			return errors.New("invalid private terminal frame")
		}
		for len(payload) > 0 {
			written, writeErr := stream.Write(ctx, payload)
			if written < 0 || written > len(payload) || written == 0 {
				return io.ErrShortWrite
			}
			payload = payload[written:]
			if writeErr != nil {
				return writeErr
			}
		}
	}
}

func copyTerminalToWebSocket(ctx context.Context, stream terminal.Stream, connection *websocket.Conn, maxBytes int64) error {
	payload := make([]byte, maxBytes)
	for {
		read, err := stream.Read(ctx, payload)
		if read < 0 || int64(read) > maxBytes || (read == 0 && err == nil) {
			return io.ErrNoProgress
		}
		if read > 0 {
			if writeErr := connection.Write(ctx, websocket.MessageBinary, append([]byte(nil), payload[:read]...)); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}
