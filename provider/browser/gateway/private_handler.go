// Package browsergateway exposes the Provider-private Browser attach bridge.
// It is not a public Browser API and never serves the locked Provider Contract.
package browsergateway

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoff"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

var ErrInvalidOptions = errors.New("invalid private Browser gateway options")

type Resolver interface {
	Resolve(context.Context, string) (reference.Endpoint, error)
}

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, tls.ConnectionState) error
}

type BindingAuthorizer interface {
	AuthorizeHandoff(context.Context, browserhandoff.OpenRequest) error
}

type Options struct {
	Resolver                  Resolver
	PeerAuthorizer            PeerAuthorizer
	BindingAuthorizer         BindingAuthorizer
	MaxMessageBytes           int64
	OperationTimeout          time.Duration
	AllowInsecureHTTPForTests bool
}

type Handler struct {
	resolver      Resolver
	peer          PeerAuthorizer
	binding       BindingAuthorizer
	maxBytes      int64
	operation     time.Duration
	insecureTests bool
	replayMu      sync.Mutex
	replayed      map[string]time.Time
}

func New(options Options) (*Handler, error) {
	maxBytes := options.MaxMessageBytes
	if maxBytes == 0 {
		maxBytes = 64 << 10
	}
	operation := options.OperationTimeout
	if operation == 0 {
		operation = 5 * time.Second
	}
	if options.Resolver == nil || options.BindingAuthorizer == nil ||
		(!options.AllowInsecureHTTPForTests && options.PeerAuthorizer == nil) ||
		maxBytes < 1024 || maxBytes > 256<<10 || operation < 100*time.Millisecond || operation > 30*time.Second {
		return nil, ErrInvalidOptions
	}
	return &Handler{resolver: options.Resolver, peer: options.PeerAuthorizer, binding: options.BindingAuthorizer,
		maxBytes: maxBytes, operation: operation, insecureTests: options.AllowInsecureHTTPForTests,
		replayed: make(map[string]time.Time)}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet ||
		(!h.insecureTests && request.TLS == nil) || request.Header.Get("Sec-WebSocket-Protocol") != browserhandoff.ProtocolID {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if !h.insecureTests && (h.peer == nil || request.TLS == nil || h.peer.AuthorizePeer(request.Context(), *request.TLS) != nil) {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{browserhandoff.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(h.maxBytes)
	kind, document, err := connection.Read(request.Context())
	if err != nil || kind != websocket.MessageText || int64(len(document)) > browserhandoff.MaxDocumentBytes {
		return
	}
	var open browserhandoff.OpenRequest
	if handoff.Decode(document, &open) != nil || open.Validate(time.Now().UTC()) != nil || !h.claim(open.RequestID, time.Now().UTC(), expiry(open.ExpiresAt)) {
		h.writeReject(connection, request.Context(), open.RequestID, "invalid_request")
		return
	}
	if err := h.binding.AuthorizeHandoff(request.Context(), open); err != nil {
		h.writeReject(connection, request.Context(), open.RequestID, "unauthorized")
		return
	}
	resolveContext, cancel := context.WithTimeout(request.Context(), h.operation)
	endpoint, err := h.resolver.Resolve(resolveContext, open.HandoffReference)
	cancel()
	expires, _ := time.Parse(time.RFC3339Nano, open.ExpiresAt)
	if err != nil || endpoint.Reference != open.HandoffReference || endpoint.SandboxID != open.SandboxID ||
		endpoint.BrowserSessionID != open.BrowserSessionID || endpoint.CapabilityProfileID != open.CapabilityProfileID ||
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
	response, _ := handoff.Encode(browserhandoff.AcceptedResponse(open.RequestID))
	if err := connection.Write(request.Context(), websocket.MessageText, response); err != nil {
		return
	}
	bridgeCtx, cancelBridge := context.WithDeadline(request.Context(), expires)
	defer cancelBridge()
	results := make(chan error, 2)
	go func() { results <- copyWebSocketToBrowser(bridgeCtx, connection, stream, h.maxBytes) }()
	go func() { results <- copyBrowserToWebSocket(bridgeCtx, stream, connection, h.maxBytes) }()
	<-results
	cancelBridge()
	_ = stream.Close()
	<-results
}

func (h *Handler) writeReject(connection *websocket.Conn, ctx context.Context, requestID, code string) {
	response, err := handoff.Encode(browserhandoff.RejectResponse(requestID, code))
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

func expiry(value string) time.Time { parsed, _ := time.Parse(time.RFC3339Nano, value); return parsed }

func copyWebSocketToBrowser(ctx context.Context, connection *websocket.Conn, stream providerbrowser.Stream, maxBytes int64) error {
	for {
		kind, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if kind != websocket.MessageText || int64(len(payload)) > maxBytes {
			return errors.New("invalid private Browser frame")
		}
		for len(payload) > 0 {
			written, writeErr := stream.Write(ctx, payload)
			if written <= 0 || written > len(payload) {
				return io.ErrShortWrite
			}
			payload = payload[written:]
			if writeErr != nil {
				return writeErr
			}
		}
	}
}

func copyBrowserToWebSocket(ctx context.Context, stream providerbrowser.Stream, connection *websocket.Conn, maxBytes int64) error {
	payload := make([]byte, maxBytes)
	for {
		read, err := stream.Read(ctx, payload)
		if read < 0 || int64(read) > maxBytes || (read == 0 && err == nil) {
			return io.ErrNoProgress
		}
		if read > 0 {
			if writeErr := connection.Write(ctx, websocket.MessageText, append([]byte(nil), payload[:read]...)); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
	}
}
