package browsergateway

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

const PrivateV2Path = browserhandoffv2.PrivatePath

type ConnectionResolver interface {
	ResolveConnection(context.Context, browserhandoffv2.OpenRequest) (reference.Endpoint, error)
}

type ConnectionStore interface {
	BindConnectionWithOwnership(context.Context, browserhandoffv2.OpenRequest, time.Time) (bool, error)
	CloseConnection(context.Context, string, string, string) error
}

// V2Options names one inventory-owned ingress principal and exact private
// route. The issuer text in Open is never treated as proof of that identity.
type V2Options struct {
	Resolver              ConnectionResolver
	Store                 ConnectionStore
	ExpectedPeerURI       string
	ExpectedHost          string
	MaxSessions           int
	OperationTimeout      time.Duration
	AuthorityPollInterval time.Duration
}

type V2Handler struct {
	resolver  ConnectionResolver
	store     ConnectionStore
	peerURI   string
	host      string
	operation time.Duration
	poll      time.Duration
	slots     chan struct{}
}

func NewV2(options V2Options) (*V2Handler, error) {
	peer, err := url.Parse(options.ExpectedPeerURI)
	if err != nil || peer.Scheme != "spiffe" || peer.Host == "" || peer.Path == "" ||
		peer.User != nil || peer.RawQuery != "" || peer.Fragment != "" ||
		len(options.ExpectedPeerURI) > 256 || options.ExpectedHost == "" || len(options.ExpectedHost) > 255 ||
		strings.ContainsAny(options.ExpectedHost, "/@?# \r\n\t") ||
		options.Resolver == nil || options.Store == nil ||
		options.MaxSessions < 1 || options.MaxSessions > 256 ||
		options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 30*time.Second ||
		options.AuthorityPollInterval < 10*time.Millisecond || options.AuthorityPollInterval > 5*time.Second {
		return nil, ErrInvalidOptions
	}
	return &V2Handler{resolver: options.Resolver, store: options.Store, peerURI: options.ExpectedPeerURI,
		host: options.ExpectedHost, operation: options.OperationTimeout, poll: options.AuthorityPollInterval,
		slots: make(chan struct{}, options.MaxSessions)}, nil
}

func (h *V2Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet || request.URL == nil ||
		request.URL.Path != PrivateV2Path || request.URL.EscapedPath() != PrivateV2Path ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.Host != h.host ||
		len(request.Header.Values("Origin")) != 0 || len(request.Header.Values("Sec-WebSocket-Protocol")) != 1 ||
		request.Header.Get("Sec-WebSocket-Protocol") != browserhandoffv2.ProtocolID ||
		!exactV2Peer(request.TLS, h.peerURI) {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{browserhandoffv2.ProtocolID}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(handoff.MaxDocumentBytes)
	readCtx, cancelRead := context.WithTimeout(request.Context(), h.operation)
	kind, document, err := connection.Read(readCtx)
	cancelRead()
	var open browserhandoffv2.OpenRequest
	if err != nil || kind != websocket.MessageText || len(document) > handoff.MaxDocumentBytes {
		h.writeV2Reject(request.Context(), connection, "invalid")
		return
	}
	open, err = browserhandoffv2.DecodeOpen(document, time.Now().UTC())
	if err != nil {
		h.writeV2Reject(request.Context(), connection, "invalid")
		return
	}
	bindCtx, cancelBind := context.WithTimeout(request.Context(), h.operation)
	created, err := h.store.BindConnectionWithOwnership(bindCtx, open, time.Now().UTC())
	cancelBind()
	if err != nil {
		h.writeV2Reject(request.Context(), connection, open.RequestID)
		return
	}
	resolveCtx, cancelResolve := context.WithTimeout(request.Context(), h.operation)
	endpoint, err := h.resolver.ResolveConnection(resolveCtx, open)
	cancelResolve()
	if err != nil || !matchesV2Endpoint(endpoint, open) {
		if created {
			h.closeV2Claim(open)
		}
		h.writeV2Reject(request.Context(), connection, open.RequestID)
		return
	}
	attachCtx, cancelAttach := context.WithTimeout(request.Context(), h.operation)
	stream, err := endpoint.Dial(attachCtx)
	cancelAttach()
	if err != nil || stream == nil {
		if created {
			h.closeV2Claim(open)
		}
		h.writeV2Reject(request.Context(), connection, open.RequestID)
		return
	}
	// Only the handler that won the one-use executor reservation can reach
	// here. A replayed identical private Open cannot close the first stream.
	defer func() {
		_ = stream.Close()
		h.closeV2Claim(open)
	}()
	response, _ := handoff.Encode(browserhandoffv2.AcceptedResponse(open.RequestID))
	if connection.Write(request.Context(), websocket.MessageText, response) != nil {
		return
	}
	expires, _ := time.Parse(time.RFC3339Nano, open.AuthorityExpiresAt)
	bridgeCtx, cancelBridge := context.WithDeadline(request.Context(), expires)
	defer cancelBridge()
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		h.monitorV2(bridgeCtx, cancelBridge, open)
	}()
	results := make(chan error, 2)
	go func() { results <- copyWebSocketToBrowser(bridgeCtx, connection, stream, handoff.MaxDocumentBytes) }()
	go func() { results <- copyBrowserToWebSocket(bridgeCtx, stream, connection, handoff.MaxDocumentBytes) }()
	<-results
	cancelBridge()
	_ = stream.Close()
	_ = connection.CloseNow()
	<-results
	<-monitorDone
}

func (h *V2Handler) closeV2Claim(open browserhandoffv2.OpenRequest) {
	closeCtx, cancel := context.WithTimeout(context.Background(), h.operation)
	_ = h.store.CloseConnection(closeCtx, open.HandoffReference, open.ConnectionEpoch, open.AuthorityDigest)
	cancel()
}

func exactV2Peer(state *tls.ConnectionState, expected string) bool {
	if state == nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 ||
		len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return false
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != expected ||
		len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return false
	}
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 || chain[0] == nil || !chain[0].Equal(leaf) {
			return false
		}
	}
	return true
}

func matchesV2Endpoint(endpoint reference.Endpoint, open browserhandoffv2.OpenRequest) bool {
	return endpoint.Reference == open.HandoffReference && endpoint.SandboxID == open.SandboxID &&
		endpoint.BrowserSessionID == open.BrowserSessionID && endpoint.CapabilityProfileID == open.CapabilityProfileID &&
		endpoint.ConnectionGeneration == open.ConnectionGeneration && endpoint.TenantBindingDigest == open.TenantBindingDigest &&
		endpoint.ExpiresAt.UTC().Format(time.RFC3339Nano) == open.HandoffExpiresAt && endpoint.Dial != nil
}

func (h *V2Handler) writeV2Reject(ctx context.Context, connection *websocket.Conn, requestID string) {
	response, err := handoff.Encode(browserhandoffv2.RejectResponse(requestID))
	if err != nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, h.operation)
	defer cancel()
	_ = connection.Write(writeCtx, websocket.MessageText, response)
}

func (h *V2Handler) monitorV2(ctx context.Context, cancel context.CancelFunc, open browserhandoffv2.OpenRequest) {
	ticker := time.NewTicker(h.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, stop := context.WithTimeout(ctx, h.operation)
			endpoint, err := h.resolver.ResolveConnection(probeCtx, open)
			stop()
			if err != nil || !matchesV2Endpoint(endpoint, open) {
				cancel()
				return
			}
		}
	}
}

var _ http.Handler = (*V2Handler)(nil)
