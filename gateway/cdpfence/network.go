package cdpfence

import (
	"context"
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	PrivateBrowserSubprotocol      = "sandbox-browser-private-fence.v1"
	privateBrowserReferenceHeader  = "X-Sandbox-Browser-Reference"
	privateBrowserTenantHeader     = "X-Sandbox-Tenant"
	privateBrowserSandboxHeader    = "X-Sandbox-ID"
	privateBrowserSessionHeader    = "X-Sandbox-Browser-Session"
	privateBrowserProfileHeader    = "X-Sandbox-Browser-Profile"
	privateBrowserGenerationHeader = "X-Sandbox-Connection-Generation"
	privateBrowserExpiryHeader     = "X-Sandbox-Authority-Expires-At"
	defaultNetworkMessageBytes     = int64(64 << 10)
	maxNetworkMessageBytes         = int64(256 << 10)
)

type NetworkOptions struct {
	Ingress                   *Ingress
	Resolver                  gateway.ReferenceResolver
	PeerAuthorizer            PeerAuthorizer
	MaxMessageBytes           int64
	AllowInsecureHTTPForTests bool
	Now                       func() time.Time
}

type PeerAuthorizer interface {
	AuthorizePeer(context.Context, tls.ConnectionState) error
}

type PeerAuthorizerFunc func(context.Context, tls.ConnectionState) error

func (f PeerAuthorizerFunc) AuthorizePeer(ctx context.Context, state tls.ConnectionState) error {
	return f(ctx, state)
}

// NetworkHandler is the private, TLS-only Browser ingress transport. Public
// clients never reach this handler; network policy must expose it only to the
// Product Gateway identity.
type NetworkHandler struct {
	ingress         *Ingress
	resolver        gateway.ReferenceResolver
	peerAuthorizer  PeerAuthorizer
	maxMessageBytes int64
	insecureTests   bool
	now             func() time.Time
}

func NewNetworkHandler(options NetworkOptions) (*NetworkHandler, error) {
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultNetworkMessageBytes
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if options.Ingress == nil || nilDependency(options.Resolver) || (!options.AllowInsecureHTTPForTests && nilDependency(options.PeerAuthorizer)) || limit < 1 || limit > maxNetworkMessageBytes {
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &NetworkHandler{ingress: options.Ingress, resolver: options.Resolver, peerAuthorizer: options.PeerAuthorizer, maxMessageBytes: limit, insecureTests: options.AllowInsecureHTTPForTests, now: now}, nil
}

func (h *NetworkHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet || (!h.insecureTests && request.TLS == nil) ||
		request.Header.Get("Sec-WebSocket-Protocol") != PrivateBrowserSubprotocol {
		http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if !h.insecureTests {
		if h.peerAuthorizer == nil || h.peerAuthorizer.AuthorizePeer(request.Context(), *request.TLS) != nil {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
	reference, subject, fence, ok := h.authority(request)
	if !ok {
		writer.Header().Set("WWW-Authenticate", "Downstream")
		http.Error(writer, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	request.Header.Del("Authorization")
	for _, name := range []string{privateBrowserReferenceHeader, privateBrowserTenantHeader, privateBrowserSandboxHeader, privateBrowserSessionHeader, privateBrowserProfileHeader, privateBrowserGenerationHeader, privateBrowserExpiryHeader} {
		request.Header.Del(name)
	}
	downstream, err := h.ingress.Open(request.Context(), subject, fence, func(ctx context.Context) (gateway.Stream, error) {
		endpoint, err := h.resolver.Resolve(ctx, reference)
		if err != nil || endpoint.Reference != reference || endpoint.SandboxID != subject.SandboxID || endpoint.RuntimeSessionID != "" ||
			endpoint.BrowserSessionID != subject.BrowserSessionID || endpoint.CapabilityProfileID != subject.CapabilityProfileID ||
			endpoint.ConnectionGeneration != subject.ConnectionGeneration || endpoint.ExpiresAt.Before(subject.ExpiresAt) || endpoint.Dial == nil {
			return nil, gateway.ErrDownstreamUnavailable
		}
		return endpoint.Dial(ctx)
	})
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{PrivateBrowserSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		_ = downstream.Close(context.Background())
		return
	}
	connection.SetReadLimit(h.maxMessageBytes)
	client := &networkWebSocketStream{connection: connection, maxMessageBytes: h.maxMessageBytes}
	proxyStreams(request.Context(), client, downstream)
}

func (h *NetworkHandler) authority(request *http.Request) (string, gateway.DownstreamFenceSubject, gateway.DownstreamFence, bool) {
	var subject gateway.DownstreamFenceSubject
	if len(request.Header.Values("Authorization")) != 1 || !strings.HasPrefix(request.Header.Get("Authorization"), "Downstream ") {
		return "", subject, gateway.DownstreamFence{}, false
	}
	claim := strings.TrimPrefix(request.Header.Get("Authorization"), "Downstream ")
	fence, err := gateway.NewDownstreamFence(claim)
	if err != nil {
		return "", subject, gateway.DownstreamFence{}, false
	}
	values := make(map[string]string, 7)
	for _, name := range []string{privateBrowserReferenceHeader, privateBrowserTenantHeader, privateBrowserSandboxHeader, privateBrowserSessionHeader, privateBrowserProfileHeader, privateBrowserGenerationHeader, privateBrowserExpiryHeader} {
		headers := request.Header.Values(name)
		if len(headers) != 1 || headers[0] == "" || strings.ContainsAny(headers[0], "\r\n\t") {
			return "", subject, gateway.DownstreamFence{}, false
		}
		values[name] = headers[0]
	}
	generation, err := strconv.ParseInt(values[privateBrowserGenerationHeader], 10, 64)
	if err != nil {
		return "", subject, gateway.DownstreamFence{}, false
	}
	expires, err := time.Parse(time.RFC3339Nano, values[privateBrowserExpiryHeader])
	if err != nil {
		return "", subject, gateway.DownstreamFence{}, false
	}
	subject = gateway.DownstreamFenceSubject{
		TenantID: values[privateBrowserTenantHeader], SandboxID: values[privateBrowserSandboxHeader],
		BrowserSessionID: values[privateBrowserSessionHeader], CapabilityProfileID: values[privateBrowserProfileHeader],
		ConnectionGeneration: generation, ExpiresAt: expires.UTC(),
	}
	now := h.now().UTC()
	reference := values[privateBrowserReferenceHeader]
	if now.IsZero() || subject.Validate() != nil || !subject.ExpiresAt.After(now) || subject.ExpiresAt.After(now.Add(gateway.MaxDownstreamClaimLifetime)) ||
		!strings.HasPrefix(reference, "ref:browser-session:") || len(reference) > 256 || strings.ContainsAny(reference, " \r\n\t") {
		return "", gateway.DownstreamFenceSubject{}, gateway.DownstreamFence{}, false
	}
	return reference, subject, fence, true
}

type networkWebSocketStream struct {
	connection      *websocket.Conn
	maxMessageBytes int64
	closeOnce       sync.Once
	closeErr        error
}

func (s *networkWebSocketStream) Receive(ctx context.Context) (gateway.Frame, error) {
	messageType, payload, err := s.connection.Read(ctx)
	if err != nil {
		return gateway.Frame{}, err
	}
	if messageType != websocket.MessageText || int64(len(payload)) > s.maxMessageBytes {
		return gateway.Frame{}, gateway.ErrDownstreamUnavailable
	}
	return gateway.Frame{Type: gateway.TextFrame, Payload: append([]byte(nil), payload...)}, nil
}

func (s *networkWebSocketStream) Send(ctx context.Context, frame gateway.Frame) error {
	if frame.Type != gateway.TextFrame || int64(len(frame.Payload)) > s.maxMessageBytes {
		return gateway.ErrDownstreamUnavailable
	}
	return s.connection.Write(ctx, websocket.MessageText, append([]byte(nil), frame.Payload...))
}

func (s *networkWebSocketStream) Close(context.Context) error {
	s.closeOnce.Do(func() { s.closeErr = s.connection.CloseNow() })
	return s.closeErr
}

func proxyStreams(parent context.Context, left, right gateway.Stream) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{}, 2)
	copyStream := func(source, destination gateway.Stream) {
		defer func() { done <- struct{}{} }()
		for {
			frame, err := source.Receive(ctx)
			if err != nil || destination.Send(ctx, frame) != nil {
				return
			}
		}
	}
	go copyStream(left, right)
	go copyStream(right, left)
	<-done
	cancel()
	_ = left.Close(context.Background())
	_ = right.Close(context.Background())
	<-done
}

var _ http.Handler = (*NetworkHandler)(nil)
var _ gateway.Stream = (*networkWebSocketStream)(nil)
