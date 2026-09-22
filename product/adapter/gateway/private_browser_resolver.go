package productgateway

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoff"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
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
)

type PrivateBrowserResolverOptions struct {
	Origin                    string
	HTTPClient                *http.Client
	MaxMessageBytes           int64
	AllowInsecureHTTPForTests bool
	// TenantBindingDigest is caller-owned Product/Gateway authority. When
	// present, the resolver uses the closed browser-handoff.v1 protocol.
	TenantBindingDigest func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence) (string, error)
}

// PrivateBrowserResolver carries only an opaque handoff and downstream fence
// over the trusted Gateway-to-ingress WSS boundary. It never resolves or
// exposes the Chromium endpoint in the Product Gateway process.
type PrivateBrowserResolver struct {
	origin          string
	httpClient      *http.Client
	maxMessageBytes int64
	bindingDigest   func(context.Context, gateway.DownstreamFenceSubject, gateway.DownstreamFence) (string, error)
}

func NewPrivateBrowserResolver(options PrivateBrowserResolverOptions) (*PrivateBrowserResolver, error) {
	parsed, err := url.Parse(options.Origin)
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultAutomationMessageSize
	}
	validScheme := err == nil && parsed.Scheme == "wss"
	if options.AllowInsecureHTTPForTests {
		validScheme = err == nil && (parsed.Scheme == "wss" || parsed.Scheme == "ws")
	}
	if !validScheme || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path == "" || options.HTTPClient == nil || limit < 1 || limit > maxAutomationMessageSize {
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &PrivateBrowserResolver{origin: parsed.String(), httpClient: options.HTTPClient, maxMessageBytes: limit, bindingDigest: options.TenantBindingDigest}, nil
}

func (r *PrivateBrowserResolver) ResolveFenced(_ context.Context, reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (gateway.Endpoint, error) {
	if r == nil || r.httpClient == nil || subject.Validate() != nil || fence.Validate() != nil ||
		!strings.HasPrefix(reference, "ref:browser-session:") || len(reference) > 256 || strings.ContainsAny(reference, "\r\n\t ") {
		return gateway.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	return gateway.Endpoint{
		Reference: reference, SandboxID: subject.SandboxID, BrowserSessionID: subject.BrowserSessionID,
		CapabilityProfileID: subject.CapabilityProfileID, ConnectionGeneration: subject.ConnectionGeneration,
		ExpiresAt: subject.ExpiresAt.UTC(),
		Dial: func(ctx context.Context) (gateway.Stream, error) {
			if r.bindingDigest != nil {
				return r.dialClosed(ctx, reference, subject, fence)
			}
			headers := http.Header{}
			headers.Set("Authorization", "Downstream "+fence.Opaque())
			headers.Set(privateBrowserReferenceHeader, reference)
			headers.Set(privateBrowserTenantHeader, subject.TenantID)
			headers.Set(privateBrowserSandboxHeader, subject.SandboxID)
			headers.Set(privateBrowserSessionHeader, subject.BrowserSessionID)
			headers.Set(privateBrowserProfileHeader, subject.CapabilityProfileID)
			headers.Set(privateBrowserGenerationHeader, strconv.FormatInt(subject.ConnectionGeneration, 10))
			headers.Set(privateBrowserExpiryHeader, subject.ExpiresAt.UTC().Format(time.RFC3339Nano))
			connection, _, err := websocket.Dial(ctx, r.origin, &websocket.DialOptions{
				HTTPClient: r.httpClient, HTTPHeader: headers, Subprotocols: []string{PrivateBrowserSubprotocol},
				CompressionMode: websocket.CompressionDisabled,
			})
			if err != nil {
				return nil, gateway.ErrDownstreamUnavailable
			}
			if connection.Subprotocol() != PrivateBrowserSubprotocol {
				_ = connection.CloseNow()
				return nil, gateway.ErrDownstreamUnavailable
			}
			connection.SetReadLimit(r.maxMessageBytes)
			return &privateBrowserStream{connection: connection, maxMessageBytes: r.maxMessageBytes}, nil
		},
	}, nil
}

func (r *PrivateBrowserResolver) dialClosed(ctx context.Context, reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (gateway.Stream, error) {
	digest, err := r.bindingDigest(ctx, subject, fence)
	if err != nil || handoff.ValidateTenantBindingDigest(digest) != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	requestID, err := randomRequestID()
	if err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection, _, err := websocket.Dial(ctx, r.origin, &websocket.DialOptions{
		HTTPClient: r.httpClient, Subprotocols: []string{browserhandoff.ProtocolID}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection.SetReadLimit(r.maxMessageBytes)
	open := browserhandoff.OpenRequest{Protocol: browserhandoff.ProtocolID, RequestID: requestID, Resource: browserhandoff.ResourceBrowser,
		TenantBindingDigest: digest, SandboxID: subject.SandboxID, BrowserSessionID: subject.BrowserSessionID,
		CapabilityProfileID: subject.CapabilityProfileID, HandoffReference: reference, ConnectionGeneration: subject.ConnectionGeneration,
		ExpiresAt: subject.ExpiresAt.UTC().Format(time.RFC3339Nano), Fence: fence.Opaque()}
	document, err := handoff.Encode(open)
	if err != nil || connection.Write(ctx, websocket.MessageText, document) != nil {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	kind, responseDocument, err := connection.Read(ctx)
	var response browserhandoff.OpenResponse
	if err != nil || kind != websocket.MessageText || handoff.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != requestID || response.Status != browserhandoff.StatusAccepted {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &privateBrowserStream{connection: connection, maxMessageBytes: r.maxMessageBytes}, nil
}

type privateBrowserStream struct {
	connection      *websocket.Conn
	maxMessageBytes int64
	closeOnce       sync.Once
	closeErr        error
}

func (s *privateBrowserStream) Receive(ctx context.Context) (gateway.Frame, error) {
	messageType, payload, err := s.connection.Read(ctx)
	if err != nil {
		return gateway.Frame{}, err
	}
	if messageType != websocket.MessageText || int64(len(payload)) > s.maxMessageBytes {
		return gateway.Frame{}, errors.New("invalid private Browser frame")
	}
	return gateway.Frame{Type: gateway.TextFrame, Payload: append([]byte(nil), payload...)}, nil
}

func (s *privateBrowserStream) Send(ctx context.Context, frame gateway.Frame) error {
	if frame.Type != gateway.TextFrame || int64(len(frame.Payload)) > s.maxMessageBytes {
		return errors.New("invalid private Browser frame")
	}
	return s.connection.Write(ctx, websocket.MessageText, append([]byte(nil), frame.Payload...))
}

func (s *privateBrowserStream) Close(context.Context) error {
	s.closeOnce.Do(func() { s.closeErr = s.connection.CloseNow() })
	return s.closeErr
}

var _ gateway.FencedReferenceResolver = (*PrivateBrowserResolver)(nil)
var _ gateway.Stream = (*privateBrowserStream)(nil)
