package productgateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const (
	PrivateTerminalSubprotocol = handoff.ProtocolID
	defaultPrivateTerminalMax  = int64(64 << 10)
	maxPrivateTerminalMax      = int64(256 << 10)
)

// PrivateTerminalResolver is the Product-owned client for the private
// Gateway-to-Provider terminal handoff. It sends only the already-authorized
// grant binding and receives a byte stream; Provider DTOs never cross here.
type PrivateTerminalResolver struct {
	origin        string
	httpClient    *http.Client
	maxBytes      int64
	openTimeout   time.Duration
	bindingDigest func(context.Context, gateway.Grant) (string, error)
	allowInsecure bool
}

type PrivateTerminalResolverOptions struct {
	Origin          string
	HTTPClient      *http.Client
	MaxMessageBytes int64
	OpenTimeout     time.Duration
	// TenantBindingDigest is caller-owned Product/Gateway authority. The
	// resolver never derives a digest from an untrusted client field.
	TenantBindingDigest func(context.Context, gateway.Grant) (string, error)
	AllowHTTPForTests   bool
}

func NewPrivateTerminalResolver(options PrivateTerminalResolverOptions) (*PrivateTerminalResolver, error) {
	parsed, err := url.Parse(options.Origin)
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultPrivateTerminalMax
	}
	timeout := options.OpenTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	validScheme := err == nil && parsed != nil && parsed.Scheme == "wss"
	if options.AllowHTTPForTests {
		validScheme = err == nil && parsed != nil && (parsed.Scheme == "wss" || parsed.Scheme == "ws")
	}
	if !validScheme || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" ||
		options.HTTPClient == nil || limit < 1024 || limit > maxPrivateTerminalMax || timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, gateway.ErrDownstreamUnavailable
	}
	client := *options.HTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &PrivateTerminalResolver{origin: parsed.String(), httpClient: &client, maxBytes: limit, openTimeout: timeout, bindingDigest: options.TenantBindingDigest, allowInsecure: options.AllowHTTPForTests}, nil
}

func (r *PrivateTerminalResolver) Resolve(ctx context.Context, reference string) (gateway.Endpoint, error) {
	return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
}

func (r *PrivateTerminalResolver) ResolveBound(ctx context.Context, grant gateway.Grant) (gateway.Endpoint, error) {
	if r == nil || ctx == nil || grant.Validate(time.Now().UTC()) != nil {
		return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
	}
	if grant.RuntimeSessionID == "" || grant.BrowserSessionID != "" {
		return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
	}
	return gateway.Endpoint{
		Reference: grant.HandoffReference, SandboxID: grant.SandboxID, RuntimeSessionID: grant.RuntimeSessionID,
		CapabilityProfileID: grant.CapabilityProfileID, ConnectionGeneration: grant.ConnectionGeneration,
		ExpiresAt: grant.ExpiresAt.UTC(),
		Dial:      func(dialCtx context.Context) (gateway.Stream, error) { return r.dial(dialCtx, grant) },
	}, nil
}

func (r *PrivateTerminalResolver) dial(ctx context.Context, grant gateway.Grant) (gateway.Stream, error) {
	if ctx == nil || r == nil || r.httpClient == nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	digest := ""
	if r.bindingDigest != nil {
		var err error
		digest, err = r.bindingDigest(ctx, grant)
		if err != nil || (digest != "" && handoff.ValidateTenantBindingDigest(digest) != nil) {
			return nil, gateway.ErrDownstreamUnavailable
		}
	}
	openCtx, cancel := context.WithTimeout(ctx, r.openTimeout)
	defer cancel()
	connection, _, err := websocket.Dial(openCtx, r.origin, &websocket.DialOptions{
		HTTPClient: r.httpClient, Subprotocols: []string{PrivateTerminalSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection.SetReadLimit(r.maxBytes)
	requestID, err := randomToken(16)
	if err != nil {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	fence, err := randomToken(32)
	if err != nil {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	open := handoff.OpenRequest{
		Protocol: handoff.ProtocolID, RequestID: requestID, Resource: handoff.ResourceTerminal,
		TenantID: grant.TenantID, SandboxID: grant.SandboxID, RuntimeSessionID: grant.RuntimeSessionID,
		CapabilityProfileID: grant.CapabilityProfileID, HandoffReference: grant.HandoffReference,
		ConnectionGeneration: grant.ConnectionGeneration, ExpiresAt: grant.ExpiresAt.UTC().Format(time.RFC3339Nano), Fence: fence, TenantBindingDigest: digest,
	}
	document, err := handoff.Encode(open)
	if err != nil || connection.Write(openCtx, websocket.MessageText, document) != nil {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	messageType, responseDocument, err := connection.Read(openCtx)
	if err != nil || messageType != websocket.MessageText || len(responseDocument) > handoff.MaxDocumentBytes {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	var response handoff.OpenResponse
	if handoff.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != requestID || response.Status != handoff.StatusAccepted {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &privateTerminalStream{connection: connection, maxBytes: r.maxBytes}, nil
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

type privateTerminalStream struct {
	connection *websocket.Conn
	maxBytes   int64
	once       sync.Once
	err        error
}

func (s *privateTerminalStream) Receive(ctx context.Context) (gateway.Frame, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return gateway.Frame{}, gateway.ErrDownstreamUnavailable
	}
	kind, payload, err := s.connection.Read(ctx)
	if err != nil {
		return gateway.Frame{}, err
	}
	if kind != websocket.MessageBinary || int64(len(payload)) > s.maxBytes {
		return gateway.Frame{}, errors.New("invalid private terminal frame")
	}
	return gateway.Frame{Type: gateway.BinaryFrame, Payload: append([]byte(nil), payload...)}, nil
}

func (s *privateTerminalStream) Send(ctx context.Context, frame gateway.Frame) error {
	if s == nil || s.connection == nil || ctx == nil || (frame.Type != gateway.BinaryFrame && frame.Type != gateway.TextFrame) || int64(len(frame.Payload)) > s.maxBytes {
		return gateway.ErrDownstreamUnavailable
	}
	return s.connection.Write(ctx, websocket.MessageBinary, append([]byte(nil), frame.Payload...))
}

func (s *privateTerminalStream) Close(context.Context) error {
	if s == nil || s.connection == nil {
		return gateway.ErrDownstreamUnavailable
	}
	s.once.Do(func() { s.err = s.connection.CloseNow() })
	return s.err
}

var _ gateway.BoundReferenceResolver = (*PrivateTerminalResolver)(nil)
var _ gateway.ReferenceResolver = (*PrivateTerminalResolver)(nil)
var _ gateway.Stream = (*privateTerminalStream)(nil)
