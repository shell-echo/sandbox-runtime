package productgateway

import (
	"context"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	"github.com/shell-echo/sandbox-runtime/internal/browseringress"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	"github.com/shell-echo/sandbox-runtime/product"
)

type PrivateBrowserV2ResolverOptions struct {
	Origin                    string
	HTTPClient                *http.Client
	Binding                   product.GatewayBinding
	MaxMessageBytes           int64
	AllowInsecureHTTPForTests bool
}

// PrivateBrowserV2Resolver binds each private attach to one already consumed
// Product grant. The caller's HMAC key and raw control lease stay in Gateway;
// the capacity claim is sent only to the independently scheduled ingress.
type PrivateBrowserV2Resolver struct {
	origin  string
	client  *http.Client
	binding product.GatewayBinding
	limit   int64
}

func NewPrivateBrowserV2Resolver(options PrivateBrowserV2ResolverOptions) (*PrivateBrowserV2Resolver, error) {
	parsed, err := url.Parse(options.Origin)
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultAutomationMessageSize
	}
	validScheme := err == nil && parsed.Scheme == "wss"
	if options.AllowInsecureHTTPForTests {
		validScheme = err == nil && (parsed.Scheme == "ws" || parsed.Scheme == "wss")
	}
	if !validScheme || parsed.Host == "" || parsed.User != nil || parsed.Path != cdpfence.BrowserActionV2Path ||
		parsed.EscapedPath() != cdpfence.BrowserActionV2Path || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || options.HTTPClient == nil || limit < 1 || limit > maxAutomationMessageSize ||
		options.Binding.ProtocolProfile != product.SessionProfileBrowserAutomation ||
		options.Binding.BrowserProviderAudience == "" || options.Binding.BrowserTenantBindingDigest == "" {
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &PrivateBrowserV2Resolver{origin: parsed.String(), client: options.HTTPClient,
		binding: options.Binding, limit: limit}, nil
}

func (r *PrivateBrowserV2Resolver) ResolveFenced(_ context.Context, reference string,
	subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence,
) (gateway.Endpoint, error) {
	if r == nil || r.client == nil {
		return gateway.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	requestID, err := randomRequestID()
	if err != nil {
		return gateway.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	open, err := browserIngressOpen(r.binding, reference, subject, fence, requestID)
	if err != nil {
		return gateway.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	return gateway.Endpoint{
		Reference: reference, SandboxID: subject.SandboxID,
		BrowserSessionID: subject.BrowserSessionID, CapabilityProfileID: subject.CapabilityProfileID,
		ConnectionGeneration: subject.ConnectionGeneration, ExpiresAt: subject.ExpiresAt,
		Dial: func(ctx context.Context) (gateway.Stream, error) { return r.dial(ctx, open) },
	}, nil
}

func (r *PrivateBrowserV2Resolver) dial(ctx context.Context, open browseringress.Open) (gateway.Stream, error) {
	connection, _, err := websocket.Dial(ctx, r.origin, &websocket.DialOptions{
		HTTPClient: r.client, Subprotocols: []string{browseringress.ProtocolID},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection.SetReadLimit(handoff.MaxDocumentBytes)
	if connection.Subprotocol() != browseringress.ProtocolID {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	document, err := handoff.Encode(open)
	if err != nil || connection.Write(ctx, websocket.MessageText, document) != nil {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	kind, responseDocument, err := connection.Read(ctx)
	response, decodeErr := browseringress.DecodeResponse(responseDocument)
	if err != nil || kind != websocket.MessageText || decodeErr != nil || response.RequestID != open.RequestID ||
		response.Status != browseringress.StatusAccepted {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection.SetReadLimit(r.limit)
	return newPrivateBrowserV2Stream(connection, r.limit), nil
}

var _ gateway.FencedReferenceResolver = (*PrivateBrowserV2Resolver)(nil)
