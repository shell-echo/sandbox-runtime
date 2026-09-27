package cdpfence

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

type V2ProviderClientOptions struct {
	Origin                    string
	HTTPClient                *http.Client
	MaxMessageBytes           int64
	AllowInsecureHTTPForTests bool
}

// V2ProviderClient holds only the ingress-to-Provider transport. Production
// callers supply an inventory-scoped TLS/CRL client authenticating the Browser
// Provider identity; this client never resolves Provider DB or Docker state.
type V2ProviderClient struct {
	origin string
	client *http.Client
	limit  int64
}

func NewV2ProviderClient(options V2ProviderClientOptions) (*V2ProviderClient, error) {
	parsed, err := url.Parse(options.Origin)
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultNetworkMessageBytes
	}
	validScheme := err == nil && parsed.Scheme == "wss"
	if options.AllowInsecureHTTPForTests {
		validScheme = err == nil && (parsed.Scheme == "ws" || parsed.Scheme == "wss")
	}
	if !validScheme || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != browserhandoffv2.PrivatePath || parsed.EscapedPath() != browserhandoffv2.PrivatePath ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		options.HTTPClient == nil || limit < 1 || limit > maxNetworkMessageBytes {
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &V2ProviderClient{origin: parsed.String(), client: options.HTTPClient, limit: limit}, nil
}

func (c *V2ProviderClient) Open(ctx context.Context, open browserhandoffv2.OpenRequest) (gateway.Stream, error) {
	if c == nil || c.client == nil || open.Validate(time.Now().UTC()) != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection, _, err := websocket.Dial(ctx, c.origin, &websocket.DialOptions{
		HTTPClient: c.client, Subprotocols: []string{browserhandoffv2.ProtocolID},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection.SetReadLimit(handoff.MaxDocumentBytes)
	if connection.Subprotocol() != browserhandoffv2.ProtocolID {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	document, err := handoff.Encode(open)
	if err != nil || connection.Write(ctx, websocket.MessageText, document) != nil {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	kind, responseDocument, err := connection.Read(ctx)
	response, decodeErr := browserhandoffv2.DecodeResponse(responseDocument)
	if err != nil || kind != websocket.MessageText || decodeErr != nil || response.RequestID != open.RequestID ||
		response.Status != browserhandoffv2.StatusAccepted {
		_ = connection.CloseNow()
		return nil, gateway.ErrDownstreamUnavailable
	}
	connection.SetReadLimit(c.limit)
	return &networkWebSocketStream{connection: connection, maxMessageBytes: c.limit}, nil
}

var _ BrowserProviderDialer = (*V2ProviderClient)(nil)
