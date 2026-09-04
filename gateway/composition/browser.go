package composition

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

// BrowserProviderResolver is the narrow trusted Provider-side Browser
// reference boundary. Its implementation must recheck the opaque reference
// and committed Browser handoff both at Resolve and at every Dial.
type BrowserProviderResolver interface {
	Resolve(context.Context, string) (browserreference.Endpoint, error)
}

// BrowserOptions contains every dependency required by the caller-owned
// Browser Gateway. This package supplies no authorization, revocation, audit,
// handshake-admission, or reconnect-policy default.
type BrowserOptions struct {
	Authorizer  gateway.Authorizer
	Revocations gateway.RevocationSource
	Recorder    gateway.Recorder
	Resolver    BrowserProviderResolver
	WebSocket   adapter.WebSocketOptions

	Clock            gateway.Clock
	MaxReconnects    int
	ReconnectBackoff time.Duration

	// Browser connections are rejected rather than queued when either local
	// bound is reached. These limits cover one BrowserService process only.
	MaxConnections           int
	MaxConnectionsPerSession int
}

// BrowserService composes one bounded public WebSocket edge with the private
// Provider Browser reference resolver. It exposes no HTTP route by itself.
type BrowserService struct {
	gateway   *gateway.Gateway
	webSocket *adapter.WebSocketServer
}

// NewBrowser fails closed unless every caller-owned policy port, the Provider
// Browser resolver, and WebSocket handshake admission are supplied.
func NewBrowser(options BrowserOptions) (*BrowserService, error) {
	for _, dependency := range []struct {
		name  string
		value any
	}{
		{"authorizer", options.Authorizer},
		{"revocations", options.Revocations},
		{"recorder", options.Recorder},
		{"Browser provider resolver", options.Resolver},
		{"WebSocket admission", options.WebSocket.Admission},
	} {
		if nilDependency(dependency.value) {
			return nil, fmt.Errorf("%w: %s is required", ErrInvalidOptions, dependency.name)
		}
	}
	if options.MaxConnections < 1 || options.MaxConnectionsPerSession < 1 {
		return nil, fmt.Errorf("%w: Browser connection capacity is required", ErrInvalidOptions)
	}
	webSocket, err := adapter.NewWebSocketServer(options.WebSocket)
	if err != nil {
		return nil, fmt.Errorf("%w: WebSocket adapter: %w", ErrInvalidOptions, err)
	}
	proxy, err := gateway.New(gateway.Options{
		Authorizer: options.Authorizer,
		Resolver: browserProviderResolver{
			resolver: options.Resolver, maxFrameBytes: options.WebSocket.MaxFrameBytes,
		},
		Revocations: options.Revocations, Recorder: options.Recorder,
		Clock: options.Clock, MaxReconnects: options.MaxReconnects,
		ReconnectBackoff:         options.ReconnectBackoff,
		MaxConnections:           options.MaxConnections,
		MaxConnectionsPerSession: options.MaxConnectionsPerSession,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Gateway: %w", ErrInvalidOptions, err)
	}
	return &BrowserService{gateway: proxy, webSocket: webSocket}, nil
}

// Serve upgrades an already caller-admitted request and applies the supplied
// Browser identity. Request extraction and identity policy remain caller-owned.
func (s *BrowserService) Serve(ctx context.Context, response http.ResponseWriter, request *http.Request, connect gateway.ConnectRequest) error {
	if s == nil || s.webSocket == nil {
		return ErrUnavailable
	}
	client, err := s.webSocket.Upgrade(response, request)
	if err != nil {
		return err
	}
	return s.Connect(ctx, connect, client)
}

// Connect applies Browser Gateway policy to an already adapted caller stream.
func (s *BrowserService) Connect(ctx context.Context, request gateway.ConnectRequest, client gateway.Stream) error {
	if s == nil || s.gateway == nil || nilDependency(client) {
		return ErrUnavailable
	}
	defer func() { _ = client.Close(context.Background()) }()
	return s.gateway.Connect(ctx, request, client)
}

type browserProviderResolver struct {
	resolver      BrowserProviderResolver
	maxFrameBytes int64
}

func (r browserProviderResolver) Resolve(ctx context.Context, value string) (gateway.Endpoint, error) {
	if r.resolver == nil {
		return gateway.Endpoint{}, ErrUnavailable
	}
	endpoint, err := r.resolver.Resolve(ctx, value)
	if err != nil {
		return gateway.Endpoint{}, err
	}
	if endpoint.Dial == nil {
		return gateway.Endpoint{}, ErrUnavailable
	}
	return gateway.Endpoint{
		Reference: endpoint.Reference, ConnectionGeneration: endpoint.ConnectionGeneration,
		SandboxID: endpoint.SandboxID, BrowserSessionID: endpoint.BrowserSessionID,
		CapabilityProfileID: endpoint.CapabilityProfileID, ExpiresAt: endpoint.ExpiresAt.UTC(),
		Dial: func(dialCtx context.Context) (gateway.Stream, error) {
			stream, err := endpoint.Dial(dialCtx)
			if err != nil {
				return nil, err
			}
			if nilDependency(stream) {
				return nil, ErrUnavailable
			}
			return adapter.NewBrowserStream(stream, adapter.BrowserOptions{MaxFrameBytes: r.maxFrameBytes})
		},
	}, nil
}

var _ gateway.ReferenceResolver = browserProviderResolver{}
