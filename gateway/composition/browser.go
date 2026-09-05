package composition

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	"github.com/shell-echo/sandbox-runtime/gateway/edge"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

// BrowserProviderResolver is the narrow trusted Provider-side Browser
// reference boundary. Its implementation must recheck the opaque reference
// and committed Browser handoff both at Resolve and at every Dial.
type BrowserProviderResolver interface {
	Resolve(context.Context, string) (browserreference.Endpoint, error)
}

// BrowserFencedProviderResolver is the narrow trusted private-ingress
// boundary for a downstream-fenced Browser connection. Subject and fence are
// supplied exactly by the Gateway after authorization and capacity admission;
// this composition does not interpret or persist the opaque claim.
type BrowserFencedProviderResolver interface {
	ResolveFenced(context.Context, string, gateway.DownstreamFenceSubject, gateway.DownstreamFence) (browserreference.Endpoint, error)
}

// BrowserOptions contains every dependency required by the caller-owned
// Browser Gateway. This package supplies no authorization, revocation, audit,
// handshake-admission, or reconnect-policy default.
type BrowserOptions struct {
	Authorizer  gateway.Authorizer
	Revocations gateway.RevocationSource
	Recorder    gateway.Recorder
	Resolver    BrowserProviderResolver
	// FencedResolver is accepted only by NewFencedBrowser. NewBrowser rejects it
	// so an intended downstream-fenced deployment cannot silently use the raw
	// Provider attachment path.
	FencedResolver BrowserFencedProviderResolver
	WebSocket      adapter.WebSocketOptions
	Edge           edge.Gate
	Capacity       gateway.ConnectionCapacity

	Clock                  gateway.Clock
	MaxReconnects          int
	ReconnectBackoff       time.Duration
	CapacityReleaseTimeout time.Duration

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
	edge      edge.Gate
}

// NewBrowser fails closed unless every caller-owned policy port, the Provider
// Browser resolver, and WebSocket handshake admission are supplied.
func NewBrowser(options BrowserOptions) (*BrowserService, error) {
	if options.FencedResolver != nil {
		return nil, fmt.Errorf("%w: downstream-fenced Browser resolver is not valid for the ordinary composition", ErrInvalidOptions)
	}
	return newBrowser(options, false)
}

// NewFencedBrowser composes only the explicit downstream-fenced Browser path.
// It rejects an ordinary resolver even when a fenced resolver is also present,
// preventing configuration from retaining a raw private-CDP bypass.
func NewFencedBrowser(options BrowserOptions) (*BrowserService, error) {
	if options.Resolver != nil {
		return nil, fmt.Errorf("%w: ordinary Browser resolver is not valid for the downstream-fenced composition", ErrInvalidOptions)
	}
	if nilDependency(options.FencedResolver) {
		return nil, fmt.Errorf("%w: downstream-fenced Browser resolver is required", ErrInvalidOptions)
	}
	return newBrowser(options, true)
}

func newBrowser(options BrowserOptions, requireDownstreamFencing bool) (*BrowserService, error) {
	for _, dependency := range []struct {
		name  string
		value any
	}{
		{"authorizer", options.Authorizer},
		{"revocations", options.Revocations},
		{"recorder", options.Recorder},
		{"WebSocket admission", options.WebSocket.Admission},
		{"public edge gate", options.Edge},
		{"authenticated connection capacity", options.Capacity},
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
	gatewayOptions := gateway.Options{
		Authorizer:  options.Authorizer,
		Revocations: options.Revocations, Recorder: options.Recorder,
		Clock: options.Clock, MaxReconnects: options.MaxReconnects,
		ReconnectBackoff:         options.ReconnectBackoff,
		Capacity:                 options.Capacity,
		CapacityReleaseTimeout:   options.CapacityReleaseTimeout,
		MaxConnections:           options.MaxConnections,
		MaxConnectionsPerSession: options.MaxConnectionsPerSession,
	}
	if requireDownstreamFencing {
		gatewayOptions.FencedResolver = browserFencedProviderResolver{
			resolver: options.FencedResolver, maxFrameBytes: options.WebSocket.MaxFrameBytes,
		}
		gatewayOptions.RequireDownstreamFencing = true
	} else {
		if nilDependency(options.Resolver) {
			return nil, fmt.Errorf("%w: Browser provider resolver is required", ErrInvalidOptions)
		}
		gatewayOptions.Resolver = browserProviderResolver{
			resolver: options.Resolver, maxFrameBytes: options.WebSocket.MaxFrameBytes,
		}
	}
	proxy, err := gateway.New(gatewayOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: Gateway: %w", ErrInvalidOptions, err)
	}
	return &BrowserService{gateway: proxy, webSocket: webSocket, edge: options.Edge}, nil
}

type browserFencedProviderResolver struct {
	resolver      BrowserFencedProviderResolver
	maxFrameBytes int64
}

func (r browserFencedProviderResolver) ResolveFenced(ctx context.Context, value string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (gateway.Endpoint, error) {
	if nilDependency(r.resolver) {
		return gateway.Endpoint{}, ErrUnavailable
	}
	endpoint, err := r.resolver.ResolveFenced(ctx, value, subject, fence)
	if err != nil {
		return gateway.Endpoint{}, err
	}
	return adaptBrowserEndpoint(endpoint, r.maxFrameBytes)
}

// Serve reserves caller-owned public-edge capacity before WebSocket admission
// and upgrade, then applies the supplied Browser identity. Request extraction
// and identity policy remain caller-owned.
func (s *BrowserService) Serve(ctx context.Context, response http.ResponseWriter, request *http.Request, connect gateway.ConnectRequest) error {
	if s == nil || s.webSocket == nil || s.edge == nil {
		return ErrUnavailable
	}
	if response == nil || request == nil {
		return adapter.ErrInvalidStream
	}
	lease, err := s.edge.Acquire(request.Context())
	if err != nil {
		return writeEdgeRejection(response, err)
	}
	if nilDependency(lease) {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return ErrUnavailable
	}
	defer lease.Release()
	client, err := s.webSocket.Upgrade(response, request)
	if err != nil {
		return err
	}
	return s.Connect(ctx, connect, client)
}

func writeEdgeRejection(response http.ResponseWriter, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, edge.ErrCapacityExhausted) || errors.Is(err, edge.ErrRateLimited) {
		retryAfter := edge.RetryAfter(err)
		if retryAfter <= 0 || retryAfter > edge.MaxWindow {
			retryAfter = time.Second
		}
		seconds := (retryAfter + time.Second - 1) / time.Second
		response.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
		http.Error(response, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return errors.Join(ErrEdgeRejected, err)
	}
	http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	return errors.Join(ErrUnavailable, err)
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
	if nilDependency(r.resolver) {
		return gateway.Endpoint{}, ErrUnavailable
	}
	endpoint, err := r.resolver.Resolve(ctx, value)
	if err != nil {
		return gateway.Endpoint{}, err
	}
	return adaptBrowserEndpoint(endpoint, r.maxFrameBytes)
}

func adaptBrowserEndpoint(endpoint browserreference.Endpoint, maxFrameBytes int64) (gateway.Endpoint, error) {
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
			return adapter.NewBrowserStream(stream, adapter.BrowserOptions{MaxFrameBytes: maxFrameBytes})
		},
	}, nil
}

var _ gateway.ReferenceResolver = browserProviderResolver{}
var _ gateway.FencedReferenceResolver = browserFencedProviderResolver{}
