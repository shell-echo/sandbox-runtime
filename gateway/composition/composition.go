// Package composition wires caller-owned Gateway policy to Provider terminal
// references and the bounded WebSocket adapters. It is not command startup or
// Provider transport composition.
package composition

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
)

var (
	ErrInvalidOptions = errors.New("invalid Runtime Gateway composition options")
	ErrUnavailable    = errors.New("Runtime Gateway composition is unavailable")
	ErrEdgeRejected   = errors.New("Browser public edge rejected request")
)

// ProviderResolver is the narrow Provider-side boundary used by this
// composition. The production implementation is reference.Resolver, which
// rechecks its durable registry and committed session handoff at Resolve and
// again at every Dial.
type ProviderResolver interface {
	Resolve(context.Context, string) (reference.Endpoint, error)
}

// Options contains every dependency needed to make the terminal Gateway
// usable. Authorization, revocation, recording, and WebSocket admission are
// caller-owned. This package deliberately supplies no defaults for them.
type Options struct {
	Authorizer  gateway.Authorizer
	Revocations gateway.RevocationSource
	Recorder    gateway.Recorder
	Resolver    ProviderResolver
	WebSocket   adapter.WebSocketOptions

	Clock            gateway.Clock
	MaxReconnects    int
	ReconnectBackoff time.Duration
}

// Service composes one bounded WebSocket edge with a caller-authorized
// Gateway. It does not parse platform identity, create Provider sessions, or
// expose an HTTP route by itself.
type Service struct {
	gateway   *gateway.Gateway
	webSocket *adapter.WebSocketServer
}

// New fails closed unless all caller-owned policy ports, the Provider resolver,
// and the WebSocket admission callback are supplied.
func New(options Options) (*Service, error) {
	for _, dependency := range []struct {
		name  string
		value any
	}{
		{"authorizer", options.Authorizer},
		{"revocations", options.Revocations},
		{"recorder", options.Recorder},
		{"provider resolver", options.Resolver},
		{"WebSocket admission", options.WebSocket.Admission},
	} {
		if nilDependency(dependency.value) {
			return nil, fmt.Errorf("%w: %s is required", ErrInvalidOptions, dependency.name)
		}
	}

	webSocket, err := adapter.NewWebSocketServer(options.WebSocket)
	if err != nil {
		return nil, fmt.Errorf("%w: WebSocket adapter: %w", ErrInvalidOptions, err)
	}
	proxy, err := gateway.New(gateway.Options{
		Authorizer:       options.Authorizer,
		Resolver:         providerResolver{resolver: options.Resolver, maxFrameBytes: options.WebSocket.MaxFrameBytes},
		Revocations:      options.Revocations,
		Recorder:         options.Recorder,
		Clock:            options.Clock,
		MaxReconnects:    options.MaxReconnects,
		ReconnectBackoff: options.ReconnectBackoff,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: Gateway: %w", ErrInvalidOptions, err)
	}
	return &Service{gateway: proxy, webSocket: webSocket}, nil
}

// Serve upgrades an already caller-admitted request, then authorizes and
// proxies the supplied caller-owned connection request. The caller continues
// to own request extraction and identity policy; this package never infers
// those fields from a Provider reference or a WebSocket request.
func (s *Service) Serve(ctx context.Context, w http.ResponseWriter, r *http.Request, request gateway.ConnectRequest) error {
	if s == nil || s.webSocket == nil {
		return ErrUnavailable
	}
	client, err := s.webSocket.Upgrade(w, r)
	if err != nil {
		return err
	}
	return s.Connect(ctx, request, client)
}

// Connect applies the composed Gateway policy to an already adapted caller
// stream. It is useful to a future transport root that has already performed
// the caller-owned handshake. The stream is closed when the connection ends,
// including early authorization or audit failures.
func (s *Service) Connect(ctx context.Context, request gateway.ConnectRequest, client gateway.Stream) error {
	if s == nil || s.gateway == nil || nilDependency(client) {
		return ErrUnavailable
	}
	defer func() { _ = client.Close(context.Background()) }()
	return s.gateway.Connect(ctx, request, client)
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	switch reflect.ValueOf(value).Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflect.ValueOf(value).IsNil()
	default:
		return false
	}
}

type providerResolver struct {
	resolver      ProviderResolver
	maxFrameBytes int64
}

func (r providerResolver) Resolve(ctx context.Context, value string) (gateway.Endpoint, error) {
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
		SandboxID: endpoint.SandboxID, RuntimeSessionID: endpoint.RuntimeSessionID,
		CapabilityProfileID: endpoint.CapabilityProfileID, ExpiresAt: endpoint.ExpiresAt.UTC(),
		Dial: func(dialCtx context.Context) (gateway.Stream, error) {
			stream, err := endpoint.Dial(dialCtx)
			if err != nil {
				return nil, err
			}
			if nilDependency(stream) {
				return nil, ErrUnavailable
			}
			return adapter.NewTerminalStream(stream, adapter.TerminalOptions{MaxFrameBytes: r.maxFrameBytes})
		},
	}, nil
}

var _ gateway.ReferenceResolver = providerResolver{}
