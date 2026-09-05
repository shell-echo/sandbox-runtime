package stack

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

var errReferenceUnavailable = errors.New("fixture Browser reference is unavailable")

type exactResolver struct {
	endpoints    map[string]wire.Endpoint
	observations *observationRecorder
}

func newExactResolver(endpoints []wire.Endpoint, observations *observationRecorder) *exactResolver {
	indexed := make(map[string]wire.Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		indexed[endpoint.HandoffReference] = endpoint
	}
	return &exactResolver{endpoints: indexed, observations: observations}
}

func (r *exactResolver) Resolve(ctx context.Context, reference string) (browserreference.Endpoint, error) {
	if r == nil || r.observations == nil || ctx == nil {
		return browserreference.Endpoint{}, errReferenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return browserreference.Endpoint{}, err
	}
	endpoint, ok := r.lookup(reference)
	binding, bound := ctx.Value(connectionContextKey{}).(connectionInput)
	if !ok || !bound || binding.request.HandoffReference != reference ||
		!endpointMatchesRequest(endpoint, binding.request) ||
		endpoint.ConnectionGeneration != binding.connectionGeneration ||
		!binding.expiresAt.After(time.Now().UTC()) {
		return browserreference.Endpoint{}, errReferenceUnavailable
	}
	if err := r.observations.record("resolve"); err != nil {
		return browserreference.Endpoint{}, errReferenceUnavailable
	}
	return browserreference.Endpoint{
		Reference: endpoint.HandoffReference, SandboxID: endpoint.SandboxID,
		BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
		ConnectionGeneration: endpoint.ConnectionGeneration, ExpiresAt: binding.expiresAt.UTC(),
		Dial: func(dialCtx context.Context) (providerbrowser.Stream, error) {
			fresh, exists := r.lookup(reference)
			if dialCtx == nil || !exists || !sameEndpoint(fresh, endpoint) || !binding.expiresAt.After(time.Now().UTC()) {
				return nil, errReferenceUnavailable
			}
			if err := dialCtx.Err(); err != nil {
				return nil, err
			}
			if err := r.observations.record("dial"); err != nil {
				return nil, errReferenceUnavailable
			}
			return newEchoStream(dialCtx), nil
		},
	}, nil
}

func (r *exactResolver) lookup(reference string) (wire.Endpoint, bool) {
	if r == nil {
		return wire.Endpoint{}, false
	}
	endpoint, ok := r.endpoints[reference]
	return endpoint, ok
}

func sameEndpoint(left, right wire.Endpoint) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID && left.SandboxID == right.SandboxID &&
		left.BrowserSessionID == right.BrowserSessionID && left.CapabilityProfileID == right.CapabilityProfileID &&
		left.HandoffReference == right.HandoffReference && left.ConnectionGeneration == right.ConnectionGeneration
}

func endpointMatchesRequest(endpoint wire.Endpoint, request gateway.ConnectRequest) bool {
	return endpoint.TenantID == request.TenantID && endpoint.SandboxID == request.SandboxID &&
		endpoint.BrowserSessionID == request.BrowserSessionID &&
		endpoint.CapabilityProfileID == request.CapabilityProfileID &&
		endpoint.HandoffReference == request.HandoffReference
}

type echoStream struct {
	connection net.Conn
	closeOnce  sync.Once
}

func newEchoStream(ctx context.Context) *echoStream {
	client, server := net.Pipe()
	go serveEcho(ctx, server)
	return &echoStream{connection: client}
}

func serveEcho(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	for {
		payload, operation, err := wsutil.ReadClientData(connection)
		if err != nil {
			return
		}
		if operation != ws.OpText && operation != ws.OpBinary {
			return
		}
		if err := wsutil.WriteServerMessage(connection, operation, payload); err != nil {
			return
		}
	}
}

func (s *echoStream) Read(ctx context.Context, target []byte) (int, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return 0, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = s.connection.SetReadDeadline(time.Now())
		close(callbackDone)
	})
	n, err := s.connection.Read(target)
	if !stop() {
		<-callbackDone
	}
	_ = s.connection.SetReadDeadline(time.Time{})
	if contextErr := ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

func (s *echoStream) Write(ctx context.Context, value []byte) (int, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return 0, io.ErrClosedPipe
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = s.connection.SetWriteDeadline(time.Now())
		close(callbackDone)
	})
	n, err := s.connection.Write(value)
	if !stop() {
		<-callbackDone
	}
	_ = s.connection.SetWriteDeadline(time.Time{})
	if contextErr := ctx.Err(); contextErr != nil {
		return n, contextErr
	}
	return n, err
}

func (s *echoStream) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() { err = s.connection.Close() })
	return err
}

var _ providerbrowser.Stream = (*echoStream)(nil)
