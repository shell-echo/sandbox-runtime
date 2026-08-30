package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// Clock makes expiry behavior deterministic without weakening the production
// default, which uses UTC wall time.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Options composes the Gateway from caller-owned policy and trusted opaque
// handoff adapters. No insecure default authorizer, resolver, or recorder is
// supplied by this package.
type Options struct {
	Authorizer       Authorizer
	Resolver         ReferenceResolver
	Revocations      RevocationSource
	Recorder         Recorder
	Clock            Clock
	MaxReconnects    int
	ReconnectBackoff time.Duration
}

type Gateway struct {
	authorizer       Authorizer
	resolver         ReferenceResolver
	revocations      RevocationSource
	recorder         Recorder
	clock            Clock
	maxReconnects    int
	reconnectBackoff time.Duration
}

func New(options Options) (*Gateway, error) {
	if options.Authorizer == nil || options.Resolver == nil || options.Revocations == nil || options.Recorder == nil {
		return nil, ErrProxyUnavailable
	}
	clock := options.Clock
	if clock == nil {
		clock = ClockFunc(func() time.Time { return time.Now().UTC() })
	}
	maxReconnects := options.MaxReconnects
	if maxReconnects == 0 {
		maxReconnects = MaxReconnectAttempts
	}
	if maxReconnects < 0 || maxReconnects > MaxReconnectAttempts {
		return nil, fmt.Errorf("%w: reconnect limit", ErrInvalidRequest)
	}
	backoff := options.ReconnectBackoff
	if backoff < 0 || backoff > MaxReconnectBackoff {
		return nil, fmt.Errorf("%w: reconnect backoff", ErrInvalidRequest)
	}
	return &Gateway{
		authorizer: options.Authorizer, resolver: options.Resolver,
		revocations: options.Revocations, recorder: options.Recorder,
		clock: clock, maxReconnects: maxReconnects, reconnectBackoff: backoff,
	}, nil
}

// Connect authorizes one user session and proxies opaque frames until the
// caller closes, the grant expires, or it is revoked. Provider disconnects
// are retried through a fresh reference resolution while retaining the same
// caller stream. The Gateway never exposes or interprets an endpoint address.
func (g *Gateway) Connect(ctx context.Context, request ConnectRequest, client Stream) error {
	if g == nil || client == nil {
		return ErrProxyUnavailable
	}
	if ctx == nil {
		return context.Canceled
	}
	if err := request.Validate(); err != nil {
		return err
	}
	now := g.clock.Now().UTC()
	if now.IsZero() {
		return ErrProxyUnavailable
	}
	grant, err := g.authorizer.Authorize(ctx, request)
	if err != nil {
		g.recordDenied(ctx, request, now, err)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return errors.Join(ErrUnauthorized, err)
	}
	if err := grant.Validate(now); err != nil || !grant.matches(request) {
		if err == nil {
			err = ErrUnauthorized
		}
		g.recordDenied(ctx, request, now, err)
		return errors.Join(ErrUnauthorized, err)
	}
	revoked, err := g.revocations.IsRevoked(ctx, grant.GrantID)
	if err != nil {
		g.recordDenied(ctx, request, now, err)
		return errors.Join(ErrProxyUnavailable, err)
	}
	if revoked {
		g.recordDenied(ctx, request, now, ErrRevoked)
		return ErrRevoked
	}
	watch, err := g.revocations.Watch(ctx, grant.GrantID)
	if err != nil {
		g.recordDenied(ctx, request, now, err)
		return errors.Join(ErrProxyUnavailable, err)
	}
	if watch == nil {
		return errors.Join(ErrProxyUnavailable, errors.New("revocation watcher is nil"))
	}
	if err := g.record(ctx, eventForGrant(grant, AuditAuthorized, now, 0, 0, 0, "")); err != nil {
		return errors.Join(ErrAuditUnavailable, err)
	}

	var reconnects int
	for {
		now = g.clock.Now().UTC()
		if !now.Before(grant.ExpiresAt) {
			_ = g.record(ctx, eventForGrant(grant, AuditExpired, now, reconnects, 0, 0, "grant expired"))
			_ = client.Close(context.Background())
			return ErrExpired
		}
		revoked, err = g.revocations.IsRevoked(ctx, grant.GrantID)
		if err != nil {
			_ = client.Close(context.Background())
			return errors.Join(ErrProxyUnavailable, err)
		}
		if revoked {
			_ = g.record(ctx, eventForGrant(grant, AuditRevoked, now, reconnects, 0, 0, "grant revoked"))
			_ = client.Close(context.Background())
			return ErrRevoked
		}

		endpoint, err := g.resolver.Resolve(ctx, grant.HandoffReference)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				_ = client.Close(context.Background())
				return err
			}
			if reconnects == 0 {
				_ = g.record(ctx, eventForGrant(grant, AuditReconnectFailed, now, reconnects, 0, 0, "handoff resolution failed"))
				_ = client.Close(context.Background())
				return errors.Join(ErrReferenceUnavailable, err)
			}
			if reconnects >= g.maxReconnects {
				_ = g.record(ctx, eventForGrant(grant, AuditReconnectFailed, now, reconnects, 0, 0, "handoff resolution failed"))
				_ = client.Close(context.Background())
				return errors.Join(ErrReconnectExhausted, err)
			}
			if err := g.waitReconnect(ctx, grant.ExpiresAt); err != nil {
				return err
			}
			reconnects++
			continue
		}
		if err := validateEndpoint(endpoint, grant, now); err != nil {
			_ = client.Close(context.Background())
			return err
		}
		backend, err := endpoint.Dial(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				_ = client.Close(context.Background())
				return err
			}
			if reconnects >= g.maxReconnects {
				_ = g.record(ctx, eventForGrant(grant, AuditReconnectFailed, now, reconnects, 0, 0, "backend dial failed"))
				_ = client.Close(context.Background())
				return errors.Join(ErrReconnectExhausted, err)
			}
			if err := g.waitReconnect(ctx, grant.ExpiresAt); err != nil {
				return err
			}
			reconnects++
			continue
		}
		if backend == nil {
			_ = client.Close(context.Background())
			return errors.Join(ErrReferenceUnavailable, errors.New("resolver returned nil backend stream"))
		}

		if err := g.record(ctx, eventForGrant(grant, connectedEvent(reconnects), now, reconnects, 0, 0, "")); err != nil {
			_ = backend.Close(context.Background())
			_ = client.Close(context.Background())
			return errors.Join(ErrAuditUnavailable, err)
		}
		result := g.proxyAttempt(ctx, client, backend, grant, watch)
		_ = backend.Close(context.Background())
		switch {
		case result.revoked:
			_ = g.record(ctx, eventForGrant(grant, AuditRevoked, g.clock.Now().UTC(), reconnects, result.frames, result.bytes, "grant revoked"))
			_ = client.Close(context.Background())
			return ErrRevoked
		case result.expired:
			_ = g.record(ctx, eventForGrant(grant, AuditExpired, g.clock.Now().UTC(), reconnects, result.frames, result.bytes, "grant expired"))
			_ = client.Close(context.Background())
			return ErrExpired
		case result.clientClosed:
			if err := g.record(ctx, eventForGrant(grant, AuditClientClosed, g.clock.Now().UTC(), reconnects, result.frames, result.bytes, "client closed")); err != nil {
				return errors.Join(ErrAuditUnavailable, err)
			}
			return nil
		case result.backendClosed:
			if err := g.record(ctx, eventForGrant(grant, AuditBackendClosed, g.clock.Now().UTC(), reconnects, result.frames, result.bytes, "backend disconnected")); err != nil {
				_ = client.Close(context.Background())
				return errors.Join(ErrAuditUnavailable, err)
			}
			if reconnects >= g.maxReconnects {
				_ = g.record(ctx, eventForGrant(grant, AuditReconnectFailed, g.clock.Now().UTC(), reconnects, result.frames, result.bytes, "reconnect limit reached"))
				_ = client.Close(context.Background())
				return ErrReconnectExhausted
			}
			if err := g.waitReconnect(ctx, grant.ExpiresAt); err != nil {
				return err
			}
			reconnects++
			continue
		default:
			_ = client.Close(context.Background())
			if result.err != nil && (errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded)) {
				return result.err
			}
			return errors.Join(ErrProxyUnavailable, result.err)
		}
	}
}

func (g *Gateway) waitReconnect(ctx context.Context, expiresAt time.Time) error {
	if !expiresAt.After(g.clock.Now().UTC()) {
		return ErrExpired
	}
	if g.reconnectBackoff == 0 {
		return nil
	}
	timer := time.NewTimer(g.reconnectBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if !expiresAt.After(g.clock.Now().UTC()) {
			return ErrExpired
		}
		return nil
	}
}

type streamSide uint8

const (
	clientSide streamSide = iota + 1
	backendSide
)

type transferResult struct {
	side   streamSide
	err    error
	frames uint64
	bytes  uint64
}

type proxyResult struct {
	clientClosed  bool
	backendClosed bool
	revoked       bool
	expired       bool
	err           error
	frames        uint64
	bytes         uint64
}

func (g *Gateway) proxyAttempt(ctx context.Context, client, backend Stream, grant Grant, watch <-chan struct{}) proxyResult {
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var revoked atomic.Bool
	var expired atomic.Bool
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		expiresIn := grant.ExpiresAt.Sub(g.clock.Now().UTC())
		if expiresIn <= 0 {
			expired.Store(true)
			cancel()
			_ = client.Close(context.Background())
			_ = backend.Close(context.Background())
			return
		}
		timer := time.NewTimer(expiresIn)
		defer timer.Stop()
		select {
		case <-watch:
			revoked.Store(true)
			cancel()
			_ = client.Close(context.Background())
			_ = backend.Close(context.Background())
		case <-timer.C:
			expired.Store(true)
			cancel()
			_ = client.Close(context.Background())
			_ = backend.Close(context.Background())
		case <-attemptCtx.Done():
		}
	}()

	results := make(chan transferResult, 2)
	go transfer(attemptCtx, clientSide, client, backend, results)
	go transfer(attemptCtx, backendSide, backend, client, results)
	first := <-results
	cancel()
	_ = backend.Close(context.Background())
	<-monitorDone
	second := <-results
	result := proxyResult{revoked: revoked.Load(), expired: expired.Load(), err: first.err}
	result.frames = first.frames + second.frames
	result.bytes = first.bytes + second.bytes
	if result.revoked || result.expired {
		return result
	}
	if ctx.Err() != nil {
		result.err = ctx.Err()
		return result
	}
	// The first completed transfer determines why this attempt ended. The
	// second transfer is normally unblocked by cancellation and therefore may
	// report context.Canceled even when the backend was the original failure.
	if first.side == clientSide {
		result.clientClosed = true
		return result
	}
	if first.side == backendSide {
		result.backendClosed = true
		return result
	}
	return result
}

func transfer(ctx context.Context, source streamSide, src, dst Stream, results chan<- transferResult) {
	var result transferResult
	for {
		frame, err := src.Receive(ctx)
		if err != nil {
			result.side, result.err = source, err
			results <- result
			return
		}
		if err := dst.Send(ctx, frame.Clone()); err != nil {
			result.side, result.err = oppositeSide(source), err
			results <- result
			return
		}
		result.frames++
		result.bytes += uint64(len(frame.Payload))
	}
}

func oppositeSide(side streamSide) streamSide {
	if side == clientSide {
		return backendSide
	}
	return clientSide
}

func validateEndpoint(endpoint Endpoint, grant Grant, now time.Time) error {
	if endpoint.Reference != grant.HandoffReference || !referencePattern.MatchString(endpoint.Reference) {
		return ErrReferenceUnavailable
	}
	if endpoint.ConnectionGeneration != grant.ConnectionGeneration {
		return ErrStaleReference
	}
	if endpoint.Dial == nil {
		return ErrReferenceUnavailable
	}
	if endpoint.ExpiresAt.IsZero() || !endpoint.ExpiresAt.After(now) {
		return ErrExpired
	}
	if grant.ExpiresAt.After(endpoint.ExpiresAt) {
		return ErrStaleReference
	}
	return nil
}

func connectedEvent(reconnects int) AuditEventType {
	if reconnects == 0 {
		return AuditConnected
	}
	return AuditReconnected
}

func eventForGrant(grant Grant, eventType AuditEventType, at time.Time, attempt int, frames, bytes uint64, reason string) AuditEvent {
	return AuditEvent{
		Type: eventType, At: at, GrantID: grant.GrantID, CallerID: grant.CallerID,
		TenantID: grant.TenantID, SandboxID: grant.SandboxID, RuntimeSessionID: grant.RuntimeSessionID,
		ConnectionGeneration: grant.ConnectionGeneration, Attempt: attempt, Frames: frames, Bytes: bytes, Reason: reason,
	}
}

func (g *Gateway) record(ctx context.Context, event AuditEvent) error {
	if event.At.IsZero() {
		event.At = g.clock.Now().UTC()
	}
	return g.recorder.Record(ctx, event)
}

func (g *Gateway) recordDenied(ctx context.Context, request ConnectRequest, at time.Time, reason error) {
	_ = g.recorder.Record(ctx, AuditEvent{
		Type: AuditDenied, At: at, CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID, Reason: reason.Error(),
	})
}
