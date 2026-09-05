package gateway

import (
	"context"
	"errors"
	"fmt"
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
	Capacity         ConnectionCapacity

	// CapacityReleaseTimeout bounds the independent cleanup context used to
	// release an acquired external capacity lease after the connection ends.
	CapacityReleaseTimeout time.Duration

	// MaxConnections and MaxConnectionsPerSession enable a non-blocking,
	// process-local capacity bound when both are non-zero. Capacity is the
	// separate post-authorization authority used for tenant-aware policy.
	MaxConnections           int
	MaxConnectionsPerSession int
}

type Gateway struct {
	authorizer             Authorizer
	resolver               ReferenceResolver
	revocations            RevocationSource
	recorder               Recorder
	clock                  Clock
	maxReconnects          int
	reconnectBackoff       time.Duration
	capacity               *connectionCapacity
	authenticatedCapacity  ConnectionCapacity
	capacityReleaseTimeout time.Duration
}

func New(options Options) (*Gateway, error) {
	if options.Authorizer == nil || options.Resolver == nil || options.Revocations == nil || options.Recorder == nil ||
		isTypedNil(options.Revocations) {
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
	if options.Capacity != nil && isTypedNil(options.Capacity) {
		return nil, fmt.Errorf("%w: connection capacity", ErrProxyUnavailable)
	}
	capacityReleaseTimeout := options.CapacityReleaseTimeout
	if capacityReleaseTimeout == 0 {
		capacityReleaseTimeout = DefaultCapacityReleaseTimeout
	}
	if capacityReleaseTimeout < MinCapacityReleaseTimeout || capacityReleaseTimeout > MaxCapacityReleaseTimeout {
		return nil, fmt.Errorf("%w: capacity release timeout", ErrInvalidRequest)
	}
	capacity, err := newConnectionCapacity(options.MaxConnections, options.MaxConnectionsPerSession)
	if err != nil {
		return nil, fmt.Errorf("%w: connection capacity", err)
	}
	return &Gateway{
		authorizer: options.Authorizer, resolver: options.Resolver,
		revocations: options.Revocations, recorder: options.Recorder,
		clock: clock, maxReconnects: maxReconnects, reconnectBackoff: backoff,
		capacity: capacity, authenticatedCapacity: options.Capacity,
		capacityReleaseTimeout: capacityReleaseTimeout,
	}, nil
}

// Connect authorizes one user session and proxies opaque frames until the
// caller closes, the grant expires, or it is revoked. Provider disconnects
// are retried through a fresh reference resolution while retaining the same
// caller stream. The Gateway never exposes or interprets an endpoint address.
func (g *Gateway) Connect(ctx context.Context, request ConnectRequest, client Stream) (resultErr error) {
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
	releaseLocal, err := g.capacity.acquire(grant)
	if err != nil {
		_ = g.record(ctx, eventForGrant(grant, AuditCapacityRejected, now, 0, 0, 0, "connection capacity exhausted"))
		return err
	}
	defer releaseLocal()
	if g.authenticatedCapacity != nil {
		lease, err := g.authenticatedCapacity.Acquire(ctx, capacitySubjectForGrant(grant))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, ErrCapacityExhausted) {
				_ = g.record(ctx, eventForGrant(grant, AuditCapacityRejected, now, 0, 0, 0, "authenticated connection capacity exhausted"))
				return err
			}
			_ = g.record(ctx, eventForGrant(grant, AuditCapacityUnavailable, now, 0, 0, 0, "connection capacity unavailable"))
			return errors.Join(ErrCapacityUnavailable, err)
		}
		if lease == nil || isTypedNil(lease) {
			_ = g.record(ctx, eventForGrant(grant, AuditCapacityUnavailable, now, 0, 0, 0, "connection capacity lease unavailable"))
			return ErrCapacityUnavailable
		}
		events := lease.Events()
		if err := initialCapacityEventError(events); err != nil {
			resultErr = err
			g.finishCapacityLease(grant, lease, &resultErr)
			return resultErr
		}
		capacityCtx, cancelCapacity, monitorDone := monitorCapacityEvents(ctx, events)
		ctx = capacityCtx
		defer func() {
			cancelCapacity(context.Canceled)
			<-monitorDone
			g.finishCapacityLease(grant, lease, &resultErr)
		}()
		if err := capacityContextError(ctx); err != nil {
			return err
		}
	}
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watch, err := g.revocations.Watch(watchCtx, revocationSubjectForGrant(grant))
	if err != nil {
		result := g.revocationSetupError(ctx, grant.ExpiresAt, err)
		g.recordAuthorityTermination(grant, result, 0, 0, 0)
		return result
	}
	if watch == nil || isTypedNil(watch) || watch.Done() == nil {
		result := g.revocationSetupError(ctx, grant.ExpiresAt, errors.New("revocation watcher is unavailable"))
		g.recordAuthorityTermination(grant, result, 0, 0, 0)
		return result
	}
	if authorityErr := g.authorityError(ctx, watch, grant.ExpiresAt); authorityErr != nil {
		g.recordAuthorityTermination(grant, authorityErr, 0, 0, 0)
		return authorityErr
	}
	authorityCtx, cancelAuthority, authorityMonitorDone := monitorRevocationWatch(ctx, watch)
	ctx = authorityCtx
	defer func() {
		cancelAuthority(context.Canceled)
		<-authorityMonitorDone
	}()
	if err := g.record(ctx, eventForGrant(grant, AuditAuthorized, now, 0, 0, 0, "")); err != nil {
		return errors.Join(ErrAuditUnavailable, err)
	}

	var reconnects int
	for {
		if authorityErr := g.authorityError(ctx, watch, grant.ExpiresAt); authorityErr != nil {
			g.recordAuthorityTermination(grant, authorityErr, reconnects, 0, 0)
			_ = client.Close(context.Background())
			return authorityErr
		}
		now = g.clock.Now().UTC()

		endpoint, err := g.resolver.Resolve(ctx, grant.HandoffReference)
		if authorityErr := g.authorityError(ctx, watch, grant.ExpiresAt); authorityErr != nil {
			g.recordAuthorityTermination(grant, authorityErr, reconnects, 0, 0)
			_ = client.Close(context.Background())
			return authorityErr
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				_ = client.Close(context.Background())
				return contextResult(ctx, err)
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
			if err := g.waitReconnect(ctx, watch, grant.ExpiresAt); err != nil {
				g.recordAuthorityTermination(grant, err, reconnects, 0, 0)
				_ = client.Close(context.Background())
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
		if authorityErr := g.authorityError(ctx, watch, grant.ExpiresAt); authorityErr != nil {
			g.recordAuthorityTermination(grant, authorityErr, reconnects, 0, 0)
			if backend != nil {
				_ = backend.Close(context.Background())
			}
			_ = client.Close(context.Background())
			return authorityErr
		}
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				_ = client.Close(context.Background())
				return contextResult(ctx, err)
			}
			if reconnects >= g.maxReconnects {
				_ = g.record(ctx, eventForGrant(grant, AuditReconnectFailed, now, reconnects, 0, 0, "backend dial failed"))
				_ = client.Close(context.Background())
				return errors.Join(ErrReconnectExhausted, err)
			}
			if err := g.waitReconnect(ctx, watch, grant.ExpiresAt); err != nil {
				g.recordAuthorityTermination(grant, err, reconnects, 0, 0)
				_ = client.Close(context.Background())
				return err
			}
			reconnects++
			continue
		}
		if backend == nil {
			_ = client.Close(context.Background())
			return errors.Join(ErrReferenceUnavailable, errors.New("resolver returned nil backend stream"))
		}
		if authorityErr := g.authorityError(ctx, watch, grant.ExpiresAt); authorityErr != nil {
			g.recordAuthorityTermination(grant, authorityErr, reconnects, 0, 0)
			_ = backend.Close(context.Background())
			_ = client.Close(context.Background())
			return authorityErr
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
			g.recordAuthorityTermination(grant, ErrRevoked, reconnects, result.frames, result.bytes)
			_ = client.Close(context.Background())
			return ErrRevoked
		case result.expired:
			g.recordAuthorityTermination(grant, ErrExpired, reconnects, result.frames, result.bytes)
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
			if err := g.waitReconnect(ctx, watch, grant.ExpiresAt); err != nil {
				g.recordAuthorityTermination(grant, err, reconnects, result.frames, result.bytes)
				_ = client.Close(context.Background())
				return err
			}
			reconnects++
			continue
		default:
			_ = client.Close(context.Background())
			if authorityErr := g.authorityError(ctx, watch, grant.ExpiresAt); authorityErr != nil {
				g.recordAuthorityTermination(grant, authorityErr, reconnects, result.frames, result.bytes)
				return authorityErr
			}
			if result.err != nil && (errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded)) {
				return result.err
			}
			return errors.Join(ErrProxyUnavailable, result.err)
		}
	}
}

func monitorCapacityEvents(parent context.Context, events <-chan CapacityEvent) (context.Context, context.CancelCauseFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancelCause(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case event, open := <-events:
			cancel(capacityEventError(event, open))
		case <-ctx.Done():
		}
	}()
	return ctx, cancel, done
}

func capacityContextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	cause := context.Cause(ctx)
	if errors.Is(cause, ErrCapacityUnavailable) {
		return cause
	}
	return nil
}

func contextResult(ctx context.Context, fallback error) error {
	if capacityErr := capacityContextError(ctx); capacityErr != nil {
		return capacityErr
	}
	return fallback
}

func monitorRevocationWatch(parent context.Context, watch RevocationWatch) (context.Context, context.CancelCauseFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancelCause(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-watch.Done():
			cancel(revocationWatchError(watch))
		case <-ctx.Done():
		}
	}()
	return ctx, cancel, done
}

func revocationWatchError(watch RevocationWatch) error {
	if watch == nil || isTypedNil(watch) || watch.Done() == nil {
		return ErrRevocationUnavailable
	}
	select {
	case <-watch.Done():
		err := watch.Err()
		switch err {
		case ErrRevoked:
			return ErrRevoked
		case context.Canceled, context.DeadlineExceeded:
			return err
		case ErrRevocationUnavailable:
			return err
		default:
			return ErrRevocationUnavailable
		}
	default:
		return nil
	}
}

func (g *Gateway) revocationSetupError(ctx context.Context, expiresAt time.Time, sourceErr error) error {
	if !g.clock.Now().UTC().Before(expiresAt) {
		return ErrExpired
	}
	if capacityErr := capacityContextError(ctx); capacityErr != nil {
		return capacityErr
	}
	if ctx != nil && ctx.Err() != nil &&
		(errors.Is(sourceErr, context.Canceled) || errors.Is(sourceErr, context.DeadlineExceeded)) {
		return ctx.Err()
	}
	return errors.Join(ErrProxyUnavailable, ErrRevocationUnavailable)
}

func (g *Gateway) authorityError(ctx context.Context, watch RevocationWatch, expiresAt time.Time) error {
	revocationErr := revocationWatchError(watch)
	if errors.Is(revocationErr, ErrRevoked) {
		return ErrRevoked
	}
	if !g.clock.Now().UTC().Before(expiresAt) {
		return ErrExpired
	}
	if capacityErr := capacityContextError(ctx); capacityErr != nil {
		return capacityErr
	}
	if revocationErr != nil {
		if errors.Is(revocationErr, context.Canceled) || errors.Is(revocationErr, context.DeadlineExceeded) {
			return revocationErr
		}
		return errors.Join(ErrProxyUnavailable, ErrRevocationUnavailable, revocationErr)
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (g *Gateway) recordAuthorityTermination(grant Grant, err error, attempt int, frames, bytes uint64) {
	switch {
	case errors.Is(err, ErrRevoked):
		g.recordBoundedEvent(eventForGrant(grant, AuditRevoked, g.clock.Now().UTC(), attempt, frames, bytes, "grant revoked"))
	case errors.Is(err, ErrExpired):
		g.recordBoundedEvent(eventForGrant(grant, AuditExpired, g.clock.Now().UTC(), attempt, frames, bytes, "grant expired"))
	case errors.Is(err, ErrRevocationUnavailable):
		g.recordBoundedEvent(eventForGrant(grant, AuditRevocationUnavailable, g.clock.Now().UTC(), attempt, frames, bytes, "revocation authority unavailable"))
	}
}

func (g *Gateway) finishCapacityLease(grant Grant, lease ConnectionLease, resultErr *error) {
	if resultErr == nil {
		return
	}
	if eventType := capacityAuditType(*resultErr); eventType != "" {
		reason := "connection capacity unavailable"
		if eventType == AuditCapacityLost {
			reason = "connection capacity lease lost"
		}
		g.recordBoundedEvent(eventForGrant(grant, eventType, g.clock.Now().UTC(), 0, 0, 0, reason))
	}
	releaseCtx, cancel := context.WithTimeout(context.Background(), g.capacityReleaseTimeout)
	releaseErr := lease.Release(releaseCtx)
	cancel()
	if releaseErr == nil {
		return
	}
	*resultErr = errors.Join(*resultErr, ErrCapacityUnavailable, releaseErr)
	g.recordBoundedEvent(eventForGrant(grant, AuditCapacityReleaseFailed, g.clock.Now().UTC(), 0, 0, 0, "connection capacity lease release failed"))
}

func (g *Gateway) recordBoundedEvent(event AuditEvent) {
	recordCtx, cancel := context.WithTimeout(context.Background(), g.capacityReleaseTimeout)
	defer cancel()
	_ = g.record(recordCtx, event)
}

func (g *Gateway) waitReconnect(ctx context.Context, watch RevocationWatch, expiresAt time.Time) error {
	if err := g.authorityError(ctx, watch, expiresAt); err != nil {
		return err
	}
	if g.reconnectBackoff == 0 {
		return nil
	}
	timer := time.NewTimer(g.reconnectBackoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return g.authorityError(ctx, watch, expiresAt)
	case <-watch.Done():
		return g.authorityError(ctx, watch, expiresAt)
	case <-timer.C:
		return g.authorityError(ctx, watch, expiresAt)
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

func (g *Gateway) proxyAttempt(ctx context.Context, client, backend Stream, grant Grant, watch RevocationWatch) proxyResult {
	attemptCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan transferResult, 2)
	go transfer(attemptCtx, clientSide, client, backend, results)
	go transfer(attemptCtx, backendSide, backend, client, results)

	expiresIn := grant.ExpiresAt.Sub(g.clock.Now().UTC())
	var expiry <-chan time.Time
	var timer *time.Timer
	expired := expiresIn <= 0
	if !expired {
		timer = time.NewTimer(expiresIn)
		expiry = timer.C
		defer timer.Stop()
	}

	var first transferResult
	haveFirst := false
	revoked := false
	if !expired {
		select {
		case first = <-results:
			haveFirst = true
		case <-watch.Done():
			revoked = true
		case <-expiry:
			expired = true
		case <-ctx.Done():
		}
	}

	// Resolve simultaneously ready authority signals with one stable priority.
	// A confirmed revocation outranks expiry, which outranks capacity loss.
	revocationErr := revocationWatchError(watch)
	revoked = errors.Is(revocationErr, ErrRevoked)
	if !expired && expiry != nil {
		select {
		case <-expiry:
			expired = true
		default:
		}
	}
	if !expired {
		expired = !g.clock.Now().UTC().Before(grant.ExpiresAt)
	}
	capacityErr := capacityContextError(ctx)
	authorityStopped := revocationErr != nil || expired || capacityErr != nil || (!haveFirst && ctx.Err() != nil)
	cancel()
	_ = backend.Close(context.Background())
	if authorityStopped {
		_ = client.Close(context.Background())
	}
	if !haveFirst {
		first = <-results
	}
	second := <-results
	result := proxyResult{revoked: revoked, expired: expired, err: first.err}
	result.frames = first.frames + second.frames
	result.bytes = first.bytes + second.bytes
	if result.revoked || result.expired {
		return result
	}
	if capacityErr != nil {
		result.err = capacityErr
		return result
	}
	if revocationErr != nil {
		if errors.Is(revocationErr, context.Canceled) || errors.Is(revocationErr, context.DeadlineExceeded) {
			result.err = revocationErr
		} else {
			result.err = errors.Join(ErrProxyUnavailable, ErrRevocationUnavailable, revocationErr)
		}
		return result
	}
	if ctx.Err() != nil {
		result.err = contextResult(ctx, ctx.Err())
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
	request := ConnectRequest{RuntimeSessionID: grant.RuntimeSessionID, BrowserSessionID: grant.BrowserSessionID, HandoffReference: endpoint.Reference}
	if endpoint.Reference != grant.HandoffReference || !request.validReference() {
		return ErrReferenceUnavailable
	}
	if endpoint.SandboxID != grant.SandboxID || endpoint.RuntimeSessionID != grant.RuntimeSessionID ||
		endpoint.BrowserSessionID != grant.BrowserSessionID || endpoint.CapabilityProfileID != grant.CapabilityProfileID {
		return ErrStaleReference
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
		BrowserSessionID:     grant.BrowserSessionID,
		ConnectionGeneration: grant.ConnectionGeneration, Attempt: attempt, Frames: frames, Bytes: bytes, Reason: reason,
	}
}

func revocationSubjectForGrant(grant Grant) RevocationSubject {
	return RevocationSubject{GrantID: grant.GrantID, ExpiresAt: grant.ExpiresAt.UTC()}
}

func (g *Gateway) record(ctx context.Context, event AuditEvent) error {
	if event.At.IsZero() {
		event.At = g.clock.Now().UTC()
	}
	return g.recorder.Record(ctx, event)
}

func (g *Gateway) recordDenied(ctx context.Context, request ConnectRequest, at time.Time, reason error) {
	boundedReason := "caller authorization denied"
	if errors.Is(reason, ErrRevoked) {
		boundedReason = "grant revoked"
	}
	_ = g.recorder.Record(ctx, AuditEvent{
		Type: AuditDenied, At: at, CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID,
		BrowserSessionID: request.BrowserSessionID, Reason: boundedReason,
	})
}
