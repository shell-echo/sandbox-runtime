// Package cdpfence implements the private Browser action-ingress state machine.
// It must be deployed as the unique path to one Browser session's Chromium
// upstream; constructing a second bypass path invalidates its fencing guarantee.
package cdpfence

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	DefaultActionTimeout  = 5 * time.Second
	DefaultCloseTimeout   = 5 * time.Second
	DefaultMaxSessions    = 1_000
	DefaultMaxActionBytes = 32 << 10
	MaxActionBytes        = 64 << 10
	MinOperationTimeout   = 50 * time.Millisecond
	MaxOperationTimeout   = 30 * time.Second
	MaxSessions           = 10_000
)

type Options struct {
	Authority      gateway.DownstreamFenceAuthority
	ActionTimeout  time.Duration
	CloseTimeout   time.Duration
	MaxSessions    int
	MaxActionBytes int64
}

// DownstreamDial opens the ingress-owned Chromium upstream only after the
// exact claim has been admitted. No direct Gateway path may reach that upstream.
type DownstreamDial func(context.Context) (gateway.Stream, error)

// Ingress serializes activation and every accepted action for one exact
// Browser session. The authority's successful decision is the admission
// linearization point; the downstream write remains inside the same gate.
type Ingress struct {
	authority      gateway.DownstreamFenceAuthority
	actionTimeout  time.Duration
	closeTimeout   time.Duration
	maxSessions    int
	maxActionBytes int64

	mu       sync.Mutex
	sessions map[sessionKey]*sessionState
}

type sessionKey struct {
	tenantID         string
	sandboxID        string
	browserSessionID string
}

type sessionState struct {
	gate   chan struct{}
	refs   int // protected by Ingress.mu
	active *Stream
}

func New(options Options) (*Ingress, error) {
	if nilDependency(options.Authority) {
		return nil, gateway.ErrDownstreamUnavailable
	}
	actionTimeout, err := operationTimeout(options.ActionTimeout, DefaultActionTimeout)
	if err != nil {
		return nil, err
	}
	closeTimeout, err := operationTimeout(options.CloseTimeout, DefaultCloseTimeout)
	if err != nil {
		return nil, err
	}
	maxSessions := options.MaxSessions
	if maxSessions == 0 {
		maxSessions = DefaultMaxSessions
	}
	if maxSessions < 1 || maxSessions > MaxSessions {
		return nil, gateway.ErrDownstreamUnavailable
	}
	maxActionBytes := options.MaxActionBytes
	if maxActionBytes == 0 {
		maxActionBytes = DefaultMaxActionBytes
	}
	if maxActionBytes < 1 || maxActionBytes > MaxActionBytes {
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &Ingress{
		authority: options.Authority, actionTimeout: actionTimeout,
		closeTimeout: closeTimeout, maxSessions: maxSessions, maxActionBytes: maxActionBytes,
		sessions: make(map[sessionKey]*sessionState),
	}, nil
}

// Open validates and activates a claim before dialing the unique upstream.
// A higher activation closes the previous stream before the replacement dial;
// a duplicate active claim and every stale or unavailable decision fail closed.
func (i *Ingress) Open(ctx context.Context, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence, dial DownstreamDial) (*Stream, error) {
	if i == nil || i.authority == nil || dial == nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := subject.Validate(); err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	if err := fence.Validate(); err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	key := keyForSubject(subject)
	state, err := i.retainState(key)
	if err != nil {
		return nil, err
	}
	releasePending := true
	defer func() {
		if releasePending {
			i.releaseReference(key, state)
		}
	}()

	operationCtx, cancel := context.WithTimeout(ctx, i.actionTimeout)
	defer cancel()
	if err := lockSession(operationCtx, state); err != nil {
		return nil, boundedContextError(ctx)
	}
	defer unlockSession(state)

	decision, err := i.authority.AuthorizeAction(operationCtx, subject, fence, i.actionTimeout)
	if err != nil {
		return nil, boundedAuthorityError(operationCtx, ctx, err)
	}
	if state.active != nil {
		if sameFence(state.active.fence, fence) || !decision.Activated {
			return nil, gateway.ErrDownstreamUnavailable
		}
		previous := state.active
		previous.closeLocked(operationCtx, gateway.ErrDownstreamFenceLost)
		if state.active == previous {
			// Never open a second Chromium upstream when the previous one could
			// not be confirmed closed.
			return nil, gateway.ErrDownstreamUnavailable
		}
	}

	downstream, dialErr := dial(operationCtx)
	if dialErr != nil || nilDependency(downstream) {
		if !nilDependency(downstream) {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), i.closeTimeout)
			_ = downstream.Close(closeCtx)
			closeCancel()
		}
		return nil, gateway.ErrDownstreamUnavailable
	}
	stream := &Stream{
		ingress: i, state: state, key: key, subject: subject,
		fence: fence, downstream: downstream,
	}
	state.active = stream
	releasePending = false
	return stream, nil
}

// Stream is the only downstream stream a fenced Gateway may receive. Receive
// drops responses from a replaced stream. Send is the complete CDP action
// boundary and never exposes private authority or upstream diagnostics.
type Stream struct {
	ingress    *Ingress
	state      *sessionState
	key        sessionKey
	subject    gateway.DownstreamFenceSubject
	fence      gateway.DownstreamFence
	downstream gateway.Stream

	closed           bool  // protected by state.gate
	downstreamClosed bool  // protected by state.gate
	terminalErr      error // protected by state.gate
	refReleased      bool  // protected by state.gate
}

func (s *Stream) Receive(ctx context.Context) (gateway.Frame, error) {
	if s == nil || s.ingress == nil || s.state == nil || nilDependency(s.downstream) {
		return gateway.Frame{}, gateway.ErrDownstreamUnavailable
	}
	if err := contextError(ctx); err != nil {
		return gateway.Frame{}, err
	}
	frame, receiveErr := s.downstream.Receive(ctx)
	if err := lockSession(ctx, s.state); err != nil {
		return gateway.Frame{}, err
	}
	defer unlockSession(s.state)
	if s.terminalErr != nil {
		return gateway.Frame{}, s.terminalErr
	}
	if s.closed || s.state.active != s {
		return gateway.Frame{}, gateway.ErrDownstreamFenceLost
	}
	if receiveErr != nil {
		return gateway.Frame{}, receiveErr
	}
	return frame.Clone(), nil
}

func (s *Stream) Send(ctx context.Context, frame gateway.Frame) error {
	if s == nil || s.ingress == nil || s.state == nil || nilDependency(s.downstream) {
		return gateway.ErrDownstreamUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if (frame.Type != gateway.TextFrame && frame.Type != gateway.BinaryFrame) ||
		int64(len(frame.Payload)) > s.ingress.maxActionBytes {
		return gateway.ErrDownstreamUnavailable
	}
	buffered := frame.Clone()
	operationCtx, cancel := context.WithTimeout(ctx, s.ingress.actionTimeout)
	defer cancel()
	if err := lockSession(operationCtx, s.state); err != nil {
		return boundedContextError(ctx)
	}
	defer unlockSession(s.state)
	if s.terminalErr != nil {
		return s.terminalErr
	}
	if s.closed || s.state.active != s {
		return gateway.ErrDownstreamFenceLost
	}
	decision, err := s.ingress.authority.AuthorizeAction(operationCtx, s.subject, s.fence, s.ingress.actionTimeout)
	if err != nil {
		bounded := boundedAuthorityError(operationCtx, ctx, err)
		s.closeLocked(operationCtx, bounded)
		return bounded
	}
	if decision.Activated {
		// An already active local stream cannot legitimately activate itself
		// again. Treat missing or rolled-back shared history as unavailable.
		s.closeLocked(operationCtx, gateway.ErrDownstreamUnavailable)
		return gateway.ErrDownstreamUnavailable
	}
	if err := s.downstream.Send(operationCtx, buffered); err != nil {
		s.closeLocked(operationCtx, gateway.ErrDownstreamUnavailable)
		return gateway.ErrDownstreamUnavailable
	}
	return nil
}

func (s *Stream) Close(ctx context.Context) error {
	if s == nil || s.ingress == nil || s.state == nil {
		return gateway.ErrDownstreamUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.ingress.closeTimeout)
	defer cancel()
	if err := lockSession(operationCtx, s.state); err != nil {
		return boundedContextError(ctx)
	}
	defer unlockSession(s.state)
	return s.closeLocked(operationCtx, nil)
}

// closeLocked logically terminates a stream and releases its session reference
// only after the downstream confirms closure. A failed close may be retried.
// reason is the fixed terminal result exposed to Receive or a later Send.
func (s *Stream) closeLocked(ctx context.Context, reason error) error {
	if reason != nil && s.terminalErr == nil {
		s.terminalErr = reason
	}
	if s.downstreamClosed {
		if s.terminalErr != nil {
			return s.terminalErr
		}
		return nil
	}
	s.closed = true
	closeParent := ctx
	if s.terminalErr != nil {
		// Authority loss and ambiguous writes are terminal cleanup. Their
		// operation context may already be canceled, so use an independent
		// bounded context that can actually close the unique upstream.
		closeParent = context.Background()
	}
	closeCtx, cancel := context.WithTimeout(closeParent, s.ingress.closeTimeout)
	closeErr := s.downstream.Close(closeCtx)
	cancel()
	if closeErr == nil {
		s.downstreamClosed = true
		if s.state.active == s {
			s.state.active = nil
		}
		if !s.refReleased {
			s.refReleased = true
			s.ingress.releaseReference(s.key, s.state)
		}
	}
	if s.terminalErr != nil {
		return s.terminalErr
	}
	if closeErr != nil {
		return gateway.ErrDownstreamUnavailable
	}
	return closeErr
}

func (i *Ingress) retainState(key sessionKey) (*sessionState, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	state := i.sessions[key]
	if state == nil {
		if len(i.sessions) >= i.maxSessions {
			return nil, gateway.ErrDownstreamUnavailable
		}
		state = &sessionState{gate: make(chan struct{}, 1)}
		state.gate <- struct{}{}
		i.sessions[key] = state
	}
	state.refs++
	return state, nil
}

func (i *Ingress) releaseReference(key sessionKey, state *sessionState) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if state.refs > 0 {
		state.refs--
	}
	if state.refs == 0 && i.sessions[key] == state {
		delete(i.sessions, key)
	}
}

func lockSession(ctx context.Context, state *sessionState) error {
	if ctx == nil || state == nil || state.gate == nil {
		return context.Canceled
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-state.gate:
		return nil
	}
}

func unlockSession(state *sessionState) { state.gate <- struct{}{} }

func keyForSubject(subject gateway.DownstreamFenceSubject) sessionKey {
	return sessionKey{
		tenantID: subject.TenantID, sandboxID: subject.SandboxID,
		browserSessionID: subject.BrowserSessionID,
	}
}

func operationTimeout(value, fallback time.Duration) (time.Duration, error) {
	if value == 0 {
		value = fallback
	}
	if value < MinOperationTimeout || value > MaxOperationTimeout {
		return 0, gateway.ErrDownstreamUnavailable
	}
	return value, nil
}

func boundedAuthorityError(operationCtx, parent context.Context, err error) error {
	if errors.Is(err, gateway.ErrDownstreamFenceLost) {
		return gateway.ErrDownstreamFenceLost
	}
	if parentErr := contextError(parent); parentErr != nil &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return parentErr
	}
	if operationCtx != nil && operationCtx.Err() != nil {
		return gateway.ErrDownstreamUnavailable
	}
	return gateway.ErrDownstreamUnavailable
}

func boundedContextError(parent context.Context) error {
	if err := contextError(parent); err != nil {
		return err
	}
	return gateway.ErrDownstreamUnavailable
}

func sameFence(left, right gateway.DownstreamFence) bool {
	return left.Opaque() == right.Opaque()
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}

var _ gateway.Stream = (*Stream)(nil)
