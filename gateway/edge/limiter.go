// Package edge provides transport-edge controls that run before a public
// Browser WebSocket is upgraded. These controls are caller-owned and do not
// replace Gateway authorization or Provider-side capacity.
package edge

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

const (
	MaxConcurrentConnections = 1_000
	MaxRequestsPerWindow     = 100_000
	MinWindow                = 100 * time.Millisecond
	MaxWindow                = time.Minute
)

var (
	ErrInvalidOptions    = errors.New("invalid Browser public-edge limiter options")
	ErrUnavailable       = errors.New("Browser public-edge limiter is unavailable")
	ErrCapacityExhausted = errors.New("Browser public-edge connection capacity exhausted")
	ErrRateLimited       = errors.New("Browser public-edge request rate exceeded")
)

// Gate reserves public-edge capacity before a WebSocket upgrade. The lease
// must remain held for the entire public connection and Release must be safe to
// call more than once.
type Gate interface {
	Acquire(context.Context) (Lease, error)
}

type Lease interface {
	Release()
}

type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// LocalOptions require explicit, bounded process-local concurrency and fixed
// window request limits. No unbounded defaults are supplied.
type LocalOptions struct {
	Clock                Clock
	MaxConcurrent        int
	MaxRequestsPerWindow int
	Window               time.Duration
}

type LocalLimiter struct {
	mu sync.Mutex

	clock                Clock
	maxConcurrent        int
	maxRequestsPerWindow int
	window               time.Duration
	windowStart          time.Time
	requests             int
	active               int
}

func NewLocalLimiter(options LocalOptions) (*LocalLimiter, error) {
	if options.MaxConcurrent < 1 || options.MaxConcurrent > MaxConcurrentConnections {
		return nil, fmt.Errorf("%w: max concurrent connections", ErrInvalidOptions)
	}
	if options.MaxRequestsPerWindow < 1 || options.MaxRequestsPerWindow > MaxRequestsPerWindow {
		return nil, fmt.Errorf("%w: max requests per window", ErrInvalidOptions)
	}
	if options.Window < MinWindow || options.Window > MaxWindow {
		return nil, fmt.Errorf("%w: request window", ErrInvalidOptions)
	}
	clock := options.Clock
	if nilDependency(clock) {
		return nil, fmt.Errorf("%w: clock", ErrInvalidOptions)
	}
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	return &LocalLimiter{
		clock:                clock,
		maxConcurrent:        options.MaxConcurrent,
		maxRequestsPerWindow: options.MaxRequestsPerWindow,
		window:               options.Window,
	}, nil
}

// Acquire counts every attempt before checking connection capacity. This keeps
// repeated capacity probes inside the request-rate budget. It never queues.
func (l *LocalLimiter) Acquire(ctx context.Context) (Lease, error) {
	if l == nil || l.clock == nil {
		return nil, ErrUnavailable
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrUnavailable)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := l.clock.Now()
	if now.IsZero() {
		return nil, fmt.Errorf("%w: zero clock", ErrUnavailable)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.windowStart.IsZero() {
		l.windowStart = now
	} else if now.Before(l.windowStart) {
		return nil, fmt.Errorf("%w: clock moved backwards", ErrUnavailable)
	} else if elapsed := now.Sub(l.windowStart); elapsed >= l.window {
		l.windowStart = l.windowStart.Add((elapsed / l.window) * l.window)
		l.requests = 0
	}
	windowEnd := l.windowStart.Add(l.window)
	if l.requests >= l.maxRequestsPerWindow {
		return nil, newRejection(ErrRateLimited, windowEnd.Sub(now))
	}
	l.requests++
	if l.active >= l.maxConcurrent {
		return nil, newRejection(ErrCapacityExhausted, time.Second)
	}
	l.active++
	return &localLease{limiter: l}, nil
}

type localLease struct {
	limiter *LocalLimiter
	once    sync.Once
}

func (l *localLease) Release() {
	if l == nil || l.limiter == nil {
		return
	}
	l.once.Do(func() {
		l.limiter.mu.Lock()
		defer l.limiter.mu.Unlock()
		if l.limiter.active > 0 {
			l.limiter.active--
		}
	})
}

type rejection struct {
	cause      error
	retryAfter time.Duration
}

func newRejection(cause error, retryAfter time.Duration) error {
	if retryAfter <= 0 {
		retryAfter = time.Second
	}
	return &rejection{cause: cause, retryAfter: retryAfter}
}

func (e *rejection) Error() string             { return e.cause.Error() }
func (e *rejection) Unwrap() error             { return e.cause }
func (e *rejection) RetryAfter() time.Duration { return e.retryAfter }

// RetryAfter returns a bounded retry hint carried by a local rejection.
func RetryAfter(err error) time.Duration {
	var value interface{ RetryAfter() time.Duration }
	if errors.As(err, &value) {
		return value.RetryAfter()
	}
	return 0
}

func nilDependency(value any) bool {
	if value == nil {
		return false
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Func || kind == reflect.Interface || kind == reflect.Pointer) && reflect.ValueOf(value).IsNil()
}

var _ Gate = (*LocalLimiter)(nil)
