package reference

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

const MaxRegistrationAttempts = 4

type Store interface {
	Create(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	FindRunning(context.Context, browser.Record) (Record, error)
	Revoke(context.Context, string, time.Time) error
}
type SessionReader interface {
	GetOpen(context.Context, string) (browser.Record, error)
}
type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Generator func() (string, error)

type Registration struct {
	Record   Record
	Evidence browser.EndpointEvidence
}

func (r Registration) Clone() Registration { r.Record = r.Record.Clone(); return r }

type Registrar struct {
	store     Store
	clock     Clock
	generator Generator
	mu        sync.Mutex
}

func NewRegistrar(store Store, clock Clock, generator Generator) (*Registrar, error) {
	if store == nil || clock == nil {
		return nil, ErrUnavailable
	}
	if generator == nil {
		generator = SecureGenerator
	}
	return &Registrar{store: store, clock: clock, generator: generator}, nil
}
func (r *Registrar) Register(ctx context.Context, source browser.Record) (Registration, error) {
	if r == nil || r.store == nil || r.clock == nil || r.generator == nil {
		return Registration{}, ErrUnavailable
	}
	if err := contextError(ctx); err != nil {
		return Registration{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, err := r.store.FindRunning(ctx, source); err == nil {
		if existing.RevokedAt != nil {
			return Registration{}, ErrUnavailable
		}
		return Registration{Record: existing.Clone(), Evidence: existing.Evidence()}, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Registration{}, err
	}
	now := r.clock.Now().UTC()
	if now.IsZero() {
		return Registration{}, ErrUnavailable
	}
	for attempt := 0; attempt < MaxRegistrationAttempts; attempt++ {
		value, err := r.generator()
		if err != nil {
			return Registration{}, err
		}
		record, err := NewRecord(value, source, now)
		if err != nil {
			return Registration{}, err
		}
		if err := r.store.Create(ctx, record); err != nil {
			if errors.Is(err, ErrAlreadyExists) {
				continue
			}
			return Registration{}, err
		}
		return Registration{Record: record.Clone(), Evidence: record.Evidence()}, nil
	}
	return Registration{}, ErrConflict
}

type Endpoint struct {
	Reference            string
	SandboxID            string
	BrowserSessionID     string
	CapabilityProfileID  string
	ConnectionGeneration int64
	ExpiresAt            time.Time
	Dial                 func(context.Context) (browser.Stream, error)
}
type Resolver struct {
	store    Store
	sessions SessionReader
	attacher browser.Attacher
	clock    Clock
}

func NewResolver(store Store, sessions SessionReader, attacher browser.Attacher, clock Clock) (*Resolver, error) {
	if store == nil || sessions == nil || attacher == nil || clock == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{store: store, sessions: sessions, attacher: attacher, clock: clock}, nil
}
func (r *Resolver) Resolve(ctx context.Context, value string) (Endpoint, error) {
	record, err := r.lookup(ctx, value)
	if err != nil {
		return Endpoint{}, err
	}
	endpoint := Endpoint{Reference: record.Reference, SandboxID: record.SandboxID, BrowserSessionID: record.BrowserSessionID, CapabilityProfileID: record.CapabilityProfileID, ConnectionGeneration: record.ConnectionGeneration, ExpiresAt: record.ExpiresAt.UTC()}
	endpoint.Dial = func(dialCtx context.Context) (browser.Stream, error) {
		fresh, err := r.lookup(dialCtx, value)
		if err != nil {
			return nil, err
		}
		stream, err := r.attacher.Attach(dialCtx, fresh.Receipt)
		if err != nil {
			if contextErr := contextError(dialCtx); contextErr != nil {
				return nil, contextErr
			}
			return nil, ErrUnavailable
		}
		if stream == nil {
			return nil, ErrUnavailable
		}
		return stream, nil
	}
	return endpoint, nil
}
func (r *Resolver) lookup(ctx context.Context, value string) (Record, error) {
	if r == nil || r.store == nil || r.sessions == nil || r.attacher == nil || r.clock == nil {
		return Record{}, ErrUnavailable
	}
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	if !referencePattern.MatchString(value) {
		return Record{}, ErrUnavailable
	}
	now := r.clock.Now().UTC()
	if now.IsZero() {
		return Record{}, ErrUnavailable
	}
	record, err := r.store.Get(ctx, value)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return Record{}, contextErr
		}
		return Record{}, ErrUnavailable
	}
	if err := record.activeAt(now); err != nil {
		return Record{}, err
	}
	source, err := getSessionAt(ctx, r.sessions, record.OperationID, now)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return Record{}, contextErr
		}
		return Record{}, ErrUnavailable
	}
	if err := record.matchesSucceeded(source); err != nil {
		return Record{}, ErrStale
	}
	return record.Clone(), nil
}
func getSessionAt(ctx context.Context, reader SessionReader, operationID string, now time.Time) (browser.Record, error) {
	if timed, ok := reader.(interface {
		GetOpenAt(context.Context, string, time.Time) (browser.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, now)
	}
	return reader.GetOpen(ctx, operationID)
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
