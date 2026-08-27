package reference

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
)

const MaxRegistrationAttempts = 4

// Store durably owns opaque reference records. It is deliberately separate
// from session authority because the two repositories have no atomic commit.
type Store interface {
	Create(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	Revoke(context.Context, string, time.Time) error
}

// SessionReader is the minimal authority check needed before resolution. A
// reference that was registered but never committed as a session handoff is
// unavailable by construction.
type SessionReader interface {
	GetOpen(context.Context, string) (session.Record, error)
}

type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Generator produces an opaque ref:session value. It must not encode backend
// or caller-owned identity.
type Generator func() (string, error)

// Registration is returned to the session coordinator. Evidence must still be
// transactionally accepted by the session authority before it can resolve.
type Registration struct {
	Record   Record
	Evidence session.EndpointEvidence
}

func (r Registration) Clone() Registration {
	r.Record = r.Record.Clone()
	return r
}

// Registrar mints one durable opaque reference for a running allocation.
type Registrar struct {
	store     Store
	clock     Clock
	generator Generator
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

func (r *Registrar) Register(ctx context.Context, source session.Record) (Registration, error) {
	if r == nil || r.store == nil || r.clock == nil || r.generator == nil {
		return Registration{}, ErrUnavailable
	}
	if err := contextError(ctx); err != nil {
		return Registration{}, err
	}
	now := r.clock.Now().UTC()
	if now.IsZero() {
		return Registration{}, ErrUnavailable
	}
	for attempt := 0; attempt < MaxRegistrationAttempts; attempt++ {
		reference, err := r.generator()
		if err != nil {
			return Registration{}, err
		}
		record, err := NewRecord(reference, source, now)
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

// Endpoint is a safe, internal projection for the later Gateway adapter. The
// Dial closure is constructed afresh by Resolve and is never persisted.
type Endpoint struct {
	Reference            string
	SandboxID            string
	RuntimeSessionID     string
	CapabilityProfileID  string
	ConnectionGeneration int64
	ExpiresAt            time.Time
	Dial                 func(context.Context) (terminal.Stream, error)
}

// Resolver validates registry state and the committed session handoff on each
// resolution. It creates a fresh terminal attach only after both checks pass.
type Resolver struct {
	store    Store
	sessions SessionReader
	attacher terminal.Attacher
	clock    Clock
}

func NewResolver(store Store, sessions SessionReader, attacher terminal.Attacher, clock Clock) (*Resolver, error) {
	if store == nil || sessions == nil || attacher == nil || clock == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{store: store, sessions: sessions, attacher: attacher, clock: clock}, nil
}

func (r *Resolver) Resolve(ctx context.Context, reference string) (Endpoint, error) {
	record, err := r.lookup(ctx, reference)
	if err != nil {
		return Endpoint{}, err
	}
	endpoint := Endpoint{
		Reference: record.Reference, SandboxID: record.SandboxID,
		RuntimeSessionID: record.RuntimeSessionID, CapabilityProfileID: record.CapabilityProfileID,
		ConnectionGeneration: record.ConnectionGeneration, ExpiresAt: record.ExpiresAt.UTC(),
	}
	endpoint.Dial = func(dialCtx context.Context) (terminal.Stream, error) {
		fresh, err := r.lookup(dialCtx, reference)
		if err != nil {
			return nil, err
		}
		stream, err := r.attacher.Attach(dialCtx, terminalReceipt(fresh.Receipt))
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

func (r *Resolver) lookup(ctx context.Context, reference string) (Record, error) {
	if r == nil || r.store == nil || r.sessions == nil || r.attacher == nil || r.clock == nil {
		return Record{}, ErrUnavailable
	}
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	if !referencePattern.MatchString(reference) {
		return Record{}, ErrUnavailable
	}
	now := r.clock.Now().UTC()
	if now.IsZero() {
		return Record{}, ErrUnavailable
	}
	record, err := r.store.Get(ctx, reference)
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

func getSessionAt(ctx context.Context, reader SessionReader, operationID string, now time.Time) (session.Record, error) {
	if timed, ok := reader.(interface {
		GetOpenAt(context.Context, string, time.Time) (session.Record, error)
	}); ok {
		return timed.GetOpenAt(ctx, operationID, now)
	}
	return reader.GetOpen(ctx, operationID)
}

func terminalReceipt(receipt session.AllocationReceipt) terminal.Receipt {
	return terminal.Receipt{
		Reference: terminal.Reference(receipt.Reference), SandboxID: receipt.SandboxID,
		RuntimeSessionID: receipt.RuntimeSessionID, OperationID: receipt.OperationID,
		AttemptID: receipt.AttemptID, FencingToken: receipt.FencingToken,
		ExpectedGeneration: receipt.ExpectedGeneration, ConnectionGeneration: receipt.ConnectionGeneration,
		AllocatedAt: receipt.AllocatedAt.UTC(), ExpiresAt: receipt.ExpiresAt.UTC(),
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
