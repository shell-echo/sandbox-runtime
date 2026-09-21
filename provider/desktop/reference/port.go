package reference

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

const MaxRegistrationAttempts = 4

type Store interface {
	Create(context.Context, Record) error
	Get(context.Context, string) (Record, error)
	FindRunning(context.Context, desktop.Record) (Record, error)
	Revoke(context.Context, string, time.Time) error
}

// BindingStore is an optional durable private registration extension. It is
// deliberately separate from the public Provider Contract and binds Product
// Gateway authority only after authenticated private admission.
type BindingStore interface {
	Bind(context.Context, string, desktophandoff.Binding) error
}
type SessionReader interface {
	GetOpen(context.Context, string) (desktop.Record, error)
}
type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Generator func() (string, error)

type Registration struct {
	Record   Record
	Evidence desktop.EndpointEvidence
}

func (r Registration) Clone() Registration { r.Record = r.Record.Clone(); return r }

type Registrar struct {
	store     Store
	clock     Clock
	generator Generator
	mu        sync.Mutex
}

func (r *Registrar) BindHandoff(ctx context.Context, binding desktophandoff.Binding) error {
	if r == nil || r.store == nil {
		return ErrUnavailable
	}
	if err := binding.Validate(r.clock.Now().UTC()); err != nil {
		return ErrInvalidRecord
	}
	store, ok := r.store.(BindingStore)
	if !ok {
		return ErrUnavailable
	}
	return store.Bind(ctx, binding.HandoffReference, binding)
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
func (r *Registrar) Register(ctx context.Context, source desktop.Record) (Registration, error) {
	return r.register(ctx, source, "")
}

func (r *Registrar) RegisterWithTenantBinding(ctx context.Context, source desktop.Record, tenantBindingDigest string) (Registration, error) {
	return r.register(ctx, source, tenantBindingDigest)
}

func (r *Registrar) register(ctx context.Context, source desktop.Record, tenantBindingDigest string) (Registration, error) {
	if r == nil || r.store == nil || r.clock == nil || r.generator == nil {
		return Registration{}, ErrUnavailable
	}
	if err := contextError(ctx); err != nil {
		return Registration{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, err := r.store.FindRunning(ctx, source); err == nil {
		if existing.RevokedAt != nil || (tenantBindingDigest != "" && existing.TenantBindingDigest != tenantBindingDigest) {
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
		var record Record
		if tenantBindingDigest == "" {
			record, err = NewRecord(value, source, now)
		} else {
			record, err = NewRecordWithTenantBinding(value, source, tenantBindingDigest, now)
		}
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

// RegisterHandoff adapts the durable registry to the Desktop application
// boundary without projecting the private registry record.
func (r *Registrar) RegisterHandoff(ctx context.Context, source desktop.Record) (desktop.EndpointEvidence, error) {
	registration, err := r.Register(ctx, source)
	if err != nil {
		return desktop.EndpointEvidence{}, err
	}
	return registration.Evidence, nil
}

// RevokeHandoff is idempotent and validates that the retained opaque
// reference is still bound to the exact succeeded source operation.
func (r *Registrar) RevokeHandoff(ctx context.Context, source desktop.Record, revokedAt time.Time) error {
	if r == nil || r.store == nil || source.Handoff == nil {
		return ErrUnavailable
	}
	record, err := r.store.Get(ctx, source.Handoff.InternalEndpointReference)
	if err != nil {
		return err
	}
	if err := record.matchesSucceeded(source); err != nil {
		return err
	}
	return r.store.Revoke(ctx, record.Reference, revokedAt.UTC())
}

// ObserveHandoffRevoked is read-only so uncertain close reconciliation never
// repeats the revoke effect.
func (r *Registrar) ObserveHandoffRevoked(ctx context.Context, source desktop.Record) (bool, error) {
	if r == nil || r.store == nil || source.Handoff == nil {
		return false, ErrUnavailable
	}
	record, err := r.store.Get(ctx, source.Handoff.InternalEndpointReference)
	if err != nil {
		return false, err
	}
	if err := record.matchesSucceeded(source); err != nil {
		return false, err
	}
	return record.RevokedAt != nil, nil
}

type Endpoint struct {
	Reference            string
	ProviderRevisionID   string
	SandboxID            string
	DesktopSessionID     string
	AllocationReference  string
	CapabilityProfileID  string
	ConnectionGeneration int64
	ExpiresAt            time.Time
	TenantBindingDigest  string
	Binding              *desktophandoff.Binding
	Attach               func(context.Context) (desktop.Attachment, error)
}
type Resolver struct {
	store    Store
	sessions SessionReader
	attacher desktop.Attacher
	clock    Clock
}

func NewResolver(store Store, sessions SessionReader, attacher desktop.Attacher, clock Clock) (*Resolver, error) {
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
	endpoint := Endpoint{Reference: record.Reference, ProviderRevisionID: record.ProviderRevisionID, SandboxID: record.SandboxID, DesktopSessionID: record.DesktopSessionID, AllocationReference: record.Receipt.Reference, CapabilityProfileID: record.CapabilityProfileID, ConnectionGeneration: record.ConnectionGeneration, ExpiresAt: record.ExpiresAt.UTC(), TenantBindingDigest: record.TenantBindingDigest, Binding: cloneBinding(record.Binding)}
	endpoint.Attach = func(attachCtx context.Context) (desktop.Attachment, error) {
		fresh, err := r.lookup(attachCtx, value)
		if err != nil {
			return desktop.Attachment{}, err
		}
		attachment, err := r.attacher.Attach(attachCtx, fresh.Receipt)
		if err != nil {
			if contextErr := contextError(attachCtx); contextErr != nil {
				return desktop.Attachment{}, contextErr
			}
			return desktop.Attachment{}, ErrUnavailable
		}
		if err := attachment.Validate(fresh.Receipt); err != nil {
			return desktop.Attachment{}, ErrUnavailable
		}
		return attachment.Clone(), nil
	}
	return endpoint, nil
}

func cloneBinding(value *desktophandoff.Binding) *desktophandoff.Binding {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
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
func getSessionAt(ctx context.Context, reader SessionReader, operationID string, now time.Time) (desktop.Record, error) {
	if timed, ok := reader.(interface {
		GetOpenAt(context.Context, string, time.Time) (desktop.Record, error)
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
