// Package repository defines atomic persistence ports for provider-local
// lifecycle state. Implementations must not become the caller's aggregate
// operation ledger or authorization source.
package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

var (
	ErrNotFound            = errors.New("lifecycle repository record not found")
	ErrAlreadyExists       = errors.New("lifecycle repository record already exists")
	ErrConflict            = errors.New("lifecycle repository conflict")
	ErrIdempotencyConflict = errors.New("lifecycle idempotency conflict")
	ErrCorrupt             = errors.New("lifecycle repository is corrupt")
	ErrDurability          = errors.New("lifecycle repository durability failure")
	ErrClosed              = errors.New("lifecycle repository is closed")
	ErrInvalidCursor       = errors.New("lifecycle event cursor is invalid")
	ErrCursorExpired       = errors.New("lifecycle event cursor is behind retention floor")
	ErrCursorAhead         = errors.New("lifecycle event cursor is ahead of latest sequence")
)

type EventPage struct {
	Events                 []lifecycle.Event
	FirstAvailableSequence uint64
	LatestSequence         uint64
	NextSequence           uint64
}

// CursorError carries only the closed, caller-safe event bounds needed to
// recover from a retained-history gap. It intentionally contains no backend
// identifiers or persistence detail.
type CursorError struct {
	Kind                   error
	FirstAvailableSequence uint64
	LatestSequence         uint64
}

func (e *CursorError) Error() string {
	if e == nil {
		return ErrInvalidCursor.Error()
	}
	return fmt.Sprintf("%s: first available sequence %d, latest sequence %d", e.Kind, e.FirstAvailableSequence, e.LatestSequence)
}

func (e *CursorError) Unwrap() []error {
	if e == nil || e.Kind == nil {
		return []error{ErrInvalidCursor}
	}
	return []error{ErrInvalidCursor, e.Kind}
}

type CreateResult struct {
	Operation lifecycle.Operation
	Replayed  bool
}

type MutationResult struct {
	Operation lifecycle.Operation
	Sandbox   lifecycle.Sandbox
	Replayed  bool
}

// Repository is the P1.2.2 provider-local persistence port. ReserveCreate is
// the atomic boundary for idempotency, initial sandbox/operation records, and
// the fencing high-water mark. Other writes must carry the current fencing
// token and expected generation.
type Repository interface {
	ReserveCreate(context.Context, string, string, lifecycle.Sandbox, lifecycle.Operation) (CreateResult, error)
	ReserveMutation(context.Context, string, string, uint64, lifecycle.Sandbox, lifecycle.Operation, lifecycle.Event) (MutationResult, error)
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
	ListSandboxes(context.Context) ([]lifecycle.Sandbox, error)
	UpdateSandbox(context.Context, lifecycle.Sandbox, uint64, uint64) error
	GetOperation(context.Context, string) (lifecycle.Operation, error)
	ListOperations(context.Context) ([]lifecycle.Operation, error)
	UpdateOperation(context.Context, lifecycle.Operation) error
	GetLease(context.Context, string) (lifecycle.Lease, error)
	ReplaceLease(context.Context, lifecycle.Lease, uint64) error
	AppendEvent(context.Context, lifecycle.Event) (lifecycle.Event, error)
	ListEvents(context.Context, string, uint64, int) ([]lifecycle.Event, error)
	ReadEvents(context.Context, string, uint64, int) (EventPage, error)
	Close() error
}
