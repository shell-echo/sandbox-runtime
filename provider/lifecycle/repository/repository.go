// Package repository defines atomic persistence ports for provider-local
// lifecycle state. Implementations must not become the caller's aggregate
// operation ledger or authorization source.
package repository

import (
	"context"
	"errors"

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
)

type CreateResult struct {
	Operation lifecycle.Operation
	Replayed  bool
}

// Repository is the P1.2.2 provider-local persistence port. ReserveCreate is
// the atomic boundary for idempotency, initial sandbox/operation records, and
// the fencing high-water mark. Other writes must carry the current fencing
// token and expected generation.
type Repository interface {
	ReserveCreate(context.Context, string, string, lifecycle.Sandbox, lifecycle.Operation) (CreateResult, error)
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
	Close() error
}
