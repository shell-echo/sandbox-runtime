// Package repository provides independent provider-local persistence for exec
// admission, cancellation intent, and retained result evidence.
package repository

import (
	"context"
	"errors"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

var (
	ErrNotFound            = errors.New("exec repository record not found")
	ErrAlreadyExists       = errors.New("exec repository record already exists")
	ErrConflict            = errors.New("exec repository conflict")
	ErrIdempotencyConflict = errors.New("exec idempotency conflict")
	ErrPending             = errors.New("exec result is pending")
	ErrExpired             = errors.New("exec result has expired")
	ErrCorrupt             = errors.New("exec repository is corrupt")
	ErrDurability          = errors.New("exec repository durability failure")
	ErrClosed              = errors.New("exec repository is closed")
)

type Repository interface {
	ReserveExecution(context.Context, providerexec.Request, providerexec.Dispatch) (providerexec.ExecutionReservation, error)
	GetExecution(context.Context, string) (providerexec.ExecutionRecord, error)
	ReserveCancellation(context.Context, providerexec.CancellationIntent) (providerexec.CancellationReservation, error)
	StoreResult(context.Context, providerexec.Result) error
	GetResult(context.Context, string, time.Time) (providerexec.Result, error)
	Close() error
}

func ContextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
