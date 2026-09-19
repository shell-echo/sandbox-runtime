// Package repository provides durable, provider-local desktop session
// authority. It remains separate from lifecycle and runtime-driver state.
package repository

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
)

var (
	ErrNotFound            = desktop.ErrAuthorityNotFound
	ErrConflict            = errors.New("desktop session authority conflict")
	ErrIdempotencyConflict = errors.New("desktop session idempotency conflict")
	ErrAlreadyExists       = errors.New("desktop session authority record already exists")
	ErrAuthorityConflict   = errors.New("desktop session sandbox authority conflict")
	ErrCorrupt             = errors.New("desktop session repository is corrupt")
	ErrDurability          = errors.New("desktop session repository durability failure")
	ErrClosed              = errors.New("desktop session repository is closed")
	ErrExpired             = desktop.ErrHandoffExpired
)

type Repository interface {
	desktop.CoordinationAuthority
	Close() error
}

// ContextError is shared by memory and file adapters.
func ContextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
