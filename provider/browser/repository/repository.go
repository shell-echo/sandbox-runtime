// Package repository provides durable, provider-local browser session
// authority. It remains separate from lifecycle and runtime-driver state.
package repository

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

var (
	ErrNotFound            = errors.New("browser session authority record not found")
	ErrConflict            = errors.New("browser session authority conflict")
	ErrIdempotencyConflict = errors.New("browser session idempotency conflict")
	ErrAlreadyExists       = errors.New("browser session authority record already exists")
	ErrAuthorityConflict   = errors.New("browser session sandbox authority conflict")
	ErrCorrupt             = errors.New("browser session repository is corrupt")
	ErrDurability          = errors.New("browser session repository durability failure")
	ErrClosed              = errors.New("browser session repository is closed")
	ErrExpired             = browser.ErrHandoffExpired
)

type Repository interface {
	browser.CoordinationAuthority
	Close() error
}

// ContextError is shared by memory and file adapters.
func ContextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
