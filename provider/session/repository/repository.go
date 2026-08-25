// Package repository provides durable, provider-local terminal-session
// authority. It is intentionally independent from lifecycle and runtime
// driver repositories.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

var (
	ErrNotFound            = session.ErrNotFound
	ErrConflict            = session.ErrConflict
	ErrIdempotencyConflict = session.ErrIdempotencyConflict
	ErrAlreadyExists       = errors.New("terminal session authority record already exists")
	ErrAuthorityConflict   = errors.New("terminal session sandbox authority conflict")
	ErrCorrupt             = errors.New("terminal session repository is corrupt")
	ErrDurability          = session.ErrDurability
	ErrClosed              = errors.New("terminal session repository is closed")
	ErrExpired             = session.ErrHandoffExpired
)

// Repository is the durable authority adapter required by session.Authority.
// Sandbox authority updates are provider-local observations supplied by a
// trusted lifecycle coordinator; they do not expose or replace that
// coordinator's aggregate state.
type Repository interface {
	session.Authority
	PutSandboxAuthority(context.Context, session.SandboxAuthority) error
	ReplaceSandboxAuthority(context.Context, session.SandboxAuthority, int64, int64) error
	GetSandboxAuthority(context.Context, string) (session.SandboxAuthority, error)
	Close() error
}

func ContextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func nowUTC() time.Time { return time.Now().UTC() }
