// Package repository defines independent durable provider-local artifact
// staging authority. It does not own lifecycle, caller, or artifact truth.
package repository

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var (
	ErrNotFound            = artifact.ErrNotFound
	ErrConflict            = artifact.ErrConflict
	ErrIdempotencyConflict = artifact.ErrIdempotencyConflict
	ErrAlreadyExists       = errors.New("artifact staging operation already exists")
	ErrCorrupt             = errors.New("artifact staging repository is corrupt")
	ErrDurability          = artifact.ErrDurability
	ErrClosed              = errors.New("artifact staging repository is closed")
)

type Repository interface {
	artifact.Authority
	PutSandboxAuthority(context.Context, artifact.SandboxAuthority) error
	ReplaceSandboxAuthority(context.Context, artifact.SandboxAuthority, int64, int64) error
	GetSandboxAuthority(context.Context, string) (artifact.SandboxAuthority, error)
	Close() error
}

func ContextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}
