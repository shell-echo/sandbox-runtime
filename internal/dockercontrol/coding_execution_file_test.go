//go:build darwin || linux

package dockercontrol

import (
	"context"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

// Ordinary-directory state-machine fixtures have no production constructor.
// This adapter deliberately exists only in tests, not in command binaries.
type executionFileFixture struct{ *controlstorage.Store }

func (*executionFileFixture) executionSourceOwner() {}
func (s *executionFileFixture) Check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrInvalidReceiptState
	}
	return s.Store.Check()
}
func initializeExecutionLedger(ctx context.Context, path string, b executionBinding, empty func(context.Context) error) (*executionLedger, error) {
	if ctx == nil || ctx.Err() != nil || b.validate() != nil {
		return nil, ErrInvalidReceiptState
	}
	s, err := controlstorage.Initialize(ctx, path, b.Storage, empty)
	if err != nil {
		return nil, err
	}
	return loadExecutionLedger(ctx, &executionFileFixture{s}, b, true)
}
func openExecutionLedger(ctx context.Context, path string, b executionBinding) (*executionLedger, error) {
	if ctx == nil || ctx.Err() != nil || b.validate() != nil {
		return nil, ErrInvalidReceiptState
	}
	s, err := controlstorage.Open(path, b.Storage)
	if err != nil {
		return nil, err
	}
	return loadExecutionLedger(ctx, &executionFileFixture{s}, b, false)
}
