package reference

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/session"
)

// RevokeSucceededHandoff durably revokes the exact opaque reference committed
// by a successful terminal-session operation. Missing and already-revoked
// references are idempotent; every retained binding is revalidated before the
// tombstone is written.
func RevokeSucceededHandoff(ctx context.Context, store Store, source session.Record, now time.Time) error {
	if store == nil || now.IsZero() {
		return ErrUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := source.Validate(); err != nil || source.Status != session.StatusSucceeded || source.Handoff == nil {
		return ErrStale
	}
	record, err := store.Get(ctx, source.Handoff.InternalEndpointReference)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := record.matchesSucceeded(source); err != nil {
		return err
	}
	if err := store.Revoke(ctx, record.Reference, now.UTC()); err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrRevoked) {
		return err
	}
	return nil
}
