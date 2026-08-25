package migration

import (
	"context"
	"errors"
	"time"
)

const (
	ShadowCapabilities = "capabilities"
	ShadowRequest      = "request"
	MaxShadowBytes     = 1 << 20
)

var ErrInvalidShadow = errors.New("invalid migration shadow validation")

// ShadowChecker is supplied by a caller-side locked Contract projection. It
// must validate without dispatching a provider operation or serving traffic.
type ShadowChecker func(context.Context, Revision, string, []byte) error

type ShadowResult struct {
	RevisionID string
	Kind       string
	Accepted   bool
	ObservedAt time.Time
}

func ShadowValidate(ctx context.Context, revision Revision, kind string, document []byte, checker ShadowChecker, now time.Time) (ShadowResult, error) {
	if ctx == nil || ctx.Err() != nil {
		if ctx == nil {
			return ShadowResult{}, context.Canceled
		}
		return ShadowResult{}, ctx.Err()
	}
	if err := revision.Validate(); err != nil || (kind != ShadowCapabilities && kind != ShadowRequest) || len(document) == 0 || len(document) > MaxShadowBytes || checker == nil || now.IsZero() {
		return ShadowResult{}, ErrInvalidShadow
	}
	if err := checker(ctx, revision, kind, append([]byte(nil), document...)); err != nil {
		return ShadowResult{RevisionID: revision.ID, Kind: kind, Accepted: false, ObservedAt: now.UTC()}, nil
	}
	return ShadowResult{RevisionID: revision.ID, Kind: kind, Accepted: true, ObservedAt: now.UTC()}, nil
}
