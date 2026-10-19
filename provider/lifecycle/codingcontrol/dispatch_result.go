package codingcontrol

import (
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

// Only the same fresh begin/dispatch call can construct a result. Neither
// historical authority reads nor a caller boolean can acknowledge a send.
// This records a transport outcome, not independent Released evidence.
type CleanupDispatchResult struct {
	create       dockercontrol.CodingCreateAuthority
	cleanup      dockercontrol.CodingCleanupAuthority
	acknowledged bool
	at           time.Time
}

func (r CleanupDispatchResult) Validate(create dockercontrol.CodingCreateAuthority, cleanup dockercontrol.CodingCleanupAuthority, now time.Time) error {
	if r.create != create || r.cleanup != cleanup || now.IsZero() || r.at.IsZero() || r.at.Before(cleanup.IssuedAt) || r.at.After(now) ||
		create.Validate(create.IssuedAt) != nil || cleanup.Validate(cleanup.IssuedAt) != nil || cleanup.OriginalAuthorityDigest != create.Digest() ||
		r.acknowledged && cleanup.Validate(r.at) != nil {
		return ErrObservation
	}
	return nil
}
func (r CleanupDispatchResult) Acknowledged() bool { return r.acknowledged }
