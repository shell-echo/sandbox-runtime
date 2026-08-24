package session

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound                 = errors.New("terminal session authority record not found")
	ErrConflict                 = errors.New("terminal session authority conflict")
	ErrIdempotencyConflict      = errors.New("terminal session idempotency conflict")
	ErrSandboxNotReady          = errors.New("terminal session sandbox is not ready")
	ErrProviderRevisionConflict = errors.New("terminal session provider revision conflict")
	ErrGenerationConflict       = errors.New("terminal session sandbox generation conflict")
	ErrLeaseExpired             = errors.New("terminal session sandbox lease has expired")
	ErrStaleFencingToken        = errors.New("terminal session fencing token is stale")
	ErrCapabilityUnsupported    = errors.New("terminal session capability profile is unsupported")
	ErrDurability               = errors.New("terminal session authority durability failure")
)

// Authority is the transactional Provider-local boundary for terminal session
// truth. ReserveOpen implementations must atomically validate sandbox ready
// state, ProviderRevision, observed generation, lease coverage through session
// expiry, current fencing, advertised terminal profile, and idempotency before
// recording an accepted operation. An idempotent replay must match the request
// digest, operation identity, and complete admitted authority identity, then
// return the original reservation. Implementations must return immutable
// snapshots and must not dispatch an allocator or runtime driver.
//
// UpdateOpen persists exactly one validated domain transition while comparing
// expectedStatus in the same transaction. A terminal record cannot be replaced
// or reopened, especially after outcome_unknown. Before storing a successful
// record and handoff, the transaction must recheck the sandbox revision, ready
// state, generation, lease coverage, and current fence. P2.3c2 supplies the
// durable implementation; P2.3c1 defines only this port and its failure
// categories.
type Authority interface {
	ReserveOpen(ctx context.Context, request OpenRequest, acceptedAt time.Time) (Reservation, error)
	GetOpen(ctx context.Context, operationID string) (Record, error)
	UpdateOpen(ctx context.Context, record Record, expectedStatus Status) error
}
