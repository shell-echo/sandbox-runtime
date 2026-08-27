package terminal

import (
	"context"
	"time"
)

// Clock keeps allocation, expiry, and observation decisions deterministic.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Allocator starts or recovers exactly one terminal resource for an immutable
// allocation identity. It returns only a backend-neutral receipt.
type Allocator interface {
	Allocate(context.Context, Allocation) (Receipt, error)
}

// Observer reconciles an existing receipt without starting replacement work.
type Observer interface {
	Observe(context.Context, Receipt) (Observation, error)
}

// Attacher creates a fresh connection to the same terminal resource. It must
// not create a replacement shell when the receipt cannot be resolved.
type Attacher interface {
	Attach(context.Context, Receipt) (Stream, error)
}

// Cleaner removes only the exact terminal resource bound to a receipt.
// Cleanup is idempotent for already-absent resources.
type Cleaner interface {
	Cleanup(context.Context, Receipt) error
}

// Runtime is the complete optional terminal data-plane capability. Other
// runtime drivers need not implement it.
type Runtime interface {
	Allocator
	Observer
	Attacher
	Cleaner
}

// Stream is a context-aware byte stream. WebSocket framing belongs to the
// later Gateway adapter and is deliberately absent here.
type Stream interface {
	Read(context.Context, []byte) (int, error)
	Write(context.Context, []byte) (int, error)
	Close() error
}
