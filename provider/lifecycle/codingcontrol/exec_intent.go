package codingcontrol

import (
	"context"
	"errors"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

var (
	ErrExecIntent         = errors.New("Coding exec intent unavailable")
	ErrExecIntentConflict = errors.New("Coding exec intent conflict")
	ErrExecIntentCapacity = errors.New("Coding exec intent capacity exhausted")
)

// ExecIntentReceipt proves only that a complete request was recorded. It is
// neither a public Accepted operation nor a fence reservation or a Control
// permit. It cannot be supplied to any runtime Executor or private transport.
// PayloadDigest hashes the internal request projection, not the Contract body.
type ExecIntentReceipt struct {
	OperationID   string
	PayloadDigest string
	RecordedAt    time.Time
	Replayed      bool
}

// ExecIntentRecorder is deliberately separate from the generic exec repository
// and Coordinator. Its caller must already have authenticated and bound the
// locked Contract request. No dispatch/recovery worker consumes this ledger.
type ExecIntentRecorder interface {
	ReserveCodingExecIntent(context.Context, providerexec.Request) (ExecIntentReceipt, error)
}
