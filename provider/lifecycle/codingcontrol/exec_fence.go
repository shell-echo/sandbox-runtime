package codingcontrol

import (
	"context"
	"errors"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

var ErrExecFence = errors.New("Coding exec fence unavailable")

// ExecFenceReceipt is historical evidence of a PG fence reservation only.
// It is not a public Accepted operation, a dispatch permit, or a claim that
// an exec exists. No Control transport or runtime Executor accepts it. Even a
// newly committed receipt requires a separate current CAS before any future
// physical dispatch; replay and read never refresh its authority or deadline.
type ExecFenceReceipt struct {
	OperationID       string
	PayloadDigest     string
	ReservationDigest string
	FencingToken      uint64
	RecordedAt        time.Time
	Replayed          bool
}

// ExecFenceRecorder is separate from execution and result recovery. Callers
// must already bind the authenticated Contract request. Read is deliberately
// available after deadline expiry to resolve an uncertain PG commit without
// making that historical reservation executable.
type ExecFenceRecorder interface {
	ReserveCodingExecFence(context.Context, providerexec.Request) (ExecFenceReceipt, error)
	ReadCodingExecFence(context.Context, string) (ExecFenceReceipt, error)
}
