package exec

import "time"

// ExecutionRecord is the provider-local immutable admission record plus any
// terminal evidence known to this repository. Terminal remains after Result
// expires so operation truth cannot regress to running.
type ExecutionRecord struct {
	Request       Request
	ReservedAt    time.Time
	Dispatch      Dispatch
	Attached      bool
	Result        *Result
	Terminal      *TerminalSummary
	ResultExpired bool
}

// ExecutionAttachment binds the executor's opaque receipt to the exact
// admitted request identity. The receipt cannot be attached to another
// operation, attempt, sandbox, fence, or generation.
type ExecutionAttachment struct {
	OperationID        string
	AttemptID          string
	SandboxID          string
	FencingToken       int64
	ExpectedGeneration int64
	Dispatch           Dispatch
}

func (a ExecutionAttachment) Clone() ExecutionAttachment { return a }

type ExecutionReservation struct {
	Execution ExecutionRecord
	Replayed  bool
}

type CancellationReservation struct {
	Intent     CancellationIntent
	ReservedAt time.Time
	Replayed   bool
}

func (r ExecutionRecord) Clone() ExecutionRecord {
	clone := r
	clone.Request = r.Request.Clone()
	clone.Result = r.Result.Clone()
	clone.Terminal = r.Terminal.Clone()
	return clone
}

func (r *Result) Clone() *Result {
	if r == nil {
		return nil
	}
	clone := *r
	clone.ExitCode = cloneExitCode(r.ExitCode)
	clone.Error = cloneResultError(r.Error)
	return &clone
}
