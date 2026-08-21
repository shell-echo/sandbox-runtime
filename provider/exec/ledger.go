package exec

// ExecutionRecord is the provider-local immutable admission record plus any
// terminal evidence known to this repository. A nil Result means pending.
type ExecutionRecord struct {
	Request       Request
	Dispatch      Dispatch
	Result        *Result
	ResultExpired bool
}

type ExecutionReservation struct {
	Execution ExecutionRecord
	Replayed  bool
}

type CancellationReservation struct {
	Intent   CancellationIntent
	Replayed bool
}

func (r ExecutionRecord) Clone() ExecutionRecord {
	clone := r
	clone.Request = r.Request.Clone()
	clone.Result = r.Result.Clone()
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
