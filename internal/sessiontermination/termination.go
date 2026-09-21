// Package sessiontermination provides a closed, identifier-free vocabulary
// for recording the first terminal event in a private data-plane session.
package sessiontermination

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

// Stage identifies the bounded subsystem that first ended a session.
type Stage string

const (
	StageAuthorityWatcher  Stage = "authority_watcher"
	StageExecutorTransport Stage = "executor_transport"
	StageMuxExec           Stage = "mux_exec"
	StageBrokerRuntime     Stage = "broker_runtime"
	StageMediaReader       Stage = "media_reader"
	StageInputWriter       Stage = "input_writer"
	StageInputResultReader Stage = "input_result_reader"
	StageRecordingTap      Stage = "recording_tap"
	StageCallerTransport   Stage = "caller_transport"
	StageCloseOrdering     Stage = "close_ordering"
)

// Cause identifies a bounded terminal condition. It intentionally cannot
// carry an error string, endpoint, path, identifier, credential, or digest.
type Cause string

const (
	CauseAuthorityDrift       Cause = "authority_drift"
	CauseAuthorityUnavailable Cause = "authority_unavailable"
	CauseBackpressure         Cause = "backpressure_limit"
	CauseProtocolViolation    Cause = "protocol_violation"
	CauseTransportClosed      Cause = "transport_closed"
	CauseRuntimeFailure       Cause = "runtime_failure"
	CauseCallerCancel         Cause = "caller_cancel"
	CauseExpiry               Cause = "expiry"
	CauseCleanClose           Cause = "clean_close"
	CauseCapacity             Cause = "capacity"
	CauseReplay               Cause = "replay"
	CauseBrokerUnavailable    Cause = "broker_unavailable"
	CauseInputTimeout         Cause = "input_timeout"
	CauseInputNonzeroExit     Cause = "input_nonzero_exit"
	CauseInputStartFailure    Cause = "input_start_failure"
)

// Record is safe to put in process logs. Both fields are members of closed
// enumerations, and String never includes the underlying error.
type Record struct {
	Stage Stage
	Cause Cause
}

func (r Record) Valid() bool { return validStage(r.Stage) && validCause(r.Cause) }

func (r Record) String() string {
	if !r.Valid() {
		return "stage=close_ordering cause=protocol_violation"
	}
	return fmt.Sprintf("stage=%s cause=%s", r.Stage, r.Cause)
}

// Parse accepts only the exact stable Record.String representation.
func Parse(value string) (Record, bool) {
	fields := strings.Split(value, " ")
	if len(fields) != 2 || !strings.HasPrefix(fields[0], "stage=") || !strings.HasPrefix(fields[1], "cause=") {
		return Record{}, false
	}
	record := Record{Stage: Stage(strings.TrimPrefix(fields[0], "stage=")), Cause: Cause(strings.TrimPrefix(fields[1], "cause="))}
	return record, record.Valid() && record.String() == value
}

// Error transports a safe first-cause record across an in-process interface.
// Error deliberately exposes only the closed record.
type Error struct{ Record Record }

func (e Error) Error() string { return e.Record.String() }

// First owns the first terminal record. Later cancellation and cleanup paths
// cannot replace the event that actually ended the session.
type First struct {
	record atomic.Pointer[Record]
}

func (f *First) Observe(stage Stage, cause Cause) bool {
	if f == nil || !validStage(stage) || !validCause(cause) {
		return false
	}
	record := &Record{Stage: stage, Cause: cause}
	return f.record.CompareAndSwap(nil, record)
}

func (f *First) Load() (Record, bool) {
	if f == nil {
		return Record{}, false
	}
	record := f.record.Load()
	if record == nil {
		return Record{}, false
	}
	return *record, true
}

func (f *First) Err() error {
	record, ok := f.Load()
	if !ok {
		return nil
	}
	return Error{Record: record}
}

// FromError preserves an already classified record and otherwise maps only
// generic lifecycle errors. Callers supply a closed default for all other
// implementation-specific errors.
func FromError(err error, stage Stage, fallback Cause) Record {
	var classified Error
	if errors.As(err, &classified) && classified.Record.Valid() {
		return classified.Record
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return Record{Stage: stage, Cause: CauseExpiry}
	case errors.Is(err, context.Canceled):
		return Record{Stage: stage, Cause: CauseCallerCancel}
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrClosedPipe), errors.Is(err, io.ErrUnexpectedEOF):
		return Record{Stage: stage, Cause: CauseTransportClosed}
	default:
		return Record{Stage: stage, Cause: fallback}
	}
}

func validStage(stage Stage) bool {
	switch stage {
	case StageAuthorityWatcher, StageExecutorTransport, StageMuxExec, StageBrokerRuntime,
		StageMediaReader, StageInputWriter, StageInputResultReader, StageRecordingTap,
		StageCallerTransport, StageCloseOrdering:
		return true
	default:
		return false
	}
}

func validCause(cause Cause) bool {
	switch cause {
	case CauseAuthorityDrift, CauseAuthorityUnavailable, CauseBackpressure,
		CauseProtocolViolation, CauseTransportClosed, CauseRuntimeFailure,
		CauseCallerCancel, CauseExpiry, CauseCleanClose, CauseCapacity, CauseReplay,
		CauseBrokerUnavailable, CauseInputTimeout, CauseInputNonzeroExit, CauseInputStartFailure:
		return true
	default:
		return false
	}
}
