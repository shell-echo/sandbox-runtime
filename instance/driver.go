package instance

import (
	"context"
	"time"
)

// RuntimeState is the backend's observed stable state. Transitional states are
// owned by Service and persisted in the Repository.
type RuntimeState string

const (
	RuntimeStopped RuntimeState = "stopped"
	RuntimeRunning RuntimeState = "running"
)

// RuntimeStopReason classifies why a runtime resource is stopped without
// exposing backend-specific diagnostic text outside the driver boundary.
type RuntimeStopReason string

const (
	RuntimeStopReasonNone         RuntimeStopReason = ""
	RuntimeStopReasonOOMKilled    RuntimeStopReason = "oom_killed"
	RuntimeStopReasonRuntimeError RuntimeStopReason = "runtime_error"
)

// RuntimeObservation describes the actual runtime resource. Failure details
// are meaningful when a previously running resource has stopped unexpectedly.
type RuntimeObservation struct {
	State      RuntimeState
	ExitCode   int
	StopReason RuntimeStopReason
}

// RuntimeResource is the identity metadata required to adopt a managed runtime
// resource when its repository record is missing.
type RuntimeResource struct {
	ID        string
	Spec      Spec
	CreatedAt time.Time
}

// Driver manages only the underlying runtime resource. Instance identity,
// persistence, and lifecycle policy belong to Service. Remove must tear down
// the resource regardless of its runtime state and be idempotent so an
// interrupted removal can be retried safely.
type Driver interface {
	Create(context.Context, string, Spec) error
	List(context.Context) ([]RuntimeResource, error)
	Inspect(context.Context, string) (RuntimeObservation, error)
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Remove(context.Context, string) error
}
