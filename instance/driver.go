package instance

import "context"

// RuntimeState is the backend's observed stable state. Transitional states are
// owned by Service and persisted in the Repository.
type RuntimeState string

const (
	RuntimeStopped RuntimeState = "stopped"
	RuntimeRunning RuntimeState = "running"
)

// Driver manages only the underlying runtime resource. Instance identity,
// persistence, and lifecycle policy belong to Service. Remove must tear down
// the resource regardless of its runtime state and be idempotent so an
// interrupted removal can be retried safely.
type Driver interface {
	Create(context.Context, string, Spec) error
	Inspect(context.Context, string) (RuntimeState, error)
	Start(context.Context, string) error
	Stop(context.Context, string) error
	Remove(context.Context, string) error
}
