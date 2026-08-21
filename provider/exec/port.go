package exec

import "context"

// Executor is the optional provider-local process execution port. Adapters
// must honor context cancellation/deadlines and return only an opaque
// provider-local reference, never backend IDs, paths, endpoints, or secrets.
type Executor interface {
	Start(context.Context, Invocation) (ExecutionReference, error)
}
