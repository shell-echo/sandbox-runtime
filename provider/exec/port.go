package exec

import "context"

// Executor is the optional provider-local process execution port. Adapters
// must honor context cancellation/deadlines and return only an opaque
// provider-local reference, never backend IDs, paths, endpoints, or secrets.
type Executor interface {
	Start(context.Context, Invocation) (ExecutionReference, error)
}

// SupportChecker rejects requests that a selected runtime cannot resolve. It
// runs before durable acceptance and must not perform an execution side effect.
type SupportChecker interface {
	CheckSupport(context.Context, Request) error
}

// Observer reconciles one previously accepted execution by immutable request
// identity. It never starts or repeats runtime work.
type Observer interface {
	Observe(context.Context, Request) (Observation, error)
}

// Canceler confirms that the exact attached execution stopped in response to
// cancellation before returning nil. A cancellation intent alone is not proof.
type Canceler interface {
	Cancel(context.Context, ExecutionAttachment) error
}

// ResultCleaner removes provider-private retained output after result expiry.
// It is idempotent and must bind cleanup to the immutable request identity.
type ResultCleaner interface {
	CleanupResult(context.Context, Request) error
}

// ResultObserver receives already-durable terminal result evidence. It may
// derive additional provider-local evidence, but it cannot alter exec truth.
type ResultObserver interface {
	ObserveResult(context.Context, Result) error
}
