package artifact

import (
	"context"
	"io"
	"time"
)

// Stager is a provider-local staging adapter. It may read the stable output
// mount, but it must return bounded evidence and never publish an artifact.
type Stager interface {
	Stage(context.Context, Request, time.Time) (Evidence, error)
}

// Output is a bounded handle to one regular file under the stable /outputs
// mount. The adapter owns the underlying backend and host-path confinement.
type Output struct {
	Content   io.ReadCloser
	SizeBytes int64
}

// OutputReader opens only a regular file in the exact Provider-owned sandbox
// generation. It must never return a host path or backend identifier.
type OutputReader interface {
	OpenOutput(context.Context, string, int64, string) (Output, error)
}

// TenantBindingChecker rechecks that the admitted tenant still owns the
// provider-local sandbox projection at staging time.
type TenantBindingChecker interface {
	CheckTenantBinding(context.Context, Request) (CheckStatus, error)
}

// ContentChecker examines bounded bytes without publishing or retaining them.
type ContentChecker interface {
	CheckContent(context.Context, Request, []byte) (CheckStatus, error)
}

// SupportChecker validates configured staging dependencies before durable
// acceptance. It must not perform the staging mutation.
type SupportChecker interface {
	CheckSupport(context.Context, Request) error
}

// EvidenceReader reads retained evidence by Provider operation ID. Evidence
// IDs, backend references, and host paths are never lookup authority here.
type EvidenceReader interface {
	GetEvidence(context.Context, string, time.Time) (Evidence, error)
}

type Reservation struct {
	Operation Operation
	Replayed  bool
}

func (r Reservation) Clone() Reservation {
	r.Operation = r.Operation.Clone()
	return r
}

// Authority atomically owns provider-local staging operation truth. It must
// validate sandbox generation and fencing during ReserveStage and use compare-
// and-set status transitions for UpdateStage.
type Authority interface {
	ReserveStage(context.Context, Request, time.Time) (Reservation, error)
	GetStage(context.Context, string) (Operation, error)
	ListStages(context.Context) ([]Operation, error)
	UpdateStage(context.Context, Operation, OperationStatus) error
	EvidenceReader
}
