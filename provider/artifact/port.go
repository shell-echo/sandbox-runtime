package artifact

import (
	"context"
	"time"
)

// Stager is a provider-local staging adapter. It may read the stable output
// mount, but it must return bounded evidence and never publish an artifact.
type Stager interface {
	Stage(context.Context, Request) (Evidence, error)
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
