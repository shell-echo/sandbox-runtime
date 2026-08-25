package usage

import (
	"context"
	"time"
)

// Collector supplies provider-local usage observations for one admitted
// operation. The calling platform remains responsible for accounting.
type Collector interface {
	Collect(context.Context, string, string, string, int64) (Evidence, error)
}

// EvidenceReader resolves usage evidence by Provider operation ID. It must not
// infer that an evidence ID and operation ID are interchangeable.
type EvidenceReader interface {
	GetEvidence(context.Context, string, time.Time) (Evidence, error)
}
