package usage

import (
	"context"
	"errors"
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

// Store retains immutable provider-local usage evidence. It is not an
// accounting or billing ledger.
type Store interface {
	EvidenceReader
	Put(context.Context, Evidence) error
	Close() error
}

// Aggregator reads mutually exclusive operation families from one Provider
// usage surface. Any duplicate authority or non-miss error fails closed.
type Aggregator struct {
	readers []EvidenceReader
}

func NewAggregator(readers ...EvidenceReader) (*Aggregator, error) {
	if len(readers) == 0 {
		return nil, ErrEvidenceUnavailable
	}
	for _, reader := range readers {
		if reader == nil {
			return nil, ErrEvidenceUnavailable
		}
	}
	return &Aggregator{readers: append([]EvidenceReader(nil), readers...)}, nil
}

func (a *Aggregator) GetEvidence(ctx context.Context, operationID string, now time.Time) (Evidence, error) {
	if ctx == nil {
		return Evidence{}, context.Canceled
	}
	if a == nil || operationID == "" || now.IsZero() {
		return Evidence{}, ErrEvidenceUnavailable
	}
	var found *Evidence
	expired := false
	for _, reader := range a.readers {
		evidence, err := reader.GetEvidence(ctx, operationID, now.UTC())
		switch {
		case errors.Is(err, ErrEvidenceNotFound):
			continue
		case errors.Is(err, ErrEvidenceExpired):
			if found != nil || expired {
				return Evidence{}, ErrEvidenceUnavailable
			}
			expired = true
			continue
		case err != nil:
			return Evidence{}, err
		}
		if evidence.OperationID != operationID || evidence.Validate(now.UTC()) != nil || found != nil || expired {
			return Evidence{}, ErrEvidenceUnavailable
		}
		copyEvidence := evidence.Clone()
		found = &copyEvidence
	}
	if found != nil {
		return found.Clone(), nil
	}
	if expired {
		return Evidence{}, ErrEvidenceExpired
	}
	return Evidence{}, ErrEvidenceNotFound
}

var _ EvidenceReader = (*Aggregator)(nil)
