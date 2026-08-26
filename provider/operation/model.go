// Package operation provides transport-neutral Provider operation views and
// aggregation across independently owned operation families.
package operation

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var resultReferencePattern = regexp.MustCompile(`^ref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,399}$`)

var (
	ErrNotFound    = errors.New("Provider operation not found")
	ErrConflict    = errors.New("Provider operation family conflict")
	ErrUnavailable = errors.New("Provider operation family unavailable")
	ErrInvalidView = errors.New("invalid Provider operation view")
)

type Type string

const (
	TypeCreate         Type = "create"
	TypeExec           Type = "exec"
	TypeCancelExec     Type = "cancel_exec"
	TypeRuntimeSession Type = "open_runtime_session"
	TypeArtifactStage  Type = "artifact_stage"
)

type Status string

const (
	StatusAccepted       Status = "accepted"
	StatusRunning        Status = "running"
	StatusSucceeded      Status = "succeeded"
	StatusFailed         Status = "failed"
	StatusCancelled      Status = "cancelled"
	StatusOutcomeUnknown Status = "outcome_unknown"
)

type Failure struct {
	Code      string
	Retryable bool
	Outcome   string
}

// View is the internal immutable projection shared by operation family
// readers. It contains no wire DTO, repository, driver, endpoint, or secret.
type View struct {
	OperationID         string
	AttemptID           string
	FencingToken        int64
	SandboxID           string
	Type                Type
	Status              Status
	ProviderOperationID string
	ResultReference     string
	ObservedAt          time.Time
	Failure             *Failure
}

func (v View) Clone() View {
	clone := v
	if v.Failure != nil {
		failure := *v.Failure
		clone.Failure = &failure
	}
	return clone
}

func (v View) Validate() error {
	if v.OperationID == "" || v.AttemptID == "" || v.SandboxID == "" || v.FencingToken < 1 || v.ObservedAt.IsZero() {
		return ErrInvalidView
	}
	if v.ResultReference != "" && !resultReferencePattern.MatchString(v.ResultReference) {
		return ErrInvalidView
	}
	switch v.Type {
	case TypeCreate, TypeExec, TypeCancelExec, TypeRuntimeSession, TypeArtifactStage:
	default:
		return ErrInvalidView
	}
	switch v.Status {
	case StatusAccepted, StatusRunning, StatusSucceeded, StatusFailed, StatusCancelled, StatusOutcomeUnknown:
	default:
		return ErrInvalidView
	}
	if v.Failure != nil && v.Status != StatusFailed && v.Status != StatusOutcomeUnknown {
		return ErrInvalidView
	}
	return nil
}

// Reader owns exactly one operation family. A miss must be reported as
// operation.ErrNotFound; all other errors remain fail-closed to the caller.
type Reader interface {
	ReadOperation(context.Context, string) (View, error)
}

type Aggregator struct {
	readers []Reader
}

func NewAggregator(readers ...Reader) (*Aggregator, error) {
	for _, reader := range readers {
		if reader == nil {
			return nil, ErrUnavailable
		}
	}
	return &Aggregator{readers: append([]Reader(nil), readers...)}, nil
}

func (a *Aggregator) ReadOperation(ctx context.Context, operationID string) (View, error) {
	if a == nil || operationID == "" {
		return View{}, ErrUnavailable
	}
	if ctx == nil {
		return View{}, context.Canceled
	}
	var found *View
	for _, reader := range a.readers {
		view, err := reader.ReadOperation(ctx, operationID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return View{}, err
		}
		if err := view.Validate(); err != nil {
			return View{}, errors.Join(ErrUnavailable, err)
		}
		if view.OperationID != operationID {
			return View{}, errors.Join(ErrConflict, ErrInvalidView)
		}
		if found != nil {
			return View{}, ErrConflict
		}
		copyView := view.Clone()
		found = &copyView
	}
	if found == nil {
		return View{}, ErrNotFound
	}
	return found.Clone(), nil
}

var _ Reader = (*Aggregator)(nil)
