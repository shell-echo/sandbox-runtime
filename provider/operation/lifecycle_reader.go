package operation

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type LifecycleReader struct {
	reader interface {
		GetOperation(context.Context, string) (lifecycle.Operation, error)
	}
}

func NewLifecycleReader(reader interface {
	GetOperation(context.Context, string) (lifecycle.Operation, error)
}) (*LifecycleReader, error) {
	if reader == nil {
		return nil, ErrUnavailable
	}
	return &LifecycleReader{reader: reader}, nil
}

func (r *LifecycleReader) ReadOperation(ctx context.Context, operationID string) (View, error) {
	operation, err := r.reader.GetOperation(ctx, operationID)
	if errors.Is(err, repository.ErrNotFound) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	if err := operation.Validate(); err != nil {
		return View{}, errors.Join(ErrUnavailable, err)
	}
	view := View{
		OperationID: operation.ID, AttemptID: operation.AttemptID, FencingToken: int64(operation.FencingToken),
		SandboxID: operation.SandboxID, Type: Type(operation.Type), Status: Status(operation.State),
		ProviderOperationID: operation.ID, ObservedAt: operation.ObservedAt.UTC(),
	}
	if operation.Failure != nil {
		outcome := string(operation.Failure.Outcome)
		view.Failure = &Failure{Code: operation.Failure.Code, Retryable: operation.Failure.Retryable, Outcome: outcome}
	}
	return view, nil
}

var _ Reader = (*LifecycleReader)(nil)
