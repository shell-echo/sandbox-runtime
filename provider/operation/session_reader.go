package operation

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
)

type SessionReader struct {
	reader interface {
		GetOperation(context.Context, string) (sessionapplication.Operation, error)
	}
}

func NewSessionReader(reader interface {
	GetOperation(context.Context, string) (sessionapplication.Operation, error)
}) (*SessionReader, error) {
	if reader == nil {
		return nil, ErrUnavailable
	}
	return &SessionReader{reader: reader}, nil
}

func (r *SessionReader) ReadOperation(ctx context.Context, operationID string) (View, error) {
	operation, err := r.reader.GetOperation(ctx, operationID)
	if errors.Is(err, session.ErrNotFound) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	view := View{
		OperationID: operation.OperationID, AttemptID: operation.AttemptID,
		FencingToken: operation.FencingToken, SandboxID: operation.SandboxID,
		Type: TypeRuntimeSession, Status: Status(operation.Status),
		ProviderOperationID: operation.OperationID, ObservedAt: operation.ObservedAt.UTC(),
	}
	if err := view.Validate(); err != nil {
		return View{}, errors.Join(ErrUnavailable, err)
	}
	return view, nil
}

var _ Reader = (*SessionReader)(nil)
