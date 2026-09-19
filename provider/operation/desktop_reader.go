package operation

import (
	"context"
	"errors"

	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

// DesktopSessionReader projects open and close Desktop operations without
// exposing repository or runtime details to the operation aggregator.
type DesktopSessionReader struct {
	reader interface {
		GetOperation(context.Context, string) (desktopapplication.Operation, error)
	}
}

func NewDesktopSessionReader(reader interface {
	GetOperation(context.Context, string) (desktopapplication.Operation, error)
}) (*DesktopSessionReader, error) {
	if reader == nil {
		return nil, ErrUnavailable
	}
	return &DesktopSessionReader{reader: reader}, nil
}

func (r *DesktopSessionReader) ReadOperation(ctx context.Context, operationID string) (View, error) {
	operation, err := r.reader.GetOperation(ctx, operationID)
	if errors.Is(err, desktoprepository.ErrNotFound) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	operationType := TypeDesktopSession
	if operation.Type == desktopapplication.OperationCloseDesktopSession {
		operationType = TypeCloseDesktopSession
	} else if operation.Type != desktopapplication.OperationOpenDesktopSession {
		return View{}, ErrUnavailable
	}
	view := View{
		OperationID: operation.OperationID, AttemptID: operation.AttemptID,
		FencingToken: operation.FencingToken, SandboxID: operation.SandboxID,
		Type: operationType, Status: Status(operation.Status), ProviderOperationID: operation.OperationID,
		ObservedAt: operation.ObservedAt.UTC(),
	}
	if err := view.Validate(); err != nil {
		return View{}, errors.Join(ErrUnavailable, err)
	}
	return view, nil
}

var _ Reader = (*DesktopSessionReader)(nil)
