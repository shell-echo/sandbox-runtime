package operation

import (
	"context"
	"errors"

	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserrepository "github.com/shell-echo/sandbox-runtime/provider/browser/repository"
)

// BrowserSessionReader projects the browser operation family without making
// the aggregator depend on browser repositories or transport DTOs.
type BrowserSessionReader struct {
	reader interface {
		GetOperation(context.Context, string) (browserapplication.Operation, error)
	}
}

func NewBrowserSessionReader(reader interface {
	GetOperation(context.Context, string) (browserapplication.Operation, error)
}) (*BrowserSessionReader, error) {
	if reader == nil {
		return nil, ErrUnavailable
	}
	return &BrowserSessionReader{reader: reader}, nil
}
func (r *BrowserSessionReader) ReadOperation(ctx context.Context, operationID string) (View, error) {
	operation, err := r.reader.GetOperation(ctx, operationID)
	if errors.Is(err, browserrepository.ErrNotFound) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	view := View{OperationID: operation.OperationID, AttemptID: operation.AttemptID, FencingToken: operation.FencingToken, SandboxID: operation.SandboxID, Type: TypeBrowserSession, Status: Status(operation.Status), ProviderOperationID: operation.OperationID, ObservedAt: operation.ObservedAt.UTC()}
	if err := view.Validate(); err != nil {
		return View{}, errors.Join(ErrUnavailable, err)
	}
	return view, nil
}

var _ Reader = (*BrowserSessionReader)(nil)
