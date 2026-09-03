package operation

import (
	"context"
	"errors"
	"testing"

	browser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
)

type browserOperationSource func(context.Context, string) (browserapplication.Operation, error)

func (f browserOperationSource) GetOperation(ctx context.Context, id string) (browserapplication.Operation, error) {
	return f(ctx, id)
}

func TestBrowserSessionReaderProjectsBrowserOperationFamily(t *testing.T) {
	source := browserapplication.Operation{OperationID: "browser-operation-1", AttemptID: "browser-attempt-1", FencingToken: 2, SandboxID: "sandbox-1", Status: browser.StatusSucceeded, ObservedAt: operationTestTime}
	reader, err := NewBrowserSessionReader(browserOperationSource(func(context.Context, string) (browserapplication.Operation, error) { return source, nil }))
	if err != nil {
		t.Fatal(err)
	}
	view, err := reader.ReadOperation(context.Background(), source.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Type != TypeBrowserSession || view.Status != StatusSucceeded || view.OperationID != source.OperationID || view.ProviderOperationID != source.OperationID {
		t.Fatalf("view = %#v", view)
	}
}

func TestBrowserSessionReaderMapsNotFoundAndInvalid(t *testing.T) {
	reader, err := NewBrowserSessionReader(browserOperationSource(func(context.Context, string) (browserapplication.Operation, error) {
		return browserapplication.Operation{}, errors.New("missing")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadOperation(context.Background(), "missing"); err == nil {
		t.Fatal("missing operation succeeded")
	}
	invalid, err := NewBrowserSessionReader(browserOperationSource(func(context.Context, string) (browserapplication.Operation, error) {
		return browserapplication.Operation{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.ReadOperation(context.Background(), "invalid"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid operation = %v", err)
	}
}
