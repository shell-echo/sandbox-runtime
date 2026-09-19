package operation

import (
	"context"
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
)

type desktopOperationSource func(context.Context, string) (desktopapplication.Operation, error)

func (f desktopOperationSource) GetOperation(ctx context.Context, id string) (desktopapplication.Operation, error) {
	return f(ctx, id)
}

func TestDesktopSessionReaderProjectsBothOperationTypes(t *testing.T) {
	for _, operationType := range []desktopapplication.OperationType{desktopapplication.OperationOpenDesktopSession, desktopapplication.OperationCloseDesktopSession} {
		t.Run(string(operationType), func(t *testing.T) {
			source := desktopapplication.Operation{
				OperationID: "desktop-operation-1", AttemptID: "desktop-attempt-1", FencingToken: 3,
				SandboxID: "sandbox-1", Status: desktop.StatusSucceeded, ObservedAt: operationTestTime, Type: operationType,
			}
			reader, err := NewDesktopSessionReader(desktopOperationSource(func(context.Context, string) (desktopapplication.Operation, error) { return source, nil }))
			if err != nil {
				t.Fatal(err)
			}
			view, err := reader.ReadOperation(context.Background(), source.OperationID)
			if err != nil || view.Status != StatusSucceeded || view.OperationID != source.OperationID {
				t.Fatalf("view = %#v, %v", view, err)
			}
			want := TypeDesktopSession
			if operationType == desktopapplication.OperationCloseDesktopSession {
				want = TypeCloseDesktopSession
			}
			if view.Type != want {
				t.Fatalf("type = %q, want %q", view.Type, want)
			}
		})
	}
}

func TestDesktopSessionReaderMapsMissAndRejectsInvalid(t *testing.T) {
	reader, _ := NewDesktopSessionReader(desktopOperationSource(func(context.Context, string) (desktopapplication.Operation, error) {
		return desktopapplication.Operation{}, desktoprepository.ErrNotFound
	}))
	if _, err := reader.ReadOperation(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	invalid, _ := NewDesktopSessionReader(desktopOperationSource(func(context.Context, string) (desktopapplication.Operation, error) {
		return desktopapplication.Operation{}, nil
	}))
	if _, err := invalid.ReadOperation(context.Background(), "invalid"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid = %v", err)
	}
}
