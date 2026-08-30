package operation

import (
	"context"
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
)

type sessionOperationReaderFunc func(context.Context, string) (sessionapplication.Operation, error)

func (f sessionOperationReaderFunc) GetOperation(ctx context.Context, operationID string) (sessionapplication.Operation, error) {
	return f(ctx, operationID)
}

func TestSessionReaderProjectsOperationFamily(t *testing.T) {
	source := sessionapplication.Operation{
		OperationID: "session-operation-1", AttemptID: "session-attempt-1", FencingToken: 3,
		SandboxID: "sandbox-1", Status: session.StatusSucceeded, ObservedAt: operationTestTime,
	}
	reader, err := NewSessionReader(sessionOperationReaderFunc(func(context.Context, string) (sessionapplication.Operation, error) {
		return source, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	view, err := reader.ReadOperation(context.Background(), source.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if view.OperationID != source.OperationID || view.Type != TypeRuntimeSession || view.Status != StatusSucceeded || view.ProviderOperationID != source.OperationID || view.ResultReference != "" || view.Failure != nil {
		t.Fatalf("session operation view = %#v", view)
	}
}

func TestSessionReaderMapsMissAndRejectsInvalidProjection(t *testing.T) {
	missing, err := NewSessionReader(sessionOperationReaderFunc(func(context.Context, string) (sessionapplication.Operation, error) {
		return sessionapplication.Operation{}, session.ErrNotFound
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.ReadOperation(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session operation = %v", err)
	}

	invalid, err := NewSessionReader(sessionOperationReaderFunc(func(context.Context, string) (sessionapplication.Operation, error) {
		return sessionapplication.Operation{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.ReadOperation(context.Background(), "invalid"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid session operation = %v", err)
	}
}

func TestNewSessionReaderRejectsNil(t *testing.T) {
	if _, err := NewSessionReader(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewSessionReader(nil) = %v", err)
	}
}
