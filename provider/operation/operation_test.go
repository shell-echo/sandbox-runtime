package operation

import (
	"context"
	"errors"
	"testing"
	"time"
)

var operationTestTime = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

type readerFunc func(context.Context, string) (View, error)

func (f readerFunc) ReadOperation(ctx context.Context, operationID string) (View, error) {
	return f(ctx, operationID)
}

func operationView(id string, kind Type) View {
	return View{OperationID: id, AttemptID: "attempt-1", FencingToken: 1, SandboxID: "sandbox-1", Type: kind, Status: StatusAccepted, ProviderOperationID: id, ObservedAt: operationTestTime}
}

func TestAggregatorReadsAllFamiliesAndOnlyAllMissIsNotFound(t *testing.T) {
	lifecycleMiss := readerFunc(func(context.Context, string) (View, error) { return View{}, ErrNotFound })
	artifactHit := operationView("artifact-1", TypeArtifactStage)
	artifactReader := readerFunc(func(_ context.Context, id string) (View, error) {
		if id == artifactHit.OperationID {
			return artifactHit, nil
		}
		return View{}, ErrNotFound
	})
	aggregator, _ := NewAggregator(lifecycleMiss, artifactReader)
	got, err := aggregator.ReadOperation(context.Background(), artifactHit.OperationID)
	if err != nil || got.Type != TypeArtifactStage {
		t.Fatalf("ReadOperation() = %#v, %v", got, err)
	}
	if _, err := aggregator.ReadOperation(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("all miss = %v, want ErrNotFound", err)
	}
}

func TestAggregatorFailsClosedOnUnavailableAndDuplicate(t *testing.T) {
	view := operationView("same", TypeCreate)
	for name, readers := range map[string][]Reader{
		"unavailable": {
			readerFunc(func(context.Context, string) (View, error) {
				return View{}, errors.Join(ErrUnavailable, errors.New("closed"))
			}),
		},
		"duplicate": {
			readerFunc(func(context.Context, string) (View, error) { return view, nil }),
			readerFunc(func(context.Context, string) (View, error) { return operationView("same", TypeArtifactStage), nil }),
		},
	} {
		t.Run(name, func(t *testing.T) {
			aggregator, _ := NewAggregator(readers...)
			if _, err := aggregator.ReadOperation(context.Background(), view.OperationID); !errors.Is(err, map[string]error{"unavailable": ErrUnavailable, "duplicate": ErrConflict}[name]) {
				t.Fatalf("ReadOperation() error = %v", err)
			}
		})
	}
}

func TestAggregatorReturnsImmutableViewAndPropagatesContext(t *testing.T) {
	view := operationView("immutable", TypeArtifactStage)
	aggregator, _ := NewAggregator(readerFunc(func(ctx context.Context, _ string) (View, error) {
		if err := ctx.Err(); err != nil {
			return View{}, err
		}
		return view, nil
	}))
	got, err := aggregator.ReadOperation(context.Background(), view.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	got.OperationID = "mutated"
	again, err := aggregator.ReadOperation(context.Background(), view.OperationID)
	if err != nil || again.OperationID != view.OperationID {
		t.Fatalf("view mutation leaked: %#v, %v", again, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := aggregator.ReadOperation(ctx, view.OperationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read = %v", err)
	}
}
