package operation

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

type ArtifactReader struct {
	reader interface {
		GetOperation(context.Context, string) (artifact.Operation, error)
	}
}

func NewArtifactReader(reader interface {
	GetOperation(context.Context, string) (artifact.Operation, error)
}) (*ArtifactReader, error) {
	if reader == nil {
		return nil, ErrUnavailable
	}
	return &ArtifactReader{reader: reader}, nil
}

func (r *ArtifactReader) ReadOperation(ctx context.Context, operationID string) (View, error) {
	operation, err := r.reader.GetOperation(ctx, operationID)
	if errors.Is(err, artifact.ErrNotFound) {
		return View{}, ErrNotFound
	}
	if err != nil {
		return View{}, err
	}
	if err := operation.Validate(); err != nil {
		return View{}, errors.Join(ErrUnavailable, err)
	}
	view := View{
		OperationID: operation.Request.OperationID, AttemptID: operation.Request.AttemptID,
		FencingToken: operation.Request.FencingToken, SandboxID: operation.Request.SandboxID,
		Type: TypeArtifactStage, Status: Status(operation.Status), ProviderOperationID: operation.Request.OperationID,
		ObservedAt: operation.ObservedAt.UTC(),
	}
	if operation.Status == artifact.OperationOutcomeUnknown {
		view.Failure = &Failure{Code: "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN", Retryable: true, Outcome: "outcome_unknown"}
	}
	return view, nil
}

var _ Reader = (*ArtifactReader)(nil)
