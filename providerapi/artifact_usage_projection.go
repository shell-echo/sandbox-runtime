package providerapi

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func (h *protectedHandler) serveArtifactStage(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	stage, err := decodeArtifactStageRequest(document, admitted, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, "artifact staging request is invalid")
		return
	}
	reservation, err := h.artifactApp.Accept(request.Context(), stage)
	if err != nil {
		status, code, retryable := mapArtifactApplicationError(err)
		writeStandardError(response, status, code, retryable, artifactErrorMessage(code))
		return
	}
	projected, err := artifactOperationProjection(reservation.Operation)
	if err != nil {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "artifact staging operation is unavailable")
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func (h *protectedHandler) serveArtifactEvidence(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	evidence, err := h.artifactApp.GetEvidence(request.Context(), admitted.OperationID)
	if err != nil {
		status, code, retryable := mapArtifactEvidenceError(err)
		writeStandardError(response, status, code, retryable, artifactErrorMessage(code))
		return
	}
	if evidence.OperationID != admitted.OperationID || evidence.AttemptID != admitted.AttemptID || evidence.FencingToken != admitted.FencingToken || evidence.SandboxID != admitted.SandboxID {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "artifact staging evidence is unavailable")
		return
	}
	projected, err := artifactEvidenceProjection(evidence, h.now().UTC())
	if err != nil {
		if errors.Is(err, artifact.ErrEvidenceExpired) {
			writeStandardError(response, http.StatusGone, "SANDBOX_ARTIFACT_EVIDENCE_EXPIRED", false, artifactErrorMessage("SANDBOX_ARTIFACT_EVIDENCE_EXPIRED"))
			return
		}
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "artifact staging evidence is unavailable")
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func (h *protectedHandler) serveUsageEvidence(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	evidence, err := h.usageReader.GetEvidence(request.Context(), admitted.OperationID, h.now().UTC())
	if err != nil {
		status, code, retryable := mapUsageEvidenceError(err)
		writeStandardError(response, status, code, retryable, usageErrorMessage(code))
		return
	}
	if evidence.OperationID != admitted.OperationID || evidence.AttemptID != admitted.AttemptID || evidence.FencingToken != admitted.FencingToken || evidence.SandboxID != admitted.SandboxID {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", true, usageErrorMessage("SANDBOX_USAGE_EVIDENCE_UNAVAILABLE"))
		return
	}
	projected, err := usageEvidenceProjection(evidence, h.now().UTC())
	if err != nil {
		if errors.Is(err, usage.ErrEvidenceExpired) {
			writeStandardError(response, http.StatusGone, "SANDBOX_USAGE_EVIDENCE_EXPIRED", false, usageErrorMessage("SANDBOX_USAGE_EVIDENCE_EXPIRED"))
			return
		}
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", true, usageErrorMessage("SANDBOX_USAGE_EVIDENCE_UNAVAILABLE"))
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func decodeArtifactStageRequest(document []byte, admitted admission.AdmissionContext, now time.Time) (artifact.Request, error) {
	var request providerv1.ArtifactStagingRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxArtifactStagingRequestBytes, &request); err != nil {
		return artifact.Request{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) {
		return artifact.Request{}, errors.New("artifact staging deadline does not match admitted context")
	}
	if request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken || string(request.RequestDigest) != admitted.RequestDigest || admitted.Operation != admission.OperationStageArtifact {
		return artifact.Request{}, errors.New("artifact staging request does not match admitted context")
	}
	if request.ExpectedGeneration < 1 || request.RetentionSeconds < int64(artifact.MinRetention/time.Second) || request.RetentionSeconds > int64(artifact.MaxRetention/time.Second) {
		return artifact.Request{}, errors.New("artifact staging bounds are invalid")
	}
	retention := time.Duration(request.RetentionSeconds) * time.Second
	if retention/time.Second != time.Duration(request.RetentionSeconds) {
		return artifact.Request{}, errors.New("artifact staging retention overflows duration")
	}
	projected := artifact.Request{
		SandboxID: admitted.SandboxID, TenantID: admitted.TenantID,
		OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: string(request.RequestDigest), Deadline: deadline,
		ArtifactReference: request.ArtifactReference, SourcePath: request.SourcePath,
		ExpectedDigest: string(request.ExpectedDigest), ExpectedMediaType: request.ExpectedMediaType,
		MaxBytes: request.MaxBytes, Retention: retention,
	}
	if err := projected.Validate(now); err != nil {
		return artifact.Request{}, err
	}
	return projected, nil
}

func artifactOperationProjection(operation artifact.Operation) (providerv1.Operation, error) {
	if err := operation.Validate(); err != nil || operation.Request.FencingToken < 1 || operation.Request.FencingToken > math.MaxInt64 {
		return providerv1.Operation{}, errors.New("invalid artifact operation projection")
	}
	projected := providerv1.Operation{
		OperationID: operation.Request.OperationID, AttemptID: operation.Request.AttemptID,
		FencingToken: operation.Request.FencingToken, SandboxID: operation.Request.SandboxID,
		Type: providerv1.OperationArtifactStage, Status: providerv1.OperationState(operation.Status),
		ProviderOperationID: operation.Request.OperationID, ObservedAt: operation.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
	if operation.Failure != "" {
		code, outcome, retryable := artifactFailureCode(operation.Failure)
		projected.Error = &providerv1.ProviderError{Code: code, Message: artifactErrorMessage(code), Retryable: retryable, Outcome: outcome}
	}
	return projected, nil
}

func artifactFailureCode(reason artifact.FailureReason) (string, providerv1.ErrorOutcome, bool) {
	switch reason {
	case artifact.FailureDispatchUnknown:
		return "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN", providerv1.OutcomeUnknownFailure, true
	case artifact.FailureSourceMissing:
		return "SANDBOX_ARTIFACT_SOURCE_MISSING", providerv1.OutcomeKnownFailed, false
	case artifact.FailureContentRejected:
		return "SANDBOX_ARTIFACT_CONTENT_REJECTED", providerv1.OutcomeKnownFailed, false
	case artifact.FailureDeadlineExpired:
		return "SANDBOX_ARTIFACT_DEADLINE_EXPIRED", providerv1.OutcomeKnownFailed, false
	case artifact.FailureCancelledBeforeRun:
		return "SANDBOX_ARTIFACT_CANCELLED", providerv1.OutcomeKnownFailed, false
	default:
		return "SANDBOX_PROVIDER_ERROR", providerv1.OutcomeKnownFailed, false
	}
}

func artifactEvidenceProjection(evidence artifact.Evidence, now time.Time) (providerv1.ArtifactStagingEvidence, error) {
	if err := evidence.Validate(now); err != nil {
		return providerv1.ArtifactStagingEvidence{}, err
	}
	return providerv1.ArtifactStagingEvidence{
		OperationID: evidence.OperationID, AttemptID: evidence.AttemptID, FencingToken: evidence.FencingToken,
		SandboxID: evidence.SandboxID, ArtifactReference: evidence.ArtifactReference, StagingReference: evidence.StagingReference,
		Status: providerv1.ArtifactStagingStatus(evidence.Status), ContentDigest: providerv1.SHA256Digest(evidence.ContentDigest),
		MediaType: evidence.MediaType, SizeBytes: evidence.SizeBytes,
		TenantBindingCheck: artifactCheckProjection(evidence.TenantBindingCheck), ActiveContentCheck: artifactCheckProjection(evidence.ActiveContentCheck),
		MalwareCheck: artifactCheckProjection(evidence.MalwareCheck), ObservedAt: evidence.ObservedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt: evidence.ExpiresAt.UTC().Format(time.RFC3339Nano), EvidenceDigest: providerv1.SHA256Digest(evidence.EvidenceDigest),
	}, nil
}

func artifactCheckProjection(check artifact.Check) providerv1.EvidenceCheck {
	return providerv1.EvidenceCheck{Status: providerv1.EvidenceCheckStatus(check.Status), CheckedAt: check.CheckedAt.UTC().Format(time.RFC3339Nano), EvidenceReference: check.EvidenceReference}
}

func usageEvidenceProjection(evidence usage.Evidence, now time.Time) (providerv1.UsageEvidence, error) {
	if err := evidence.Validate(now); err != nil {
		return providerv1.UsageEvidence{}, err
	}
	entries := make([]providerv1.UsageEntry, len(evidence.Entries))
	for index, entry := range evidence.Entries {
		entries[index] = providerv1.UsageEntry{
			EntryID: entry.EntryID, SandboxID: entry.SandboxID, OperationID: entry.OperationID,
			Meter: providerv1.MeterID(entry.Meter), Quantity: entry.Quantity, Unit: entry.Unit,
			MeterSource: providerv1.MeterSource(entry.MeterSource), EvidenceReference: entry.EvidenceReference,
			OccurredAt: entry.OccurredAt.UTC().Format(time.RFC3339Nano),
		}
	}
	return providerv1.UsageEvidence{
		EvidenceID: evidence.EvidenceID, SandboxID: evidence.SandboxID, OperationID: evidence.OperationID,
		AttemptID: evidence.AttemptID, FencingToken: evidence.FencingToken, Entries: entries,
		ReconciliationStatus: providerv1.UsageReconciliationStatus(evidence.ReconciliationStatus),
		ObservedAt:           evidence.ObservedAt.UTC().Format(time.RFC3339Nano), RetainedUntil: evidence.RetainedUntil.UTC().Format(time.RFC3339Nano),
		EvidenceDigest: providerv1.SHA256Digest(evidence.EvidenceDigest),
	}, nil
}

func mapArtifactApplicationError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, artifact.ErrTenantBinding):
		return http.StatusForbidden, "SANDBOX_FORBIDDEN", false
	case errors.Is(err, artifact.ErrUnsupportedChecks):
		return http.StatusUnprocessableEntity, "SANDBOX_CAPABILITY_UNSUPPORTED", false
	case errors.Is(err, artifact.ErrIdempotencyConflict):
		return http.StatusConflict, "SANDBOX_IDEMPOTENCY_CONFLICT", false
	case errors.Is(err, artifact.ErrGenerationConflict):
		return http.StatusConflict, "SANDBOX_GENERATION_CONFLICT", false
	case errors.Is(err, artifact.ErrStaleFencingToken), errors.Is(err, artifact.ErrConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, artifact.ErrInvalidRequest), errors.Is(err, artifact.ErrDeadlineExpired):
		return http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false
	case errors.Is(err, artifact.ErrSandboxNotReady), errors.Is(err, artifact.ErrSandboxLeaseExpired), errors.Is(err, artifact.ErrDurability), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func mapArtifactEvidenceError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, artifact.ErrEvidenceNotFound), errors.Is(err, artifact.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND", false
	case errors.Is(err, artifact.ErrEvidenceExpired):
		return http.StatusGone, "SANDBOX_ARTIFACT_EVIDENCE_EXPIRED", false
	case errors.Is(err, artifact.ErrEvidencePending):
		return http.StatusServiceUnavailable, "SANDBOX_ARTIFACT_EVIDENCE_PENDING", true
	case errors.Is(err, artifact.ErrOutcomeUnknown):
		return http.StatusServiceUnavailable, "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func mapUsageEvidenceError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, usage.ErrEvidenceNotFound):
		return http.StatusNotFound, "SANDBOX_USAGE_EVIDENCE_NOT_FOUND", false
	case errors.Is(err, usage.ErrEvidenceExpired):
		return http.StatusGone, "SANDBOX_USAGE_EVIDENCE_EXPIRED", false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, usage.ErrEvidenceUnavailable):
		return http.StatusServiceUnavailable, "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_USAGE_EVIDENCE_UNAVAILABLE", true
	}
}

func artifactErrorMessage(code string) string {
	switch code {
	case "SANDBOX_ARTIFACT_EVIDENCE_NOT_FOUND":
		return "artifact staging evidence was not found"
	case "SANDBOX_ARTIFACT_EVIDENCE_PENDING":
		return "artifact staging evidence is not ready"
	case "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN":
		return "artifact staging outcome requires reconciliation"
	case "SANDBOX_ARTIFACT_EVIDENCE_EXPIRED":
		return "artifact staging evidence has expired"
	case "SANDBOX_ARTIFACT_SOURCE_MISSING":
		return "artifact staging source was not found"
	case "SANDBOX_ARTIFACT_CONTENT_REJECTED":
		return "artifact content was rejected"
	case "SANDBOX_ARTIFACT_DEADLINE_EXPIRED":
		return "artifact staging deadline expired"
	case "SANDBOX_ARTIFACT_CANCELLED":
		return "artifact staging was cancelled before dispatch"
	case "SANDBOX_IDEMPOTENCY_CONFLICT":
		return "artifact staging idempotency key conflicts with a different request"
	case "SANDBOX_GENERATION_CONFLICT":
		return "artifact staging generation conflicts with provider-local state"
	default:
		return "artifact staging operation is unavailable"
	}
}

func usageErrorMessage(code string) string {
	switch code {
	case "SANDBOX_USAGE_EVIDENCE_NOT_FOUND":
		return "usage evidence was not found"
	case "SANDBOX_USAGE_EVIDENCE_EXPIRED":
		return "usage evidence has expired"
	default:
		return "usage evidence is temporarily unavailable"
	}
}

func operationViewProjection(view provideroperation.View) (providerv1.Operation, error) {
	if err := view.Validate(); err != nil || view.FencingToken > math.MaxInt64 {
		return providerv1.Operation{}, errors.New("invalid Provider operation view")
	}
	projected := providerv1.Operation{
		OperationID: view.OperationID, AttemptID: view.AttemptID, FencingToken: view.FencingToken,
		SandboxID: view.SandboxID, Type: providerv1.OperationType(view.Type), Status: providerv1.OperationState(view.Status),
		ProviderOperationID: view.ProviderOperationID, ResultReference: view.ResultReference,
		ObservedAt: view.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
	if view.Failure != nil {
		code := strings.ToUpper(strings.ReplaceAll(view.Failure.Code, "-", "_"))
		if code == "" {
			code = "SANDBOX_PROVIDER_ERROR"
		}
		outcome := providerv1.OutcomeKnownFailed
		if view.Failure.Outcome == "outcome_unknown" {
			outcome = providerv1.OutcomeUnknownFailure
		}
		projected.Error = &providerv1.ProviderError{Code: code, Message: operationErrorMessage(code), Retryable: view.Failure.Retryable, Outcome: outcome}
	}
	return projected, nil
}

func operationErrorMessage(code string) string {
	if code == "SANDBOX_ARTIFACT_OUTCOME_UNKNOWN" {
		return artifactErrorMessage(code)
	}
	if strings.HasPrefix(code, "SANDBOX_EXEC_") {
		return execErrorMessage(code)
	}
	return lifecycleErrorMessage(code)
}
