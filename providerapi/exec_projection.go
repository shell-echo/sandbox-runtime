package providerapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	execapplication "github.com/shell-echo/sandbox-runtime/provider/exec/application"
	execrepository "github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func (h *protectedHandler) serveExec(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	execRequest, err := decodeExecRequest(document, admitted, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, execErrorMessage("SANDBOX_INVALID_REQUEST"))
		return
	}
	operation, err := h.execApp.AcceptExec(request.Context(), execRequest)
	if err != nil {
		status, code, retryable := mapExecApplicationError(err, false)
		writeStandardError(response, status, code, retryable, execErrorMessage(code))
		return
	}
	projected, err := operationViewProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, execErrorMessage("SANDBOX_PROVIDER_UNAVAILABLE"))
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func (h *protectedHandler) serveExecCancellation(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	intent, err := decodeExecCancellation(document, admitted, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, execErrorMessage("SANDBOX_INVALID_REQUEST"))
		return
	}
	operation, err := h.execApp.AcceptCancellation(request.Context(), intent)
	if err != nil {
		status, code, retryable := mapExecApplicationError(err, true)
		writeStandardError(response, status, code, retryable, execErrorMessage(code))
		return
	}
	projected, err := operationViewProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, execErrorMessage("SANDBOX_PROVIDER_UNAVAILABLE"))
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func (h *protectedHandler) serveExecResult(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	result, err := h.execApp.GetResult(request.Context(), admitted.OperationID)
	if err != nil {
		status, code, retryable := mapExecResultError(err)
		writeStandardError(response, status, code, retryable, execErrorMessage(code))
		return
	}
	if result.OperationID != admitted.OperationID || result.AttemptID != admitted.AttemptID || result.FencingToken != admitted.FencingToken || result.SandboxID != admitted.SandboxID {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, execErrorMessage("SANDBOX_PROVIDER_UNAVAILABLE"))
		return
	}
	projected, err := execResultProjection(result)
	if err != nil {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, execErrorMessage("SANDBOX_PROVIDER_UNAVAILABLE"))
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func decodeExecRequest(document []byte, admitted admission.AdmissionContext, now time.Time) (providerexec.Request, error) {
	var request providerv1.ExecRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxExecRequestBytes, &request); err != nil {
		return providerexec.Request{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) || admitted.Operation != admission.OperationExec ||
		request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken || string(request.RequestDigest) != admitted.RequestDigest {
		return providerexec.Request{}, providerexec.ErrInvalidRequest
	}
	retention := time.Duration(request.ResultRetentionSeconds) * time.Second
	if request.ResultRetentionSeconds < 1 || retention/time.Second != time.Duration(request.ResultRetentionSeconds) {
		return providerexec.Request{}, providerexec.ErrInvalidRequest
	}
	projected := providerexec.Request{
		SandboxID: admitted.SandboxID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: string(request.RequestDigest), Deadline: deadline,
		Command: append([]string(nil), request.Command...), WorkingDirectory: request.WorkingDirectory,
		ResultRetention: retention, Environment: cloneStringMap(request.Environment),
		SecretReferenceIDs: append([]string(nil), request.SecretReferenceIDs...), SecretGrantID: request.SecretGrantID,
		SecretGrantDigest: string(request.SecretGrantDigest), StdinReference: request.StdinReference,
	}
	if request.Capture != nil {
		if request.Capture.Stdout != nil {
			projected.CaptureStdout = *request.Capture.Stdout
		}
		if request.Capture.Stderr != nil {
			projected.CaptureStderr = *request.Capture.Stderr
		}
		if request.Capture.MaxBytes != nil {
			projected.CaptureMaxBytes = *request.Capture.MaxBytes
		}
	}
	if err := projected.Validate(now); err != nil {
		return providerexec.Request{}, err
	}
	return projected, nil
}

func decodeExecCancellation(document []byte, admitted admission.AdmissionContext, now time.Time) (providerexec.CancellationIntent, error) {
	var request providerv1.CancelExecRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxCancelExecRequestBytes, &request); err != nil {
		return providerexec.CancellationIntent{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) || admitted.Operation != admission.OperationCancelExec ||
		request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken || string(request.RequestDigest) != admitted.RequestDigest {
		return providerexec.CancellationIntent{}, providerexec.ErrInvalidCancellation
	}
	intent := providerexec.CancellationIntent{
		SandboxID: admitted.SandboxID, OperationID: request.OperationID, AttemptID: request.AttemptID,
		FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: string(request.RequestDigest), Deadline: deadline,
		TargetOperationID: request.TargetOperationID, TargetAttemptID: request.TargetAttemptID,
		Reason: providerexec.CancellationReason(request.Reason),
	}
	if err := intent.Validate(now); err != nil {
		return providerexec.CancellationIntent{}, err
	}
	return intent, nil
}

func execResultProjection(result providerexec.Result) (providerv1.ExecResult, error) {
	if err := result.Validate(); err != nil {
		return providerv1.ExecResult{}, err
	}
	projected := providerv1.ExecResult{
		OperationID: result.OperationID, AttemptID: result.AttemptID, FencingToken: result.FencingToken,
		SandboxID: result.SandboxID, Status: providerv1.ExecResultStatus(result.Status), Signal: result.Signal,
		StdoutReference: result.StdoutReference, StderrReference: result.StderrReference,
		StartedAt: result.StartedAt.UTC().Format(time.RFC3339Nano), CompletedAt: result.CompletedAt.UTC().Format(time.RFC3339Nano),
		RetainedUntil: result.RetainedUntil.UTC().Format(time.RFC3339Nano),
	}
	if result.ExitCode != nil {
		exitCode := int64(*result.ExitCode)
		projected.ExitCode = &exitCode
	}
	if result.Error != nil {
		projected.Error = &providerv1.ProviderError{
			Code: result.Error.Code, Message: result.Error.Message, Retryable: result.Error.Retryable,
			Outcome: providerv1.ErrorOutcome(result.Error.Outcome),
		}
	}
	return projected, nil
}

func mapExecApplicationError(err error, cancellation bool) (int, string, bool) {
	switch {
	case errors.Is(err, execrepository.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_EXEC_NOT_FOUND", false
	case errors.Is(err, execrepository.ErrIdempotencyConflict):
		return http.StatusConflict, "SANDBOX_IDEMPOTENCY_CONFLICT", false
	case errors.Is(err, lifecycle.ErrGenerationConflict):
		return http.StatusConflict, "SANDBOX_GENERATION_CONFLICT", false
	case errors.Is(err, execrepository.ErrAlreadyExists), errors.Is(err, providerexec.ErrExecutionNotRunning):
		if cancellation {
			return http.StatusUnprocessableEntity, "SANDBOX_EXEC_NOT_CANCELLABLE", false
		}
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, execrepository.ErrConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, providerexec.ErrUnsupportedRequest), errors.Is(err, execapplication.ErrSandboxNotReady), errors.Is(err, execapplication.ErrSandboxExpired), errors.Is(err, lifecyclerepository.ErrNotFound):
		return http.StatusUnprocessableEntity, "SANDBOX_EXEC_UNSUPPORTED", false
	case errors.Is(err, providerexec.ErrInvalidRequest), errors.Is(err, providerexec.ErrInvalidCancellation), errors.Is(err, providerexec.ErrDeadlineExpired):
		return http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func mapExecResultError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, execrepository.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_EXEC_RESULT_NOT_FOUND", false
	case errors.Is(err, execrepository.ErrExpired):
		return http.StatusGone, "SANDBOX_EXEC_RESULT_EXPIRED", false
	case errors.Is(err, execrepository.ErrPending):
		return http.StatusServiceUnavailable, "SANDBOX_EXEC_RESULT_PENDING", true
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func execErrorMessage(code string) string {
	switch code {
	case "SANDBOX_INVALID_REQUEST":
		return "execution request is invalid"
	case "SANDBOX_EXEC_NOT_FOUND", "SANDBOX_EXEC_RESULT_NOT_FOUND":
		return "execution was not found"
	case "SANDBOX_EXEC_RESULT_EXPIRED":
		return "execution result has expired"
	case "SANDBOX_EXEC_RESULT_PENDING":
		return "execution result is not ready"
	case "SANDBOX_EXEC_FAILED":
		return "execution could not be started"
	case "SANDBOX_EXEC_OUTCOME_UNKNOWN":
		return "execution outcome requires reconciliation"
	case "SANDBOX_EXEC_NOT_CANCELLABLE":
		return "execution cannot accept cancellation"
	case "SANDBOX_EXEC_UNSUPPORTED":
		return "execution policy is unsupported"
	case "SANDBOX_IDEMPOTENCY_CONFLICT":
		return "execution idempotency key conflicts with a different request"
	case "SANDBOX_GENERATION_CONFLICT":
		return "sandbox generation conflicts with provider-local state"
	case "SANDBOX_CONFLICT":
		return "execution request conflicts with provider-local state"
	default:
		return "execution service is temporarily unavailable"
	}
}

func cloneStringMap(value map[string]string) map[string]string {
	if value == nil {
		return nil
	}
	clone := make(map[string]string, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}
