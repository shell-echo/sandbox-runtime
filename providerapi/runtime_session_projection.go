package providerapi

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

var runtimeSessionEndpointPattern = regexp.MustCompile(`^ref:session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func (h *protectedHandler) serveRuntimeSessionOpen(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	open, err := decodeRuntimeSessionOpenRequest(document, admitted, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, "terminal session request is invalid")
		return
	}
	operation, err := h.sessionApp.Open(request.Context(), open)
	if err != nil {
		status, code, retryable := mapRuntimeSessionError(err)
		writeStandardError(response, status, code, retryable, runtimeSessionErrorMessage(code))
		return
	}
	projected, err := runtimeSessionOperationProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "terminal session operation could not be projected")
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func (h *protectedHandler) serveRuntimeSessionHandoff(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	handoff, err := h.sessionApp.GetHandoff(request.Context(), admitted.OperationID)
	if err != nil {
		status, code, retryable := mapRuntimeSessionError(err)
		writeStandardError(response, status, code, retryable, runtimeSessionErrorMessage(code))
		return
	}
	if !h.now().UTC().Before(handoff.ExpiresAt) {
		writeStandardError(response, http.StatusGone, "SANDBOX_RUNTIME_SESSION_EXPIRED", false, runtimeSessionErrorMessage("SANDBOX_RUNTIME_SESSION_EXPIRED"))
		return
	}
	projected, err := runtimeSessionHandoffProjection(handoff)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "terminal session handoff could not be projected")
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func decodeRuntimeSessionOpenRequest(document []byte, admitted admission.AdmissionContext, now time.Time) (session.OpenRequest, error) {
	var request providerv1.RuntimeSessionOpenRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxRuntimeSessionOpenRequestBytes, &request); err != nil {
		return session.OpenRequest{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) {
		return session.OpenRequest{}, errors.New("terminal session deadline does not match admitted context")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil {
		return session.OpenRequest{}, errors.New("terminal session expiry is invalid")
	}
	if request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken ||
		string(request.RequestDigest) != admitted.RequestDigest || request.ExpectedGeneration < 1 || request.RuntimeType != providerv1.TerminalRuntimeTerminal ||
		admitted.ProviderRevisionID == "" {
		return session.OpenRequest{}, errors.New("terminal session request does not match admitted context")
	}
	if request.FencingToken > math.MaxInt64 {
		return session.OpenRequest{}, errors.New("terminal session fencing token exceeds supported range")
	}
	open := session.OpenRequest{
		SandboxID:           admitted.SandboxID,
		ProviderRevisionID:  admitted.ProviderRevisionID,
		OperationID:         request.OperationID,
		AttemptID:           request.AttemptID,
		FencingToken:        request.FencingToken,
		IdempotencyKey:      request.IdempotencyKey,
		RequestDigest:       string(request.RequestDigest),
		Deadline:            deadline,
		ExpectedGeneration:  request.ExpectedGeneration,
		RuntimeSessionID:    request.RuntimeSessionID,
		RuntimeType:         session.RuntimeTerminal,
		CapabilityProfileID: request.CapabilityProfileID,
		ExpiresAt:           expiresAt,
	}
	if err := open.Validate(now); err != nil {
		return session.OpenRequest{}, err
	}
	return open, nil
}

func runtimeSessionOperationProjection(operation sessionapplication.Operation) (providerv1.Operation, error) {
	if err := lifecycle.ValidateIdentifier(operation.OperationID); err != nil {
		return providerv1.Operation{}, err
	}
	if err := lifecycle.ValidateIdentifier(operation.AttemptID); err != nil {
		return providerv1.Operation{}, err
	}
	if err := lifecycle.ValidateIdentifier(operation.SandboxID); err != nil {
		return providerv1.Operation{}, err
	}
	if operation.FencingToken < 1 || operation.ObservedAt.IsZero() {
		return providerv1.Operation{}, errors.New("invalid terminal session operation projection")
	}
	switch operation.Status {
	case session.StatusAccepted, session.StatusRunning, session.StatusSucceeded, session.StatusFailed, session.StatusCancelled, session.StatusOutcomeUnknown:
	default:
		return providerv1.Operation{}, errors.New("invalid terminal session operation status")
	}
	return providerv1.Operation{
		OperationID:         operation.OperationID,
		AttemptID:           operation.AttemptID,
		FencingToken:        operation.FencingToken,
		SandboxID:           operation.SandboxID,
		Type:                providerv1.OperationOpenRuntimeSession,
		Status:              providerv1.OperationState(operation.Status),
		ProviderOperationID: operation.OperationID,
		ObservedAt:          operation.ObservedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func runtimeSessionHandoffProjection(handoff sessionapplication.Handoff) (providerv1.RuntimeSessionHandoff, error) {
	if err := lifecycle.ValidateIdentifier(handoff.OperationID); err != nil {
		return providerv1.RuntimeSessionHandoff{}, err
	}
	if err := lifecycle.ValidateIdentifier(handoff.AttemptID); err != nil {
		return providerv1.RuntimeSessionHandoff{}, err
	}
	if err := lifecycle.ValidateIdentifier(handoff.SandboxID); err != nil {
		return providerv1.RuntimeSessionHandoff{}, err
	}
	if err := lifecycle.ValidateIdentifier(handoff.RuntimeSessionID); err != nil {
		return providerv1.RuntimeSessionHandoff{}, err
	}
	if err := lifecycle.ValidateIdentifier(handoff.CapabilityProfileID); err != nil {
		return providerv1.RuntimeSessionHandoff{}, err
	}
	if handoff.FencingToken < 1 || handoff.ConnectionGeneration < 1 || handoff.ExpiresAt.IsZero() ||
		handoff.RuntimeType != session.RuntimeTerminal || handoff.Protocol != session.ProtocolWebSocket ||
		!runtimeSessionEndpointPattern.MatchString(handoff.InternalEndpointReference) {
		return providerv1.RuntimeSessionHandoff{}, errors.New("invalid terminal session handoff projection")
	}
	return providerv1.RuntimeSessionHandoff{
		OperationID:               handoff.OperationID,
		AttemptID:                 handoff.AttemptID,
		FencingToken:              handoff.FencingToken,
		SandboxID:                 handoff.SandboxID,
		RuntimeSessionID:          handoff.RuntimeSessionID,
		RuntimeType:               providerv1.TerminalRuntimeTerminal,
		CapabilityProfileID:       handoff.CapabilityProfileID,
		Protocol:                  providerv1.TerminalProtocolWebSocket,
		InternalEndpointReference: handoff.InternalEndpointReference,
		ConnectionGeneration:      handoff.ConnectionGeneration,
		ExpiresAt:                 handoff.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func mapRuntimeSessionError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, sessionapplication.ErrHandoffPending):
		return http.StatusServiceUnavailable, "SANDBOX_RUNTIME_SESSION_PENDING", true
	case errors.Is(err, session.ErrHandoffExpired):
		return http.StatusGone, "SANDBOX_RUNTIME_SESSION_EXPIRED", false
	case errors.Is(err, session.ErrHandoffUnavailable):
		return http.StatusNotFound, "SANDBOX_RUNTIME_SESSION_UNAVAILABLE", false
	case errors.Is(err, session.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_NOT_FOUND", false
	case errors.Is(err, session.ErrIdempotencyConflict):
		return http.StatusConflict, "SANDBOX_IDEMPOTENCY_CONFLICT", false
	case errors.Is(err, session.ErrConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, session.ErrGenerationConflict):
		return http.StatusConflict, "SANDBOX_GENERATION_CONFLICT", false
	case errors.Is(err, session.ErrStaleFencingToken):
		return http.StatusConflict, "SANDBOX_STALE_FENCING_TOKEN", false
	case errors.Is(err, session.ErrProviderRevisionConflict):
		return http.StatusConflict, "SANDBOX_PROVIDER_REVISION_CONFLICT", false
	case errors.Is(err, session.ErrSandboxNotReady), errors.Is(err, session.ErrLeaseExpired), errors.Is(err, session.ErrCapabilityUnsupported):
		return http.StatusUnprocessableEntity, "SANDBOX_CAPABILITY_UNSUPPORTED", false
	case errors.Is(err, session.ErrInvalidRequest), errors.Is(err, session.ErrDeadlineExpired), errors.Is(err, session.ErrInvalidExpiry):
		return http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false
	case errors.Is(err, sessionapplication.ErrInvalidApplication), errors.Is(err, session.ErrDurability), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func runtimeSessionErrorMessage(code string) string {
	switch code {
	case "SANDBOX_RUNTIME_SESSION_PENDING":
		return "terminal session handoff is not ready"
	case "SANDBOX_RUNTIME_SESSION_EXPIRED":
		return "terminal session handoff has expired"
	case "SANDBOX_RUNTIME_SESSION_UNAVAILABLE":
		return "terminal session handoff is unavailable"
	case "SANDBOX_CAPABILITY_UNSUPPORTED":
		return "terminal session capability or sandbox state is unsupported"
	case "SANDBOX_PROVIDER_REVISION_CONFLICT":
		return "terminal session Provider revision conflicts with provider-local state"
	default:
		return lifecycleErrorMessage(code)
	}
}
