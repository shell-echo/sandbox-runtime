package providerapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

var desktopSessionEndpointPattern = regexp.MustCompile(`^ref:desktop-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func (h *protectedHandler) serveDesktopSessionOpen(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	open, err := decodeDesktopSessionOpenRequest(document, admitted, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, "desktop session request is invalid")
		return
	}
	operation, err := h.desktopApp.Open(request.Context(), open)
	if err != nil {
		status, code, retryable := mapDesktopSessionError(err)
		writeStandardError(response, status, code, retryable, desktopSessionErrorMessage(code))
		return
	}
	if !desktopOperationMatchesAdmission(operation, admitted) {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "desktop session operation is unavailable")
		return
	}
	projected, err := desktopSessionOperationProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "desktop session operation could not be projected")
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func (h *protectedHandler) serveDesktopSessionHandoff(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	handoff, err := h.desktopApp.GetHandoff(request.Context(), admitted.OperationID)
	if err != nil {
		status, code, retryable := mapDesktopSessionError(err)
		writeStandardError(response, status, code, retryable, desktopSessionErrorMessage(code))
		return
	}
	if !desktopHandoffMatchesAdmission(handoff, admitted) {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "desktop session handoff is unavailable")
		return
	}
	if !h.now().UTC().Before(handoff.ExpiresAt) {
		writeStandardError(response, http.StatusGone, "SANDBOX_DESKTOP_SESSION_EXPIRED", false, desktopSessionErrorMessage("SANDBOX_DESKTOP_SESSION_EXPIRED"))
		return
	}
	projected, err := desktopSessionHandoffProjection(handoff)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "desktop session handoff could not be projected")
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func (h *protectedHandler) serveDesktopSessionClose(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	closeRequest, err := decodeDesktopSessionCloseRequest(document, admitted, request.URL.Path, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, "desktop session close request is invalid")
		return
	}
	operation, err := h.desktopApp.CloseDesktopSession(request.Context(), closeRequest)
	if err != nil {
		status, code, retryable := mapDesktopSessionError(err)
		writeStandardError(response, status, code, retryable, desktopSessionErrorMessage(code))
		return
	}
	if !desktopOperationMatchesAdmission(operation, admitted) {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "desktop session close operation is unavailable")
		return
	}
	projected, err := desktopSessionOperationProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "desktop session close operation could not be projected")
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func decodeDesktopSessionCloseRequest(document []byte, admitted admission.AdmissionContext, path string, now time.Time) (desktop.CloseRequest, error) {
	var request providerv1.DesktopSessionCloseRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxDesktopSessionCloseRequestBytes, &request); err != nil {
		return desktop.CloseRequest{}, err
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 5 || parts[3] != "desktop-sessions" || !strings.HasSuffix(parts[4], ":close") {
		return desktop.CloseRequest{}, errors.New("desktop session close path is invalid")
	}
	desktopSessionID := strings.TrimSuffix(parts[4], ":close")
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) || admitted.Operation != admission.OperationCloseDesktopSession ||
		request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken ||
		string(request.RequestDigest) != admitted.RequestDigest || request.ExpectedGeneration < 1 || request.DesktopSessionID != desktopSessionID ||
		admitted.ProviderRevisionID == "" {
		return desktop.CloseRequest{}, errors.New("desktop session close request does not match admitted context")
	}
	closeRequest := desktop.CloseRequest{
		SandboxID: admitted.SandboxID, ProviderRevisionID: admitted.ProviderRevisionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: string(request.RequestDigest), Deadline: deadline,
		ExpectedGeneration: request.ExpectedGeneration, DesktopSessionID: request.DesktopSessionID,
		ConnectionGeneration: request.ConnectionGeneration, Reason: request.Reason,
	}
	if err := closeRequest.Validate(now); err != nil {
		return desktop.CloseRequest{}, err
	}
	return closeRequest, nil
}

func decodeDesktopSessionOpenRequest(document []byte, admitted admission.AdmissionContext, now time.Time) (desktop.OpenRequest, error) {
	var request providerv1.DesktopSessionOpenRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxDesktopSessionOpenRequestBytes, &request); err != nil {
		return desktop.OpenRequest{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) {
		return desktop.OpenRequest{}, errors.New("desktop session deadline does not match admitted context")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil {
		return desktop.OpenRequest{}, errors.New("desktop session expiry is invalid")
	}
	if request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken ||
		string(request.RequestDigest) != admitted.RequestDigest || request.ExpectedGeneration < 1 ||
		request.CapabilityProfileID != desktop.CapabilityProfileID || admitted.ProviderRevisionID == "" {
		return desktop.OpenRequest{}, errors.New("desktop session request does not match admitted context")
	}
	open := desktop.OpenRequest{
		SandboxID: admitted.SandboxID, ProviderRevisionID: admitted.ProviderRevisionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: string(request.RequestDigest), Deadline: deadline,
		ExpectedGeneration: request.ExpectedGeneration, DesktopSessionID: request.DesktopSessionID,
		CapabilityProfileID: request.CapabilityProfileID, ExpiresAt: expiresAt,
	}
	if err := open.Validate(now); err != nil {
		return desktop.OpenRequest{}, err
	}
	return open, nil
}

func desktopSessionOperationProjection(operation desktopapplication.Operation) (providerv1.Operation, error) {
	for _, identifier := range []string{operation.OperationID, operation.AttemptID, operation.SandboxID} {
		if err := lifecycle.ValidateIdentifier(identifier); err != nil {
			return providerv1.Operation{}, err
		}
	}
	if operation.FencingToken < 1 || operation.ObservedAt.IsZero() {
		return providerv1.Operation{}, errors.New("invalid desktop session operation projection")
	}
	switch operation.Status {
	case desktop.StatusAccepted, desktop.StatusRunning, desktop.StatusSucceeded, desktop.StatusFailed, desktop.StatusCancelled, desktop.StatusOutcomeUnknown:
	default:
		return providerv1.Operation{}, errors.New("invalid desktop session operation status")
	}
	operationType := providerv1.OperationOpenDesktopSession
	if operation.Type == desktopapplication.OperationCloseDesktopSession {
		operationType = providerv1.OperationCloseDesktopSession
	} else if operation.Type != "" && operation.Type != desktopapplication.OperationOpenDesktopSession {
		return providerv1.Operation{}, errors.New("invalid desktop session operation type")
	}
	return providerv1.Operation{
		OperationID: operation.OperationID, AttemptID: operation.AttemptID, FencingToken: operation.FencingToken,
		SandboxID: operation.SandboxID, Type: operationType,
		Status: providerv1.OperationState(operation.Status), ProviderOperationID: operation.OperationID,
		ObservedAt: operation.ObservedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func desktopSessionHandoffProjection(handoff desktopapplication.Handoff) (providerv1.DesktopSessionHandoff, error) {
	for _, identifier := range []string{handoff.OperationID, handoff.AttemptID, handoff.SandboxID, handoff.DesktopSessionID, handoff.CapabilityProfileID} {
		if err := lifecycle.ValidateIdentifier(identifier); err != nil {
			return providerv1.DesktopSessionHandoff{}, err
		}
	}
	if handoff.FencingToken < 1 || handoff.ConnectionGeneration < 1 || handoff.ExpiresAt.IsZero() ||
		handoff.CapabilityProfileID != desktop.CapabilityProfileID || handoff.Protocol != desktop.ProtocolWebRTC ||
		handoff.MediaProfileID != desktop.MediaProfileID || handoff.ControlProfileID != desktop.ControlProfileID ||
		!desktopSessionEndpointPattern.MatchString(handoff.InternalEndpointReference) {
		return providerv1.DesktopSessionHandoff{}, errors.New("invalid desktop session handoff projection")
	}
	return providerv1.DesktopSessionHandoff{
		OperationID: handoff.OperationID, AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken,
		SandboxID: handoff.SandboxID, DesktopSessionID: handoff.DesktopSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, Protocol: providerv1.DesktopProtocolWebRTC,
		MediaProfileID: handoff.MediaProfileID, ControlProfileID: handoff.ControlProfileID,
		InternalEndpointReference: handoff.InternalEndpointReference, ConnectionGeneration: handoff.ConnectionGeneration,
		ExpiresAt: handoff.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func desktopOperationMatchesAdmission(operation desktopapplication.Operation, admitted admission.AdmissionContext) bool {
	return operation.OperationID == admitted.OperationID && operation.AttemptID == admitted.AttemptID &&
		operation.FencingToken == admitted.FencingToken && operation.SandboxID == admitted.SandboxID
}

func desktopHandoffMatchesAdmission(handoff desktopapplication.Handoff, admitted admission.AdmissionContext) bool {
	return handoff.OperationID == admitted.OperationID && handoff.AttemptID == admitted.AttemptID &&
		handoff.FencingToken == admitted.FencingToken && handoff.SandboxID == admitted.SandboxID
}

func mapDesktopSessionError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, desktopapplication.ErrHandoffPending):
		return http.StatusServiceUnavailable, "SANDBOX_DESKTOP_SESSION_PENDING", true
	case errors.Is(err, desktop.ErrHandoffExpired):
		return http.StatusGone, "SANDBOX_DESKTOP_SESSION_EXPIRED", false
	case errors.Is(err, desktop.ErrHandoffRevoked):
		return http.StatusGone, "SANDBOX_DESKTOP_SESSION_REVOKED", false
	case errors.Is(err, desktop.ErrHandoffUnavailable):
		return http.StatusNotFound, "SANDBOX_DESKTOP_SESSION_UNAVAILABLE", false
	case errors.Is(err, desktoprepository.ErrNotFound), errors.Is(err, lifecyclerepository.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_NOT_FOUND", false
	case errors.Is(err, desktoprepository.ErrIdempotencyConflict):
		return http.StatusConflict, "SANDBOX_IDEMPOTENCY_CONFLICT", false
	case errors.Is(err, desktop.ErrGenerationConflict):
		return http.StatusConflict, "SANDBOX_GENERATION_CONFLICT", false
	case errors.Is(err, desktop.ErrStaleFencingToken):
		return http.StatusConflict, "SANDBOX_STALE_FENCING_TOKEN", false
	case errors.Is(err, desktop.ErrProviderRevisionConflict):
		return http.StatusConflict, "SANDBOX_PROVIDER_REVISION_CONFLICT", false
	case errors.Is(err, desktop.ErrNetworkPolicyConflict), errors.Is(err, desktop.ErrDesktopConflict), errors.Is(err, desktop.ErrAllocationConflict),
		errors.Is(err, desktoprepository.ErrConflict), errors.Is(err, desktoprepository.ErrAlreadyExists), errors.Is(err, desktoprepository.ErrAuthorityConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, desktop.ErrDesktopCapacity):
		return http.StatusTooManyRequests, "SANDBOX_CAPACITY_EXHAUSTED", true
	case errors.Is(err, desktop.ErrSandboxNotReady), errors.Is(err, desktop.ErrLeaseExpired), errors.Is(err, desktop.ErrCapabilityUnsupported), errors.Is(err, desktop.ErrDesktopUnsupported):
		return http.StatusUnprocessableEntity, "SANDBOX_CAPABILITY_UNSUPPORTED", false
	case errors.Is(err, desktop.ErrInvalidRequest), errors.Is(err, desktop.ErrDeadlineExpired), errors.Is(err, desktop.ErrInvalidExpiry):
		return http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false
	case errors.Is(err, desktopapplication.ErrInvalidApplication), errors.Is(err, desktoprepository.ErrCorrupt), errors.Is(err, desktoprepository.ErrDurability),
		errors.Is(err, desktoprepository.ErrClosed), errors.Is(err, desktop.ErrAllocationUnknown), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func desktopSessionErrorMessage(code string) string {
	switch code {
	case "SANDBOX_DESKTOP_SESSION_PENDING":
		return "desktop session handoff is not ready"
	case "SANDBOX_DESKTOP_SESSION_EXPIRED":
		return "desktop session handoff has expired"
	case "SANDBOX_DESKTOP_SESSION_REVOKED":
		return "desktop session handoff has been revoked"
	case "SANDBOX_DESKTOP_SESSION_UNAVAILABLE":
		return "desktop session handoff is unavailable"
	case "SANDBOX_CAPABILITY_UNSUPPORTED":
		return "desktop session capability or sandbox state is unsupported"
	case "SANDBOX_PROVIDER_REVISION_CONFLICT":
		return "desktop session Provider revision conflicts with provider-local state"
	default:
		return lifecycleErrorMessage(code)
	}
}
