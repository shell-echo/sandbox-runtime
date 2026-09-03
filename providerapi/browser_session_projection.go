package providerapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserrepository "github.com/shell-echo/sandbox-runtime/provider/browser/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

var browserSessionEndpointPattern = regexp.MustCompile(`^ref:browser-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

func (h *protectedHandler) serveBrowserSessionOpen(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	open, err := decodeBrowserSessionOpenRequest(document, admitted, h.now().UTC())
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, "browser session request is invalid")
		return
	}
	operation, err := h.browserApp.Open(request.Context(), open)
	if err != nil {
		status, code, retryable := mapBrowserSessionError(err)
		writeStandardError(response, status, code, retryable, browserSessionErrorMessage(code))
		return
	}
	if !browserOperationMatchesAdmission(operation, admitted) {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "browser session operation is unavailable")
		return
	}
	projected, err := browserSessionOperationProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "browser session operation could not be projected")
		return
	}
	writeJSON(response, http.StatusAccepted, projected)
}

func (h *protectedHandler) serveBrowserSessionHandoff(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	handoff, err := h.browserApp.GetHandoff(request.Context(), admitted.OperationID)
	if err != nil {
		status, code, retryable := mapBrowserSessionError(err)
		writeStandardError(response, status, code, retryable, browserSessionErrorMessage(code))
		return
	}
	if !browserHandoffMatchesAdmission(handoff, admitted) {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "browser session handoff is unavailable")
		return
	}
	if !h.now().UTC().Before(handoff.ExpiresAt) {
		writeStandardError(response, http.StatusGone, "SANDBOX_BROWSER_SESSION_EXPIRED", false, browserSessionErrorMessage("SANDBOX_BROWSER_SESSION_EXPIRED"))
		return
	}
	projected, err := browserSessionHandoffProjection(handoff)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "browser session handoff could not be projected")
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func decodeBrowserSessionOpenRequest(document []byte, admitted admission.AdmissionContext, now time.Time) (browser.OpenRequest, error) {
	var request providerv1.BrowserSessionOpenRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxBrowserSessionOpenRequestBytes, &request); err != nil {
		return browser.OpenRequest{}, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) {
		return browser.OpenRequest{}, errors.New("browser session deadline does not match admitted context")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil {
		return browser.OpenRequest{}, errors.New("browser session expiry is invalid")
	}
	if request.OperationID != admitted.OperationID || request.AttemptID != admitted.AttemptID || request.FencingToken != admitted.FencingToken ||
		string(request.RequestDigest) != admitted.RequestDigest || request.ExpectedGeneration < 1 ||
		request.CapabilityProfileID != browser.CapabilityProfileID || admitted.ProviderRevisionID == "" {
		return browser.OpenRequest{}, errors.New("browser session request does not match admitted context")
	}
	open := browser.OpenRequest{
		SandboxID: admitted.SandboxID, ProviderRevisionID: admitted.ProviderRevisionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: string(request.RequestDigest), Deadline: deadline,
		ExpectedGeneration: request.ExpectedGeneration, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, ExpiresAt: expiresAt,
	}
	if err := open.Validate(now); err != nil {
		return browser.OpenRequest{}, err
	}
	return open, nil
}

func browserSessionOperationProjection(operation browserapplication.Operation) (providerv1.Operation, error) {
	for _, identifier := range []string{operation.OperationID, operation.AttemptID, operation.SandboxID} {
		if err := lifecycle.ValidateIdentifier(identifier); err != nil {
			return providerv1.Operation{}, err
		}
	}
	if operation.FencingToken < 1 || operation.ObservedAt.IsZero() {
		return providerv1.Operation{}, errors.New("invalid browser session operation projection")
	}
	switch operation.Status {
	case browser.StatusAccepted, browser.StatusRunning, browser.StatusSucceeded, browser.StatusFailed, browser.StatusCancelled, browser.StatusOutcomeUnknown:
	default:
		return providerv1.Operation{}, errors.New("invalid browser session operation status")
	}
	return providerv1.Operation{
		OperationID: operation.OperationID, AttemptID: operation.AttemptID, FencingToken: operation.FencingToken,
		SandboxID: operation.SandboxID, Type: providerv1.OperationOpenBrowserSession,
		Status: providerv1.OperationState(operation.Status), ProviderOperationID: operation.OperationID,
		ObservedAt: operation.ObservedAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func browserSessionHandoffProjection(handoff browserapplication.Handoff) (providerv1.BrowserSessionHandoff, error) {
	for _, identifier := range []string{handoff.OperationID, handoff.AttemptID, handoff.SandboxID, handoff.BrowserSessionID, handoff.CapabilityProfileID} {
		if err := lifecycle.ValidateIdentifier(identifier); err != nil {
			return providerv1.BrowserSessionHandoff{}, err
		}
	}
	if handoff.FencingToken < 1 || handoff.ConnectionGeneration < 1 || handoff.ExpiresAt.IsZero() ||
		handoff.CapabilityProfileID != browser.CapabilityProfileID || handoff.Protocol != browser.ProtocolWebSocket ||
		!browserSessionEndpointPattern.MatchString(handoff.InternalEndpointReference) {
		return providerv1.BrowserSessionHandoff{}, errors.New("invalid browser session handoff projection")
	}
	return providerv1.BrowserSessionHandoff{
		OperationID: handoff.OperationID, AttemptID: handoff.AttemptID, FencingToken: handoff.FencingToken,
		SandboxID: handoff.SandboxID, BrowserSessionID: handoff.BrowserSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, Protocol: providerv1.BrowserProtocolWebSocket,
		InternalEndpointReference: handoff.InternalEndpointReference, ConnectionGeneration: handoff.ConnectionGeneration,
		ExpiresAt: handoff.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, nil
}

func browserOperationMatchesAdmission(operation browserapplication.Operation, admitted admission.AdmissionContext) bool {
	return operation.OperationID == admitted.OperationID && operation.AttemptID == admitted.AttemptID &&
		operation.FencingToken == admitted.FencingToken && operation.SandboxID == admitted.SandboxID
}

func browserHandoffMatchesAdmission(handoff browserapplication.Handoff, admitted admission.AdmissionContext) bool {
	return handoff.OperationID == admitted.OperationID && handoff.AttemptID == admitted.AttemptID &&
		handoff.FencingToken == admitted.FencingToken && handoff.SandboxID == admitted.SandboxID
}

func mapBrowserSessionError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, browserapplication.ErrHandoffPending):
		return http.StatusServiceUnavailable, "SANDBOX_BROWSER_SESSION_PENDING", true
	case errors.Is(err, browser.ErrHandoffExpired):
		return http.StatusGone, "SANDBOX_BROWSER_SESSION_EXPIRED", false
	case errors.Is(err, browser.ErrHandoffUnavailable):
		return http.StatusNotFound, "SANDBOX_BROWSER_SESSION_UNAVAILABLE", false
	case errors.Is(err, browserrepository.ErrNotFound), errors.Is(err, lifecyclerepository.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_NOT_FOUND", false
	case errors.Is(err, browserrepository.ErrIdempotencyConflict):
		return http.StatusConflict, "SANDBOX_IDEMPOTENCY_CONFLICT", false
	case errors.Is(err, browser.ErrGenerationConflict):
		return http.StatusConflict, "SANDBOX_GENERATION_CONFLICT", false
	case errors.Is(err, browser.ErrStaleFencingToken):
		return http.StatusConflict, "SANDBOX_STALE_FENCING_TOKEN", false
	case errors.Is(err, browser.ErrProviderRevisionConflict):
		return http.StatusConflict, "SANDBOX_PROVIDER_REVISION_CONFLICT", false
	case errors.Is(err, browser.ErrNetworkPolicyConflict), errors.Is(err, browser.ErrBrowserConflict), errors.Is(err, browser.ErrAllocationConflict),
		errors.Is(err, browserrepository.ErrConflict), errors.Is(err, browserrepository.ErrAlreadyExists), errors.Is(err, browserrepository.ErrAuthorityConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, browser.ErrSandboxNotReady), errors.Is(err, browser.ErrLeaseExpired), errors.Is(err, browser.ErrCapabilityUnsupported), errors.Is(err, browser.ErrBrowserUnsupported):
		return http.StatusUnprocessableEntity, "SANDBOX_CAPABILITY_UNSUPPORTED", false
	case errors.Is(err, browser.ErrInvalidRequest), errors.Is(err, browser.ErrDeadlineExpired), errors.Is(err, browser.ErrInvalidExpiry):
		return http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false
	case errors.Is(err, browserapplication.ErrInvalidApplication), errors.Is(err, browserrepository.ErrCorrupt), errors.Is(err, browserrepository.ErrDurability),
		errors.Is(err, browserrepository.ErrClosed), errors.Is(err, browser.ErrAllocationUnknown), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func browserSessionErrorMessage(code string) string {
	switch code {
	case "SANDBOX_BROWSER_SESSION_PENDING":
		return "browser session handoff is not ready"
	case "SANDBOX_BROWSER_SESSION_EXPIRED":
		return "browser session handoff has expired"
	case "SANDBOX_BROWSER_SESSION_UNAVAILABLE":
		return "browser session handoff is unavailable"
	case "SANDBOX_CAPABILITY_UNSUPPORTED":
		return "browser session capability or sandbox state is unsupported"
	case "SANDBOX_PROVIDER_REVISION_CONFLICT":
		return "browser session Provider revision conflicts with provider-local state"
	default:
		return lifecycleErrorMessage(code)
	}
}
