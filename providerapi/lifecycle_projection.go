package providerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

var errUnsupportedCreateCapability = errors.New("requested Provider capability is unsupported")

func (h *protectedHandler) serveCreate(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte, _ protectedRoute) {
	create, err := decodeCreateRequest(document, admitted, h.now().UTC())
	if err != nil {
		status, code := http.StatusBadRequest, "SANDBOX_INVALID_REQUEST"
		if errors.Is(err, errUnsupportedCreateCapability) {
			status, code = http.StatusUnprocessableEntity, "SANDBOX_CAPABILITY_UNSUPPORTED"
		}
		writeStandardError(response, status, code, false, "sandbox create request is invalid")
		return
	}
	result, err := h.application.AcceptCreate(request.Context(), create)
	if err != nil {
		status, code, retryable := mapLifecycleError(err)
		writeStandardError(response, status, code, retryable, lifecycleErrorMessage(code))
		return
	}
	operation, err := operationProjection(result.Operation)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "sandbox provider operation could not be projected")
		return
	}
	writeJSON(response, http.StatusAccepted, operation)
}

func (h *protectedHandler) serveSandboxStatus(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	sandbox, err := h.application.GetSandbox(request.Context(), admitted.SandboxID)
	if err != nil {
		status, code, retryable := mapLifecycleError(err)
		writeStandardError(response, status, code, retryable, lifecycleErrorMessage(code))
		return
	}
	status, err := sandboxProjection(sandbox)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "sandbox status could not be projected")
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (h *protectedHandler) serveOperation(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext) {
	if h.operationReader != nil {
		view, err := h.operationReader.ReadOperation(request.Context(), admitted.OperationID)
		if err != nil {
			status, code, retryable := mapOperationReaderError(err)
			writeStandardError(response, status, code, retryable, operationErrorMessage(code))
			return
		}
		if view.OperationID != admitted.OperationID || view.AttemptID != admitted.AttemptID || view.FencingToken != admitted.FencingToken || view.SandboxID != admitted.SandboxID {
			writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "sandbox operation is unavailable")
			return
		}
		projected, err := operationViewProjection(view)
		if err != nil {
			writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "sandbox operation is unavailable")
			return
		}
		writeJSON(response, http.StatusOK, projected)
		return
	}
	operation, err := h.application.GetOperation(request.Context(), admitted.OperationID)
	if err != nil {
		status, code, retryable := mapLifecycleError(err)
		writeStandardError(response, status, code, retryable, lifecycleErrorMessage(code))
		return
	}
	projected, err := operationProjection(operation)
	if err != nil {
		writeStandardError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false, "sandbox operation could not be projected")
		return
	}
	writeJSON(response, http.StatusOK, projected)
}

func mapOperationReaderError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, provideroperation.ErrNotFound):
		return http.StatusNotFound, "SANDBOX_NOT_FOUND", false
	case errors.Is(err, provideroperation.ErrConflict):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	case errors.Is(err, provideroperation.ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}

func decodeCreateRequest(document []byte, admitted admission.AdmissionContext, now time.Time) (lifecycle.CreateRequest, error) {
	var request providerv1.CreateRequest
	if err := providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxCreateRequestBytes, &request); err != nil {
		return lifecycle.CreateRequest{}, err
	}
	if request.ProtocolVersion != providerv1.APIVersionV1 || request.FencingToken <= 0 {
		return lifecycle.CreateRequest{}, errors.New("invalid Provider create envelope")
	}
	if request.FencingToken > math.MaxInt64 {
		return lifecycle.CreateRequest{}, errors.New("Provider fencing token exceeds supported range")
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineAt)
	if err != nil || !deadline.Equal(parseAdmissionTime(admitted.DeadlineAt)) {
		return lifecycle.CreateRequest{}, errors.New("Provider deadline does not match admitted context")
	}
	if admitted.OperationID != request.OperationID || admitted.AttemptID != request.AttemptID || admitted.FencingToken != request.FencingToken || admitted.SandboxID != request.Spec.SandboxID || admitted.TenantID != request.Spec.TenantID || admitted.WorkOrderID != request.Spec.WorkOrderID || admitted.ProviderRevisionID != request.Spec.ProviderRevisionID {
		return lifecycle.CreateRequest{}, errors.New("Provider create request does not match admitted context")
	}
	if len(request.Spec.RequiredCapabilities) != 0 || len(request.Spec.OptionalCapabilities) != 0 {
		return lifecycle.CreateRequest{}, errUnsupportedCreateCapability
	}
	if request.Spec.Network.Mode != providerv1.NetworkNone || request.Spec.Network.PolicyReference != "" || (request.Spec.Network.EgressGatewayRequired != nil && *request.Spec.Network.EgressGatewayRequired) {
		return lifecycle.CreateRequest{}, errors.New("Provider network policy is not supported")
	}
	if request.Spec.Workspace.Mode != providerv1.WorkspaceEphemeral || request.Spec.Workspace.CommitMode != providerv1.WorkspaceReadOnly || request.Spec.Workspace.SnapshotReference != "" || (request.Spec.Workspace.MountPath != "" && request.Spec.Workspace.MountPath != providerv1.WorkspaceMount) {
		return lifecycle.CreateRequest{}, errors.New("Provider workspace policy is not supported")
	}
	if request.Spec.Image.Reference == "" || request.Spec.Image.Digest == "" {
		return lifecycle.CreateRequest{}, errors.New("Provider image reference and digest are required")
	}
	if err := lifecycle.ValidateDigest(string(request.Spec.Image.Digest)); err != nil {
		return lifecycle.CreateRequest{}, err
	}
	if request.Spec.Security.PrivilegeLevel != providerv1.PrivilegeUnprivileged || request.Spec.Security.RootFilesystem != providerv1.RootFilesystemReadOnly || request.Spec.Security.AllowPrivilegeEscalation || request.Spec.Security.HostNamespaceAccess {
		return lifecycle.CreateRequest{}, errors.New("Provider security policy is not supported")
	}
	if request.Spec.Resources.CPUMillis <= 0 || request.Spec.Resources.MemoryBytes <= 0 || request.Spec.Resources.EphemeralStorageBytes <= 0 || request.Spec.Resources.PIDsLimit <= 0 {
		return lifecycle.CreateRequest{}, errors.New("Provider resource limits are invalid")
	}
	leaseExpiresAt, err := time.Parse(time.RFC3339Nano, request.Spec.Lease.ExpiresAt)
	if err != nil {
		return lifecycle.CreateRequest{}, errors.New("Provider lease expiry is invalid")
	}
	for name, value := range map[string]string{
		"branch_id":              request.Spec.BranchID,
		"provider_resolution_id": request.Spec.ProviderResolutionID,
	} {
		if err := lifecycle.ValidateIdentifier(value); err != nil {
			return lifecycle.CreateRequest{}, fmt.Errorf("%s: %w", name, err)
		}
	}
	if request.Spec.AgentRunID != "" {
		if err := lifecycle.ValidateIdentifier(request.Spec.AgentRunID); err != nil {
			return lifecycle.CreateRequest{}, err
		}
	}
	create := lifecycle.CreateRequest{
		OperationID:    request.OperationID,
		AttemptID:      request.AttemptID,
		FencingToken:   uint64(request.FencingToken),
		IdempotencyKey: request.IdempotencyKey,
		RequestDigest:  string(request.RequestDigest),
		Deadline:       deadline,
		Spec: lifecycle.SandboxSpec{
			SandboxID:          request.Spec.SandboxID,
			TenantID:           request.Spec.TenantID,
			WorkOrderID:        request.Spec.WorkOrderID,
			WorkspaceID:        request.Spec.WorkspaceID,
			ProviderRevisionID: request.Spec.ProviderRevisionID,
			RuntimeProfile:     request.Spec.RuntimeProfile,
			SandboxSlotKey:     string(request.Spec.SandboxSlotKey),
			LeaseExpiresAt:     leaseExpiresAt,
		},
	}
	if err := create.Validate(now); err != nil {
		return lifecycle.CreateRequest{}, err
	}
	return create, nil
}

func operationProjection(operation lifecycle.Operation) (providerv1.Operation, error) {
	if err := operation.Validate(); err != nil {
		return providerv1.Operation{}, fmt.Errorf("validate lifecycle operation: %w", err)
	}
	if operation.FencingToken > math.MaxInt64 {
		return providerv1.Operation{}, errors.New("operation fencing token exceeds Provider wire range")
	}
	projected := providerv1.Operation{
		OperationID:         operation.ID,
		AttemptID:           operation.AttemptID,
		FencingToken:        int64(operation.FencingToken),
		SandboxID:           operation.SandboxID,
		Type:                providerv1.OperationType(operation.Type),
		Status:              providerv1.OperationState(operation.State),
		ProviderOperationID: operation.ID,
		ObservedAt:          operation.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
	if operation.Failure != nil {
		outcome := providerv1.OutcomeKnownFailed
		if operation.Failure.Outcome == lifecycle.FailureUnknown {
			outcome = providerv1.OutcomeUnknownFailure
		}
		projected.Error = &providerv1.ProviderError{
			Code:      strings.ToUpper(strings.ReplaceAll(operation.Failure.Code, "-", "_")),
			Message:   lifecycleErrorMessage(strings.ToUpper(strings.ReplaceAll(operation.Failure.Code, "-", "_"))),
			Retryable: operation.Failure.Retryable,
			Outcome:   outcome,
		}
	}
	return projected, nil
}

func sandboxProjection(sandbox lifecycle.Sandbox) (providerv1.Status, error) {
	if err := sandbox.Validate(); err != nil {
		return providerv1.Status{}, fmt.Errorf("validate lifecycle sandbox: %w", err)
	}
	if sandbox.Generation > math.MaxInt64 || sandbox.ObservedGeneration > math.MaxInt64 {
		return providerv1.Status{}, errors.New("sandbox generation exceeds Provider wire range")
	}
	return providerv1.Status{
		SandboxID: sandbox.ID, TenantID: sandbox.TenantID, WorkOrderID: sandbox.WorkOrderID,
		WorkspaceID: sandbox.WorkspaceID, ProviderRevisionID: sandbox.ProviderRevisionID,
		DesiredState: providerv1.DesiredState(sandbox.DesiredState), ObservedState: providerv1.ObservedState(sandbox.ObservedState),
		Generation: int64(sandbox.Generation), ObservedGeneration: int64(sandbox.ObservedGeneration), RuntimeProfile: sandbox.RuntimeProfile,
		LeaseExpiresAt: sandbox.LeaseExpiresAt.UTC().Format(time.RFC3339Nano), CreatedAt: sandbox.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: sandbox.UpdatedAt.UTC().Format(time.RFC3339Nano), SandboxSlotKey: providerv1.SandboxSlotKey(sandbox.SandboxSlotKey),
	}, nil
}

func parseAdmissionTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func mapLifecycleError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, repository.ErrNotFound), errors.Is(err, repository.ErrAlreadyExists):
		if errors.Is(err, repository.ErrAlreadyExists) {
			return http.StatusConflict, "SANDBOX_CONFLICT", false
		}
		return http.StatusNotFound, "SANDBOX_NOT_FOUND", false
	case errors.Is(err, repository.ErrIdempotencyConflict):
		return http.StatusConflict, "SANDBOX_IDEMPOTENCY_CONFLICT", false
	case errors.Is(err, lifecycle.ErrGenerationConflict):
		return http.StatusConflict, "SANDBOX_GENERATION_CONFLICT", false
	case errors.Is(err, lifecycle.ErrStaleFencingToken):
		return http.StatusConflict, "SANDBOX_STALE_FENCING_TOKEN", false
	case errors.Is(err, repository.ErrConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, repository.ErrClosed), errors.Is(err, repository.ErrDurability), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	default:
		return http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false
	}
}

func lifecycleErrorMessage(code string) string {
	switch code {
	case "SANDBOX_CONFLICT":
		return "sandbox request conflicts with provider-local state"
	case "SANDBOX_IDEMPOTENCY_CONFLICT":
		return "sandbox idempotency key conflicts with a different request digest"
	case "SANDBOX_GENERATION_CONFLICT":
		return "sandbox generation conflicts with provider-local state"
	case "SANDBOX_STALE_FENCING_TOKEN":
		return "sandbox fencing token is stale"
	case "SANDBOX_NOT_FOUND":
		return "sandbox resource was not found"
	case "SANDBOX_PROVIDER_UNAVAILABLE":
		return "sandbox provider is temporarily unavailable"
	case "SANDBOX_CAPABILITY_UNSUPPORTED":
		return "requested sandbox capability is unsupported"
	default:
		return "sandbox request is invalid"
	}
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
