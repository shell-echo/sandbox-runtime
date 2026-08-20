package providerapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const providerUnavailableRetryAfterSeconds = 1

var admissionTraceCounter atomic.Uint64

// ProtectedTransportOptions supplies the already-composed application gate.
// The composition root must construct it from frozen operator trust material;
// a nil value keeps the Provider listener discovery-only.
type ProtectedTransportOptions struct {
	Gate *admission.ProtectedOperationGate
}

type protectedHandler struct {
	identity *clientIdentityAdmission
	gate     *admission.ProtectedOperationGate
}

type protectedRoute struct {
	operation        admission.Operation
	maxBodyBytes     int64
	allowUnavailable bool
}

func newProtectedHandler(identity *clientIdentityAdmission, options ProtectedTransportOptions) (http.Handler, error) {
	if identity == nil || options.Gate == nil {
		return nil, errors.New("protected Provider transport requires mTLS identity and admission gate")
	}
	return &protectedHandler{identity: identity, gate: options.Gate}, nil
}

func (h *protectedHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	route, pathValues, ok := matchProtectedRoute(request)
	if !ok {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	facts, err := h.identity.protectedFacts(request)
	if err != nil {
		writeAdmissionError(response, http.StatusUnauthorized, "SANDBOX_UNAUTHENTICATED", false)
		return
	}
	if err := h.gate.AuthenticateBearer(request.Context(), facts.compactBearer); err != nil {
		if errors.Is(err, admission.ErrUnauthenticated) {
			writeAdmissionError(response, http.StatusUnauthorized, "SANDBOX_UNAUTHENTICATED", false)
		} else {
			writeAdmissionError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true)
		}
		return
	}
	values := request.Header.Values(admission.AdmissionContextHeader)
	if len(values) != 1 {
		writeAdmissionError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false)
		return
	}
	context, err := admission.DecodeAdmissionContextCarrier(values[0])
	if err != nil || context.Operation != route.operation || context.ValidateTarget(request) != nil {
		writeAdmissionError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false)
		return
	}
	if context.ControllerSubject != facts.caller {
		writeAdmissionError(response, http.StatusForbidden, "SANDBOX_FORBIDDEN", false)
		return
	}
	if sandboxID := pathValues["sandbox_id"]; sandboxID != "" && context.SandboxID != sandboxID {
		writeAdmissionError(response, http.StatusForbidden, "SANDBOX_FORBIDDEN", false)
		return
	}
	if operationID := pathValues["operation_id"]; operationID != "" && context.OperationID != operationID {
		writeAdmissionError(response, http.StatusForbidden, "SANDBOX_FORBIDDEN", false)
		return
	}
	document, status := protectedDocument(request, context, route, pathValues)
	if status != 0 {
		writeAdmissionError(response, status, "SANDBOX_INVALID_REQUEST", false)
		return
	}
	binding := context.TokenBinding(facts.caller)
	err = h.gate.Admit(request.Context(), admission.ProtectedOperationRequest{
		CompactToken: facts.compactBearer,
		Binding:      binding,
		Document:     document,
	})
	if err != nil {
		switch {
		case errors.Is(err, admission.ErrUnauthenticated):
			writeAdmissionError(response, http.StatusUnauthorized, "SANDBOX_UNAUTHENTICATED", false)
		case errors.Is(err, admission.ErrForbidden):
			writeAdmissionError(response, http.StatusForbidden, "SANDBOX_FORBIDDEN", false)
		case errors.Is(err, admission.ErrConflict):
			writeAdmissionError(response, http.StatusConflict, "SANDBOX_CONFLICT", false)
		default:
			if route.allowUnavailable {
				writeAdmissionError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true)
			} else {
				writeAdmissionError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false)
			}
		}
		return
	}
	// P1.1c deliberately stops after admission. No repository, driver, or
	// lifecycle operation is started until a later slice owns its response.
	if route.allowUnavailable {
		writeAdmissionError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true)
	} else {
		writeAdmissionError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false)
	}
}

func writeAdmissionError(response http.ResponseWriter, status int, code string, retryable bool) {
	traceID := newAdmissionTraceID()
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Request-ID", traceID)
	if retryable {
		response.Header().Set("Retry-After", strconv.Itoa(providerUnavailableRetryAfterSeconds))
	}
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(providerv1.StandardError{
		Code: code, Message: "sandbox provider operation is not available", Retryable: retryable, TraceID: traceID,
	})
}

func newAdmissionTraceID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return "provider-" + strconv.FormatUint(admissionTraceCounter.Add(1), 10)
}

func protectedDocument(request *http.Request, context admission.AdmissionContext, route protectedRoute, pathValues map[string]string) ([]byte, int) {
	if request.Method == http.MethodGet {
		if request.ContentLength != 0 || len(request.TransferEncoding) != 0 || request.Body != nil && request.Body != http.NoBody {
			return nil, http.StatusBadRequest
		}
		return readDescriptor(context, request, pathValues)
	}
	if !strings.EqualFold(request.Header.Get("Content-Type"), "application/json") {
		return nil, http.StatusBadRequest
	}
	if request.ContentLength > route.maxBodyBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	if request.Body == nil {
		return nil, http.StatusBadRequest
	}
	limited := io.LimitReader(request.Body, route.maxBodyBytes+1)
	document, err := io.ReadAll(limited)
	if err != nil || int64(len(document)) > route.maxBodyBytes || len(document) == 0 {
		return nil, http.StatusRequestEntityTooLarge
	}
	return document, 0
}

func readDescriptor(context admission.AdmissionContext, request *http.Request, pathValues map[string]string) ([]byte, int) {
	document := map[string]any{
		"operation":     string(context.Operation),
		"sandbox_id":    context.SandboxID,
		"operation_id":  context.OperationID,
		"attempt_id":    context.AttemptID,
		"fencing_token": context.FencingToken,
	}
	if operationID := pathValues["operation_id"]; operationID != "" {
		document["operation_id"] = operationID
	}
	if context.Operation == admission.OperationReadEvents {
		sequence := int64(0)
		if value := request.URL.Query().Get("after_sequence"); value != "" {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil || parsed < 0 || parsed > 9007199254740991 {
				return nil, http.StatusBadRequest
			}
			sequence = parsed
		}
		document["after_sequence"] = sequence
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, http.StatusBadRequest
	}
	return encoded, 0
}

func matchProtectedRoute(request *http.Request) (protectedRoute, map[string]string, bool) {
	if request == nil {
		return protectedRoute{}, nil, false
	}
	path := strings.Trim(request.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[0] == "v1" && parts[1] == "sandboxes" && request.Method == http.MethodPost {
		return protectedRoute{operation: admission.OperationCreate, maxBodyBytes: providerv1.MaxCreateRequestBytes, allowUnavailable: true}, map[string]string{}, true
	}
	if path == "v1/sandboxes:restore" && request.Method == http.MethodPost {
		return protectedRoute{operation: admission.OperationRestore, maxBodyBytes: providerv1.MaxRestoreRequestBytes, allowUnavailable: true}, map[string]string{}, true
	}
	if len(parts) >= 3 && parts[0] == "v1" && parts[1] == "sandboxes" && parts[2] != "" {
		if len(parts) == 3 && request.Method == http.MethodPost && strings.HasSuffix(parts[2], ":terminate") {
			id := strings.TrimSuffix(parts[2], ":terminate")
			if id != "" {
				return protectedRoute{operation: admission.OperationTerminate, maxBodyBytes: providerv1.MaxTerminateRequestBytes, allowUnavailable: true}, map[string]string{"sandbox_id": id}, true
			}
		}
		values := map[string]string{"sandbox_id": parts[2]}
		if len(parts) == 3 && request.Method == http.MethodGet {
			return protectedRoute{operation: admission.OperationReadSandbox, allowUnavailable: true}, values, true
		}
		if len(parts) == 4 && request.Method == http.MethodPost {
			operations := map[string]struct {
				operation   admission.Operation
				maxBody     int64
				unavailable bool
			}{
				"desired-state":    {admission.OperationSetDesiredState, providerv1.MaxDesiredStateRequestBytes, true},
				"lease":            {admission.OperationExtendLease, providerv1.MaxLeaseRequestBytes, true},
				"exec":             {admission.OperationExec, providerv1.MaxExecRequestBytes, true},
				"exec:cancel":      {admission.OperationCancelExec, providerv1.MaxCancelExecRequestBytes, false},
				"runtime-sessions": {admission.OperationOpenRuntimeSession, providerv1.MaxRuntimeSessionOpenRequestBytes, true},
				"snapshots":        {admission.OperationSnapshot, providerv1.MaxSnapshotRequestBytes, true},
				":terminate":       {admission.OperationTerminate, providerv1.MaxTerminateRequestBytes, true},
			}
			if candidate, ok := operations[parts[3]]; ok {
				return protectedRoute{operation: candidate.operation, maxBodyBytes: candidate.maxBody, allowUnavailable: candidate.unavailable}, values, true
			}
		}
		if len(parts) == 4 && parts[3] == "events" && request.Method == http.MethodGet {
			return protectedRoute{operation: admission.OperationReadEvents, allowUnavailable: true}, values, true
		}
	}
	if len(parts) >= 3 && parts[0] == "v1" && parts[1] == "operations" && parts[2] != "" {
		values := map[string]string{"operation_id": parts[2]}
		if len(parts) == 3 && request.Method == http.MethodGet {
			return protectedRoute{operation: admission.OperationReadOperation, allowUnavailable: true}, values, true
		}
		if len(parts) == 4 && request.Method == http.MethodGet {
			switch parts[3] {
			case "exec-result":
				return protectedRoute{operation: admission.OperationReadResult, allowUnavailable: false}, values, true
			case "snapshot-manifest":
				return protectedRoute{operation: admission.OperationReadSnapshotManifest, allowUnavailable: true}, values, true
			}
		}
	}
	return protectedRoute{}, nil, false
}
