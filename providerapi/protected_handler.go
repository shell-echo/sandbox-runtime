package providerapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const providerUnavailableRetryAfterSeconds = 1

var admissionTraceCounter atomic.Uint64

// ProtectedTransportOptions supplies the already-composed application gate.
// The composition root must construct it from frozen operator trust material;
// a nil value keeps the Provider listener discovery-only.
type ProtectedTransportOptions struct {
	Gate                *admission.ProtectedOperationGate
	Application         LifecycleApplication
	SessionApplication  RuntimeSessionApplication
	ArtifactApplication ArtifactApplication
	ExecApplication     ExecApplication
	UsageEvidenceReader usage.EvidenceReader
	OperationReader     provideroperation.Reader
	Now                 func() time.Time
	capabilitySnapshot  provider.CapabilitySnapshot
}

// LifecycleApplication is the narrow Provider application boundary. Its
// implementation owns provider-local state and must not expose instance or
// runtime-driver models through this transport package.
type LifecycleApplication interface {
	AcceptCreate(context.Context, lifecycle.CreateRequest) (repository.CreateResult, error)
	GetSandbox(context.Context, string) (lifecycle.Sandbox, error)
	GetOperation(context.Context, string) (lifecycle.Operation, error)
}

// RuntimeSessionApplication is the narrow terminal-session application
// boundary. It returns bounded projections rather than repository records.
type RuntimeSessionApplication interface {
	Open(context.Context, session.OpenRequest) (sessionapplication.Operation, error)
	GetHandoff(context.Context, string) (sessionapplication.Handoff, error)
}

// ArtifactApplication is the narrow Provider-local artifact boundary. The
// transport accepts work and reads retained evidence only through this port;
// it never calls a stager or repository directly.
type ArtifactApplication interface {
	Accept(context.Context, artifact.Request) (artifact.Reservation, error)
	GetOperation(context.Context, string) (artifact.Operation, error)
	GetEvidence(context.Context, string) (artifact.Evidence, error)
}

// ExecApplication is the bounded vertically composed exec application. It
// exposes no repository, lifecycle-driver, or backend-engine type.
type ExecApplication interface {
	AcceptExec(context.Context, providerexec.Request) (provideroperation.View, error)
	AcceptCancellation(context.Context, providerexec.CancellationIntent) (provideroperation.View, error)
	GetResult(context.Context, string) (providerexec.Result, error)
}

type protectedHandler struct {
	identity        *clientIdentityAdmission
	gate            *admission.ProtectedOperationGate
	application     LifecycleApplication
	sessionApp      RuntimeSessionApplication
	artifactApp     ArtifactApplication
	execApp         ExecApplication
	usageReader     usage.EvidenceReader
	operationReader provideroperation.Reader
	capabilities    provider.CapabilitySnapshot
	now             func() time.Time
}

type protectedRoute struct {
	operation        admission.Operation
	maxBodyBytes     int64
	allowUnavailable bool
	oversizeStatus   int
}

func newProtectedHandler(identity *clientIdentityAdmission, options ProtectedTransportOptions) (http.Handler, error) {
	if identity == nil || options.Gate == nil {
		return nil, errors.New("protected Provider transport requires mTLS identity and admission gate")
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &protectedHandler{
		identity: identity, gate: options.Gate, application: options.Application,
		sessionApp: options.SessionApplication, artifactApp: options.ArtifactApplication,
		execApp:     options.ExecApplication,
		usageReader: options.UsageEvidenceReader, operationReader: options.OperationReader,
		capabilities: options.capabilitySnapshot, now: now,
	}, nil
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
	if err := validateProtectedDocument(route, document); err != nil {
		writeAdmissionError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false)
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
		case errors.Is(err, admission.ErrInvalidRequestDocument):
			writeAdmissionError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false)
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
	if route.operation == admission.OperationReadOperation && (h.application != nil || h.operationReader != nil) {
		h.serveOperation(response, request, context)
		return
	}
	if h.application != nil {
		switch route.operation {
		case admission.OperationCreate:
			h.serveCreate(response, request, context, document, route)
			return
		case admission.OperationReadSandbox:
			h.serveSandboxStatus(response, request, context)
			return
		}
	}
	if h.artifactApp != nil {
		switch route.operation {
		case admission.OperationStageArtifact:
			h.serveArtifactStage(response, request, context, document)
			return
		case admission.OperationReadArtifactStagingEvidence:
			h.serveArtifactEvidence(response, request, context)
			return
		}
	}
	if h.execApp != nil {
		switch route.operation {
		case admission.OperationExec:
			h.serveExec(response, request, context, document)
			return
		case admission.OperationCancelExec:
			h.serveExecCancellation(response, request, context, document)
			return
		case admission.OperationReadResult:
			h.serveExecResult(response, request, context)
			return
		}
	}
	if h.usageReader != nil && route.operation == admission.OperationReadUsageEvidence {
		h.serveUsageEvidence(response, request, context)
		return
	}
	if h.sessionApp != nil {
		switch route.operation {
		case admission.OperationOpenRuntimeSession:
			h.serveRuntimeSessionOpen(response, request, context, document)
			return
		case admission.OperationReadRuntimeSession:
			h.serveRuntimeSessionHandoff(response, request, context)
			return
		}
	}
	// P1.2.4 deliberately leaves reserved lifecycle families behind the
	// admission boundary. No repository, driver, or lifecycle operation is
	// started for those routes.
	if route.allowUnavailable {
		writeAdmissionError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true)
	} else {
		writeAdmissionError(response, http.StatusInternalServerError, "SANDBOX_PROVIDER_ERROR", false)
	}
}

// validateProtectedDocument performs the route schema check before mutation
// admission can consume replay/fencing state. It intentionally does not check
// token bindings or semantic correlation; those remain the gate's authority.
func validateProtectedDocument(route protectedRoute, document []byte) error {
	switch route.operation {
	case admission.OperationCreate:
		var request providerv1.CreateRequest
		return providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxCreateRequestBytes, &request)
	case admission.OperationOpenRuntimeSession:
		var request providerv1.RuntimeSessionOpenRequest
		return providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxRuntimeSessionOpenRequestBytes, &request)
	case admission.OperationStageArtifact:
		var request providerv1.ArtifactStagingRequest
		return providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxArtifactStagingRequestBytes, &request)
	case admission.OperationExec:
		var request providerv1.ExecRequest
		return providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxExecRequestBytes, &request)
	case admission.OperationCancelExec:
		var request providerv1.CancelExecRequest
		return providerv1.DecodeStrict(bytes.NewReader(document), providerv1.MaxCancelExecRequestBytes, &request)
	default:
		return nil
	}
}

func writeAdmissionError(response http.ResponseWriter, status int, code string, retryable bool) {
	writeStandardError(response, status, code, retryable, "sandbox provider operation is not available")
}

func writeStandardError(response http.ResponseWriter, status int, code string, retryable bool, message string) {
	traceID := newAdmissionTraceID()
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Request-ID", traceID)
	if retryable {
		response.Header().Set("Retry-After", strconv.Itoa(providerUnavailableRetryAfterSeconds))
	}
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(providerv1.StandardError{
		Code: code, Message: message, Retryable: retryable, TraceID: traceID,
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
		return nil, route.bodyLimitStatus()
	}
	if request.Body == nil {
		return nil, http.StatusBadRequest
	}
	limited := io.LimitReader(request.Body, route.maxBodyBytes+1)
	document, err := io.ReadAll(limited)
	if err != nil || int64(len(document)) > route.maxBodyBytes || len(document) == 0 {
		return nil, route.bodyLimitStatus()
	}
	return document, 0
}

func (route protectedRoute) bodyLimitStatus() int {
	if route.oversizeStatus != 0 {
		return route.oversizeStatus
	}
	return http.StatusRequestEntityTooLarge
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
		return protectedRoute{operation: admission.OperationCreate, maxBodyBytes: providerv1.MaxCreateRequestBytes, allowUnavailable: true, oversizeStatus: http.StatusBadRequest}, map[string]string{}, true
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
				"artifacts:stage":  {admission.OperationStageArtifact, providerv1.MaxArtifactStagingRequestBytes, true},
				":terminate":       {admission.OperationTerminate, providerv1.MaxTerminateRequestBytes, true},
			}
			if candidate, ok := operations[parts[3]]; ok {
				oversizeStatus := 0
				if candidate.operation == admission.OperationOpenRuntimeSession || candidate.operation == admission.OperationStageArtifact ||
					candidate.operation == admission.OperationExec || candidate.operation == admission.OperationCancelExec {
					oversizeStatus = http.StatusBadRequest
				}
				return protectedRoute{operation: candidate.operation, maxBodyBytes: candidate.maxBody, allowUnavailable: candidate.unavailable, oversizeStatus: oversizeStatus}, values, true
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
			case "runtime-session":
				return protectedRoute{operation: admission.OperationReadRuntimeSession, allowUnavailable: true}, values, true
			case "exec-result":
				return protectedRoute{operation: admission.OperationReadResult, allowUnavailable: false}, values, true
			case "snapshot-manifest":
				return protectedRoute{operation: admission.OperationReadSnapshotManifest, allowUnavailable: true}, values, true
			case "artifact-staging-evidence":
				return protectedRoute{operation: admission.OperationReadArtifactStagingEvidence, allowUnavailable: true}, values, true
			case "usage-evidence":
				return protectedRoute{operation: admission.OperationReadUsageEvidence, allowUnavailable: true}, values, true
			}
		}
	}
	return protectedRoute{}, nil, false
}
