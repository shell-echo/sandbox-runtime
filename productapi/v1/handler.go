package productapiv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const maxCreateWorkspaceBytes int64 = 65536

type Handler struct {
	application   *product.Application
	authenticator productapi.Authenticator
	requestIDs    product.IDGenerator
	controls      *product.ControlService
	sessions      *product.SessionService
	grants        *product.GrantService
}

func NewHandler(application *product.Application, authenticator productapi.Authenticator, requestIDs product.IDGenerator) (*Handler, error) {
	return NewHandlerWithControl(application, nil, authenticator, requestIDs)
}

func NewHandlerWithControl(application *product.Application, controls *product.ControlService, authenticator productapi.Authenticator, requestIDs product.IDGenerator) (*Handler, error) {
	return NewHandlerWithServices(application, controls, nil, authenticator, requestIDs)
}

func NewHandlerWithServices(application *product.Application, controls *product.ControlService, sessions *product.SessionService, authenticator productapi.Authenticator, requestIDs product.IDGenerator) (*Handler, error) {
	return NewCompleteHandler(application, controls, sessions, nil, authenticator, requestIDs)
}

func NewCompleteHandler(application *product.Application, controls *product.ControlService, sessions *product.SessionService, grants *product.GrantService, authenticator productapi.Authenticator, requestIDs product.IDGenerator) (*Handler, error) {
	if application == nil || productapi.IsNilAuthenticator(authenticator) || requestIDs == nil {
		return nil, product.ErrInvalid
	}
	return &Handler{application: application, controls: controls, sessions: sessions, grants: grants, authenticator: authenticator, requestIDs: requestIDs}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID, err := h.requestIDs.NewID("req")
	if err != nil {
		requestID = "req_unavailable"
	}
	if supplied := request.Header.Values("X-Request-ID"); len(supplied) == 1 && validRequestID(supplied[0]) {
		requestID = supplied[0]
	}
	writer.Header().Set("X-Request-ID", requestID)
	writer.Header().Set("Cache-Control", "no-store")

	principal, ok := h.authenticate(request)
	if !ok {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		writeError(writer, http.StatusUnauthorized, "PRODUCT_UNAUTHENTICATED", "authentication is required", false, requestID)
		return
	}

	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/capabilities":
		writeJSON(writer, http.StatusOK, CapabilityDocument{
			ContractNamespace: "urn:shell-echo:sandbox-runtime:product-v1alpha1",
			ContractVersion:   "0.1.0", Capabilities: []ProductCapability{}, MaxPageSize: 200,
		})
	case request.Method == http.MethodPost && request.URL.Path == "/api/v1/workspaces":
		h.createWorkspace(writer, request, principal, requestID)
	case request.Method == http.MethodGet && request.URL.Path == "/api/v1/workspaces":
		h.listWorkspaces(writer, request, principal, requestID)
	case request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/control-leases"):
		h.controlLease(writer, request, principal, requestID)
	case (request.Method == http.MethodGet || request.Method == http.MethodPost) && strings.Contains(request.URL.Path, "/sessions"):
		h.sessionsRoute(writer, request, principal, requestID)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/workspaces/"):
		identifier, exact := singleIdentifier(request.URL.Path, "/api/v1/workspaces/")
		if !exact {
			writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
			return
		}
		h.getWorkspace(writer, request, principal, requestID, identifier)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/operations/"):
		identifier, exact := singleIdentifier(request.URL.Path, "/api/v1/operations/")
		if !exact {
			writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
			return
		}
		h.getOperation(writer, request, principal, requestID, identifier)
	default:
		writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
	}
}

func (h *Handler) listWorkspaces(writer http.ResponseWriter, request *http.Request, principal productapi.Principal, requestID string) {
	query := request.URL.Query()
	for name := range query {
		if name != "cursor" && name != "limit" {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid query parameter", false, requestID)
			return
		}
	}
	cursor, ok := singleQuery(query, "cursor")
	if !ok || len(cursor) > 1024 {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid cursor", false, requestID)
		return
	}
	limit := 50
	if value, present := query["limit"]; present {
		if len(value) != 1 {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid limit", false, requestID)
			return
		}
		parsed, err := strconv.Atoi(value[0])
		if err != nil || parsed < 1 || parsed > 200 {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid limit", false, requestID)
			return
		}
		limit = parsed
	}
	items, next, err := h.application.ListWorkspaces(request.Context(), principal.TenantID, principal.Actor, cursor, limit)
	if err != nil {
		writeApplicationError(writer, err, requestID)
		return
	}
	projected := make([]Workspace, 0, len(items))
	for _, item := range items {
		projected = append(projected, toWorkspace(item))
	}
	writeJSON(writer, http.StatusOK, WorkspacePage{Items: projected, NextCursor: next})
}

func singleQuery(query map[string][]string, name string) (string, bool) {
	values, present := query[name]
	if !present {
		return "", true
	}
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func (h *Handler) sessionsRoute(writer http.ResponseWriter, request *http.Request, principal productapi.Principal, requestID string) {
	if h.sessions == nil {
		writeApplicationError(writer, product.ErrCapabilityUnsupported, requestID)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/workspaces/") && strings.HasSuffix(request.URL.Path, "/sessions") {
		workspaceID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/api/v1/workspaces/"), "/sessions")
		if workspaceID == "" || strings.Contains(workspaceID, "/") {
			writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
			return
		}
		if request.Method == http.MethodGet {
			items, err := h.sessions.List(request.Context(), principal.TenantID, principal.Actor, workspaceID, 50)
			if err != nil {
				writeApplicationError(writer, err, requestID)
				return
			}
			projected := make([]RuntimeSession, 0, len(items))
			for _, item := range items {
				projected = append(projected, toSession(item))
			}
			writeJSON(writer, http.StatusOK, SessionPage{Items: projected})
			return
		}
		if principal.Role != productapi.RoleOwner {
			writeError(writer, http.StatusForbidden, "PRODUCT_FORBIDDEN", "action is forbidden", false, requestID)
			return
		}
		key, ok := singleHeader(request, "Idempotency-Key")
		if !ok || !jsonContentType(request.Header.Get("Content-Type")) {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid mutation metadata", false, requestID)
			return
		}
		var input CreateSessionRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 65536, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		operation, _, err := h.sessions.Create(request.Context(), principal.TenantID, principal.Actor, workspaceID, key, product.CreateSessionRequest{ExpectedWorkspaceVersion: input.ExpectedWorkspaceVersion, SlotKey: input.SlotKey, Kind: input.Kind, ProtocolProfile: input.ProtocolProfile, ExpiresInSeconds: input.ExpiresInSeconds, RecordingPolicy: input.RecordingPolicy})
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusAccepted, toOperation(operation))
		return
	}
	if !strings.HasPrefix(request.URL.Path, "/api/v1/sessions/") {
		writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
		return
	}
	value := strings.TrimPrefix(request.URL.Path, "/api/v1/sessions/")
	if request.Method == http.MethodPost && strings.HasSuffix(value, "/connections") {
		if principal.Role != productapi.RoleOwner || h.grants == nil {
			writeError(writer, http.StatusForbidden, "PRODUCT_FORBIDDEN", "action is forbidden", false, requestID)
			return
		}
		sessionID := strings.TrimSuffix(value, "/connections")
		if sessionID == "" || strings.Contains(sessionID, "/") {
			writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
			return
		}
		key, ok := singleHeader(request, "Idempotency-Key")
		if !ok || !jsonContentType(request.Header.Get("Content-Type")) {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid mutation metadata", false, requestID)
			return
		}
		var input CreateConnectionRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 32768, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		grant, _, err := h.grants.Create(request.Context(), principal.TenantID, principal.Actor, sessionID, key, product.CreateConnectionRequest{ExpectedSessionVersion: input.ExpectedSessionVersion, ProtocolProfile: input.ProtocolProfile, ControlLeaseID: input.ControlLeaseID, ControlFence: input.ControlFence})
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusCreated, toConnectionGrant(grant))
		return
	}
	if request.Method == http.MethodGet && !strings.Contains(value, ":") {
		session, err := h.sessions.Get(request.Context(), principal.TenantID, principal.Actor, value)
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusOK, toSession(session))
		return
	}
	if request.Method != http.MethodPost || principal.Role != productapi.RoleOwner {
		writeError(writer, http.StatusForbidden, "PRODUCT_FORBIDDEN", "action is forbidden", false, requestID)
		return
	}
	key, ok := singleHeader(request, "Idempotency-Key")
	if !ok || !jsonContentType(request.Header.Get("Content-Type")) {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid mutation metadata", false, requestID)
		return
	}
	if strings.HasSuffix(value, ":close") {
		sessionID := strings.TrimSuffix(value, ":close")
		var input CloseSessionRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 32768, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		operation, _, err := h.sessions.Close(request.Context(), principal.TenantID, principal.Actor, sessionID, key, product.CloseSessionRequest{ExpectedVersion: input.ExpectedVersion, Reason: input.Reason})
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusAccepted, toOperation(operation))
		return
	}
	if strings.HasSuffix(value, ":resize") {
		sessionID := strings.TrimSuffix(value, ":resize")
		var input ResizeSessionRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 32768, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		operation, _, err := h.sessions.Resize(request.Context(), principal.TenantID, principal.Actor, sessionID, key, input.ExpectedVersion, input.Columns, input.Rows, input.ControlLeaseID, input.ControlFence)
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusAccepted, toOperation(operation))
		return
	}
	writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
}

func singleHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	return func() (string, bool) {
		if len(values) != 1 {
			return "", false
		}
		return values[0], true
	}()
}

func (h *Handler) controlLease(writer http.ResponseWriter, request *http.Request, principal productapi.Principal, requestID string) {
	if principal.Role != productapi.RoleOwner || h.controls == nil {
		writeError(writer, http.StatusForbidden, "PRODUCT_FORBIDDEN", "action is forbidden", false, requestID)
		return
	}
	keyValues := request.Header.Values("Idempotency-Key")
	if len(keyValues) != 1 {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "exactly one idempotency key is required", false, requestID)
		return
	}
	if !jsonContentType(request.Header.Get("Content-Type")) {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "content type must be application/json", false, requestID)
		return
	}
	workspaceID, leaseID, action, ok := parseControlPath(request.URL.Path)
	if !ok {
		writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
		return
	}
	switch action {
	case "acquire":
		var input AcquireControlLeaseRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 32768, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		lease, _, err := h.controls.Acquire(request.Context(), principal.TenantID, principal.Actor, workspaceID, keyValues[0], product.AcquireControlLeaseRequest{ExpectedWorkspaceVersion: input.ExpectedWorkspaceVersion, Scope: product.ControlScope{Type: input.Scope.ScopeType, ID: input.Scope.ScopeID}, DurationSeconds: input.DurationSeconds})
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusCreated, toControlLease(lease))
	case "renew":
		var input RenewControlLeaseRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 32768, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		lease, _, err := h.controls.Renew(request.Context(), principal.TenantID, principal.Actor, workspaceID, leaseID, keyValues[0], product.RenewControlLeaseRequest{Fence: input.Fence, DurationSeconds: input.DurationSeconds})
		if err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writeJSON(writer, http.StatusOK, toControlLease(lease))
	case "release":
		var input ReleaseControlLeaseRequest
		if err := decodeStrict(request.Context(), writer, request.Body, 32768, &input); err != nil {
			writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
			return
		}
		if _, err := h.controls.Release(request.Context(), principal.TenantID, principal.Actor, workspaceID, leaseID, keyValues[0], input.Fence, input.Reason); err != nil {
			writeApplicationError(writer, err, requestID)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}

func parseControlPath(path string) (workspaceID, leaseID, action string, ok bool) {
	prefix := "/api/v1/workspaces/"
	if !strings.HasPrefix(path, prefix) {
		return "", "", "", false
	}
	remaining := strings.TrimPrefix(path, prefix)
	parts := strings.Split(remaining, "/")
	if len(parts) == 2 && parts[0] != "" && parts[1] == "control-leases" {
		return parts[0], "", "acquire", true
	}
	if len(parts) != 3 || parts[0] == "" || parts[1] != "control-leases" {
		return "", "", "", false
	}
	switch {
	case strings.HasSuffix(parts[2], ":renew"):
		return parts[0], strings.TrimSuffix(parts[2], ":renew"), "renew", strings.TrimSuffix(parts[2], ":renew") != ""
	case strings.HasSuffix(parts[2], ":release"):
		return parts[0], strings.TrimSuffix(parts[2], ":release"), "release", strings.TrimSuffix(parts[2], ":release") != ""
	}
	return "", "", "", false
}

func (h *Handler) authenticate(request *http.Request) (productapi.Principal, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return productapi.Principal{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n") {
		return productapi.Principal{}, false
	}
	principal, err := h.authenticator.Authenticate(request.Context(), token)
	return principal, err == nil
}

func (h *Handler) createWorkspace(writer http.ResponseWriter, request *http.Request, principal productapi.Principal, requestID string) {
	if principal.Role != productapi.RoleOwner {
		writeError(writer, http.StatusForbidden, "PRODUCT_FORBIDDEN", "action is forbidden", false, requestID)
		return
	}
	if !jsonContentType(request.Header.Get("Content-Type")) {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "content type must be application/json", false, requestID)
		return
	}
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "exactly one idempotency key is required", false, requestID)
		return
	}
	var input CreateWorkspaceRequest
	if err := decodeStrict(request.Context(), writer, request.Body, maxCreateWorkspaceBytes, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request body", false, requestID)
		return
	}
	capabilities := make([]product.CapabilityRequirement, 0, len(input.PrimarySlot.RequiredCapabilities))
	for _, capability := range input.PrimarySlot.RequiredCapabilities {
		capabilities = append(capabilities, product.CapabilityRequirement{
			CapabilityID: capability.CapabilityID, Version: capability.Version, ProfileID: capability.ProfileID,
		})
	}
	result, err := h.application.CreateWorkspace(request.Context(), principal.TenantID, principal.Actor, keys[0], product.CreateWorkspaceRequest{
		DisplayName: input.DisplayName, LifetimeSeconds: input.LifetimeSeconds,
		PrimarySlot: product.SlotSpec{
			SlotKey: input.PrimarySlot.SlotKey, Kind: input.PrimarySlot.Kind, ProfileID: input.PrimarySlot.ProfileID,
			RequiredCapabilities: capabilities, DesiredState: input.PrimarySlot.DesiredState,
		},
	})
	if err != nil {
		writeApplicationError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusAccepted, toOperation(result.Operation))
}

func (h *Handler) getWorkspace(writer http.ResponseWriter, request *http.Request, principal productapi.Principal, requestID, workspaceID string) {
	workspace, err := h.application.GetWorkspace(request.Context(), principal.TenantID, principal.Actor, workspaceID)
	if err != nil {
		writeApplicationError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, toWorkspace(workspace))
}

func (h *Handler) getOperation(writer http.ResponseWriter, request *http.Request, principal productapi.Principal, requestID, operationID string) {
	operation, err := h.application.GetOperation(request.Context(), principal.TenantID, principal.Actor, operationID)
	if err != nil {
		writeApplicationError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, toOperation(operation))
}

func writeApplicationError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, product.ErrInvalid):
		writeError(writer, http.StatusBadRequest, "PRODUCT_INVALID_REQUEST", "invalid request", false, requestID)
	case errors.Is(err, product.ErrNotFound):
		writeError(writer, http.StatusNotFound, "PRODUCT_NOT_FOUND", "resource not found", false, requestID)
	case errors.Is(err, product.ErrForbidden):
		writeError(writer, http.StatusForbidden, "PRODUCT_FORBIDDEN", "action is forbidden", false, requestID)
	case errors.Is(err, product.ErrIdempotencyConflict):
		writeError(writer, http.StatusConflict, "PRODUCT_IDEMPOTENCY_CONFLICT", "idempotency key conflicts with retained request", false, requestID)
	case errors.Is(err, product.ErrCapabilityUnsupported):
		writeError(writer, http.StatusUnprocessableEntity, "PRODUCT_CAPABILITY_UNSUPPORTED", "requested capability is unavailable", false, requestID)
	case errors.Is(err, product.ErrStoreOutcomeUnknown):
		writeError(writer, http.StatusServiceUnavailable, "PRODUCT_OUTCOME_UNKNOWN", "command outcome requires reconciliation", true, requestID)
	case errors.Is(err, product.ErrVersionConflict):
		writeError(writer, http.StatusConflict, "PRODUCT_VERSION_CONFLICT", "resource version conflicts with retained state", false, requestID)
	case errors.Is(err, product.ErrControlConflict):
		writeError(writer, http.StatusConflict, "PRODUCT_CONTROL_CONFLICT", "control scope is already held", false, requestID)
	case errors.Is(err, product.ErrControlStale):
		writeError(writer, http.StatusConflict, "PRODUCT_CONTROL_STALE", "control authority is stale", false, requestID)
	case errors.Is(err, product.ErrQuotaExceeded):
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusTooManyRequests, "PRODUCT_RATE_LIMITED", "product quota is exhausted", true, requestID)
	default:
		writeError(writer, http.StatusServiceUnavailable, "PRODUCT_DEPENDENCY_UNAVAILABLE", "product dependency is unavailable", true, requestID)
	}
}

func writeError(writer http.ResponseWriter, status int, code, message string, retryable bool, requestID string) {
	writeJSON(writer, status, ProductError{Code: code, Message: message, Retryable: retryable, RequestID: requestID})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func jsonContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func singleIdentifier(value, prefix string) (string, bool) {
	identifier := strings.TrimPrefix(value, prefix)
	if identifier == "" || strings.Contains(identifier, "/") || strings.ContainsAny(identifier, "?#") {
		return "", false
	}
	return identifier, true
}

func validRequestID(value string) bool {
	if len(value) < 1 || len(value) > 200 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') && !strings.ContainsRune("._:-", rune(character)) {
			return false
		}
	}
	return true
}

func decodeStrict(ctx context.Context, writer http.ResponseWriter, source io.ReadCloser, maximum int64, destination any) error {
	if ctx == nil || source == nil || maximum <= 0 {
		return product.ErrInvalid
	}
	defer source.Close()
	data, err := io.ReadAll(http.MaxBytesReader(writer, source, maximum))
	if err != nil {
		return err
	}
	if err := rejectDuplicateMembers(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("request contains trailing JSON")
	}
	return ctx.Err()
}

func rejectDuplicateMembers(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, object := token.(json.Delim)
		if !object {
			return nil
		}
		switch delimiter {
		case '{':
			members := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || members[key] {
					return errors.New("request contains a duplicate JSON member")
				}
				members[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request contains trailing JSON")
	}
	return nil
}
