package productapiv1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const maxCreateWorkspaceBytes int64 = 65536

type Handler struct {
	application   *product.Application
	authenticator productapi.Authenticator
	requestIDs    product.IDGenerator
}

func NewHandler(application *product.Application, authenticator productapi.Authenticator, requestIDs product.IDGenerator) (*Handler, error) {
	if application == nil || productapi.IsNilAuthenticator(authenticator) || requestIDs == nil {
		return nil, product.ErrInvalid
	}
	return &Handler{application: application, authenticator: authenticator, requestIDs: requestIDs}, nil
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
