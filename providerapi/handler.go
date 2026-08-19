package providerapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/shell-echo/sandbox-runtime/provider"
)

const capabilitiesPath = "/v1/capabilities"

// newCapabilitiesHandler constructs a GET-only immutable capability endpoint.
// It reads and validates the source exactly once and freezes the encoded bytes
// before the returned handler can serve traffic. It remains package-private so
// callers cannot bypass the mTLS-only Provider server composition.
func newCapabilitiesHandler(ctx context.Context, source provider.CapabilityReader) (http.Handler, error) {
	if ctx == nil {
		return nil, errors.New("capability construction context is nil")
	}
	if source == nil {
		return nil, errors.New("capability source is nil")
	}
	snapshot, err := source.CapabilitySnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("read capability snapshot: %w", err)
	}
	document := mapCapabilities(snapshot)
	if err := validateCapabilities(document); err != nil {
		return nil, fmt.Errorf("validate Provider v1 capability response: %w", err)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode Provider v1 capability response: %w", err)
	}

	return &capabilitiesHandler{encoded: append([]byte(nil), encoded...)}, nil
}

type capabilitiesHandler struct {
	encoded []byte
}

func (h *capabilitiesHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != capabilitiesPath {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery || requestHasBodyMetadata(request) {
		// Discovery has no request document. Do not read Body: an unknown-length
		// or transfer-encoded request could otherwise block or consume unbounded input.
		response.WriteHeader(http.StatusBadRequest)
		return
	}

	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(h.encoded)
}

func requestHasBodyMetadata(request *http.Request) bool {
	return request.ContentLength != 0 || len(request.TransferEncoding) != 0
}
