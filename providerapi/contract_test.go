package providerapi

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
)

const contractSourceRootEnvironment = "AGENT_CONTRACT_SOURCE_ROOT"

func TestLockedCapabilityResponseSchema(t *testing.T) {
	sourceRoot := os.Getenv(contractSourceRootEnvironment)
	if sourceRoot == "" {
		t.Skip(contractSourceRootEnvironment + " is not set")
	}
	projection, err := providercontract.Load(context.Background(),
		"../compatibility/agent-platform/contract.lock.json", sourceRoot)
	if err != nil {
		t.Fatalf("load locked Provider projection: %v", err)
	}

	source := &capabilityReaderSpy{snapshot: validSnapshot(t, int64Pointer(4096), int64Pointer(0))}
	handler, err := newCapabilitiesHandler(context.Background(), source)
	if err != nil {
		t.Fatalf("construct capability handler: %v", err)
	}
	response := serve(handler, http.MethodGet, capabilitiesPath, "")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if err := projection.Validate("sandbox-capabilities.schema.json", response.Body.Bytes()); err != nil {
		t.Fatalf("actual encoded capability response is invalid: %v", err)
	}
}
