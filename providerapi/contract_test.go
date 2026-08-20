package providerapi

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
)

func localContractSourceRoot(t *testing.T) string {
	t.Helper()
	if sourceRoot := os.Getenv("SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT"); sourceRoot != "" {
		return sourceRoot
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve local Contract source root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

func TestLockedCapabilityResponseSchema(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	projection, err := providercontract.Load(context.Background(),
		filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json"), sourceRoot)
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
	if err := projection.Validate("provider-capabilities.schema.json", response.Body.Bytes()); err != nil {
		t.Fatalf("actual encoded capability response is invalid: %v", err)
	}
}
