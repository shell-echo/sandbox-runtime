package providerapi

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
	"github.com/shell-echo/sandbox-runtime/provider"
)

func TestLockedCapabilitiesResponseProjection(t *testing.T) {
	sourceRoot := os.Getenv("AGENT_CONTRACT_SOURCE_ROOT")
	if sourceRoot == "" {
		t.Skip("AGENT_CONTRACT_SOURCE_ROOT is not set")
	}
	projection, err := providercontract.Load(context.Background(),
		"../compatibility/agent-platform/contract.lock.json", sourceRoot)
	if err != nil {
		t.Fatalf("load locked Provider projection: %v", err)
	}
	service, err := provider.NewStaticCapabilityService("spr_projection", provider.Limits{
		MaxCPUMillis: 1000, MaxMemoryBytes: 512 << 20,
		MaxEphemeralStorageBytes: 64 << 20, MaxLeaseSeconds: 3600,
		MaxExecSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	applicationValue, err := service.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wireValue, err := projectCapabilities(applicationValue)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(wireValue)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("sandbox-capabilities.schema.json", document); err != nil {
		t.Fatalf("capability response violates locked projection: %v", err)
	}
}
