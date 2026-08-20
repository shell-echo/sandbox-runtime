package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
)

const contractSourceRootEnvironment = "SANDBOX_RUNTIME_CONTRACT_SOURCE_ROOT"

func TestLockedContractProjection(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	lockPath := filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json")
	projection, err := providercontract.Load(context.Background(), lockPath, sourceRoot)
	if err != nil {
		t.Fatalf("load local Provider projection: %v", err)
	}

	factories := map[string]func() any{
		"provider-capabilities.schema.json": func() any { return &Capabilities{} },
		"standard-error.schema.json":        func() any { return &StandardError{} },
	}
	expectedNames := make([]string, 0, len(factories))
	for name := range factories {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(expectedNames)
	if names := projection.SchemaNames(); !reflect.DeepEqual(names, expectedNames) {
		t.Fatalf("Provider projection = %v, want %v", names, expectedNames)
	}
	if limits := projection.RequestBodyLimits(); len(limits) != 0 {
		t.Fatalf("Provider request body limits = %v, want none for discovery-only Contract", limits)
	}

	fixtures := map[string]string{
		"provider-capabilities.schema.json": "capabilities.json",
		"standard-error.schema.json":        "standard-error.json",
	}
	for schemaName, fixtureName := range fixtures {
		t.Run("fixture/"+fixtureName, func(t *testing.T) {
			document, err := projection.ReadExample(fixtureName)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate(schemaName, document); err != nil {
				t.Fatalf("local fixture is invalid: %v", err)
			}
			destination := factories[schemaName]()
			if err := DecodeStrict(bytes.NewReader(document), 1<<20, destination); err != nil {
				t.Fatalf("decode local fixture into wire DTO: %v", err)
			}
			projected, err := json.Marshal(destination)
			if err != nil {
				t.Fatalf("encode wire DTO projection: %v", err)
			}
			if err := projection.Validate(schemaName, projected); err != nil {
				t.Fatalf("wire DTO projection is invalid: %v", err)
			}
		})
	}

	t.Run("schema mismatch", func(t *testing.T) {
		document := []byte(`{"provider_revision_id":"provider-revision-local-v1","api_version":"v1","capabilities":[],"runtime_profiles":[],"snapshot_restore_profiles":[],"limits":{}}`)
		if err := projection.Validate("provider-capabilities.schema.json", document); err == nil {
			t.Fatal("Validate() error = nil, want Schema mismatch")
		}
	})
}

func localContractSourceRoot(t *testing.T) string {
	t.Helper()
	if sourceRoot := os.Getenv(contractSourceRootEnvironment); sourceRoot != "" {
		return sourceRoot
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve local Contract source root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
