package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
)

const contractSourceRootEnvironment = "AGENT_CONTRACT_SOURCE_ROOT"

func TestLockedContractProjection(t *testing.T) {
	sourceRoot := os.Getenv(contractSourceRootEnvironment)
	if sourceRoot == "" {
		t.Skip(contractSourceRootEnvironment + " is not set")
	}
	projection, err := providercontract.Load(context.Background(),
		"../../compatibility/agent-platform/contract.lock.json", sourceRoot)
	if err != nil {
		t.Fatalf("load locked Provider projection: %v", err)
	}

	factories := map[string]func() any{
		"sandbox-cancel-exec-request.schema.json":          func() any { return &CancelExecRequest{} },
		"sandbox-capabilities.schema.json":                 func() any { return &Capabilities{} },
		"sandbox-create-request.schema.json":               func() any { return &CreateRequest{} },
		"sandbox-desired-state-request.schema.json":        func() any { return &DesiredStateRequest{} },
		"sandbox-exec-request.schema.json":                 func() any { return &ExecRequest{} },
		"sandbox-exec-result.schema.json":                  func() any { return &ExecResult{} },
		"sandbox-lease-request.schema.json":                func() any { return &LeaseRequest{} },
		"sandbox-operation.schema.json":                    func() any { return &Operation{} },
		"sandbox-restore-request.schema.json":              func() any { return &RestoreRequest{} },
		"sandbox-runtime-session-endpoint.schema.json":     func() any { return &RuntimeSessionEndpoint{} },
		"sandbox-runtime-session-open-request.schema.json": func() any { return &RuntimeSessionOpenRequest{} },
		"sandbox-snapshot-manifest.schema.json":            func() any { return &SnapshotManifest{} },
		"sandbox-snapshot-request.schema.json":             func() any { return &SnapshotRequest{} },
		"sandbox-status.schema.json":                       func() any { return &Status{} },
		"sandbox-terminate-request.schema.json":            func() any { return &TerminateRequest{} },
		"standard-error.schema.json":                       func() any { return &StandardError{} },
	}
	expectedNames := make([]string, 0, len(factories))
	for name := range factories {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(expectedNames)
	if names := projection.SchemaNames(); !reflect.DeepEqual(names, expectedNames) {
		t.Fatalf("Provider projection = %v, want %v", names, expectedNames)
	}
	expectedLimits := map[string]int64{
		"sandbox-create-request.schema.json":               MaxCreateRequestBytes,
		"sandbox-restore-request.schema.json":              MaxRestoreRequestBytes,
		"sandbox-desired-state-request.schema.json":        MaxDesiredStateRequestBytes,
		"sandbox-lease-request.schema.json":                MaxLeaseRequestBytes,
		"sandbox-exec-request.schema.json":                 MaxExecRequestBytes,
		"sandbox-cancel-exec-request.schema.json":          MaxCancelExecRequestBytes,
		"sandbox-runtime-session-open-request.schema.json": MaxRuntimeSessionOpenRequestBytes,
		"sandbox-snapshot-request.schema.json":             MaxSnapshotRequestBytes,
		"sandbox-terminate-request.schema.json":            MaxTerminateRequestBytes,
	}
	if limits := projection.RequestBodyLimits(); !reflect.DeepEqual(limits, expectedLimits) {
		t.Fatalf("Provider request limits = %v, want %v", limits, expectedLimits)
	}

	fixtures := map[string]string{
		"sandbox-cancel-exec-request.schema.json":          "sandbox-cancel-exec-request.json",
		"sandbox-capabilities.schema.json":                 "sandbox-capabilities.json",
		"sandbox-create-request.schema.json":               "sandbox-create-request.json",
		"sandbox-desired-state-request.schema.json":        "sandbox-desired-state-request.json",
		"sandbox-exec-request.schema.json":                 "sandbox-exec-request.json",
		"sandbox-lease-request.schema.json":                "sandbox-lease-request.json",
		"sandbox-restore-request.schema.json":              "sandbox-restore-request.json",
		"sandbox-runtime-session-open-request.schema.json": "sandbox-runtime-session-open-request.json",
		"sandbox-snapshot-request.schema.json":             "sandbox-snapshot-request.json",
		"sandbox-status.schema.json":                       "sandbox-status.json",
		"sandbox-terminate-request.schema.json":            "sandbox-terminate-request.json",
	}
	for schemaName, fixtureName := range fixtures {
		t.Run("fixture/"+fixtureName, func(t *testing.T) {
			document, err := projection.ReadExample(fixtureName)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate(schemaName, document); err != nil {
				t.Fatalf("locked fixture is invalid: %v", err)
			}
			destination := factories[schemaName]()
			limit := int64(1 << 20)
			if requestLimit, ok := expectedLimits[schemaName]; ok {
				limit = requestLimit
			}
			if err := DecodeStrict(bytes.NewReader(document), limit, destination); err != nil {
				t.Fatalf("decode locked fixture into wire DTO: %v", err)
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

	synthetic := map[string]any{
		"sandbox-exec-result.schema.json": &ExecResult{
			OperationID: "op-1", AttemptID: "attempt-1", FencingToken: 1,
			SandboxID: "sandbox-1", Status: ExecCompleted,
			StartedAt: "2026-07-30T08:00:00Z", CompletedAt: "2026-07-30T08:00:01Z",
			Usage: []UsageEntry{{
				EntryID: "usage-1", SandboxID: "sandbox-1", Meter: MeterExecCount,
				Quantity: 1, Unit: "count", MeterSource: MeterSourceRuntime,
				OccurredAt: "2026-07-30T08:00:01Z",
			}},
		},
		"sandbox-operation.schema.json": &Operation{
			OperationID: "op-1", AttemptID: "attempt-1", FencingToken: 1,
			SandboxID: "sandbox-1", Type: OperationCreate, Status: OperationAccepted,
			ObservedAt: "2026-07-30T08:00:00Z",
		},
		"sandbox-runtime-session-endpoint.schema.json": &RuntimeSessionEndpoint{
			OperationID: "op-1", AttemptID: "attempt-1", FencingToken: 1,
			SandboxID: "sandbox-1", RuntimeSessionID: "session-1",
			ProviderSessionID: "provider-session-1", RuntimeType: RuntimeTerminal,
			Protocol: ProtocolWebSocket, InternalEndpointReference: "route:terminal-1",
			ConnectionGeneration: 1, ExpiresAt: "2026-07-30T08:05:00Z",
		},
		"sandbox-snapshot-manifest.schema.json": &SnapshotManifest{
			SnapshotID: "snapshot-1", SandboxID: "sandbox-1",
			SourceProviderRevisionID: "provider-revision-1", SourceRuntimeRevision: "runtime-1",
			Level: SnapshotWorkspace, Portability: PortabilitySameRevision,
			CompatibilityProfile: "sandbox-snapshot-workspace-v1",
			Digest:               SHA256Digest("sha256:" + string(bytes.Repeat([]byte("a"), 64))),
			SizeBytes:            0, CreatedAt: "2026-07-30T08:00:00Z",
			ContentReference: "snapshot:content-1",
		},
		"standard-error.schema.json": &StandardError{
			Code: "SANDBOX_SPEC_INVALID", Message: "invalid request", Retryable: false,
			TraceID: "trace-1",
		},
	}
	for schemaName, document := range synthetic {
		t.Run("constructed/"+schemaName, func(t *testing.T) {
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("encode constructed Provider DTO: %v", err)
			}
			if err := projection.Validate(schemaName, encoded); err != nil {
				t.Fatalf("constructed Provider DTO is invalid: %v", err)
			}
		})
	}

	t.Run("schema mismatch", func(t *testing.T) {
		document := mutatedFixture(t, projection, "sandbox-capabilities.json", func(value map[string]any) {
			value["limits"].(map[string]any)["max_cpu_millis"] = "many"
		})
		if err := projection.Validate("sandbox-capabilities.schema.json", document); err == nil {
			t.Fatal("Validate() error = nil, want Schema type mismatch")
		}
	})

	t.Run("critical enum", func(t *testing.T) {
		document := mutatedFixture(t, projection, "sandbox-desired-state-request.json", func(value map[string]any) {
			value["desired_state"] = "terminated"
		})
		if err := projection.Validate("sandbox-desired-state-request.schema.json", document); err == nil {
			t.Fatal("Validate() error = nil, want enum rejection")
		}
		if err := DecodeStrict(bytes.NewReader(document), 1<<20, &DesiredStateRequest{}); err == nil {
			t.Fatal("DecodeStrict() error = nil, want closed enum rejection")
		}
	})

	t.Run("critical digest and slot identifiers", func(t *testing.T) {
		document := mutatedFixture(t, projection, "sandbox-create-request.json", func(value map[string]any) {
			value["request_digest"] = "sha256:invalid"
			value["spec"].(map[string]any)["sandbox_slot_key"] = "Primary Code"
		})
		if err := projection.Validate("sandbox-create-request.schema.json", document); err == nil {
			t.Fatal("Validate() error = nil, want identifier rejection")
		}
		if err := DecodeStrict(bytes.NewReader(document), 1<<20, &CreateRequest{}); err == nil {
			t.Fatal("DecodeStrict() error = nil, want identifier rejection")
		}
	})
}

func mutatedFixture(t *testing.T, projection *providercontract.Projection, name string, mutate func(map[string]any)) []byte {
	t.Helper()
	document, err := projection.ReadExample(name)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(document, &value); err != nil {
		t.Fatalf("decode fixture for in-memory mutation: %v", err)
	}
	mutate(value)
	document, err = json.Marshal(value)
	if err != nil {
		t.Fatalf("encode in-memory fixture mutation: %v", err)
	}
	return document
}
