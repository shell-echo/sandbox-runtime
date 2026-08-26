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
		"admission-context.schema.json":            func() any { return &map[string]any{} },
		"admission-target.schema.json":             func() any { return &map[string]any{} },
		"artifact-staging-evidence.schema.json":    func() any { return &ArtifactStagingEvidence{} },
		"artifact-staging-request.schema.json":     func() any { return &ArtifactStagingRequest{} },
		"cancel-exec-request.schema.json":          func() any { return &CancelExecRequest{} },
		"create-sandbox-request.schema.json":       func() any { return &CreateRequest{} },
		"exec-request.schema.json":                 func() any { return &ExecRequest{} },
		"exec-result.schema.json":                  func() any { return &ExecResult{} },
		"runtime-session-handoff.schema.json":      func() any { return &RuntimeSessionHandoff{} },
		"runtime-session-open-request.schema.json": func() any { return &RuntimeSessionOpenRequest{} },
		"usage-evidence.schema.json":               func() any { return &UsageEvidence{} },
		"provider-capabilities.schema.json":        func() any { return &Capabilities{} },
		"provider-error.schema.json":               func() any { return &ProviderError{} },
		"provider-operation.schema.json":           func() any { return &Operation{} },
		"sandbox-status.schema.json":               func() any { return &Status{} },
		"standard-error.schema.json":               func() any { return &StandardError{} },
	}
	expectedNames := make([]string, 0, len(factories))
	for name := range factories {
		expectedNames = append(expectedNames, name)
	}
	sort.Strings(expectedNames)
	if names := projection.SchemaNames(); !reflect.DeepEqual(names, expectedNames) {
		t.Fatalf("Provider projection = %v, want %v", names, expectedNames)
	}
	if limits := projection.RequestBodyLimits(); !reflect.DeepEqual(limits, map[string]int64{
		"cancel-exec-request.schema.json":          65536,
		"create-sandbox-request.schema.json":       1 << 20,
		"exec-request.schema.json":                 262144,
		"artifact-staging-request.schema.json":     65536,
		"runtime-session-open-request.schema.json": 65536,
	}) {
		t.Fatalf("Provider request body limits = %v, want create request limit", limits)
	}

	fixtures := map[string]string{
		"admission-context.schema.json":            "admission-context.json",
		"admission-target.schema.json":             "admission-target.json",
		"artifact-staging-evidence.schema.json":    "artifact-staging-evidence.json",
		"artifact-staging-request.schema.json":     "artifact-staging-request.json",
		"cancel-exec-request.schema.json":          "cancel-exec-request.json",
		"create-sandbox-request.schema.json":       "create-sandbox-request.json",
		"exec-request.schema.json":                 "exec-request.json",
		"exec-result.schema.json":                  "exec-result.json",
		"runtime-session-handoff.schema.json":      "runtime-session-handoff.json",
		"runtime-session-open-request.schema.json": "runtime-session-open-request.json",
		"usage-evidence.schema.json":               "usage-evidence.json",
		"provider-capabilities.schema.json":        "capabilities.json",
		"provider-error.schema.json":               "provider-error.json",
		"provider-operation.schema.json":           "provider-operation.json",
		"sandbox-status.schema.json":               "sandbox-status.json",
		"standard-error.schema.json":               "standard-error.json",
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

	t.Run("artifact stage operation", func(t *testing.T) {
		document, err := projection.ReadExample("provider-operation-artifact-stage.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := projection.Validate("provider-operation.schema.json", document); err != nil {
			t.Fatalf("artifact stage operation fixture is invalid: %v", err)
		}
		var operation Operation
		if err := DecodeStrict(bytes.NewReader(document), 1<<20, &operation); err != nil {
			t.Fatalf("decode artifact stage operation: %v", err)
		}
		if operation.Type != OperationArtifactStage {
			t.Fatalf("operation type = %q, want %q", operation.Type, OperationArtifactStage)
		}
	})
}

func TestLockedTerminalCapabilityAdvertisementProjection(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	projection, err := providercontract.Load(context.Background(), filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json"), sourceRoot)
	if err != nil {
		t.Fatalf("load local Provider projection: %v", err)
	}
	document, err := projection.ReadExample("capabilities-terminal.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-capabilities.schema.json", document); err != nil {
		t.Fatalf("terminal capability fixture is invalid: %v", err)
	}
	var capabilities Capabilities
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &capabilities); err != nil {
		t.Fatalf("decode terminal capability fixture: %v", err)
	}
	if len(capabilities.Capabilities) != 1 || capabilities.Capabilities[0].ID != CapabilityTerminal ||
		len(capabilities.Capabilities[0].Versions) != 1 || capabilities.Capabilities[0].Versions[0] != "1.0.0" ||
		len(capabilities.Capabilities[0].Profiles) != 1 || capabilities.Capabilities[0].Profiles[0] != "terminal-v1" {
		t.Fatalf("terminal capability projection = %#v", capabilities.Capabilities)
	}
	if len(capabilities.RuntimeProfiles) != 1 || capabilities.RuntimeProfiles[0].ID != "sandbox-runtime-terminal-v1" ||
		len(capabilities.RuntimeProfiles[0].CapabilityProfileIDs) != 1 || capabilities.RuntimeProfiles[0].CapabilityProfileIDs[0] != "terminal-v1" {
		t.Fatalf("terminal runtime profile projection = %#v", capabilities.RuntimeProfiles)
	}
	projected, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-capabilities.schema.json", projected); err != nil {
		t.Fatalf("terminal capability DTO projection is invalid: %v", err)
	}

	semanticRules, err := os.ReadFile(filepath.Join(sourceRoot, "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var semantics struct {
		Rules []struct {
			ID       string   `json:"id"`
			Method   string   `json:"method"`
			Path     string   `json:"path"`
			Scope    string   `json:"scope"`
			Requires []string `json:"requires"`
			Response struct {
				CapabilityID string `json:"capability_id"`
				ProfileMap   string `json:"capability_profile_to_runtime_profile"`
			} `json:"response"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(semanticRules, &semantics); err != nil {
		t.Fatalf("decode local semantic rules: %v", err)
	}
	for _, rule := range semantics.Rules {
		if rule.ID != "capabilities-terminal-profile-advertisement" {
			continue
		}
		if rule.Method != "GET" || rule.Path != "/v1/capabilities" || rule.Scope != "terminal-session-advertisement" ||
			rule.Response.CapabilityID != "sandbox.terminal" || rule.Response.ProfileMap != "explicit-capability_profile_ids" {
			t.Fatalf("terminal advertisement semantic rule = %#v", rule)
		}
		for _, requirement := range []string{
			"terminal-disabled-means-zero-advertisement",
			"sandbox-terminal-capability-must-advertise-at-least-one-version",
			"advertised-terminal-version-must-be-sandbox-capability-requirement-compatible-semver",
			"terminal-capability-profile-must-map-to-an-advertised-runtime-profile",
			"terminal-capability-profile-must-match-runtime-session-fixtures",
			"session-admission-must-match-exact-advertised-capability-version-profile-and-runtime-profile",
		} {
			if !containsString(rule.Requires, requirement) {
				t.Fatalf("terminal advertisement semantic rule is missing %q", requirement)
			}
		}
		return
	}
	t.Fatal("local Contract is missing terminal capability advertisement semantic rule")
}

func TestLockedTerminalSessionContractConsistency(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	projection, err := providercontract.Load(context.Background(), filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json"), sourceRoot)
	if err != nil {
		t.Fatalf("load local Provider projection: %v", err)
	}

	capabilityDocument, err := projection.ReadExample("capabilities-terminal.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-capabilities.schema.json", capabilityDocument); err != nil {
		t.Fatalf("terminal capability fixture is invalid: %v", err)
	}
	var capabilities Capabilities
	if err := DecodeStrict(bytes.NewReader(capabilityDocument), 1<<20, &capabilities); err != nil {
		t.Fatalf("decode terminal capability fixture: %v", err)
	}
	if len(capabilities.Capabilities) != 1 || len(capabilities.Capabilities[0].Versions) != 1 || len(capabilities.Capabilities[0].Profiles) != 1 || len(capabilities.RuntimeProfiles) != 1 {
		t.Fatalf("terminal capability fixture must contain one version, profile, and runtime profile: %#v", capabilities)
	}
	terminal := capabilities.Capabilities[0]
	profileID := terminal.Profiles[0]
	if terminal.ID != CapabilityTerminal || !containsString(capabilities.RuntimeProfiles[0].CapabilityProfileIDs, profileID) {
		t.Fatalf("terminal capability profile is not mapped to the canonical runtime profile: %#v", capabilities)
	}

	openDocument, err := projection.ReadExample("runtime-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var openRequest RuntimeSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(openDocument), MaxRuntimeSessionOpenRequestBytes, &openRequest); err != nil {
		t.Fatalf("decode runtime session open fixture: %v", err)
	}
	handoffDocument, err := projection.ReadExample("runtime-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	var handoff RuntimeSessionHandoff
	if err := DecodeStrict(bytes.NewReader(handoffDocument), 1<<20, &handoff); err != nil {
		t.Fatalf("decode runtime session handoff fixture: %v", err)
	}
	if openRequest.CapabilityProfileID != profileID || handoff.CapabilityProfileID != profileID {
		t.Fatalf("terminal profile mismatch: advertised=%q open=%q handoff=%q", profileID, openRequest.CapabilityProfileID, handoff.CapabilityProfileID)
	}

	createDocument, err := projection.ReadExample("create-sandbox-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var createRequest map[string]any
	if err := json.Unmarshal(createDocument, &createRequest); err != nil {
		t.Fatalf("decode create sandbox fixture: %v", err)
	}
	spec, ok := createRequest["spec"].(map[string]any)
	if !ok {
		t.Fatal("create sandbox fixture is missing spec object")
	}
	spec["runtime_profile"] = capabilities.RuntimeProfiles[0].ID
	spec["required_capabilities"] = []any{map[string]any{
		"id": string(terminal.ID), "version": terminal.Versions[0], "profile": profileID,
	}}
	projectedCreate, err := json.Marshal(createRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("create-sandbox-request.schema.json", projectedCreate); err != nil {
		t.Fatalf("advertised terminal version/profile cannot form a valid sandbox requirement: %v", err)
	}
}

func TestLockedCodingShellCapabilityAdvertisementProjection(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	projection, err := providercontract.Load(context.Background(), filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json"), sourceRoot)
	if err != nil {
		t.Fatalf("load local Provider projection: %v", err)
	}
	document, err := projection.ReadExample("capabilities-coding-shell.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-capabilities.schema.json", document); err != nil {
		t.Fatalf("coding/shell capability fixture is invalid: %v", err)
	}
	var capabilities Capabilities
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &capabilities); err != nil {
		t.Fatalf("decode coding/shell capability fixture: %v", err)
	}
	if len(capabilities.Capabilities) != 2 || len(capabilities.RuntimeProfiles) != 1 {
		t.Fatalf("coding/shell capability shape = %#v", capabilities)
	}
	byID := make(map[CapabilityID]Capability, len(capabilities.Capabilities))
	for _, capability := range capabilities.Capabilities {
		byID[capability.ID] = capability
	}
	if exec := byID[CapabilityExec]; !reflect.DeepEqual(exec.Versions, []string{"1.0.0"}) || !reflect.DeepEqual(exec.Profiles, []string{"exec-v1"}) {
		t.Fatalf("exec capability = %#v", exec)
	}
	if terminal := byID[CapabilityTerminal]; !reflect.DeepEqual(terminal.Versions, []string{"1.0.0"}) || !reflect.DeepEqual(terminal.Profiles, []string{"terminal-v1"}) {
		t.Fatalf("terminal capability = %#v", terminal)
	}
	runtimeProfile := capabilities.RuntimeProfiles[0]
	if runtimeProfile.ID != "sandbox-runtime-coding-shell-v1" || !reflect.DeepEqual(runtimeProfile.CapabilityProfileIDs, []string{"exec-v1", "terminal-v1"}) {
		t.Fatalf("coding/shell runtime profile = %#v", runtimeProfile)
	}

	semanticRules, err := os.ReadFile(filepath.Join(sourceRoot, "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var semantics struct {
		Rules []struct {
			ID       string   `json:"id"`
			Method   string   `json:"method"`
			Path     string   `json:"path"`
			Scope    string   `json:"scope"`
			Requires []string `json:"requires"`
			Response struct {
				CapabilityIDs      []string `json:"capability_ids"`
				CapabilityProfiles []string `json:"capability_profiles"`
				RuntimeProfileID   string   `json:"runtime_profile_id"`
				ProfileMap         string   `json:"capability_profile_to_runtime_profile"`
				StableMounts       []string `json:"stable_mounts"`
				EvidenceRoutes     []string `json:"required_evidence_routes"`
			} `json:"response"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(semanticRules, &semantics); err != nil {
		t.Fatalf("decode local semantic rules: %v", err)
	}
	for _, rule := range semantics.Rules {
		if rule.ID != "capabilities-coding-shell-profile-advertisement" {
			continue
		}
		if rule.Method != "GET" || rule.Path != "/v1/capabilities" || rule.Scope != "coding-shell-advertisement" ||
			!reflect.DeepEqual(rule.Response.CapabilityIDs, []string{"sandbox.exec", "sandbox.terminal"}) ||
			!reflect.DeepEqual(rule.Response.CapabilityProfiles, []string{"exec-v1", "terminal-v1"}) ||
			rule.Response.RuntimeProfileID != "sandbox-runtime-coding-shell-v1" || rule.Response.ProfileMap != "explicit-capability_profile_ids" ||
			!reflect.DeepEqual(rule.Response.StableMounts, []string{"/inputs", "/workspace", "/outputs", "/tmp"}) || len(rule.Response.EvidenceRoutes) != 2 {
			t.Fatalf("coding/shell advertisement semantic rule = %#v", rule)
		}
		for _, requirement := range []string{
			"coding-shell-advertisement-is-atomic",
			"create-fixture-requires-exact-advertised-runtime-and-capabilities",
			"artifact-staging-and-usage-evidence-routes-remain-required",
			"disabled-composition-means-zero-advertisement",
		} {
			if !containsString(rule.Requires, requirement) {
				t.Fatalf("coding/shell advertisement semantic rule is missing %q", requirement)
			}
		}
		return
	}
	t.Fatal("local Contract is missing coding/shell capability advertisement semantic rule")
}

func TestLockedCodingShellContractConsistency(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	projection, err := providercontract.Load(context.Background(), filepath.Join(sourceRoot, "compatibility/sandbox-runtime/contract.lock.json"), sourceRoot)
	if err != nil {
		t.Fatalf("load local Provider projection: %v", err)
	}

	capabilityDocument, err := projection.ReadExample("capabilities-coding-shell.json")
	if err != nil {
		t.Fatal(err)
	}
	var capabilities Capabilities
	if err := DecodeStrict(bytes.NewReader(capabilityDocument), 1<<20, &capabilities); err != nil {
		t.Fatalf("decode coding/shell capabilities: %v", err)
	}
	if len(capabilities.RuntimeProfiles) != 1 {
		t.Fatalf("coding/shell runtime profiles = %#v", capabilities.RuntimeProfiles)
	}
	capabilityByID := make(map[string]CapabilityRequirement, len(capabilities.Capabilities))
	for _, capability := range capabilities.Capabilities {
		if len(capability.Versions) != 1 || len(capability.Profiles) != 1 {
			t.Fatalf("coding/shell capability must have one locked version and profile: %#v", capability)
		}
		capabilityByID[string(capability.ID)] = CapabilityRequirement{ID: string(capability.ID), Version: capability.Versions[0], Profile: capability.Profiles[0]}
	}

	createDocument, err := projection.ReadExample("create-sandbox-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("create-sandbox-request.schema.json", createDocument); err != nil {
		t.Fatalf("coding/shell create fixture is invalid: %v", err)
	}
	var create CreateRequest
	if err := DecodeStrict(bytes.NewReader(createDocument), MaxCreateRequestBytes, &create); err != nil {
		t.Fatalf("decode coding/shell create fixture: %v", err)
	}
	if create.Spec.RuntimeProfile != capabilities.RuntimeProfiles[0].ID || len(create.Spec.RequiredCapabilities) != len(capabilityByID) {
		t.Fatalf("coding/shell create profile = %#v", create.Spec)
	}
	for _, requirement := range create.Spec.RequiredCapabilities {
		if expected, ok := capabilityByID[requirement.ID]; !ok || requirement != expected {
			t.Fatalf("create capability requirement %#v is not exactly advertised; want %#v", requirement, expected)
		}
	}

	openDocument, err := projection.ReadExample("runtime-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var open RuntimeSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(openDocument), MaxRuntimeSessionOpenRequestBytes, &open); err != nil {
		t.Fatalf("decode runtime session fixture: %v", err)
	}
	handoffDocument, err := projection.ReadExample("runtime-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	var handoff RuntimeSessionHandoff
	if err := DecodeStrict(bytes.NewReader(handoffDocument), 1<<20, &handoff); err != nil {
		t.Fatalf("decode runtime session handoff fixture: %v", err)
	}
	terminal := capabilityByID[string(CapabilityTerminal)]
	if open.CapabilityProfileID != terminal.Profile || handoff.CapabilityProfileID != terminal.Profile {
		t.Fatalf("terminal session profile mismatch: advertised=%q open=%q handoff=%q", terminal.Profile, open.CapabilityProfileID, handoff.CapabilityProfileID)
	}

	for schema, fixture := range map[string]string{
		"artifact-staging-evidence.schema.json": "artifact-staging-evidence.json",
		"usage-evidence.schema.json":            "usage-evidence.json",
	} {
		document, err := projection.ReadExample(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := projection.Validate(schema, document); err != nil {
			t.Fatalf("required coding/shell evidence fixture %s is invalid: %v", fixture, err)
		}
	}
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

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
