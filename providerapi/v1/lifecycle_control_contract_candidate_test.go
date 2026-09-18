package v1

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"github.com/shell-echo/sandbox-runtime/internal/suitedigest"
	"go.yaml.in/yaml/v3"
)

func TestLocalLifecycleControlCapabilityAdvertisement(t *testing.T) {
	root := localContractSourceRoot(t)
	document := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/capabilities-coding-shell-lifecycle-control.json"))
	compiler := jsonschemaecma.NewCompiler()
	for _, resource := range []struct{ id, name string }{
		{"urn:shell-echo:sandbox-runtime:contract:provider-capabilities:v1", "provider-capabilities.schema.json"},
		{"urn:shell-echo:sandbox-runtime:contract:capability:v1", "capability.schema.json"},
		{"urn:shell-echo:sandbox-runtime:contract:runtime-profile:v1", "runtime-profile.schema.json"},
		{"urn:shell-echo:sandbox-runtime:contract:snapshot-restore-profile:v1", "snapshot-restore-profile.schema.json"},
		{"urn:shell-echo:sandbox-runtime:contract:provider-limits:v1", "provider-limits.schema.json"},
	} {
		if err := compiler.AddResource(resource.id, readCandidateJSON(t, filepath.Join(root, "contract/schemas", resource.name))); err != nil {
			t.Fatalf("add %s: %v", resource.name, err)
		}
	}
	schema, err := compiler.Compile("urn:shell-echo:sandbox-runtime:contract:provider-capabilities:v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("control capability fixture is invalid: %v", err)
	}
	capabilities := document.(map[string]any)["capabilities"].([]any)
	want := map[string]string{
		"sandbox.exec": "exec-v1", "sandbox.terminal": "terminal-v1",
		"sandbox.lifecycle-control": "lifecycle-control-v1", "sandbox.terminal-control": "terminal-control-v1",
		"sandbox.terminal-connect": "terminal-connect-v1",
	}
	for _, item := range capabilities {
		capability := item.(map[string]any)
		id := capability["id"].(string)
		profile, ok := want[id]
		if !ok || !reflect.DeepEqual(capability["versions"], []any{"1.0.0"}) || !reflect.DeepEqual(capability["profiles"], []any{profile}) {
			t.Fatalf("unexpected control capability: %#v", capability)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("missing control capabilities: %#v", want)
	}
	runtimeProfile := document.(map[string]any)["runtime_profiles"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(runtimeProfile["capability_profile_ids"], []any{"exec-v1", "terminal-v1", "lifecycle-control-v1", "terminal-control-v1", "terminal-connect-v1"}) {
		t.Fatalf("control runtime profile = %#v", runtimeProfile)
	}
	requireCandidateRule(t, root, "capabilities-lifecycle-control-profile-advertisement")
}

func TestLocalLifecycleDesiredStateSchemaAndSemantics(t *testing.T) {
	root := localContractSourceRoot(t)
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:desired-state-request:v1", "desired-state-request.schema.json", "desired-state-request.json")
	assertCandidateRoute(t, root, "/v1/sandboxes/{sandbox_id}/desired-state", "post", "../schemas/desired-state-request.schema.json", "sandbox.lifecycle-control", "lifecycle-control-v1")
	rule := requireCandidateRule(t, root, "lifecycle-desired-state-control")
	requireValues(t, "desired-state requires", rule["requires"].([]any), "ready-or-suspended-only", "runtime-observation-before-success", "outcome-unknown-attempt-immutable")
}

func TestLocalLifecycleLeaseSchemaAndSemantics(t *testing.T) {
	root := localContractSourceRoot(t)
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:lease-request:v1", "lease-request.schema.json", "lease-request.json")
	assertCandidateRoute(t, root, "/v1/sandboxes/{sandbox_id}/lease", "post", "../schemas/lease-request.schema.json", "sandbox.lifecycle-control", "lifecycle-control-v1")
	rule := requireCandidateRule(t, root, "lifecycle-lease-renewal-and-expiry")
	requireValues(t, "lease requires", rule["requires"].([]any), "generation-is-not-incremented", "expiry-uses-reconciled-runtime-cleanup", "runtime-absence-before-terminal-observation")
}

func TestLocalLifecycleTerminationCleanupAndReconciliation(t *testing.T) {
	root := localContractSourceRoot(t)
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:terminate-request:v1", "terminate-request.schema.json", "terminate-request.json")
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:provider-operation:v1", "provider-operation.schema.json", "provider-operation-lifecycle.json")
	assertCandidateRoute(t, root, "/v1/sandboxes/{sandbox_id}:terminate", "post", "../schemas/terminate-request.schema.json", "sandbox.lifecycle-control", "lifecycle-control-v1")
	rule := requireCandidateRule(t, root, "lifecycle-termination-reconciliation")
	requireValues(t, "termination requires", rule["requires"].([]any), "exact-owned-runtime-removal", "runtime-absence-before-success", "restart-reconciliation", "outcome-unknown-attempt-immutable")
}

func TestLocalLifecycleEventsPollingAndCursors(t *testing.T) {
	root := localContractSourceRoot(t)
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:lifecycle-event-page:v1", "lifecycle-event-page.schema.json", "lifecycle-event-page.json")
	assertCandidateRoute(t, root, "/v1/sandboxes/{sandbox_id}/events", "get", "../schemas/lifecycle-event-page.schema.json", "sandbox.lifecycle-control", "lifecycle-control-v1")
	rule := requireCandidateRule(t, root, "lifecycle-event-cursor")
	responses := rule["response"].(map[string]any)
	if responses["cursor_ahead_status"] != float64(409) || responses["cursor_expired_status"] != float64(410) {
		t.Fatalf("event cursor responses = %#v", responses)
	}
	if !reflect.DeepEqual(responses["cursor_error_details"], []any{"first_available_sequence", "latest_sequence"}) {
		t.Fatalf("event cursor details = %#v", responses["cursor_error_details"])
	}
	compiler := jsonschemaecma.NewCompiler()
	const standardErrorID = "urn:shell-echo:sandbox-runtime:contract:standard-error:v1"
	if err := compiler.AddResource(standardErrorID, readCandidateJSON(t, filepath.Join(root, "contract/schemas/standard-error.schema.json"))); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(standardErrorID)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(map[string]any{
		"code": "SANDBOX_EVENT_CURSOR_EXPIRED", "message": "cursor expired", "retryable": false, "trace_id": "trace-1",
		"details": map[string]any{"first_available_sequence": float64(7), "latest_sequence": float64(12)},
	}); err != nil {
		t.Fatalf("cursor error details are not Contract-valid: %v", err)
	}
	requireValues(t, "event forbids", rule["forbids"].([]any), "silent-cursor-rewind", "sse", "long-polling")
}

func TestLocalTerminalControlCapabilityAdvertisement(t *testing.T) {
	root := localContractSourceRoot(t)
	rule := requireCandidateRule(t, root, "capabilities-terminal-control-profile-advertisement")
	requireValues(t, "terminal-control requires", rule["requires"].([]any), "sandbox-terminal-version-1.0.0-with-terminal-v1-profile-on-same-runtime", "handoff-revocation-before-cleanup", "exact-allocation-absence-confirmation")

	suite, err := suitedigest.Load(filepath.Join(root, "contract/conformance/provider-v1/suite.json"), suitedigest.DigestProfile)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := suite.RequiredProfile("sandbox-runtime-provider-v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"lifecycle-control-capability-advertisement", "lifecycle-desired-state-schema-and-semantics",
		"lifecycle-lease-schema-and-semantics", "lifecycle-termination-cleanup-and-reconciliation",
		"lifecycle-events-polling-and-cursors", "terminal-control-capability-advertisement",
		"runtime-session-close-schema-and-semantics",
	} {
		if !containsString(profile.Tests, id) {
			t.Fatalf("candidate Suite is missing %q", id)
		}
	}
	manifest := readCandidateJSON(t, filepath.Join(root, "contract/compatibility/contract-manifest.json")).(map[string]any)
	resources := make(map[string]struct{})
	for _, item := range manifest["resources"].([]any) {
		resources[item.(map[string]any)["path"].(string)] = struct{}{}
	}
	for _, path := range []string{
		"schemas/desired-state-request.schema.json", "schemas/lease-request.schema.json", "schemas/terminate-request.schema.json",
		"schemas/lifecycle-event-page.schema.json", "schemas/runtime-session-close-request.schema.json",
		"fixtures/desired-state-request.json", "fixtures/lease-request.json", "fixtures/terminate-request.json",
		"fixtures/lifecycle-event-page.json", "fixtures/runtime-session-close-request.json",
		"fixtures/provider-operation-lifecycle.json", "fixtures/provider-operation-runtime-session-close.json",
		"fixtures/capabilities-coding-shell-lifecycle-control.json",
	} {
		if _, ok := resources[path]; !ok {
			t.Fatalf("candidate manifest is missing %q", path)
		}
	}
}

func TestLocalRuntimeSessionCloseSchemaAndSemantics(t *testing.T) {
	root := localContractSourceRoot(t)
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:runtime-session-close-request:v1", "runtime-session-close-request.schema.json", "runtime-session-close-request.json")
	validateCandidateFixture(t, root, "urn:shell-echo:sandbox-runtime:contract:provider-operation:v1", "provider-operation.schema.json", "provider-operation-runtime-session-close.json")
	assertCandidateRoute(t, root, "/v1/sandboxes/{sandbox_id}/runtime-sessions/{runtime_session_id}:close", "post", "../schemas/runtime-session-close-request.schema.json", "sandbox.terminal-control", "terminal-control-v1")
	rule := requireCandidateRule(t, root, "runtime-session-close-control")
	requireValues(t, "runtime-session close requires", rule["requires"].([]any), "handoff-reference-revoked-before-terminal-cleanup", "absence-confirmed-before-success", "reconnect-denied-after-revocation", "outcome-unknown-attempt-immutable")

	for _, name := range []string{"admission-context.schema.json", "protected-operation-jws-claims.schema.json"} {
		document := readCandidateJSON(t, filepath.Join(root, "contract/schemas", name)).(map[string]any)
		operations := document["properties"].(map[string]any)["operation"].(map[string]any)["enum"].([]any)
		if !containsAny(operations, "close_runtime_session") {
			t.Fatalf("%s does not admit close_runtime_session", name)
		}
	}
	bindings := requireCandidateRule(t, root, "protected-admission-contract-ids")["operation_bindings"].([]any)
	for _, item := range bindings {
		binding := item.(map[string]any)
		if binding["operation"] == "close_runtime_session" && binding["contract_id"] == "urn:shell-echo:sandbox-runtime:request:close-runtime-session:v1" {
			return
		}
	}
	t.Fatal("close_runtime_session admission binding is missing")
}

func validateCandidateFixture(t *testing.T, root, id, schemaName, fixtureName string) {
	t.Helper()
	compiler := jsonschemaecma.NewCompiler()
	if id != "urn:shell-echo:sandbox-runtime:contract:provider-error:v1" {
		if err := compiler.AddResource("urn:shell-echo:sandbox-runtime:contract:provider-error:v1", readCandidateJSON(t, filepath.Join(root, "contract/schemas/provider-error.schema.json"))); err != nil {
			t.Fatal(err)
		}
	}
	if err := compiler.AddResource(id, readCandidateJSON(t, filepath.Join(root, "contract/schemas", schemaName))); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(readCandidateJSON(t, filepath.Join(root, "contract/fixtures", fixtureName))); err != nil {
		t.Fatalf("%s does not validate against %s: %v", fixtureName, schemaName, err)
	}
}

func assertCandidateRoute(t *testing.T, root, path, method, schemaRef, capabilityID, profile string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "contract/openapi/sandbox-runtime-provider-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var openAPI map[string]any
	if err := yaml.Unmarshal(data, &openAPI); err != nil {
		t.Fatal(err)
	}
	operation := openAPI["paths"].(map[string]any)[path].(map[string]any)[method].(map[string]any)
	required := operation["x-required-capability"].(map[string]any)
	if required["id"] != capabilityID || required["version"] != "1.0.0" || required["profile"] != profile {
		t.Fatalf("%s required capability = %#v", path, required)
	}
	if operation["x-max-encoded-body-bytes"] != nil && operation["x-max-encoded-body-bytes"] != 65536 {
		t.Fatalf("%s body bound = %v", path, operation["x-max-encoded-body-bytes"])
	}
	responses := operation["responses"].(map[string]any)
	var actualRef any
	if method == "get" {
		actualRef = responses["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	} else {
		actualRef = operation["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)["$ref"]
	}
	if actualRef != schemaRef {
		t.Fatalf("%s schema = %v, want %s", path, actualRef, schemaRef)
	}
}

func requireCandidateRule(t *testing.T, root, id string) map[string]any {
	t.Helper()
	document := readCandidateJSON(t, filepath.Join(root, "contract/semantic-rules/provider-v1.json")).(map[string]any)
	for _, item := range document["rules"].([]any) {
		rule := item.(map[string]any)
		if rule["id"] == id {
			return rule
		}
	}
	t.Fatalf("candidate semantic rule %q is missing", id)
	return nil
}
