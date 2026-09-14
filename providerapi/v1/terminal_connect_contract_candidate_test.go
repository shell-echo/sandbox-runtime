package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"github.com/shell-echo/sandbox-runtime/internal/suitedigest"
	"go.yaml.in/yaml/v3"
)

const terminalConnectSchemaID = "urn:shell-echo:sandbox-runtime:contract:runtime-session-connect-descriptor:v1"

func TestLocalTerminalConnectSchemaAndFixtures(t *testing.T) {
	root := localContractSourceRoot(t)
	schemaValue := readCandidateJSON(t, filepath.Join(root, "contract/schemas/runtime-session-connect-descriptor.schema.json"))
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(terminalConnectSchemaID, schemaValue); err != nil {
		t.Fatalf("add terminal-connect schema: %v", err)
	}
	schema, err := compiler.Compile(terminalConnectSchemaID)
	if err != nil {
		t.Fatalf("compile terminal-connect schema: %v", err)
	}

	accepted := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/runtime-session-connect-descriptor.json"))
	if err := schema.Validate(accepted); err != nil {
		t.Fatalf("terminal-connect fixture is invalid: %v", err)
	}
	handoff := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/runtime-session-handoff.json"))
	if !reflect.DeepEqual(accepted, handoff) {
		t.Fatalf("terminal-connect descriptor must exactly match the retained handoff JSON value\nconnect=%#v\nhandoff=%#v", accepted, handoff)
	}
	for _, schemaName := range []string{"runtime-session-handoff.schema.json", "runtime-session-connect-descriptor.schema.json"} {
		document := readCandidateJSON(t, filepath.Join(root, "contract/schemas", schemaName)).(map[string]any)
		properties := document["properties"].(map[string]any)
		for _, propertyName := range []string{"fencing_token", "connection_generation"} {
			property := properties[propertyName].(map[string]any)
			if property["maximum"] != float64(9007199254740991) {
				t.Fatalf("%s %s maximum = %v", schemaName, propertyName, property["maximum"])
			}
		}
	}

	rejections := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/runtime-session-connect-rejections.json")).(map[string]any)
	cases, ok := rejections["cases"].([]any)
	if !ok || len(cases) < 4 {
		t.Fatalf("terminal-connect rejection cases = %#v", rejections["cases"])
	}
	for _, item := range cases {
		candidate := item.(map[string]any)
		name := candidate["name"].(string)
		t.Run(name, func(t *testing.T) {
			if err := schema.Validate(candidate["document"]); err == nil {
				t.Fatal("terminal-connect schema accepted rejection fixture")
			}
		})
	}
}

func TestLocalTerminalConnectCapabilityAdvertisement(t *testing.T) {
	root := localContractSourceRoot(t)
	document := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/capabilities-terminal-connect.json")).(map[string]any)
	compiler := jsonschemaecma.NewCompiler()
	for _, resource := range []struct {
		id   string
		path string
	}{
		{id: "urn:shell-echo:sandbox-runtime:contract:provider-capabilities:v1", path: "provider-capabilities.schema.json"},
		{id: "urn:shell-echo:sandbox-runtime:contract:capability:v1", path: "capability.schema.json"},
		{id: "urn:shell-echo:sandbox-runtime:contract:runtime-profile:v1", path: "runtime-profile.schema.json"},
		{id: "urn:shell-echo:sandbox-runtime:contract:snapshot-restore-profile:v1", path: "snapshot-restore-profile.schema.json"},
		{id: "urn:shell-echo:sandbox-runtime:contract:provider-limits:v1", path: "provider-limits.schema.json"},
	} {
		value := readCandidateJSON(t, filepath.Join(root, "contract/schemas", resource.path))
		if err := compiler.AddResource(resource.id, value); err != nil {
			t.Fatalf("add %s: %v", resource.path, err)
		}
	}
	capabilitySchema, err := compiler.Compile("urn:shell-echo:sandbox-runtime:contract:provider-capabilities:v1")
	if err != nil {
		t.Fatalf("compile Provider capabilities schema: %v", err)
	}
	if err := capabilitySchema.Validate(document); err != nil {
		t.Fatalf("terminal-connect capability fixture is invalid: %v", err)
	}
	if !validTerminalConnectAdvertisement(document) {
		t.Fatal("terminal-connect capability fixture violates terminal-connect advertisement semantics")
	}
	capabilities := document["capabilities"].([]any)
	if len(capabilities) != 2 {
		t.Fatalf("terminal-connect capability count = %d, want 2", len(capabilities))
	}
	want := map[string]struct {
		version string
		profile string
	}{
		"sandbox.terminal":         {version: "1.0.0", profile: "terminal-v1"},
		"sandbox.terminal-connect": {version: "1.0.0", profile: "terminal-connect-v1"},
	}
	for _, item := range capabilities {
		capability := item.(map[string]any)
		id := capability["id"].(string)
		expected, ok := want[id]
		if !ok || !reflect.DeepEqual(capability["versions"], []any{expected.version}) || !reflect.DeepEqual(capability["profiles"], []any{expected.profile}) {
			t.Fatalf("terminal-connect capability = %#v", capability)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("terminal-connect fixture is missing capabilities: %#v", want)
	}
	profiles := document["runtime_profiles"].([]any)
	if len(profiles) != 1 {
		t.Fatalf("terminal-connect runtime profiles = %#v", profiles)
	}
	profile := profiles[0].(map[string]any)
	if profile["id"] != "sandbox-runtime-terminal-connect-v1" || !reflect.DeepEqual(profile["capability_profile_ids"], []any{"terminal-v1", "terminal-connect-v1"}) {
		t.Fatalf("terminal-connect runtime profile = %#v", profile)
	}

	codingShell := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/capabilities-coding-shell-terminal-connect.json")).(map[string]any)
	if err := capabilitySchema.Validate(codingShell); err != nil {
		t.Fatalf("coding/shell terminal-connect capability fixture is invalid: %v", err)
	}
	if !validTerminalConnectAdvertisement(codingShell) {
		t.Fatal("coding/shell terminal-connect capability fixture violates terminal-connect advertisement semantics")
	}
	codingCapabilities := codingShell["capabilities"].([]any)
	if len(codingCapabilities) != 3 {
		t.Fatalf("coding/shell terminal-connect capability count = %d, want 3", len(codingCapabilities))
	}
	codingProfiles := codingShell["runtime_profiles"].([]any)
	if len(codingProfiles) != 1 {
		t.Fatalf("coding/shell terminal-connect runtime profiles = %#v", codingProfiles)
	}
	codingProfile := codingProfiles[0].(map[string]any)
	if codingProfile["id"] != "sandbox-runtime-coding-shell-v1" || !reflect.DeepEqual(codingProfile["capability_profile_ids"], []any{"exec-v1", "terminal-v1", "terminal-connect-v1"}) {
		t.Fatalf("coding/shell terminal-connect runtime profile = %#v", codingProfile)
	}

	rejections := readCandidateJSON(t, filepath.Join(root, "contract/fixtures/capabilities-terminal-connect-rejections.json")).(map[string]any)
	cases, ok := rejections["cases"].([]any)
	if !ok || len(cases) != 6 {
		t.Fatalf("terminal-connect capability rejection cases = %#v, want 6 cases", rejections["cases"])
	}
	for _, item := range cases {
		candidate := item.(map[string]any)
		name := candidate["name"].(string)
		t.Run("reject/"+name, func(t *testing.T) {
			document := candidate["document"].(map[string]any)
			if err := capabilitySchema.Validate(document); err != nil {
				t.Fatalf("semantic rejection fixture must remain Schema-valid: %v", err)
			}
			if validTerminalConnectAdvertisement(document) {
				t.Fatal("terminal-connect advertisement semantics accepted rejection fixture")
			}
		})
	}
}

func TestLocalTerminalConnectAdmissionAndWebSocketContract(t *testing.T) {
	root := localContractSourceRoot(t)
	openAPIData, err := os.ReadFile(filepath.Join(root, "contract/openapi/sandbox-runtime-provider-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var openAPI map[string]any
	if err := yaml.Unmarshal(openAPIData, &openAPI); err != nil {
		t.Fatalf("decode local OpenAPI: %v", err)
	}
	paths := openAPI["paths"].(map[string]any)
	route, ok := paths["/v1/runtime-sessions:connect"].(map[string]any)
	if !ok {
		t.Fatal("OpenAPI is missing the static terminal-connect route")
	}
	if len(route) != 1 {
		t.Fatalf("terminal-connect path item must contain only GET, got %#v", route)
	}
	operation, ok := route["get"].(map[string]any)
	if !ok {
		t.Fatalf("terminal-connect GET operation = %#v", route["get"])
	}
	if _, ok := operation["requestBody"]; ok {
		t.Fatal("terminal-connect GET operation must not define a request body")
	}
	requiredCapability := operation["x-required-capability"].(map[string]any)
	if requiredCapability["id"] != "sandbox.terminal-connect" || requiredCapability["version"] != "1.0.0" || requiredCapability["profile"] != "terminal-connect-v1" {
		t.Fatalf("terminal-connect required capability = %#v", requiredCapability)
	}
	if operation["x-websocket-protocol"] != "sandbox-runtime-terminal.v1" ||
		operation["x-websocket-compression"] != "forbidden" ||
		operation["x-websocket-message-mode"] != "binary-ordered-bytes-message-boundaries-not-semantic" ||
		operation["x-max-websocket-message-bytes"] != 65536 {
		t.Fatalf("terminal-connect WebSocket extensions = %#v", operation)
	}
	if operation["x-websocket-authority-deadline"] != "handoff-expires-at" {
		t.Fatalf("terminal-connect WebSocket authority deadline = %v", operation["x-websocket-authority-deadline"])
	}
	securityItems, ok := operation["security"].([]any)
	if !ok || len(securityItems) != 1 {
		t.Fatalf("terminal-connect security requirements = %#v", operation["security"])
	}
	security, ok := securityItems[0].(map[string]any)
	if !ok || len(security) != 2 {
		t.Fatalf("terminal-connect security requirement = %#v", securityItems[0])
	}
	for _, scheme := range []string{"mutualTLS", "bearerAuth"} {
		values, ok := security[scheme].([]any)
		if !ok || len(values) != 0 {
			t.Fatalf("terminal-connect security scheme %q = %#v", scheme, security[scheme])
		}
	}
	operationParameters, ok := operation["parameters"].([]any)
	if !ok || len(operationParameters) != 3 {
		t.Fatalf("terminal-connect operation parameters = %#v", operation["parameters"])
	}
	wantParameterReferences := map[string]bool{
		"#/components/parameters/AdmissionContextHeader":      false,
		"#/components/parameters/RuntimeSessionHandoffHeader": false,
	}
	var subprotocolParameter map[string]any
	for _, item := range operationParameters {
		parameter := item.(map[string]any)
		if reference, ok := parameter["$ref"].(string); ok {
			if _, expected := wantParameterReferences[reference]; !expected {
				t.Fatalf("unexpected terminal-connect parameter reference %q", reference)
			}
			wantParameterReferences[reference] = true
			continue
		}
		if parameter["in"] == "query" {
			t.Fatalf("terminal-connect operation defines query parameter %#v", parameter)
		}
		if parameter["name"] == "Sec-WebSocket-Protocol" {
			subprotocolParameter = parameter
			continue
		}
		t.Fatalf("unexpected terminal-connect parameter %#v", parameter)
	}
	for reference, found := range wantParameterReferences {
		if !found {
			t.Fatalf("terminal-connect operation is missing parameter reference %q", reference)
		}
	}
	if subprotocolParameter == nil || subprotocolParameter["in"] != "header" || subprotocolParameter["required"] != true {
		t.Fatalf("terminal-connect WebSocket subprotocol parameter = %#v", subprotocolParameter)
	}
	subprotocolSchema := subprotocolParameter["schema"].(map[string]any)
	if subprotocolSchema["type"] != "string" || subprotocolSchema["const"] != "sandbox-runtime-terminal.v1" {
		t.Fatalf("terminal-connect WebSocket subprotocol schema = %#v", subprotocolSchema)
	}
	responses := operation["responses"].(map[string]any)
	for _, status := range []string{"101", "400", "401", "403", "404", "409", "410", "422", "429", "503"} {
		if _, ok := responses[status]; !ok {
			t.Fatalf("terminal-connect OpenAPI response is missing %s", status)
		}
	}
	upgradeResponse := responses["101"].(map[string]any)
	upgradeHeaders := upgradeResponse["headers"].(map[string]any)
	selectedSubprotocol := upgradeHeaders["Sec-WebSocket-Protocol"].(map[string]any)
	selectedSubprotocolSchema := selectedSubprotocol["schema"].(map[string]any)
	if selectedSubprotocol["required"] != true || selectedSubprotocolSchema["type"] != "string" || selectedSubprotocolSchema["const"] != "sandbox-runtime-terminal.v1" {
		t.Fatalf("terminal-connect 101 selected subprotocol = %#v", selectedSubprotocol)
	}
	parameters := openAPI["components"].(map[string]any)["parameters"].(map[string]any)
	handoffHeader := parameters["RuntimeSessionHandoffHeader"].(map[string]any)
	if handoffHeader["name"] != "X-Sandbox-Runtime-Session-Handoff" || handoffHeader["in"] != "header" || handoffHeader["required"] != true ||
		handoffHeader["x-exactly-one-value"] != true || handoffHeader["x-content-encoding"] != "base64url-unpadded" || handoffHeader["x-max-decoded-bytes"] != 4096 {
		t.Fatalf("terminal-connect handoff header = %#v", handoffHeader)
	}
	handoffHeaderSchema := handoffHeader["schema"].(map[string]any)
	if handoffHeaderSchema["type"] != "string" || handoffHeaderSchema["minLength"] != 1 || handoffHeaderSchema["maxLength"] != 5462 || handoffHeaderSchema["pattern"] != "^[A-Za-z0-9_-]+$" {
		t.Fatalf("terminal-connect handoff carrier schema = %#v", handoffHeaderSchema)
	}
	decodedSchema := handoffHeader["x-decoded-schema"].(map[string]any)
	if decodedSchema["$ref"] != "../schemas/runtime-session-connect-descriptor.schema.json" {
		t.Fatalf("terminal-connect decoded header schema = %#v", decodedSchema)
	}

	for _, schemaName := range []string{"admission-context.schema.json", "protected-operation-jws-claims.schema.json"} {
		document := readCandidateJSON(t, filepath.Join(root, "contract/schemas", schemaName)).(map[string]any)
		properties := document["properties"].(map[string]any)
		operations := properties["operation"].(map[string]any)["enum"].([]any)
		if !containsAny(operations, "connect_runtime_session") {
			t.Fatalf("%s does not admit connect_runtime_session", schemaName)
		}
		fencingToken := properties["fencing_token"].(map[string]any)
		if fencingToken["maximum"] != float64(9007199254740991) {
			t.Fatalf("%s fencing_token maximum = %v", schemaName, fencingToken["maximum"])
		}
	}

	semantics := readCandidateJSON(t, filepath.Join(root, "contract/semantic-rules/provider-v1.json")).(map[string]any)
	wantRules := map[string]bool{
		"capabilities-terminal-connect-profile-advertisement":      false,
		"capabilities-coding-shell-terminal-connect-advertisement": false,
		"runtime-session-connect-admission":                        false,
		"runtime-session-connect-websocket":                        false,
	}
	var operationBinding map[string]any
	rulesByID := make(map[string]map[string]any)
	for _, item := range semantics["rules"].([]any) {
		rule := item.(map[string]any)
		id, _ := rule["id"].(string)
		rulesByID[id] = rule
		if _, ok := wantRules[id]; ok {
			wantRules[id] = true
		}
		if id == "protected-admission-contract-ids" {
			for _, bindingItem := range rule["operation_bindings"].([]any) {
				binding := bindingItem.(map[string]any)
				if binding["operation"] == "connect_runtime_session" {
					operationBinding = binding
				}
			}
		}
	}
	for id, found := range wantRules {
		if !found {
			t.Fatalf("terminal-connect semantic rule %q is missing", id)
		}
	}
	for _, ruleID := range []string{"capabilities-terminal-connect-profile-advertisement", "capabilities-coding-shell-terminal-connect-advertisement"} {
		if rulesByID[ruleID]["rejection_fixture"] != "capabilities-terminal-connect-rejections.json" {
			t.Fatalf("semantic rule %q does not bind the terminal-connect rejection fixture", ruleID)
		}
	}
	if operationBinding == nil || operationBinding["contract_id"] != "urn:shell-echo:sandbox-runtime:descriptor:runtime-session-connect:v1" || operationBinding["digest_profile"] != "rfc8785-full-document-v1" {
		t.Fatalf("terminal-connect admission binding = %#v", operationBinding)
	}
	admissionRule := rulesByID["runtime-session-connect-admission"]
	if admissionRule["method"] != "GET" || admissionRule["path"] != "/v1/runtime-sessions:connect" {
		t.Fatalf("terminal-connect admission route = %#v", admissionRule)
	}
	requestRule := admissionRule["request"].(map[string]any)
	if requestRule["body"] != "forbidden" || requestRule["query"] != "forbidden" {
		t.Fatalf("terminal-connect admission request bounds = %#v", requestRule)
	}
	handoffCarrierRule := requestRule["handoff_header"].(map[string]any)
	if handoffCarrierRule["name"] != "X-Sandbox-Runtime-Session-Handoff" || handoffCarrierRule["value_count"] != float64(1) ||
		handoffCarrierRule["encoding"] != "base64url-unpadded" || handoffCarrierRule["max_encoded_characters"] != float64(5462) ||
		handoffCarrierRule["max_decoded_bytes"] != float64(4096) || handoffCarrierRule["schema"] != "runtime-session-connect-descriptor.schema.json" ||
		handoffCarrierRule["logging"] != "forbidden" {
		t.Fatalf("terminal-connect semantic handoff carrier = %#v", handoffCarrierRule)
	}
	requireValues(t, "runtime-session-connect-admission requires", admissionRule["requires"].([]any),
		"protected-admission",
		"fresh-jti-consumed-before-resolution",
		"empty-normalized-query",
		"origin-header-absent",
		"admission-context-and-jws-exactly-bind-full-descriptor",
		"descriptor-exactly-equals-retained-successful-handoff",
		"current-time-precedes-token-deadline-and-handoff-expiry",
		"fresh-reference-resolution-and-terminal-attach-per-connection",
	)
	requireValues(t, "runtime-session-connect-admission forbids", admissionRule["forbids"].([]any),
		"redirect",
		"proxy-discovery",
		"origin-header",
		"query-correlation",
		"path-correlation",
		"handoff-header-logging",
		"resolution-before-admission",
	)
	for ruleID, requirement := range map[string]string{
		"capabilities-terminal-profile-advertisement":     "optional-terminal-connect-is-governed-by-capabilities-terminal-connect-profile-advertisement",
		"capabilities-coding-shell-profile-advertisement": "optional-terminal-connect-is-governed-by-capabilities-coding-shell-terminal-connect-advertisement",
		"runtime-session-connect-admission":               "descriptor-exactly-equals-retained-successful-handoff",
		"runtime-session-connect-websocket":               "binary-messages-only",
	} {
		rule := rulesByID[ruleID]
		if rule == nil || !containsAny(rule["requires"].([]any), requirement) {
			t.Fatalf("semantic rule %q is missing %q", ruleID, requirement)
		}
	}
	websocketRule := rulesByID["runtime-session-connect-websocket"]
	if websocketRule == nil {
		t.Fatal("terminal-connect WebSocket rule is missing")
	}
	requireValues(t, "runtime-session-connect-websocket requires", websocketRule["requires"].([]any),
		"http-1.1-websocket-upgrade",
		"exact-sandbox-runtime-terminal.v1-subprotocol",
		"compression-disabled",
		"binary-messages-only",
		"ordered-terminal-bytes",
		"message-boundaries-have-no-terminal-semantics",
		"maximum-message-bytes-65536",
		"active-stream-closes-no-later-than-handoff-expiry",
		"pre-expiry-admission-does-not-extend-stream-authority",
		"context-cancellation-closes-attach",
		"terminal-end-closes-websocket",
	)
	websocket := websocketRule["websocket"].(map[string]any)
	if websocket["subprotocol"] != "sandbox-runtime-terminal.v1" || websocket["compression"] != "forbidden" ||
		websocket["message_type"] != "binary" || websocket["max_message_bytes"] != float64(65536) ||
		websocket["message_boundaries"] != "not-semantic" || websocket["authority_deadline"] != "handoff-expires-at" {
		t.Fatalf("terminal-connect WebSocket semantics = %#v", websocket)
	}
	requireValues(t, "runtime-session-connect-websocket forbids", websocketRule["forbids"].([]any),
		"stream-after-handoff-expiry",
		"text-terminal-message",
		"permessage-deflate",
		"backend-error-disclosure",
		"reference-or-credential-in-close-reason",
	)

	suite, err := suitedigest.Load(filepath.Join(root, "contract/conformance/provider-v1/suite.json"), suitedigest.DigestProfile)
	if err != nil {
		t.Fatalf("verify lock-selected local Suite: %v", err)
	}
	profile, err := suite.RequiredProfile("sandbox-runtime-provider-v1")
	if err != nil {
		t.Fatal(err)
	}
	wantCases := []string{"terminal-connect-schema-and-fixtures", "terminal-connect-capability-advertisement", "terminal-connect-admission-and-websocket-contract"}
	for _, wantCase := range wantCases {
		if !containsString(profile.Tests, wantCase) {
			t.Fatalf("lock-selected local Suite is missing terminal-connect case %q", wantCase)
		}
	}

	manifest := readCandidateJSON(t, filepath.Join(root, "contract/compatibility/contract-manifest.json")).(map[string]any)
	wantResources := map[string]string{
		"schemas/runtime-session-connect-descriptor.schema.json":   terminalConnectSchemaID,
		"fixtures/capabilities-terminal-connect.json":              "urn:shell-echo:sandbox-runtime:fixture:capabilities-terminal-connect:v1",
		"fixtures/capabilities-coding-shell-terminal-connect.json": "urn:shell-echo:sandbox-runtime:fixture:capabilities-coding-shell-terminal-connect:v1",
		"fixtures/capabilities-terminal-connect-rejections.json":   "urn:shell-echo:sandbox-runtime:fixture:capabilities-terminal-connect-rejections:v1",
		"fixtures/runtime-session-connect-descriptor.json":         "urn:shell-echo:sandbox-runtime:fixture:runtime-session-connect-descriptor:v1",
		"fixtures/runtime-session-connect-rejections.json":         "urn:shell-echo:sandbox-runtime:fixture:runtime-session-connect-rejections:v1",
	}
	for _, item := range manifest["resources"].([]any) {
		resource := item.(map[string]any)
		path := resource["path"].(string)
		if expectedID, ok := wantResources[path]; ok {
			if resource["id"] != expectedID {
				t.Fatalf("manifest resource %s ID = %v, want %s", path, resource["id"], expectedID)
			}
			delete(wantResources, path)
		}
	}
	if len(wantResources) != 0 {
		t.Fatalf("manifest is missing terminal-connect resources: %#v", wantResources)
	}
}

func validTerminalConnectAdvertisement(document map[string]any) bool {
	capabilityItems, ok := document["capabilities"].([]any)
	if !ok {
		return false
	}
	capabilities := make(map[string]map[string]any, len(capabilityItems))
	for _, item := range capabilityItems {
		capability, ok := item.(map[string]any)
		if !ok {
			return false
		}
		id, ok := capability["id"].(string)
		if !ok {
			return false
		}
		if _, duplicate := capabilities[id]; duplicate {
			return false
		}
		capabilities[id] = capability
	}

	terminal := capabilities["sandbox.terminal"]
	connect := capabilities["sandbox.terminal-connect"]
	if terminal == nil || connect == nil ||
		!reflect.DeepEqual(terminal["versions"], []any{"1.0.0"}) ||
		!reflect.DeepEqual(terminal["profiles"], []any{"terminal-v1"}) ||
		!reflect.DeepEqual(connect["versions"], []any{"1.0.0"}) ||
		!reflect.DeepEqual(connect["profiles"], []any{"terminal-connect-v1"}) {
		return false
	}

	runtimeItems, ok := document["runtime_profiles"].([]any)
	if !ok || len(runtimeItems) != 1 {
		return false
	}
	runtimeProfile, ok := runtimeItems[0].(map[string]any)
	if !ok {
		return false
	}

	if exec := capabilities["sandbox.exec"]; exec != nil {
		return len(capabilities) == 3 &&
			reflect.DeepEqual(exec["versions"], []any{"1.0.0"}) &&
			reflect.DeepEqual(exec["profiles"], []any{"exec-v1"}) &&
			runtimeProfile["id"] == "sandbox-runtime-coding-shell-v1" &&
			reflect.DeepEqual(runtimeProfile["capability_profile_ids"], []any{"exec-v1", "terminal-v1", "terminal-connect-v1"})
	}
	return len(capabilities) == 2 &&
		runtimeProfile["id"] == "sandbox-runtime-terminal-connect-v1" &&
		reflect.DeepEqual(runtimeProfile["capability_profile_ids"], []any{"terminal-v1", "terminal-connect-v1"})
}

func containsAny(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func requireValues(t *testing.T, field string, values []any, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !containsAny(values, want) {
			t.Fatalf("%s is missing %q", field, want)
		}
	}
}

func readCandidateJSON(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			t.Fatalf("decode %s: multiple JSON values", path)
		}
		t.Fatalf("decode %s trailer: %v", path, err)
	}
	return value
}
