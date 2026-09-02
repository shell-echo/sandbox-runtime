package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestLockedBrowserSessionOpenRequestProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("browser-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("browser-session-open-request.schema.json", document); err != nil {
		t.Fatalf("browser session open request fixture is invalid: %v", err)
	}
	var request BrowserSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(document), MaxBrowserSessionOpenRequestBytes, &request); err != nil {
		t.Fatalf("decode browser session open request: %v", err)
	}
	projected, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("browser-session-open-request.schema.json", projected); err != nil {
		t.Fatalf("browser session open request DTO projection is invalid: %v", err)
	}
}

func TestLockedBrowserSessionOperationProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("provider-operation-browser-session.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", document); err != nil {
		t.Fatalf("browser session operation fixture is invalid: %v", err)
	}
	var operation Operation
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &operation); err != nil {
		t.Fatalf("decode browser session operation: %v", err)
	}
	if operation.Type != OperationOpenBrowserSession {
		t.Fatalf("browser session operation type = %q, want %q", operation.Type, OperationOpenBrowserSession)
	}
	projected, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-operation.schema.json", projected); err != nil {
		t.Fatalf("browser session operation DTO projection is invalid: %v", err)
	}
}

func TestLockedBrowserSessionHandoffProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("browser-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("browser-session-handoff.schema.json", document); err != nil {
		t.Fatalf("browser session handoff fixture is invalid: %v", err)
	}
	var handoff BrowserSessionHandoff
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &handoff); err != nil {
		t.Fatalf("decode browser session handoff: %v", err)
	}
	if handoff.Protocol != BrowserProtocolWebSocket || handoff.InternalEndpointReference != "ref:browser-session:opaque-1" || handoff.ConnectionGeneration != 1 {
		t.Fatalf("browser session handoff = %#v", handoff)
	}
	projected, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("browser-session-handoff.schema.json", projected); err != nil {
		t.Fatalf("browser session handoff DTO projection is invalid: %v", err)
	}
}

func TestLockedBrowserSessionUsageEvidenceProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("browser-session-usage-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("usage-evidence.schema.json", document); err != nil {
		t.Fatalf("browser session usage evidence fixture is invalid: %v", err)
	}
	var evidence UsageEvidence
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &evidence); err != nil {
		t.Fatalf("decode browser session usage evidence: %v", err)
	}
	if len(evidence.Entries) != 1 || evidence.Entries[0].Meter != MeterBrowserSession || evidence.Entries[0].Unit != "milliseconds" ||
		evidence.Entries[0].OperationID != evidence.OperationID || evidence.AttemptID == "" || evidence.FencingToken < 1 {
		t.Fatalf("browser session usage evidence = %#v", evidence)
	}
	projected, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("usage-evidence.schema.json", projected); err != nil {
		t.Fatalf("browser session usage evidence DTO projection is invalid: %v", err)
	}
}

func TestLockedBrowserCapabilityContractConsistency(t *testing.T) {
	projection := lockedExecProjection(t)
	capabilityDocument, err := projection.ReadExample("capabilities-browser.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-capabilities.schema.json", capabilityDocument); err != nil {
		t.Fatalf("browser capability fixture is invalid: %v", err)
	}
	var capabilities Capabilities
	if err := DecodeStrict(bytes.NewReader(capabilityDocument), 1<<20, &capabilities); err != nil {
		t.Fatalf("decode browser capabilities: %v", err)
	}
	if len(capabilities.Capabilities) != 1 || len(capabilities.RuntimeProfiles) != 1 {
		t.Fatalf("browser capability shape = %#v", capabilities)
	}
	capability := capabilities.Capabilities[0]
	runtimeProfile := capabilities.RuntimeProfiles[0]
	if capability.ID != CapabilityBrowser || !reflect.DeepEqual(capability.Versions, []string{"1.0.0"}) ||
		!reflect.DeepEqual(capability.Profiles, []string{"browser-v1"}) || runtimeProfile.ID != "sandbox-runtime-browser-v1" ||
		!reflect.DeepEqual(runtimeProfile.CapabilityProfileIDs, []string{"browser-v1"}) {
		t.Fatalf("browser capability mapping = %#v / %#v", capability, runtimeProfile)
	}

	createDocument, err := projection.ReadExample("create-sandbox-browser-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("create-sandbox-request.schema.json", createDocument); err != nil {
		t.Fatalf("browser create fixture is invalid: %v", err)
	}
	var create CreateRequest
	if err := DecodeStrict(bytes.NewReader(createDocument), MaxCreateRequestBytes, &create); err != nil {
		t.Fatalf("decode browser create fixture: %v", err)
	}
	wantRequirement := CapabilityRequirement{ID: string(CapabilityBrowser), Version: "1.0.0", Profile: "browser-v1"}
	if create.Spec.RuntimeProfile != runtimeProfile.ID || !reflect.DeepEqual(create.Spec.RequiredCapabilities, []CapabilityRequirement{wantRequirement}) ||
		create.Spec.PlacementConstraints.ResourceClass != ResourceBrowser || create.Spec.Network.Mode != NetworkRestricted ||
		create.Spec.Network.EgressGatewayRequired == nil || !*create.Spec.Network.EgressGatewayRequired {
		t.Fatalf("browser create authority = %#v", create.Spec)
	}

	openDocument, err := projection.ReadExample("browser-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var open BrowserSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(openDocument), MaxBrowserSessionOpenRequestBytes, &open); err != nil {
		t.Fatal(err)
	}
	handoffDocument, err := projection.ReadExample("browser-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	var handoff BrowserSessionHandoff
	if err := DecodeStrict(bytes.NewReader(handoffDocument), 1<<20, &handoff); err != nil {
		t.Fatal(err)
	}
	if open.CapabilityProfileID != capability.Profiles[0] || handoff.CapabilityProfileID != capability.Profiles[0] ||
		open.BrowserSessionID != handoff.BrowserSessionID || open.OperationID != handoff.OperationID || open.AttemptID != handoff.AttemptID ||
		open.FencingToken != handoff.FencingToken {
		t.Fatalf("browser session fixtures are not correlated: open=%#v handoff=%#v", open, handoff)
	}
}

func TestLocalContractBrowserSessionSemanticRules(t *testing.T) {
	sourceRoot := localContractSourceRoot(t)
	data, err := os.ReadFile(filepath.Join(sourceRoot, "contract/semantic-rules/provider-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Rules []struct {
			ID       string   `json:"id"`
			Method   string   `json:"method"`
			Path     string   `json:"path"`
			Scope    string   `json:"scope"`
			Requires []string `json:"requires"`
			Forbids  []string `json:"forbids"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		method, path, scope string
		required            []string
		forbidden           []string
	}{
		"browser-session-open-bounded": {
			"POST", "/v1/sandboxes/{sandbox_id}/browser-sessions", "browser-sessions",
			[]string{"strict-browser-session-open-request-schema", "browser-capability-version-and-profile-required", "fail-before-dispatch-on-stale-fencing"},
			[]string{"terminal-runtime-session-route-reuse", "gateway-user-or-tenant-scope", "network-policy-override", "plaintext-secret"},
		},
		"browser-session-gateway-handoff": {
			"GET", "/v1/operations/{operation_id}/browser-session", "browser-sessions",
			[]string{"opaque-browser-endpoint-reference", "gateway-resolves-reference-under-independent-user-and-tenant-authorization", "connection-generation", "expiry-enforced"},
			[]string{"url", "ip-address", "port", "browser-debugging-endpoint", "provider-access-token-reference"},
		},
		"browser-session-security-boundary": {
			"", "", "browser-data-plane",
			[]string{"caller-owned-gateway-user-and-tenant-authorization", "caller-owned-gateway-revocation", "fresh-reference-resolution-on-every-connect"},
			[]string{"provider-owned-user-authorization", "allow-all-gateway-fallback", "public-provider-browser-endpoint"},
		},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] || rule.Method != expected.method || rule.Path != expected.path || rule.Scope != expected.scope {
			t.Fatalf("browser semantic rule %q identity = %#v", rule.ID, rule)
		}
		found[rule.ID] = true
		for _, requirement := range expected.required {
			if !containsString(rule.Requires, requirement) {
				t.Fatalf("browser semantic rule %q is missing requirement %q", rule.ID, requirement)
			}
		}
		for _, forbidden := range expected.forbidden {
			if !containsString(rule.Forbids, forbidden) {
				t.Fatalf("browser semantic rule %q is missing forbidden value %q", rule.ID, forbidden)
			}
		}
	}
	for id := range want {
		if !found[id] {
			t.Fatalf("local Contract is missing browser semantic rule %q", id)
		}
	}

	openAPI, err := os.ReadFile(filepath.Join(sourceRoot, "contract/openapi/sandbox-runtime-provider-v1.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var specification struct {
		Paths map[string]map[string]struct {
			OperationID        string `yaml:"operationId"`
			RequiredCapability struct {
				ID      string `yaml:"id"`
				Version string `yaml:"version"`
				Profile string `yaml:"profile"`
			} `yaml:"x-required-capability"`
			Responses map[string]any `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPI, &specification); err != nil {
		t.Fatal(err)
	}
	for path, method := range map[string]string{
		"/v1/sandboxes/{sandbox_id}/browser-sessions":   "post",
		"/v1/operations/{operation_id}/browser-session": "get",
	} {
		operation, ok := specification.Paths[path][method]
		if !ok || operation.RequiredCapability.ID != "sandbox.browser" || operation.RequiredCapability.Version != "1.0.0" || operation.RequiredCapability.Profile != "browser-v1" {
			t.Fatalf("browser OpenAPI route %s %s = %#v", method, path, operation)
		}
		if method == "post" {
			if operation.OperationID != "openBrowserSession" || operation.Responses["202"] == nil {
				t.Fatalf("browser open OpenAPI operation = %#v", operation)
			}
		} else if operation.OperationID != "getBrowserSessionHandoff" || operation.Responses["200"] == nil || operation.Responses["410"] == nil {
			t.Fatalf("browser handoff OpenAPI operation = %#v", operation)
		}
	}
}

func TestLocalContractBrowserSessionSecurityMatrix(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("browser-session-security-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		GatewayOwnership map[string]string `json:"gateway_ownership"`
		Cases            []struct {
			Name     string `json:"name"`
			Boundary string `json:"boundary"`
			Result   string `json:"result"`
			Status   int    `json:"status"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(document, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"user_authorization", "tenant_authorization", "revocation", "audit", "reconnect_policy"} {
		if fixture.GatewayOwnership[field] != "caller-owned" {
			t.Fatalf("browser Gateway ownership %q = %q", field, fixture.GatewayOwnership[field])
		}
	}
	if len(fixture.Cases) < 9 {
		t.Fatalf("browser security cases = %d, want at least 9", len(fixture.Cases))
	}
	want := map[string]struct {
		boundary string
		result   string
		status   int
	}{
		"wrong controller identity": {"provider-admission", "deny-before-dispatch", http.StatusForbidden},
		"cross tenant context":      {"provider-and-gateway", "deny-before-resolution", http.StatusForbidden},
		"expired handoff":           {"provider-and-gateway", "deny-before-resolution", http.StatusGone},
		"raw endpoint disclosure":   {"provider-projection", "reject-document", 0},
	}
	for _, testCase := range fixture.Cases {
		expected, ok := want[testCase.Name]
		if ok && (testCase.Boundary != expected.boundary || testCase.Result != expected.result || testCase.Status != expected.status) {
			t.Fatalf("browser security case %q = %#v", testCase.Name, testCase)
		}
		delete(want, testCase.Name)
	}
	if len(want) != 0 {
		t.Fatalf("browser security matrix is missing cases: %v", want)
	}
}

func TestBrowserSessionRejectionFixtures(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("browser-session-rejections.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name     string          `json:"name"`
			Schema   string          `json:"schema"`
			Document json.RawMessage `json:"document"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(document, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) < 7 {
		t.Fatalf("browser rejection fixture count = %d, want at least 7", len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.Schema == "" || len(testCase.Document) == 0 {
				t.Fatal("rejection fixture must contain schema and document")
			}
			if err := projection.Validate(testCase.Schema, testCase.Document); err == nil {
				t.Fatal("rejection fixture unexpectedly validates")
			}
		})
	}
}
