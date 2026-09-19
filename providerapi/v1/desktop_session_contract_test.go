package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestLockedDesktopSessionOpenRequestProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("desktop-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("desktop-session-open-request.schema.json", document); err != nil {
		t.Fatalf("desktop session open request fixture is invalid: %v", err)
	}
	var request DesktopSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(document), MaxDesktopSessionOpenRequestBytes, &request); err != nil {
		t.Fatalf("decode desktop session open request: %v", err)
	}
	projected, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("desktop-session-open-request.schema.json", projected); err != nil {
		t.Fatalf("desktop session open request DTO projection is invalid: %v", err)
	}
	if err := DecodeStrict(bytes.NewReader([]byte(`{"unknown":true}`)), MaxDesktopSessionOpenRequestBytes, &DesktopSessionOpenRequest{}); err == nil {
		t.Fatal("desktop session open strict decoder accepted an unknown field")
	}
	if err := DecodeStrict(bytes.NewReader(make([]byte, MaxDesktopSessionOpenRequestBytes+1)), MaxDesktopSessionOpenRequestBytes, &DesktopSessionOpenRequest{}); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("desktop session open oversized decode = %v", err)
	}
}

func TestLockedDesktopSessionCloseRequestProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("desktop-session-close-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("desktop-session-close-request.schema.json", document); err != nil {
		t.Fatalf("desktop session close request fixture is invalid: %v", err)
	}
	var request DesktopSessionCloseRequest
	if err := DecodeStrict(bytes.NewReader(document), MaxDesktopSessionCloseRequestBytes, &request); err != nil {
		t.Fatalf("decode desktop session close request: %v", err)
	}
	projected, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("desktop-session-close-request.schema.json", projected); err != nil {
		t.Fatalf("desktop session close request DTO projection is invalid: %v", err)
	}
	if err := DecodeStrict(bytes.NewReader([]byte(`{"unknown":true}`)), MaxDesktopSessionCloseRequestBytes, &DesktopSessionCloseRequest{}); err == nil {
		t.Fatal("desktop session close strict decoder accepted an unknown field")
	}
	if err := DecodeStrict(bytes.NewReader(make([]byte, MaxDesktopSessionCloseRequestBytes+1)), MaxDesktopSessionCloseRequestBytes, &DesktopSessionCloseRequest{}); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("desktop session close oversized decode = %v", err)
	}
}

func TestLockedDesktopSessionOperationProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	tests := map[string]OperationType{
		"provider-operation-desktop-session.json":       OperationOpenDesktopSession,
		"provider-operation-desktop-session-close.json": OperationCloseDesktopSession,
	}
	for name, wantType := range tests {
		t.Run(name, func(t *testing.T) {
			document, err := projection.ReadExample(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Validate("provider-operation.schema.json", document); err != nil {
				t.Fatalf("desktop session operation fixture is invalid: %v", err)
			}
			var operation Operation
			if err := DecodeStrict(bytes.NewReader(document), 1<<20, &operation); err != nil {
				t.Fatalf("decode desktop session operation: %v", err)
			}
			if operation.Type != wantType {
				t.Fatalf("desktop session operation type = %q, want %q", operation.Type, wantType)
			}
		})
	}
}

func TestLockedDesktopSessionHandoffProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("desktop-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("desktop-session-handoff.schema.json", document); err != nil {
		t.Fatalf("desktop session handoff fixture is invalid: %v", err)
	}
	var handoff DesktopSessionHandoff
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &handoff); err != nil {
		t.Fatalf("decode desktop session handoff: %v", err)
	}
	if handoff.Protocol != DesktopProtocolWebRTC || handoff.MediaProfileID != "desktop-media-v1" ||
		handoff.ControlProfileID != "desktop-control-v1" || handoff.InternalEndpointReference != "ref:desktop-session:opaque-1" ||
		handoff.ConnectionGeneration != 1 {
		t.Fatalf("desktop session handoff = %#v", handoff)
	}
	projected, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("desktop-session-handoff.schema.json", projected); err != nil {
		t.Fatalf("desktop session handoff DTO projection is invalid: %v", err)
	}
}

func TestLockedDesktopSessionUsageEvidenceProjection(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("desktop-session-usage-evidence.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("usage-evidence.schema.json", document); err != nil {
		t.Fatalf("desktop session usage evidence fixture is invalid: %v", err)
	}
	var evidence UsageEvidence
	if err := DecodeStrict(bytes.NewReader(document), 1<<20, &evidence); err != nil {
		t.Fatalf("decode desktop session usage evidence: %v", err)
	}
	if len(evidence.Entries) != 1 || evidence.Entries[0].Meter != MeterDesktopSession || evidence.Entries[0].Unit != "milliseconds" ||
		evidence.Entries[0].OperationID != evidence.OperationID || evidence.AttemptID == "" || evidence.FencingToken < 1 {
		t.Fatalf("desktop session usage evidence = %#v", evidence)
	}
}

func TestLockedDesktopCapabilityContractConsistency(t *testing.T) {
	projection := lockedExecProjection(t)
	capabilityDocument, err := projection.ReadExample("capabilities-desktop.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("provider-capabilities.schema.json", capabilityDocument); err != nil {
		t.Fatalf("desktop capability fixture is invalid: %v", err)
	}
	var capabilities Capabilities
	if err := DecodeStrict(bytes.NewReader(capabilityDocument), 1<<20, &capabilities); err != nil {
		t.Fatalf("decode desktop capabilities: %v", err)
	}
	if len(capabilities.Capabilities) != 1 || len(capabilities.RuntimeProfiles) != 1 {
		t.Fatalf("desktop capability shape = %#v", capabilities)
	}
	capability := capabilities.Capabilities[0]
	runtimeProfile := capabilities.RuntimeProfiles[0]
	if capability.ID != CapabilityDesktop || !reflect.DeepEqual(capability.Versions, []string{"1.0.0"}) ||
		!reflect.DeepEqual(capability.Profiles, []string{"desktop-v1"}) || runtimeProfile.ID != "sandbox-runtime-desktop-v1" ||
		!reflect.DeepEqual(runtimeProfile.CapabilityProfileIDs, []string{"desktop-v1"}) {
		t.Fatalf("desktop capability mapping = %#v / %#v", capability, runtimeProfile)
	}

	createDocument, err := projection.ReadExample("create-sandbox-desktop-request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Validate("create-sandbox-request.schema.json", createDocument); err != nil {
		t.Fatalf("desktop create fixture is invalid: %v", err)
	}
	var create CreateRequest
	if err := DecodeStrict(bytes.NewReader(createDocument), MaxCreateRequestBytes, &create); err != nil {
		t.Fatalf("decode desktop create fixture: %v", err)
	}
	wantRequirement := CapabilityRequirement{ID: string(CapabilityDesktop), Version: "1.0.0", Profile: "desktop-v1"}
	if create.Spec.RuntimeProfile != runtimeProfile.ID || !reflect.DeepEqual(create.Spec.RequiredCapabilities, []CapabilityRequirement{wantRequirement}) ||
		create.Spec.PlacementConstraints == nil || create.Spec.PlacementConstraints.ResourceClass != ResourceDesktop ||
		create.Spec.Network.Mode != NetworkRestricted || create.Spec.Network.EgressGatewayRequired == nil || !*create.Spec.Network.EgressGatewayRequired {
		t.Fatalf("desktop create authority = %#v", create.Spec)
	}

	openDocument, err := projection.ReadExample("desktop-session-open-request.json")
	if err != nil {
		t.Fatal(err)
	}
	var open DesktopSessionOpenRequest
	if err := DecodeStrict(bytes.NewReader(openDocument), MaxDesktopSessionOpenRequestBytes, &open); err != nil {
		t.Fatal(err)
	}
	handoffDocument, err := projection.ReadExample("desktop-session-handoff.json")
	if err != nil {
		t.Fatal(err)
	}
	var handoff DesktopSessionHandoff
	if err := DecodeStrict(bytes.NewReader(handoffDocument), 1<<20, &handoff); err != nil {
		t.Fatal(err)
	}
	if open.CapabilityProfileID != capability.Profiles[0] || handoff.CapabilityProfileID != capability.Profiles[0] ||
		open.DesktopSessionID != handoff.DesktopSessionID || open.OperationID != handoff.OperationID ||
		open.AttemptID != handoff.AttemptID || open.FencingToken != handoff.FencingToken {
		t.Fatalf("desktop session fixtures are not correlated: open=%#v handoff=%#v", open, handoff)
	}
}

func TestLocalContractDesktopSessionSemanticRules(t *testing.T) {
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
		"desktop-session-open-bounded": {
			"POST", "/v1/sandboxes/{sandbox_id}/desktop-sessions", "desktop-sessions",
			[]string{"strict-desktop-session-open-request-schema", "desktop-capability-version-and-profile-required", "fail-before-dispatch-on-stale-fencing"},
			[]string{"terminal-or-browser-session-route-reuse", "input-event", "clipboard-content", "plaintext-secret"},
		},
		"desktop-session-close-control": {
			"POST", "/v1/sandboxes/{sandbox_id}/desktop-sessions/{desktop_session_id}:close", "desktop-sessions",
			[]string{"handoff-reference-revoked-before-desktop-cleanup", "absence-confirmed-before-success", "expiry-invokes-the-same-revocation-and-cleanup-path"},
			[]string{"terminal-or-browser-session-close-reuse", "success-before-revocation-and-absence"},
		},
		"desktop-session-gateway-handoff": {
			"GET", "/v1/operations/{operation_id}/desktop-session", "desktop-sessions",
			[]string{"opaque-desktop-endpoint-reference", "webrtc-protocol", "desktop-media-v1-profile", "desktop-control-v1-profile", "expired-or-revoked-handoff-is-410"},
			[]string{"url", "sdp", "ice-candidate", "credential"},
		},
	}
	found := make(map[string]bool, len(want))
	for _, rule := range document.Rules {
		expected, ok := want[rule.ID]
		if !ok {
			continue
		}
		if found[rule.ID] || rule.Method != expected.method || rule.Path != expected.path || rule.Scope != expected.scope {
			t.Fatalf("desktop semantic rule %q identity = %#v", rule.ID, rule)
		}
		found[rule.ID] = true
		for _, requirement := range expected.required {
			if !containsString(rule.Requires, requirement) {
				t.Fatalf("desktop semantic rule %q is missing requirement %q", rule.ID, requirement)
			}
		}
		for _, forbidden := range expected.forbidden {
			if !containsString(rule.Forbids, forbidden) {
				t.Fatalf("desktop semantic rule %q is missing forbidden value %q", rule.ID, forbidden)
			}
		}
	}
	for id := range want {
		if !found[id] {
			t.Fatalf("local Contract is missing desktop semantic rule %q", id)
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
	wantRoutes := map[string]struct {
		method, operationID string
		status              string
	}{
		"/v1/sandboxes/{sandbox_id}/desktop-sessions":                            {"post", "openDesktopSession", "202"},
		"/v1/sandboxes/{sandbox_id}/desktop-sessions/{desktop_session_id}:close": {"post", "closeDesktopSession", "202"},
		"/v1/operations/{operation_id}/desktop-session":                          {"get", "getDesktopSessionHandoff", "200"},
	}
	for path, expected := range wantRoutes {
		operation, ok := specification.Paths[path][expected.method]
		if !ok || operation.RequiredCapability.ID != "sandbox.desktop" || operation.RequiredCapability.Version != "1.0.0" || operation.RequiredCapability.Profile != "desktop-v1" ||
			operation.OperationID != expected.operationID || operation.Responses[expected.status] == nil {
			t.Fatalf("desktop OpenAPI route %s %s = %#v", expected.method, path, operation)
		}
	}
}

func TestLocalContractDesktopSessionStateAndSecurity(t *testing.T) {
	projection := lockedExecProjection(t)
	stateDocument, err := projection.ReadExample("desktop-session-state-machine.json")
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		InitialState   string   `json:"initial_state"`
		TerminalStates []string `json:"terminal_states"`
		Transitions    []struct {
			From  string `json:"from"`
			To    string `json:"to"`
			Cause string `json:"cause"`
		} `json:"transitions"`
		Authority struct {
			HandoffReadableOnlyIn    []string `json:"handoff_readable_only_in"`
			ExpiredOrRevokedStatus   int      `json:"expired_or_revoked_resolution_status"`
			GenerationMismatchStatus int      `json:"generation_mismatch_status"`
			TerminalStatesAbsorbing  bool     `json:"terminal_states_absorbing"`
			UnknownOutcomeRedispatch bool     `json:"unknown_outcome_blind_redispatch"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(stateDocument, &state); err != nil {
		t.Fatal(err)
	}
	if state.InitialState != "requested" || !reflect.DeepEqual(state.TerminalStates, []string{"closed", "expired", "failed"}) ||
		!reflect.DeepEqual(state.Authority.HandoffReadableOnlyIn, []string{"active"}) || state.Authority.ExpiredOrRevokedStatus != http.StatusGone ||
		state.Authority.GenerationMismatchStatus != http.StatusConflict || !state.Authority.TerminalStatesAbsorbing || state.Authority.UnknownOutcomeRedispatch {
		t.Fatalf("desktop session state authority = %#v", state)
	}
	causes := make(map[string]bool)
	for _, transition := range state.Transitions {
		causes[transition.Cause] = true
	}
	for _, cause := range []string{"successful-handoff-commit", "uncertain-open-dispatch", "durable-close-intent", "expiry-intent", "revoked-and-absence-confirmed", "uncertain-close-dispatch"} {
		if !causes[cause] {
			t.Fatalf("desktop state machine is missing transition cause %q", cause)
		}
	}

	securityDocument, err := projection.ReadExample("desktop-session-security-matrix.json")
	if err != nil {
		t.Fatal(err)
	}
	var security struct {
		GatewayOwnership map[string]string `json:"gateway_ownership"`
		Cases            []struct {
			Name     string `json:"name"`
			Boundary string `json:"boundary"`
			Result   string `json:"result"`
			Status   int    `json:"status"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(securityDocument, &security); err != nil {
		t.Fatal(err)
	}
	if security.GatewayOwnership["end_user_authorization"] != "caller-owned" || security.GatewayOwnership["control_lease"] != "caller-owned" ||
		security.GatewayOwnership["revocation"] != "caller-owned-and-provider-enforced" || len(security.Cases) < 12 {
		t.Fatalf("desktop security authority = %#v", security)
	}
	wantCases := map[string]int{"wrong controller identity": http.StatusForbidden, "expired handoff": http.StatusGone, "revoked handoff": http.StatusGone, "stale connection generation": http.StatusConflict, "desktop session capacity exhausted": http.StatusTooManyRequests}
	for _, testCase := range security.Cases {
		if wantStatus, ok := wantCases[testCase.Name]; ok {
			if testCase.Status != wantStatus {
				t.Fatalf("desktop security case %q status = %d, want %d", testCase.Name, testCase.Status, wantStatus)
			}
			delete(wantCases, testCase.Name)
		}
	}
	if len(wantCases) != 0 {
		t.Fatalf("desktop security matrix is missing cases: %v", wantCases)
	}
}

func TestDesktopSessionRejectionFixtures(t *testing.T) {
	projection := lockedExecProjection(t)
	document, err := projection.ReadExample("desktop-session-rejections.json")
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
	if len(fixture.Cases) < 8 {
		t.Fatalf("desktop rejection fixture count = %d, want at least 8", len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			if err := projection.Validate(testCase.Schema, testCase.Document); err == nil {
				t.Fatal("rejection fixture unexpectedly validates")
			}
		})
	}
}
