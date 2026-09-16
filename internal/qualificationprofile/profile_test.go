package qualificationprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockedProfileMatchesClosedSchema(t *testing.T) {
	profileBytes, err := readRepositoryFile("../..", ProfilePath, maxProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	schemaBytes, err := readRepositoryFile("../..", ProfileSchemaPath, maxSchemaBytes)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := decodeStrictJSON(profileBytes, &value); err != nil {
		t.Fatal(err)
	}
	if err := validateSchema(schemaBytes, value); err != nil {
		t.Fatal(err)
	}
}

func TestLockedCodingShellV1Profile(t *testing.T) {
	report, err := VerifyCodingShellV1(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	if report.ProfileID != ProfileID || report.ProfileVersion != ProfileVersion ||
		report.ProfileDigest != ExpectedProfileDigest || report.SchemaDigest != ExpectedSchemaDigest ||
		report.InitialCases != 15 || report.RestartCases != 5 || report.Interactions != 41 {
		t.Fatalf("unexpected verification report: %+v", report)
	}
	initial, ok := report.OrderedCaseIDs("initial")
	if !ok || len(initial) != report.InitialCases || initial[0] != "initial.locked-capability-discovery" ||
		initial[len(initial)-1] != "initial.provider-mtls-caller-binding-rejection" {
		t.Fatalf("unexpected initial case order: %#v", initial)
	}
	reconstruction, ok := report.OrderedCaseIDs("reconstruction")
	if !ok || len(reconstruction) != report.RestartCases || reconstruction[0] != "reconstruction.locked-capability-discovery" ||
		reconstruction[len(reconstruction)-1] != "reconstruction.same-shell-reconnect" {
		t.Fatalf("unexpected reconstruction case order: %#v", reconstruction)
	}
	initial[0] = "modified"
	again, ok := report.OrderedCaseIDs("initial")
	if !ok || again[0] != "initial.locked-capability-discovery" {
		t.Fatal("OrderedCaseIDs returned mutable profile state")
	}
	if unknown, ok := report.OrderedCaseIDs("unknown"); ok || unknown != nil {
		t.Fatalf("unknown phase order = %#v, %v", unknown, ok)
	}
	orchestration, ok := report.Orchestration("initial")
	if !ok || orchestration.PhaseID != "initial" || orchestration.DependsOnPhase != nil || len(orchestration.Cases) != 15 ||
		orchestration.Cases[0].CaseID != "initial.locked-capability-discovery" || orchestration.Cases[0].TimeoutSeconds != 120 ||
		len(orchestration.Cases[0].DependsOn) != 0 || len(orchestration.Cases[0].Interactions) != 3 ||
		orchestration.Cases[0].Interactions[0].InteractionID != "controller-a-capabilities" ||
		orchestration.Cases[1].DependsOn[0] != "initial.locked-capability-discovery" {
		t.Fatalf("unexpected initial orchestration projection: %+v", orchestration)
	}
	interactionCount := 0
	for _, scenario := range orchestration.Cases {
		interactionCount += len(scenario.Interactions)
	}
	if interactionCount != 33 {
		t.Fatalf("initial orchestration interaction count = %d, want 33", interactionCount)
	}
	orchestration.Cases[0].CaseID = "changed"
	orchestration.Cases[1].DependsOn[0] = "changed"
	orchestration.Cases[0].Interactions[0].CountsToward[0] = "changed"
	againOrchestration, ok := report.Orchestration("initial")
	if !ok || againOrchestration.Cases[0].CaseID != "initial.locked-capability-discovery" ||
		againOrchestration.Cases[1].DependsOn[0] != "initial.locked-capability-discovery" ||
		againOrchestration.Cases[0].Interactions[0].CountsToward[0] != "provider_http_requests" {
		t.Fatal("Orchestration returned mutable profile state")
	}
	if unknown, ok := report.Orchestration("unknown"); ok || len(unknown.Cases) != 0 {
		t.Fatalf("unknown phase orchestration = %+v, %v", unknown, ok)
	}
	reconstructionRequirements := report.Reconstruction()
	if got := strings.Join(reconstructionRequirements.RestartComponents, ","); got != "provider,external_caller,qualification_adapter,caller_gateway" ||
		strings.Join(reconstructionRequirements.PreserveStores, ",") != "provider_local_state,caller_owned_correlation_state,runtime_resource_state" ||
		reconstructionRequirements.CallerStateOwner != "external_caller" ||
		strings.Join(reconstructionRequirements.ReinjectionForbidden, ",") != "sandbox_id,operation_id,attempt_id,idempotency_key,fencing_token,runtime_session_id,handoff_reference" ||
		!reconstructionRequirements.AdapterInvocation.SanitizedTranscriptRequired || reconstructionRequirements.AdapterInvocation.TranscriptDigestProfile != "rfc8785-full-document-v1" ||
		len(reconstructionRequirements.AdapterInvocation.AllowedHarnessFields) != 7 || reconstructionRequirements.AdapterInvocation.ObservedBy != "process_supervisor" ||
		reconstructionRequirements.ShellContinuityChallenge.EstablishedInCase != "initial.gateway-terminal-byte-round-trip" ||
		reconstructionRequirements.ShellContinuityChallenge.VerifiedInCase != "reconstruction.same-shell-reconnect" ||
		reconstructionRequirements.ShellContinuityChallenge.GeneratedBy != "gateway_observer" || reconstructionRequirements.ShellContinuityChallenge.RawChallengeInEvidence {
		t.Fatalf("unexpected reconstruction requirements: %+v", reconstructionRequirements)
	}
	reconstructionRequirements.RestartComponents[0] = "changed"
	reconstructionRequirements.PreserveStores[0] = "changed"
	reconstructionRequirements.ReinjectionForbidden[0] = "changed"
	reconstructionRequirements.AdapterInvocation.AllowedHarnessFields[0] = "changed"
	againReconstruction := report.Reconstruction()
	if againReconstruction.RestartComponents[0] != "provider" || againReconstruction.PreserveStores[0] != "provider_local_state" ||
		againReconstruction.ReinjectionForbidden[0] != "sandbox_id" || againReconstruction.AdapterInvocation.AllowedHarnessFields[0] != "invocation_id" {
		t.Fatal("Reconstruction returned mutable profile state")
	}
	observationPlan := report.ObservationPlan()
	observationCount := 0
	interactionCount = 0
	for _, phase := range observationPlan {
		for _, scenario := range phase.Cases {
			interactionCount += len(scenario.Interactions)
			for _, interaction := range scenario.Interactions {
				observationCount += len(interaction.RequiredObservations)
			}
		}
	}
	if len(observationPlan) != 2 || len(observationPlan[0].Cases) != 15 || len(observationPlan[1].Cases) != 5 || interactionCount != 41 || observationCount != 91 ||
		observationPlan[0].Cases[0].Interactions[0].Surface != "provider_http" || observationPlan[0].Cases[0].Interactions[0].Method != "GET" ||
		observationPlan[0].Cases[0].Interactions[0].RouteTemplate != "/v1/capabilities" || len(observationPlan[0].Cases[0].Interactions[0].RequiredObservations) == 0 {
		t.Fatalf("unexpected observation plan: phases=%d interactions=%d observations=%d", len(observationPlan), interactionCount, observationCount)
	}
	observationPlan[0].Cases[0].Interactions[0].Outcomes[0].Transport = "changed"
	observationPlan[0].Cases[0].Interactions[0].RequiredObservations[0].ObservationID = "changed"
	if got := report.ObservationPlan()[0].Cases[0].Interactions[0]; got.Outcomes[0].Transport == "changed" || got.RequiredObservations[0].ObservationID == "changed" {
		t.Fatal("ObservationPlan returned mutable profile state")
	}
	inventory := report.Inventory()
	if len(inventory.Topology.Actors) != 4 || len(inventory.Topology.ProcessIsolationGroups) != 10 ||
		len(inventory.Artifacts) != 11 || len(inventory.ConfigurationIDs) != 10 || len(inventory.Phases) != 2 ||
		len(inventory.Phases[0].CaseIDs) != 15 || len(inventory.Phases[1].CaseIDs) != 5 {
		t.Fatalf("unexpected definition inventory: %+v", inventory)
	}
	if inventory.ConfigurationIDs[0] != "architecture" || inventory.ConfigurationIDs[9] != "scenario_inventory" ||
		inventory.Artifacts[0].ArtifactID != "provider" || inventory.Artifacts[10].ArtifactID != "teardown" {
		t.Fatalf("definition inventory order differs from profile: %+v", inventory)
	}
	if inventory.Limits.MaxSandboxes != 1 || inventory.Limits.MaxCaseSeconds != 120 ||
		inventory.Limits.MaxExecutionSeconds != 1800 || inventory.Limits.MaxCleanupSeconds != 300 ||
		inventory.Limits.MaxTotalWallClockSeconds != 2100 || inventory.Limits.SandboxCPUMillis != 500 ||
		inventory.Limits.SandboxMemoryBytes != 268435456 || inventory.Limits.SandboxEphemeralStorageBytes != 268435456 ||
		inventory.Limits.SandboxPIDs != 64 {
		t.Fatalf("definition runtime limits differ from profile: %+v", inventory.Limits)
	}
	if inventory.Cleanup.Authority != "operator-owned-run-namespace-teardown-within-disposable-target" ||
		!inventory.Cleanup.PreRunBaselineRequired || !inventory.Cleanup.QueryScopeIdentityRequired ||
		!inventory.Cleanup.QueryScopeExcludesHarnessControl || len(inventory.Cleanup.InspectorScope) != 5 ||
		inventory.Cleanup.PreRunRunOwnedResourceCount != 0 || inventory.Cleanup.PostTeardownRunOwnedResourceCount != 0 ||
		inventory.Cleanup.PostTeardownStabilitySamples != 3 || inventory.Cleanup.PostTeardownStabilityIntervalMS != 1000 {
		t.Fatalf("definition cleanup requirements differ from profile: %+v", inventory.Cleanup)
	}
	*inventory.Topology.Actors[0].TenantBinding = "changed"
	inventory.Topology.ProcessIsolationGroups[0][0] = "changed"
	inventory.Artifacts[0].ArtifactID = "changed"
	inventory.ConfigurationIDs[0] = "changed"
	inventory.Cleanup.InspectorScope[0] = "changed"
	inventory.Phases[0].CaseIDs[0] = "changed"
	againInventory := report.Inventory()
	if *againInventory.Topology.Actors[0].TenantBinding != "tenant_a" ||
		againInventory.Topology.ProcessIsolationGroups[0][0] != "provider" ||
		againInventory.Artifacts[0].ArtifactID != "provider" || againInventory.ConfigurationIDs[0] != "architecture" ||
		againInventory.Cleanup.InspectorScope[0] != "runtime_allocations" ||
		againInventory.Phases[0].CaseIDs[0] != "initial.locked-capability-discovery" {
		t.Fatal("Inventory returned mutable profile state")
	}
}

func TestTrustAnchorRejectsResignedProfileMutation(t *testing.T) {
	document, err := readRepositoryFile("../..", ProfilePath, maxProfileBytes)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := decodeStrictJSON(document, &value); err != nil {
		t.Fatal(err)
	}
	value["execution_mode"] = "resigned-substitute"
	digest, err := computeProfileDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value["profile_digest"] = digest
	mutated, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyProfileIdentity(mutated); err == nil || !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("verifyProfileIdentity = %v", err)
	}
	if err := VerifyCodingShellV1ProfileDocument(mutated); err == nil || !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("VerifyCodingShellV1ProfileDocument = %v", err)
	}
}

func TestRawDigestUsesLowercaseSHA256(t *testing.T) {
	digest := sha256.Sum256([]byte("profile"))
	want := "sha256:" + hex.EncodeToString(digest[:])
	if got := rawDigest([]byte("profile")); got != want {
		t.Fatalf("rawDigest = %q, want %q", got, want)
	}
}

func TestReadRepositoryFileRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "profile.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if _, err := readRepositoryFile(root, "profile.json", 1024); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("readRepositoryFile = %v", err)
	}
}

func TestValidateReplayRejectsMissingAndChangedOriginals(t *testing.T) {
	original := interaction{
		InteractionID:    "create",
		Surface:          "provider_http",
		Actor:            "controller_a",
		Method:           "POST",
		RouteTemplate:    "/v1/sandboxes",
		LogicalRequestID: "create",
		CountsToward:     []string{"distinct_provider_mutations"},
	}
	replayTarget := "create"
	for name, test := range map[string]struct {
		candidate interaction
		originals map[string]interaction
	}{
		"missing original": {
			candidate: interaction{InteractionID: "replay", LogicalRequestID: "create", ReplayOf: &replayTarget},
			originals: map[string]interaction{},
		},
		"changed actor": {
			candidate: interaction{InteractionID: "replay", Surface: "provider_http", Actor: "controller_b", Method: "POST", RouteTemplate: "/v1/sandboxes", LogicalRequestID: "create", ReplayOf: &replayTarget},
			originals: map[string]interaction{"create": original},
		},
		"duplicate without replay": {
			candidate: original,
			originals: map[string]interaction{"create": original},
		},
		"non-create replay": {
			candidate: interaction{InteractionID: "replay", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "exec", ReplayOf: stringPointer("exec")},
			originals: map[string]interaction{"exec": {InteractionID: "exec", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes/{sandbox_id}/exec", LogicalRequestID: "exec"}},
		},
		"replay counted as distinct": {
			candidate: interaction{InteractionID: "replay", Surface: "provider_http", Actor: "controller_a", Method: "POST", RouteTemplate: "/v1/sandboxes", LogicalRequestID: "create", ReplayOf: &replayTarget, CountsToward: []string{"distinct_provider_mutations"}},
			originals: map[string]interaction{"create": original},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateReplay(test.candidate, test.originals); err == nil {
				t.Fatal("validateReplay accepted invalid replay")
			}
		})
	}
}

func TestValidateInteractionRejectsProviderOperationOutsideCodingShellProfile(t *testing.T) {
	candidate := interaction{
		InteractionID:    "browser",
		Surface:          "provider_http",
		Method:           "POST",
		RouteTemplate:    "/v1/sandboxes/{sandbox_id}/browser-sessions",
		LogicalRequestID: "browser",
		CountsToward:     []string{"provider_http_requests", "provider_mutation_write_attempts", "distinct_provider_mutations"},
		MaxWireAttempts:  1,
	}
	if err := validateInteraction(candidate, nil); err == nil || !strings.Contains(err.Error(), "outside the coding/shell profile") {
		t.Fatalf("validateInteraction = %v", err)
	}
}

func TestValidateInteractionRejectsWireAttemptLimitAboveReportCapacity(t *testing.T) {
	candidate := interaction{InteractionID: "oversized", LogicalRequestID: "oversized", MaxWireAttempts: 65}
	if err := validateInteraction(candidate, nil); err == nil || !strings.Contains(err.Error(), "invalid occurrence accounting") {
		t.Fatalf("validateInteraction(max_wire_attempts=65) = %v", err)
	}
}

func TestValidateProviderHTTPOutcomeClassification(t *testing.T) {
	finalRetryable := false
	transientRetryable := true
	openAPI := map[string]any{
		"paths": map[string]any{
			"/v1/capabilities": map[string]any{
				"get": map[string]any{
					"responses": map[string]any{
						"200": map[string]any{},
						"403": map[string]any{},
						"429": map[string]any{},
						"503": map[string]any{},
					},
				},
			},
		},
	}
	base := interaction{InteractionID: "capabilities", Method: "GET", RouteTemplate: "/v1/capabilities"}
	for name, test := range map[string]struct {
		outcome   outcome
		transient bool
	}{
		"final transient status": {
			outcome: outcome{Transport: "http-response", StatusCode: intPointer(429), ErrorCodePolicy: "contract-unconstrained", Retryable: &finalRetryable},
		},
		"transient final status": {
			outcome:   outcome{Transport: "http-response", StatusCode: intPointer(403), ErrorCodePolicy: "contract-unconstrained", Retryable: &transientRetryable},
			transient: true,
		},
		"success with error policy": {
			outcome: outcome{Transport: "http-response", StatusCode: intPointer(200), ErrorCodePolicy: "contract-unconstrained", Retryable: &finalRetryable},
		},
		"error without policy": {
			outcome: outcome{Transport: "http-response", StatusCode: intPointer(403), ErrorCodePolicy: "none", Retryable: &finalRetryable},
		},
		"retry after mismatch": {
			outcome:   outcome{Transport: "http-response", StatusCode: intPointer(503), ErrorCodePolicy: "contract-unconstrained", Retryable: &transientRetryable, RetryAfterRequired: boolPointer(true)},
			transient: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProviderOutcome(base, test.outcome, test.transient, openAPI); err == nil {
				t.Fatal("validateProviderOutcome accepted an invalid outcome classification")
			}
		})
	}
}

func TestValidateInteractionAcceptsNonHTTPProviderTransients(t *testing.T) {
	finalRetryable := false
	transientRetryable := true
	retryAfter := false
	openAPI := map[string]any{
		"paths": map[string]any{
			"/v1/capabilities": map[string]any{
				"get": map[string]any{
					"responses": map[string]any{"200": map[string]any{}},
				},
			},
		},
	}
	for _, transport := range []string{"transport-unavailable", "deadline-exceeded"} {
		t.Run(transport, func(t *testing.T) {
			candidate := interaction{
				InteractionID:    "capabilities",
				Surface:          "provider_http",
				Method:           "GET",
				RouteTemplate:    "/v1/capabilities",
				LogicalRequestID: "capabilities",
				CountsToward:     []string{"provider_http_requests"},
				MaxWireAttempts:  2,
				Outcomes: []outcome{{
					Transport:          "http-response",
					StatusCode:         intPointer(200),
					ErrorCodePolicy:    "none",
					Retryable:          &finalRetryable,
					RetryAfterRequired: &retryAfter,
				}},
				TransientOutcomes: []outcome{{
					Transport:          transport,
					ErrorCodePolicy:    "none",
					Retryable:          &transientRetryable,
					RetryAfterRequired: &retryAfter,
				}},
			}
			if err := validateInteraction(candidate, openAPI); err != nil {
				t.Fatalf("validateInteraction = %v", err)
			}
		})
	}
}

func TestValidateObservationsRejectsCrossBinding(t *testing.T) {
	candidate := interaction{
		InteractionID:    "read",
		Surface:          "provider_http",
		Actor:            "controller_a",
		LogicalRequestID: "read",
		RequiredObservations: []requiredObservation{{
			ObservationID: "response-observed",
			Source:        "provider_observer",
			Actor:         "controller_b",
			Subject:       "read",
			Correlation:   "read",
		}},
	}
	if err := validateObservations(candidate, map[string]struct{}{"provider_observer": {}}); err == nil {
		t.Fatal("validateObservations accepted a mismatched actor")
	}
}

func TestValidateInteractionAccountingRejectsMovedCounter(t *testing.T) {
	status := 200
	candidate := interaction{
		InteractionID:   "read",
		Surface:         "provider_http",
		Method:          "GET",
		RouteTemplate:   "/v1/sandboxes/{sandbox_id}",
		CountsToward:    []string{"provider_http_requests", "sandboxes"},
		Outcomes:        []outcome{{StatusCode: &status}},
		MaxWireAttempts: 1,
	}
	if err := validateInteractionAccounting(candidate); err == nil {
		t.Fatal("validateInteractionAccounting accepted a sandbox counter on a read")
	}
}

func TestValidateErrorPolicyRejectsCodeStatusMismatch(t *testing.T) {
	status := 403
	err := validateErrorPolicy("stale", outcome{
		StatusCode:      &status,
		ErrorCodePolicy: "exact",
		ErrorCodes:      []string{"SANDBOX_STALE_FENCING_TOKEN"},
	})
	if err == nil {
		t.Fatal("validateErrorPolicy accepted a stale-fence code on HTTP 403")
	}
}

func TestStrictJSONRejectsDuplicateMembersAndTrailingValues(t *testing.T) {
	for name, document := range map[string][]byte{
		"duplicate": []byte(`{"a":1,"a":2}`),
		"trailing":  []byte(`{} {}`),
		"surrogate": []byte(`{"value":"\uD800"}`),
	} {
		t.Run(name, func(t *testing.T) {
			var value any
			if err := decodeStrictJSON(document, &value); err == nil {
				t.Fatal("decodeStrictJSON accepted invalid input")
			}
		})
	}
}

func intPointer(value int) *int {
	return &value
}

func stringPointer(value string) *string {
	return &value
}

func boolPointer(value bool) *bool {
	return &value
}
