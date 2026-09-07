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
