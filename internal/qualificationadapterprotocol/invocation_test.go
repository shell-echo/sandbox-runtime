package qualificationadapterprotocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestInvocationDetailsStructuredProjectionAndNumericSpellings(t *testing.T) {
	codec := loadCodecForTest(t)
	document := string(marshalProtocolValue(t, invocationExampleForSchemaTest()))
	document = strings.ReplaceAll(document, `"max_bytes":4096`, `"max_bytes":4096e0`)
	document = strings.ReplaceAll(document, `"file_descriptor":3`, `"file_descriptor":3e0`)
	message, err := codec.DecodeInvocation(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	details, err := InvocationDetailsFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if details.InvocationID != "invocation-initial" || details.Phase != "initial" ||
		details.ProfilePath != "/qualification/profile.json" || details.ProviderOrigin != "https://provider.invalid" ||
		details.GatewayProbeEndpoint != "wss://gateway.invalid/terminal" || details.CallerStateRoot != "/caller-state" ||
		len(details.CredentialChannels) != 1 || details.CredentialChannels[0].ChannelID != "controller-a-provider" ||
		details.CredentialChannels[0].Actor == nil || *details.CredentialChannels[0].Actor != "controller_a" ||
		details.CredentialChannels[0].MaxBytes != 4096 || details.CredentialChannels[0].FileDescriptor != 3 {
		t.Fatalf("wrong invocation details: %+v", details)
	}
	*details.CredentialChannels[0].Actor = "changed"
	if bytes.Contains(message.Document, []byte("changed")) {
		t.Fatal("structured invocation aliases decoded document")
	}
	if _, err := InvocationDetailsFrom(DecodedMessage{}); err != ErrInvocationDetails {
		t.Fatal(err)
	}
}

func TestInvocationDetailsRejectsDuplicateChannelOrDescriptor(t *testing.T) {
	codec := loadCodecForTest(t)
	for _, duplicate := range []string{"channel-id", "file-descriptor"} {
		t.Run(duplicate, func(t *testing.T) {
			value := invocationExampleForSchemaTest()
			first := value["credential_channel_descriptors"].([]any)[0]
			second := map[string]any{
				"channel_id": "controller-a-trust", "role": "provider_trust", "actor": nil,
				"media_type": "application/vnd.example.trust+json", "max_bytes": float64(2048), "file_descriptor": float64(4),
			}
			if duplicate == "channel-id" {
				second["channel_id"] = "controller-a-provider"
			} else {
				second["file_descriptor"] = float64(3)
			}
			value["credential_channel_descriptors"] = []any{first, second}
			message, err := codec.DecodeInvocation(bytes.NewReader(marshalProtocolValue(t, value)))
			if err != nil {
				t.Fatal("schema should not implement keyed uniqueness", err)
			}
			if _, err := InvocationDetailsFrom(message); err != ErrInvocationDetails {
				t.Fatal("semantic duplicate accepted", err)
			}
			machine := NewPhaseStateMachine()
			if _, err := machine.ReadStartup(startupDecoderForTest(t, codec)); err != nil {
				t.Fatal(err)
			}
			if err := machine.AuthorizeInvocationInput(); err != nil {
				t.Fatal(err)
			}
			if err := machine.RecordInvocationDelivered(message); err == nil || machine.State() != PhaseStateFailed {
				t.Fatal("state machine accepted semantic duplicate", err)
			}
		})
	}
}

func TestScenarioProgressFromReturnsOnlyBoundedOrchestrationFields(t *testing.T) {
	codec := loadCodecForTest(t)
	value := scenarioResultForStateTest(3, "initial", "initial.locked-capability-discovery", "completed")
	value["interactions"] = []any{map[string]any{
		"interaction_id": "controller-a-capabilities", "surface": "provider_http", "actor": "controller_a",
		"method": "GET", "route_template": "/v1/capabilities", "logical_request_id": "capability-a",
		"replay_of": nil, "wire_attempts": float64(2), "transient_outcomes": []any{},
		"final_outcome":           map[string]any{"transport": "http-response", "status_code": float64(200), "error_code": nil, "retryable": false, "retry_after_present": false},
		"mutation_write_observed": false, "observation_ids": []any{"provider-capability-a"},
	}}
	value["assertions"] = []any{map[string]any{"assertion_id": "capability-a-valid", "result": "asserted"}}
	value["observation_ids"] = []any{"provider-capability-a"}
	decoder := codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, value), '\n')))
	message, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	progress, err := ScenarioProgressFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if progress.CaseID != "initial.locked-capability-discovery" || progress.Disposition != "completed" ||
		progress.ReasonCode != nil || len(progress.Interactions) != 1 ||
		progress.Interactions[0].InteractionID != "controller-a-capabilities" || progress.Interactions[0].WireAttempts != 2 {
		t.Fatalf("scenario progress = %#v", progress)
	}
	if _, err := ScenarioProgressFrom(DecodedMessage{}); err != ErrScenarioProgress {
		t.Fatalf("unvalidated message error = %v", err)
	}
	evidence, err := ScenarioEvidenceFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.CaseID != progress.CaseID || evidence.Disposition != progress.Disposition ||
		len(evidence.Assertions) != 1 || evidence.Assertions[0] != (CallerAssertion{AssertionID: "capability-a-valid", Result: "asserted"}) {
		t.Fatalf("scenario evidence = %#v", evidence)
	}
	evidence.Assertions[0].Result = "changed"
	if bytes.Contains(message.Document, []byte("changed")) {
		t.Fatal("scenario evidence aliases decoded document")
	}
	if _, err := ScenarioEvidenceFrom(DecodedMessage{}); err != ErrScenarioEvidence {
		t.Fatalf("unvalidated evidence error = %v", err)
	}
}
