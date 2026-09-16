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
