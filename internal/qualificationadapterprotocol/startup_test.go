package qualificationadapterprotocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestStartupIdentityStructuredCopyAndUniqueChannels(t *testing.T) {
	codec := loadCodecForTest(t)
	valid := startupIdentityForCodecTest()
	valid["credential_channel_requirements"] = []any{
		map[string]any{"channel_id": "a", "role": "provider_credentials", "actor": "controller_a", "media_type": "application/example", "max_bytes": float64(1)},
		map[string]any{"channel_id": "b", "role": "provider_trust", "actor": nil, "media_type": "application/example", "max_bytes": float64(2)},
	}
	decoder := codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, valid), '\n')))
	machine := NewPhaseStateMachine()
	message, err := machine.ReadStartup(decoder)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := StartupIdentityFrom(message)
	if err != nil {
		t.Fatal(err)
	}
	if identity.ProtocolID != ProtocolID || identity.ProtocolVersion != ProtocolVersion ||
		identity.ProtocolSchemaDigest != ExpectedProtocolSchemaDigest || identity.ProtocolSemanticsDigest != ExpectedProtocolSemanticsDigest ||
		identity.CallerRelease.Kind != "source-revision" || identity.CallerRelease.Value != strings.Repeat("a", 40) || !identity.CallerRelease.Immutable ||
		identity.AdapterRelease.Kind != "source-revision" || identity.AdapterRelease.Value != strings.Repeat("a", 40) || !identity.AdapterRelease.Immutable ||
		identity.ContractRevision != "22ba6987ea5fbc37d53942720133c0acad199edd" || identity.ContractTree != "c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38" ||
		identity.ProfileID != "sandbox-runtime-external-caller-coding-shell-v1" || identity.ProfileVersion != "1.0.0" ||
		identity.ProfileDigest != "sha256:4effea27fd3d7668b88eeb95c69e19b51556914b7949b1a39ce522b2aec46c14" || identity.ExpectedValuesInjectedByHarness ||
		len(identity.CredentialChannels) != 2 || identity.CredentialChannels[0].Actor == nil || identity.CredentialChannels[1].Actor != nil {
		t.Fatal(identity)
	}
	copy := CloneStartupIdentity(identity)
	*copy.CredentialChannels[0].Actor = "changed"
	copy.CredentialChannels[0].ChannelID = "changed"
	if *identity.CredentialChannels[0].Actor != "controller_a" || identity.CredentialChannels[0].ChannelID != "a" {
		t.Fatal("clone aliased identity")
	}
	// Structured projection must preserve valid JSON number spellings accepted
	// by the locked codec and RFC 8785 equality rules.
	document := strings.ReplaceAll(string(marshalProtocolValue(t, valid)), `"max_bytes":1`, `"max_bytes":1e0`)
	decoder = codec.NewOutputDecoder(strings.NewReader(document + "\n"))
	machine = NewPhaseStateMachine()
	message, err = machine.ReadStartup(decoder)
	if err != nil {
		t.Fatal(err)
	}
	identity, err = StartupIdentityFrom(message)
	if err != nil || identity.CredentialChannels[0].MaxBytes != 1 {
		t.Fatal("equivalent numeric spelling rejected", err)
	}

	duplicate := startupIdentityForCodecTest()
	first := duplicate["credential_channel_requirements"].([]any)[0]
	second := map[string]any{
		"channel_id": "controller-a-provider", "role": "provider_trust", "actor": nil,
		"media_type": "application/vnd.example.trust+json", "max_bytes": float64(2048),
	}
	duplicate["credential_channel_requirements"] = []any{first, second}
	decoder = codec.NewOutputDecoder(bytes.NewReader(append(marshalProtocolValue(t, duplicate), '\n')))
	machine = NewPhaseStateMachine()
	if _, err := machine.ReadStartup(decoder); err == nil || machine.State() != PhaseStateFailed {
		t.Fatal("duplicate channel accepted")
	}
	if _, err := StartupIdentityFrom(DecodedMessage{}); err != ErrStartupIdentity {
		t.Fatal(err)
	}
}
