package qualificationadapterprotocol

import (
	"encoding/json"
	"errors"
)

var ErrStartupIdentity = errors.New("adapter startup identity rejected")

type ReleaseIdentity struct {
	Kind      string
	Value     string
	Immutable bool
}

type CredentialChannelRequirement struct {
	ChannelID string
	Role      string
	Actor     *string
	MediaType string
	MaxBytes  int64
}

// StartupIdentity is a structured copy of one schema- and authority-validated
// startup record. Release values remain caller-owner assertions; this type does
// not attest their provenance or bind them to source outside the process.
type StartupIdentity struct {
	ProtocolID                      string
	ProtocolVersion                 string
	ProtocolSchemaDigest            string
	ProtocolSemanticsDigest         string
	CallerRelease                   ReleaseIdentity
	AdapterRelease                  ReleaseIdentity
	ContractRevision                string
	ContractTree                    string
	ProfileID                       string
	ProfileVersion                  string
	ProfileDigest                   string
	ExpectedValuesInjectedByHarness bool
	CredentialChannels              []CredentialChannelRequirement
}

type startupIdentityDocument struct {
	ProtocolID                      string                                 `json:"protocol_id"`
	ProtocolVersion                 string                                 `json:"protocol_version"`
	ProtocolSchemaDigest            string                                 `json:"protocol_schema_digest"`
	ProtocolSemanticsDigest         string                                 `json:"protocol_semantics_digest"`
	CallerRelease                   releaseIdentityDocument                `json:"caller_release_identity"`
	AdapterRelease                  releaseIdentityDocument                `json:"adapter_release_identity"`
	ContractRevision                string                                 `json:"contract_revision"`
	ContractTree                    string                                 `json:"contract_tree"`
	ProfileID                       string                                 `json:"profile_id"`
	ProfileVersion                  string                                 `json:"profile_version"`
	ProfileDigest                   string                                 `json:"profile_digest"`
	ExpectedValuesInjectedByHarness bool                                   `json:"expected_values_injected_by_harness"`
	CredentialChannels              []credentialChannelRequirementDocument `json:"credential_channel_requirements"`
}

type releaseIdentityDocument struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Immutable bool   `json:"immutable"`
}

type credentialChannelRequirementDocument struct {
	ChannelID string  `json:"channel_id"`
	Role      string  `json:"role"`
	Actor     *string `json:"actor"`
	MediaType string  `json:"media_type"`
	MaxBytes  float64 `json:"max_bytes"`
}

// StartupIdentityFrom accepts only the intact, adapter-to-harness startup
// envelope produced by this locked Codec. It additionally enforces semantic
// channel-ID uniqueness, which JSON Schema uniqueItems cannot express by key.
// Errors contain no raw record or identity values.
func StartupIdentityFrom(message DecodedMessage) (StartupIdentity, error) {
	if !decodedEnvelopeIntact(message) || message.direction != decodedAdapterToHarness ||
		message.outputDecoder == nil || message.MessageType != "startup_identity" ||
		message.Sequence == nil || *message.Sequence != 0 {
		return StartupIdentity{}, ErrStartupIdentity
	}
	var document startupIdentityDocument
	// The locked Codec has already schema-validated message_type and sequence
	// and retained their semantic values in the intact envelope above. Do not
	// decode sequence into a Go integer here: JSON spellings such as 0e0 are
	// valid and canonically equivalent to 0 under the cross-phase rules.
	if json.Unmarshal(message.Document, &document) != nil {
		return StartupIdentity{}, ErrStartupIdentity
	}
	seen := make(map[string]struct{}, len(document.CredentialChannels))
	channels := make([]CredentialChannelRequirement, len(document.CredentialChannels))
	for i, channel := range document.CredentialChannels {
		if _, exists := seen[channel.ChannelID]; exists {
			return StartupIdentity{}, ErrStartupIdentity
		}
		seen[channel.ChannelID] = struct{}{}
		var actor *string
		if channel.Actor != nil {
			value := *channel.Actor
			actor = &value
		}
		channels[i] = CredentialChannelRequirement{ChannelID: channel.ChannelID, Role: channel.Role,
			Actor: actor, MediaType: channel.MediaType, MaxBytes: int64(channel.MaxBytes)}
	}
	return StartupIdentity{
		ProtocolID: document.ProtocolID, ProtocolVersion: document.ProtocolVersion,
		ProtocolSchemaDigest: document.ProtocolSchemaDigest, ProtocolSemanticsDigest: document.ProtocolSemanticsDigest,
		CallerRelease:    ReleaseIdentity{document.CallerRelease.Kind, document.CallerRelease.Value, document.CallerRelease.Immutable},
		AdapterRelease:   ReleaseIdentity{document.AdapterRelease.Kind, document.AdapterRelease.Value, document.AdapterRelease.Immutable},
		ContractRevision: document.ContractRevision, ContractTree: document.ContractTree,
		ProfileID: document.ProfileID, ProfileVersion: document.ProfileVersion, ProfileDigest: document.ProfileDigest,
		ExpectedValuesInjectedByHarness: document.ExpectedValuesInjectedByHarness, CredentialChannels: channels,
	}, nil
}

// CloneStartupIdentity prevents a stored channel slice or actor pointer from
// becoming caller-mutable when crossing supervisor package boundaries.
func CloneStartupIdentity(value StartupIdentity) StartupIdentity {
	value.CredentialChannels = append([]CredentialChannelRequirement(nil), value.CredentialChannels...)
	for i := range value.CredentialChannels {
		if value.CredentialChannels[i].Actor != nil {
			actor := *value.CredentialChannels[i].Actor
			value.CredentialChannels[i].Actor = &actor
		}
	}
	return value
}
