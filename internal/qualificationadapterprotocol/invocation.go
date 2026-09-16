package qualificationadapterprotocol

import (
	"encoding/json"
	"errors"
)

var ErrInvocationDetails = errors.New("adapter invocation details rejected")

type CredentialChannelDescriptor struct {
	ChannelID      string
	Role           string
	Actor          *string
	MediaType      string
	MaxBytes       int64
	FileDescriptor int
}

// InvocationDetails is a structured copy of one schema-validated invocation.
// It contains no credential payload. Location values are private runtime input
// and must not be logged or copied into qualification evidence.
type InvocationDetails struct {
	InvocationID         string
	Phase                string
	ProfilePath          string
	ProviderOrigin       string
	GatewayProbeEndpoint string
	CallerStateRoot      string
	CredentialChannels   []CredentialChannelDescriptor
}

type invocationDetailsDocument struct {
	InvocationID         string                                `json:"invocation_id"`
	Phase                string                                `json:"phase"`
	ProfilePath          string                                `json:"profile_path"`
	ProviderOrigin       string                                `json:"provider_origin"`
	GatewayProbeEndpoint string                                `json:"gateway_probe_endpoint"`
	CallerStateRoot      string                                `json:"caller_state_root"`
	CredentialChannels   []credentialChannelDescriptorDocument `json:"credential_channel_descriptors"`
}

type credentialChannelDescriptorDocument struct {
	ChannelID      string  `json:"channel_id"`
	Role           string  `json:"role"`
	Actor          *string `json:"actor"`
	MediaType      string  `json:"media_type"`
	MaxBytes       float64 `json:"max_bytes"`
	FileDescriptor float64 `json:"file_descriptor"`
}

// InvocationDetailsFrom accepts only an intact harness-to-adapter invocation
// produced by the locked Codec. It additionally enforces semantic uniqueness
// for channel IDs and file descriptors, which JSON Schema uniqueItems cannot
// express by one object field. Errors contain no invocation values.
func InvocationDetailsFrom(message DecodedMessage) (InvocationDetails, error) {
	if !decodedEnvelopeIntact(message) || message.direction != decodedHarnessToAdapter ||
		message.outputDecoder != nil || message.MessageType != "invocation" || message.Sequence != nil ||
		message.InvocationID == nil || message.Phase == nil || message.WireBytes != message.DocumentBytes {
		return InvocationDetails{}, ErrInvocationDetails
	}
	var document invocationDetailsDocument
	if json.Unmarshal(message.Document, &document) != nil ||
		document.InvocationID != *message.InvocationID || document.Phase != *message.Phase {
		return InvocationDetails{}, ErrInvocationDetails
	}
	seenIDs := make(map[string]struct{}, len(document.CredentialChannels))
	seenDescriptors := make(map[int]struct{}, len(document.CredentialChannels))
	channels := make([]CredentialChannelDescriptor, len(document.CredentialChannels))
	for i, channel := range document.CredentialChannels {
		descriptor := int(channel.FileDescriptor)
		if _, exists := seenIDs[channel.ChannelID]; exists {
			return InvocationDetails{}, ErrInvocationDetails
		}
		if _, exists := seenDescriptors[descriptor]; exists {
			return InvocationDetails{}, ErrInvocationDetails
		}
		seenIDs[channel.ChannelID] = struct{}{}
		seenDescriptors[descriptor] = struct{}{}
		var actor *string
		if channel.Actor != nil {
			value := *channel.Actor
			actor = &value
		}
		channels[i] = CredentialChannelDescriptor{
			ChannelID: channel.ChannelID, Role: channel.Role, Actor: actor,
			MediaType: channel.MediaType, MaxBytes: int64(channel.MaxBytes), FileDescriptor: descriptor,
		}
	}
	return InvocationDetails{
		InvocationID: document.InvocationID, Phase: document.Phase,
		ProfilePath: document.ProfilePath, ProviderOrigin: document.ProviderOrigin,
		GatewayProbeEndpoint: document.GatewayProbeEndpoint, CallerStateRoot: document.CallerStateRoot,
		CredentialChannels: channels,
	}, nil
}
