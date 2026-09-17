package qualificationadapterprotocol

import (
	"encoding/json"
	"errors"
)

var (
	ErrInvocationDetails = errors.New("adapter invocation details rejected")
	ErrScenarioProgress  = errors.New("adapter scenario progress rejected")
	ErrScenarioEvidence  = errors.New("adapter scenario evidence rejected")
	ErrTerminalStatus    = errors.New("adapter terminal status rejected")
)

// TerminalErrorCodeFrom returns only the locked, schema-validated public
// protocol error classification. It never exposes adapter output bytes.
func TerminalErrorCodeFrom(message DecodedMessage) (string, error) {
	if message.validatedBy == nil || message.direction != decodedAdapterToHarness ||
		message.MessageType != "protocol_error" || message.errorCode == nil {
		return "", ErrTerminalStatus
	}
	return *message.errorCode, nil
}

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

// InteractionProgress is the bounded orchestration projection of one
// adapter-reported interaction. It deliberately omits outcomes, assertions,
// observation references, request material, and every caller correlation.
type InteractionProgress struct {
	InteractionID string
	WireAttempts  int
}

// ScenarioProgress is the only scenario-result projection exposed to the
// execution harness while the supervisor retains custody of raw stdout.
type ScenarioProgress struct {
	CaseID       string
	Disposition  string
	ReasonCode   *string
	Interactions []InteractionProgress
}

// CallerAssertion is the closed caller-owned assertion projection retained
// for final report assembly. It contains no request, endpoint, credential or
// caller correlation value.
type CallerAssertion struct {
	AssertionID string
	Result      string
}

// ScenarioEvidence is available only after a scenario_result passed the
// locked output schema. It is separate from ScenarioProgress so the execution
// harness remains request- and assertion-free.
type ScenarioEvidence struct {
	CaseID      string
	Disposition string
	Assertions  []CallerAssertion
}

type scenarioProgressDocument struct {
	CaseID       string  `json:"case_id"`
	Disposition  string  `json:"disposition"`
	ReasonCode   *string `json:"reason_code"`
	Interactions []struct {
		InteractionID string `json:"interaction_id"`
		WireAttempts  int    `json:"wire_attempts"`
	} `json:"interactions"`
}

type scenarioEvidenceDocument struct {
	CaseID      string `json:"case_id"`
	Disposition string `json:"disposition"`
	Assertions  []struct {
		AssertionID string `json:"assertion_id"`
		Result      string `json:"result"`
	} `json:"assertions"`
}

// ScenarioProgressFrom returns a defensive, sanitized projection only for a
// schema-validated adapter-to-harness scenario_result. The raw document never
// leaves the protocol/supervisor boundary.
func ScenarioProgressFrom(message DecodedMessage) (ScenarioProgress, error) {
	if message.validatedBy == nil || message.direction != decodedAdapterToHarness ||
		message.MessageType != "scenario_result" || message.CaseID == nil ||
		message.disposition == nil {
		return ScenarioProgress{}, ErrScenarioProgress
	}
	var document scenarioProgressDocument
	if err := json.Unmarshal(message.Document, &document); err != nil ||
		document.CaseID != *message.CaseID || document.Disposition != *message.disposition {
		return ScenarioProgress{}, ErrScenarioProgress
	}
	result := ScenarioProgress{
		CaseID: document.CaseID, Disposition: document.Disposition,
		ReasonCode:   cloneString(document.ReasonCode),
		Interactions: make([]InteractionProgress, len(document.Interactions)),
	}
	for index, interaction := range document.Interactions {
		result.Interactions[index] = InteractionProgress{
			InteractionID: interaction.InteractionID,
			WireAttempts:  interaction.WireAttempts,
		}
	}
	return result, nil
}

// ScenarioEvidenceFrom returns only the locked case identity, disposition and
// caller-owned assertion tuples from one validated scenario_result. The raw
// adapter document never crosses the protocol boundary.
func ScenarioEvidenceFrom(message DecodedMessage) (ScenarioEvidence, error) {
	if message.validatedBy == nil || message.direction != decodedAdapterToHarness ||
		message.MessageType != "scenario_result" || message.CaseID == nil ||
		message.disposition == nil {
		return ScenarioEvidence{}, ErrScenarioEvidence
	}
	var document scenarioEvidenceDocument
	if err := json.Unmarshal(message.Document, &document); err != nil ||
		document.CaseID != *message.CaseID || document.Disposition != *message.disposition {
		return ScenarioEvidence{}, ErrScenarioEvidence
	}
	result := ScenarioEvidence{
		CaseID: document.CaseID, Disposition: document.Disposition,
		Assertions: make([]CallerAssertion, len(document.Assertions)),
	}
	for index, assertion := range document.Assertions {
		result.Assertions[index] = CallerAssertion{
			AssertionID: assertion.AssertionID,
			Result:      assertion.Result,
		}
	}
	return result, nil
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
