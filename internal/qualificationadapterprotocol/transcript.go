package qualificationadapterprotocol

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/gowebpki/jcs"
)

// TranscriptComponents is the closed four-component identity projection.
// Process identities are sanitized observer IDs, never OS PIDs or backend IDs.
type TranscriptComponents struct {
	Provider             string `json:"provider"`
	ExternalCaller       string `json:"external_caller"`
	QualificationAdapter string `json:"qualification_adapter"`
	CallerGateway        string `json:"caller_gateway"`
}

// TranscriptSupervisorPhase contains only facts outside the protocol codec's
// custody. A process supervisor must supply these from its own observations.
// Supplying these values does not prove a process ran. No raw stderr or secret
// payload is accepted by this interface; zero counters must be observed zeros.
type TranscriptSupervisorPhase struct {
	ProcessIdentities           TranscriptComponents
	ExecutableDigests           TranscriptComponents
	ConfigurationDigests        TranscriptComponents
	StderrWireBytes             int64
	CredentialPayloadTotalBytes int64
}

// TranscriptProjection is a caller-owned canonical digest preimage, without a
// trailing LF or embedded digest. Modifying Document invalidates Digest.
// It is not a report, receipt, qualification result, or independent observation.
type TranscriptProjection struct {
	Document json.RawMessage
	Digest   string
}

// ProjectTranscript materializes the locked two-phase projection only after
// both streams reach terminal, EOF and a supplied clean exit. Protocol fields
// and counts come solely from accepted state and codec observations. External
// process facts are mandatory supplied inputs, not inferred successes.
// Report/payload cross-binding is a separate evidence-validator responsibility.
func (r *RunStateMachine) ProjectTranscript(initial, reconstruction *TranscriptSupervisorPhase) (TranscriptProjection, error) {
	invalid := func() (TranscriptProjection, error) {
		return TranscriptProjection{}, errors.New("adapter transcript projection unavailable or invalid")
	}
	if !r.Complete() || initial == nil || reconstruction == nil ||
		r.initial.codec == nil || r.initial.codec.transcriptSchema == nil ||
		!slices.Equal(r.initial.credentialRoles, r.reconstruction.credentialRoles) {
		return invalid()
	}
	// Every component must have a fresh observer identity after reconstruction.
	left, right := initial.ProcessIdentities, reconstruction.ProcessIdentities
	if left.Provider == right.Provider || left.ExternalCaller == right.ExternalCaller ||
		left.QualificationAdapter == right.QualificationAdapter || left.CallerGateway == right.CallerGateway {
		return invalid()
	}
	phases := make([]any, 0, 2)
	for i, m := range []*PhaseStateMachine{r.initial, r.reconstruction} {
		observation := []*TranscriptSupervisorPhase{initial, reconstruction}[i]
		// Bound supplied strings before JSON allocation or Schema validation.
		if !observation.ProcessIdentities.bounded(200) || !observation.ExecutableDigests.bounded(71) ||
			!observation.ConfigurationDigests.bounded(71) ||
			m.decoder == nil || m.decoder.failure != nil || !m.decoder.eof ||
			m.decoder.Records() != len(m.messageTypes) || m.decoder.TotalWireBytes() != m.observedOutputWireBytes ||
			observation.CredentialPayloadTotalBytes > m.credentialPayloadLimit {
			return invalid()
		}
		counts := make(map[string]int, len(adapterToHarnessMessageTypes))
		for _, kind := range adapterToHarnessMessageTypes {
			counts[kind] = 0
		}
		for _, kind := range m.messageTypes {
			counts[kind]++
		}
		var completion, errorCode any
		if m.terminal.completion != "" {
			completion = m.terminal.completion
		}
		if m.terminal.errorCode != "" {
			errorCode = m.terminal.errorCode
		}
		phases = append(phases, map[string]any{
			"phase_id":                 m.invocation.phase,
			"invocation_id":            m.invocation.invocationID,
			"process_identities":       observation.ProcessIdentities,
			"executable_digests":       observation.ExecutableDigests,
			"configuration_digests":    observation.ConfigurationDigests,
			"supplied_field_names":     append([]string(nil), allowedHarnessFields...),
			"credential_channel_roles": append([]string(nil), m.credentialRoles...),
			"message_types":            append([]string(nil), m.messageTypes...),
			"message_counts":           counts,
			"bounded_byte_counts": map[string]any{
				"invocation_wire_bytes":           m.invocation.wireBytes,
				"adapter_stdout_wire_bytes":       m.observedOutputWireBytes,
				"adapter_stderr_wire_bytes":       observation.StderrWireBytes,
				"adapter_output_complete_records": m.decoder.Records(),
				"credential_channel_count":        len(m.credentialRoles),
				"credential_payload_total_bytes":  observation.CredentialPayloadTotalBytes,
			},
			"terminal_state": map[string]any{
				"terminal_message_type":       m.terminal.messageType,
				"completion":                  completion,
				"error_code":                  errorCode,
				"stdout_eof_observed":         true,
				"clean_process_exit_observed": true,
			},
		})
	}
	value := map[string]any{
		"format_version":            1,
		"transcript_type":           "sandbox-runtime-external-caller-adapter-transcript",
		"transcript_version":        ProtocolVersion,
		"protocol_id":               ProtocolID,
		"protocol_version":          ProtocolVersion,
		"protocol_schema_digest":    ExpectedProtocolSchemaDigest,
		"protocol_semantics_digest": ExpectedProtocolSemanticsDigest,
		"phase_order":               []string{"initial", "reconstruction"},
		"invocation_ids":            []string{r.initial.invocation.invocationID, r.reconstruction.invocation.invocationID},
		"phases":                    phases,
	}
	document, err := json.Marshal(value)
	if err != nil {
		return invalid()
	}
	decoded, err := decodeStrictValue(document)
	if err != nil || r.initial.codec.transcriptSchema.Validate(decoded) != nil {
		return invalid()
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return invalid()
	}
	return TranscriptProjection{Document: canonical, Digest: rawDigest(canonical)}, nil
}

func (c TranscriptComponents) bounded(maxBytes int) bool {
	for _, value := range []string{c.Provider, c.ExternalCaller, c.QualificationAdapter, c.CallerGateway} {
		if len(value) == 0 || len(value) > maxBytes {
			return false
		}
	}
	return true
}
