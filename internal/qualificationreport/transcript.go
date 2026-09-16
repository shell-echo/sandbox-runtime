package qualificationreport

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
)

func lockedTranscriptProjectionRules() map[string]any {
	return map[string]any{
		"payload":  "process-supervisor.json",
		"field":    "adapter_transcript_projection",
		"presence": "non-null-iff-report-adapter-transcript-non-null",
		"embedded_schema_matches_separate_locked_authority": true,
		"digest_profile":       "rfc8785-full-document-v1",
		"digest_excludes_only": "nothing",
		"binds_protocol_phase_invocation_process_executable_configuration_and_allowed_fields": true,
		"credential_roles_equal_in_order_across_phases":                                       true,
		"message_counts_and_record_count_derived_from_ordered_types":                          true,
		"channel_count_equals_role_count":                                                     true,
		"message_types_replay_terminal_and_case_order":                                        true,
		"scenario_dispositions_constrain_status_not_determine_outcome":                        true,
		"physical_byte_counts_eof_exit_and_process_truth_remain_supervisor_inputs":            true,
	}
}

// The embedded resource keeps the report Schema self-contained. Verify its
// complete value against the separately pinned protocol projection authority.
func validateEmbeddedTranscriptAuthority(sourceRoot string, reportSchema []byte) error {
	document, err := readSourceFile(sourceRoot, TranscriptSchemaPath, maxReportBytes)
	if err != nil || evidencefiles.RawDigest(document) != ExpectedTranscriptSchemaDigest {
		return errors.New("qualification transcript schema authority unavailable or changed")
	}
	var expected any
	var report map[string]any
	if decodeStrictJSON(document, &expected) != nil || decodeStrictJSON(reportSchema, &report) != nil {
		return errors.New("qualification transcript schema authority invalid")
	}
	defs, ok := report["$defs"].(map[string]any)
	if !ok || !reflect.DeepEqual(defs["adapterTranscriptProjection"], expected) {
		return errors.New("qualification embedded transcript schema differs from locked authority")
	}
	return nil
}

type transcriptDocument struct {
	ProtocolID      string            `json:"protocol_id"`
	ProtocolVersion string            `json:"protocol_version"`
	SchemaDigest    string            `json:"protocol_schema_digest"`
	SemanticsDigest string            `json:"protocol_semantics_digest"`
	PhaseOrder      []string          `json:"phase_order"`
	InvocationIDs   []string          `json:"invocation_ids"`
	Phases          []transcriptPhase `json:"phases"`
}

type transcriptPhase struct {
	PhaseID        string            `json:"phase_id"`
	InvocationID   string            `json:"invocation_id"`
	Processes      map[string]string `json:"process_identities"`
	Executables    map[string]string `json:"executable_digests"`
	Configurations map[string]string `json:"configuration_digests"`
	Fields         []string          `json:"supplied_field_names"`
	Roles          []string          `json:"credential_channel_roles"`
	Types          []string          `json:"message_types"`
	Counts         map[string]int    `json:"message_counts"`
	Bytes          struct {
		Records  int `json:"adapter_output_complete_records"`
		Channels int `json:"credential_channel_count"`
	} `json:"bounded_byte_counts"`
	Terminal struct {
		Type       string  `json:"terminal_message_type"`
		Completion *string `json:"completion"`
		ErrorCode  *string `json:"error_code"`
		EOF        bool    `json:"stdout_eof_observed"`
		CleanExit  bool    `json:"clean_process_exit_observed"`
	} `json:"terminal_state"`
}

// Shape/limits are checked by the closed payload Schema before this function.
// This proves canonical content and binding consistency, not honest observation
// of a process, physical bytes, timing, or caller independence.
func validateTranscriptBinding(report reportDocument, payload *processSupervisorPayload) error {
	invalid := func() error { return errors.New("qualification transcript projection or report binding invalid") }
	if payload == nil {
		return invalid()
	}
	ref := report.Invocation.AdapterTranscript
	if ref == nil {
		if payload.AdapterTranscriptProjection != nil || payload.AdapterTranscript != nil {
			return invalid()
		}
		return nil
	}
	if payload.AdapterTranscriptProjection == nil || payload.AdapterTranscript == nil ||
		!reflect.DeepEqual(ref, payload.AdapterTranscript) {
		return invalid()
	}
	document, err := json.Marshal(payload.AdapterTranscriptProjection)
	if err != nil {
		return invalid()
	}
	canonical, err := jcs.Transform(document)
	if err != nil || evidencefiles.RawDigest(canonical) != ref.Digest || ref.DigestProfile != "rfc8785-full-document-v1" {
		return invalid()
	}
	var projection transcriptDocument
	if json.Unmarshal(canonical, &projection) != nil {
		return invalid()
	}
	if projection.ProtocolID != AdapterProtocolID || projection.ProtocolVersion != AdapterProtocolVersion ||
		projection.SchemaDigest != ExpectedAdapterProtocolSchemaDigest || projection.SemanticsDigest != ExpectedAdapterProtocolSemanticsDigest ||
		!slices.Equal(projection.PhaseOrder, []string{"initial", "reconstruction"}) || len(projection.Phases) != 2 ||
		!slices.Equal(projection.InvocationIDs, ref.InvocationIDs) || len(projection.InvocationIDs) != 2 ||
		!slices.Equal(projection.Phases[0].Roles, projection.Phases[1].Roles) || len(report.Phases) != 2 {
		return invalid()
	}
	for i, phase := range projection.Phases {
		if phase.PhaseID != projection.PhaseOrder[i] || phase.PhaseID != report.Phases[i].PhaseID ||
			phase.InvocationID != projection.InvocationIDs[i] || !slices.Equal(phase.Fields, ref.AllowedFields) ||
			!phase.Terminal.EOF || !phase.Terminal.CleanExit {
			return invalid()
		}
		processes := [][]processIdentity{report.Invocation.InitialProcesses, report.Invocation.ReconstructionProcesses}[i]
		if len(processes) != 4 || len(phase.Processes) != 4 || len(phase.Executables) != 4 || len(phase.Configurations) != 4 {
			return invalid()
		}
		for _, process := range processes {
			if phase.Processes[process.Component] != process.ProcessID || phase.Executables[process.Component] != process.ExecutableDigest ||
				phase.Configurations[process.Component] != process.ConfigurationDigest {
				return invalid()
			}
		}
		if !validTranscriptMessages(phase, report.Phases[i].ScenarioIDs, report.ScenarioResults) {
			return invalid()
		}
	}
	return nil
}

// Replay the lossy message-type projection without inventing case results.
// Sequential cases are recovered from the locked report phase inventory. A
// completed adapter assertion is not a report pass: independent evidence still
// determines passed/failed/incomplete through the existing report validator.
func validTranscriptMessages(p transcriptPhase, cases []string, results []scenarioResult) bool {
	if len(p.Types) < 2 || p.Types[0] != "startup_identity" || p.Types[len(p.Types)-1] != p.Terminal.Type ||
		p.Bytes.Records != len(p.Types) || p.Bytes.Channels != len(p.Roles) {
		return false
	}
	counts := map[string]int{"startup_identity": 0, "invocation_accepted": 0, "scenario_started": 0, "scenario_result": 0, "invocation_finished": 0, "protocol_error": 0}
	for _, kind := range p.Types {
		if _, ok := counts[kind]; !ok {
			return false
		}
		counts[kind]++
	}
	if !reflect.DeepEqual(counts, p.Counts) {
		return false
	}
	if p.Terminal.Type == "protocol_error" && p.Terminal.ErrorCode != nil && *p.Terminal.ErrorCode == "invalid_invocation" {
		if len(p.Types) != 2 || p.Terminal.Completion != nil {
			return false
		}
		return transcriptStatusesMatch(cases, results, nil, false)
	}
	if len(p.Types) < 3 || p.Types[1] != "invocation_accepted" {
		return false
	}
	started := false
	dispositions := []string{}
	for _, kind := range p.Types[2 : len(p.Types)-1] {
		if len(dispositions) >= len(cases) {
			return false
		}
		switch kind {
		case "scenario_started":
			if started {
				return false
			}
			started = true
		case "scenario_result":
			disposition := "not_executed"
			if started {
				disposition = "completed"
			}
			dispositions = append(dispositions, disposition)
			started = false
		default:
			return false
		}
	}
	if p.Terminal.Type == "invocation_finished" {
		want := "completed"
		if slices.Contains(dispositions, "not_executed") {
			want = "stopped"
		}
		if started || len(dispositions) != len(cases) || p.Terminal.Completion == nil || *p.Terminal.Completion != want || p.Terminal.ErrorCode != nil {
			return false
		}
	} else if p.Terminal.Type != "protocol_error" || p.Terminal.Completion != nil || p.Terminal.ErrorCode == nil ||
		!slices.Contains([]string{"credential_channel_failed", "caller_start_failed", "scenario_execution_failed", "output_failed", "internal_failure"}, *p.Terminal.ErrorCode) {
		return false
	}
	return transcriptStatusesMatch(cases, results, dispositions, started)
}

func transcriptStatusesMatch(cases []string, results []scenarioResult, dispositions []string, started bool) bool {
	byID := make(map[string]string, len(results))
	for _, result := range results {
		byID[result.CaseID] = result.Status
	}
	for i, id := range cases {
		status := byID[id]
		if status == "" {
			return false
		}
		if i < len(dispositions) && dispositions[i] == "completed" {
			if status == "not_executed" {
				return false
			}
		} else if i == len(dispositions) && started {
			if status != "incomplete" && status != "failed" {
				return false
			}
		} else if status != "not_executed" {
			return false
		}
	}
	return true
}
