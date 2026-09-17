// Package qualificationadapterprotocol verifies the locked P2.7c adapter
// process protocol and transcript-projection definitions and provides its
// runtime-independent strict codec and ordered per-phase state prefix through
// scenario results. It does not launch an adapter or qualify a caller.
package qualificationadapterprotocol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

const (
	ProtocolID       = "sandbox-runtime-external-caller-adapter-v1"
	ProtocolVersion  = "1.0.0"
	ProtocolSchemaID = "urn:shell-echo:sandbox-runtime:qualification:external-caller-adapter-protocol:v1"

	ProtocolSchemaPath    = "qualification/external-caller-coding-shell-v1/adapter-protocol.schema.json"
	ProtocolSemanticsPath = "qualification/external-caller-coding-shell-v1/adapter-protocol.semantics.json"
	TranscriptSchemaID    = "urn:shell-echo:sandbox-runtime:qualification:external-caller-adapter-transcript:v1"
	TranscriptSchemaPath  = "qualification/external-caller-coding-shell-v1/adapter-transcript.schema.json"

	ExpectedProtocolSchemaDigest    = "sha256:fdee270ca27003693b2ce504da769c9779825312e1dd4e06b5caf8578f5ee03c"
	ExpectedProtocolSemanticsDigest = "sha256:997c49cd1a5b2c050d48333a973dd78b611221f869bf709cf6d1a8d771795a99"
	ExpectedTranscriptSchemaDigest  = "sha256:d2eb229f55528df8ba68426cc5b7da9d1bd6a78a412707d656b77c1effeff293"

	maxDefinitionBytes      = 2 << 20
	maxCaseDuration         = 120 * time.Second
	maxRunExecutionDuration = 1800 * time.Second
	maxProcessReapDuration  = 5 * time.Second
)

var (
	allowedHarnessFields = []string{
		"invocation_id",
		"phase",
		"profile_path",
		"provider_origin",
		"gateway_probe_endpoint",
		"credential_channel_descriptors",
		"caller_state_root",
	}
	forbiddenCorrelationFields = []string{
		"sandbox_id",
		"operation_id",
		"attempt_id",
		"idempotency_key",
		"fencing_token",
		"runtime_session_id",
		"handoff_reference",
	}
	locationBindingFields = []string{
		"profile_path",
		"provider_origin",
		"gateway_probe_endpoint",
		"caller_state_root",
	}
	runtimeLocationOverlapRules = []string{
		"profile_path:caller_state_root",
		"profile_path:working_directory",
		"profile_path:evidence_root",
		"caller_state_root:working_directory",
		"caller_state_root:evidence_root",
	}
	locationFreezePrecedes = []string{
		"credential-material-acquisition-or-generation",
		"forbidden-correlation-material-acquisition-or-generation",
		"adapter-process-start",
		"provider-or-gateway-network-io",
	}
	outputBindingMessageTypes = []string{
		"invocation_accepted",
		"scenario_started",
		"scenario_result",
		"invocation_finished",
	}
	postBindingProtocolErrorCodes = []string{
		"credential_channel_failed",
		"caller_start_failed",
		"scenario_execution_failed",
		"output_failed",
		"internal_failure",
	}
	processFailureConditions = []string{
		"context-canceled",
		"deadline-exceeded",
		"invalid-or-out-of-order-message",
		"duplicate-or-skipped-sequence",
		"input-or-output-limit-exceeded",
		"ambiguous-credential-delivery",
		"unexpected-eof",
		"unexpected-process-exit",
	}
	harnessToAdapterMessageTypes = []string{
		"invocation",
	}
	adapterToHarnessMessageTypes = []string{
		"startup_identity",
		"invocation_accepted",
		"scenario_started",
		"scenario_result",
		"invocation_finished",
		"protocol_error",
	}
	stateMachineStates = []string{
		"awaiting-startup",
		"ready-for-invocation",
		"awaiting-invocation-acceptance",
		"awaiting-next-scenario",
		"awaiting-started-result",
		"awaiting-terminal",
		"terminal-observed",
		"terminal-eof-observed",
		"complete",
		"failed",
	}
	sanitizedTranscriptFields = []string{
		"protocol_id",
		"protocol_version",
		"protocol_schema_digest",
		"protocol_semantics_digest",
		"invocation_ids",
		"phase_order",
		"process_identities",
		"executable_digests",
		"configuration_digests",
		"supplied_field_names",
		"credential_channel_roles",
		"message_types",
		"message_counts",
		"bounded_byte_counts",
		"terminal_state",
	}
	sanitizedTranscriptExcludedFields = []string{
		"field_values",
		"credential_payloads",
		"provider_origin",
		"gateway_probe_endpoint",
		"profile_path",
		"caller_state_root",
		"raw_requests",
		"raw_responses",
		"raw_endpoints",
		"raw_correlation_values",
		"stderr",
	}
)

// Report identifies the exact protocol definition that passed verification.
// It intentionally carries no process execution or external-caller result.
type Report struct {
	ProtocolID             string
	ProtocolVersion        string
	SchemaDigest           string
	SemanticsDigest        string
	TranscriptSchemaDigest string
	caseOrder              map[string][]string
}

// VerifyDefinition checks the content anchors, referenced P2.7 authorities,
// closed schema, and the operational invariants needed by the next process
// implementation slice.
func VerifyDefinition(ctx context.Context, sourceRoot string) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("adapter protocol verification requires context")
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	profileReport, err := qualificationprofile.VerifyCodingShellV1(ctx, sourceRoot)
	if err != nil {
		return Report{}, fmt.Errorf("verify qualification profile before adapter protocol: %w", err)
	}
	initialCases, initialOK := profileReport.OrderedCaseIDs("initial")
	reconstructionCases, reconstructionOK := profileReport.OrderedCaseIDs("reconstruction")
	if !initialOK || !reconstructionOK {
		return Report{}, errors.New("verified qualification profile case order is unavailable")
	}

	protocolSchema, err := readRepositoryFile(sourceRoot, ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		return Report{}, fmt.Errorf("read adapter protocol schema: %w", err)
	}
	semantics, err := readRepositoryFile(sourceRoot, ProtocolSemanticsPath, maxDefinitionBytes)
	if err != nil {
		return Report{}, fmt.Errorf("read adapter protocol semantics: %w", err)
	}
	reportSchema, err := readRepositoryFile(sourceRoot, qualificationreport.ReportSchemaPath, maxDefinitionBytes)
	if err != nil {
		return Report{}, fmt.Errorf("read qualification report schema: %w", err)
	}
	transcriptSchema, err := readRepositoryFile(sourceRoot, TranscriptSchemaPath, maxDefinitionBytes)
	if err != nil {
		return Report{}, fmt.Errorf("read adapter transcript schema: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}

	if got := rawDigest(protocolSchema); got != ExpectedProtocolSchemaDigest {
		return Report{}, fmt.Errorf("adapter protocol schema digest %s does not match trust anchor %s", got, ExpectedProtocolSchemaDigest)
	}
	if got := rawDigest(semantics); got != ExpectedProtocolSemanticsDigest {
		return Report{}, fmt.Errorf("adapter protocol semantics digest %s does not match trust anchor %s", got, ExpectedProtocolSemanticsDigest)
	}
	if got := rawDigest(reportSchema); got != qualificationreport.ExpectedReportSchemaDigest {
		return Report{}, fmt.Errorf("qualification report schema digest %s does not match trust anchor %s", got, qualificationreport.ExpectedReportSchemaDigest)
	}
	if got := rawDigest(transcriptSchema); got != ExpectedTranscriptSchemaDigest {
		return Report{}, fmt.Errorf("adapter transcript schema digest %s does not match trust anchor %s", got, ExpectedTranscriptSchemaDigest)
	}

	compiled, err := compileProtocolSchema(protocolSchema, reportSchema)
	if err != nil {
		return Report{}, err
	}
	compiledTranscript, err := compileTranscriptSchema(transcriptSchema)
	if err != nil {
		return Report{}, err
	}
	semanticValue, err := decodeStrictObject(semantics)
	if err != nil {
		return Report{}, fmt.Errorf("decode adapter protocol semantics: %w", err)
	}
	if err := validateSemantics(semanticValue); err != nil {
		return Report{}, err
	}
	if err := validateLockedExamples(compiled); err != nil {
		return Report{}, err
	}
	if err := validateLockedTranscriptExample(compiledTranscript); err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	return Report{
		ProtocolID:             ProtocolID,
		ProtocolVersion:        ProtocolVersion,
		SchemaDigest:           ExpectedProtocolSchemaDigest,
		SemanticsDigest:        ExpectedProtocolSemanticsDigest,
		TranscriptSchemaDigest: ExpectedTranscriptSchemaDigest,
		caseOrder: map[string][]string{
			"initial":        initialCases,
			"reconstruction": reconstructionCases,
		},
	}, nil
}

func compileProtocolSchema(protocolDocument, reportDocument []byte) (*jsonschema.Schema, error) {
	protocolValue, err := decodeStrictValue(protocolDocument)
	if err != nil {
		return nil, fmt.Errorf("decode adapter protocol schema: %w", err)
	}
	reportValue, err := decodeStrictValue(reportDocument)
	if err != nil {
		return nil, fmt.Errorf("decode qualification report schema: %w", err)
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(ProtocolSchemaID, protocolValue); err != nil {
		return nil, fmt.Errorf("load adapter protocol schema: %w", err)
	}
	if err := compiler.AddResource(qualificationreport.ReportSchemaID, reportValue); err != nil {
		return nil, fmt.Errorf("load qualification report schema: %w", err)
	}
	compiled, err := compiler.Compile(ProtocolSchemaID)
	if err != nil {
		return nil, fmt.Errorf("compile adapter protocol schema: %w", err)
	}
	return compiled, nil
}

func compileTranscriptSchema(document []byte) (*jsonschema.Schema, error) {
	value, err := decodeStrictValue(document)
	if err != nil {
		return nil, fmt.Errorf("decode adapter transcript schema: %w", err)
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(TranscriptSchemaID, value); err != nil {
		return nil, fmt.Errorf("load adapter transcript schema: %w", err)
	}
	compiled, err := compiler.Compile(TranscriptSchemaID)
	if err != nil {
		return nil, fmt.Errorf("compile adapter transcript schema: %w", err)
	}
	return compiled, nil
}

func lockedStateTransitions() []any {
	transition := func(from []string, event, guard, to string) any {
		return map[string]any{
			"from":  stringsToAny(from),
			"event": event,
			"guard": guard,
			"to":    to,
		}
	}
	return []any{
		transition([]string{"awaiting-startup"}, "startup_identity", "sequence-zero-and-locked-startup-authority", "ready-for-invocation"),
		transition([]string{"ready-for-invocation"}, "validated-invocation-delivered", "single-schema-valid-invocation-delivered-and-supervisor-reference-captured", "awaiting-invocation-acceptance"),
		transition([]string{"awaiting-invocation-acceptance"}, "invocation_accepted", "sequence-one-and-reference-binding-valid", "awaiting-next-scenario"),
		transition([]string{"awaiting-invocation-acceptance"}, "protocol_error", "pre-binding-invalid-invocation-branch", "terminal-observed"),
		transition([]string{"awaiting-next-scenario"}, "scenario_started", "next-locked-profile-case", "awaiting-started-result"),
		transition([]string{"awaiting-next-scenario"}, "scenario_result", "next-locked-profile-case-not-executed-and-more-cases-remain", "awaiting-next-scenario"),
		transition([]string{"awaiting-next-scenario"}, "scenario_result", "final-locked-profile-case-not-executed", "awaiting-terminal"),
		transition([]string{"awaiting-started-result"}, "scenario_result", "same-locked-profile-case-completed-and-more-cases-remain", "awaiting-next-scenario"),
		transition([]string{"awaiting-started-result"}, "scenario_result", "same-final-locked-profile-case-completed", "awaiting-terminal"),
		transition([]string{"awaiting-next-scenario", "awaiting-started-result", "awaiting-terminal"}, "protocol_error", "post-binding-failure-branch-and-next-contiguous-sequence", "terminal-observed"),
		transition([]string{"awaiting-terminal"}, "invocation_finished", "next-contiguous-sequence-and-completion-matches-dispositions", "terminal-observed"),
		transition([]string{"terminal-observed"}, "stdout_eof", "no-post-terminal-byte-observed", "terminal-eof-observed"),
		transition([]string{"terminal-eof-observed"}, "clean_process_exit", "bounded-wait-reported-successful-process-exit", "complete"),
	}
}

func lockedTranscriptByteCountSources() map[string]any {
	return map[string]any{
		"invocation_wire_bytes":           "codec-invocation-wire-bytes",
		"adapter_stdout_wire_bytes":       "codec-adapter-stdout-total-wire-bytes",
		"adapter_stderr_wire_bytes":       "process-supervisor-bounded-stderr-wire-bytes",
		"adapter_output_complete_records": "codec-complete-record-count",
		"credential_channel_count":        "validated-invocation-credential-descriptor-count",
		"credential_payload_total_bytes":  "process-supervisor-successfully-written-credential-payload-bytes",
	}
}

func validateSemantics(value map[string]any) error {
	checks := []struct {
		path []string
		want any
	}{
		{[]string{"format_version"}, float64(1)},
		{[]string{"semantics_id"}, "sandbox-runtime-external-caller-adapter-protocol-semantics-v1"},
		{[]string{"semantics_version"}, ProtocolVersion},
		{[]string{"protocol_schema", "path"}, ProtocolSchemaPath},
		{[]string{"protocol_schema", "digest"}, ExpectedProtocolSchemaDigest},
		{[]string{"protocol_schema", "schema_id"}, ProtocolSchemaID},
		{[]string{"profile", "profile_id"}, qualificationprofile.ProfileID},
		{[]string{"profile", "profile_version"}, qualificationprofile.ProfileVersion},
		{[]string{"profile", "profile_digest"}, qualificationprofile.ExpectedProfileDigest},
		{[]string{"profile", "schema_digest"}, qualificationprofile.ExpectedSchemaDigest},
		{[]string{"report_schema", "path"}, qualificationreport.ReportSchemaPath},
		{[]string{"report_schema", "digest"}, qualificationreport.ExpectedReportSchemaDigest},
		{[]string{"report_schema", "schema_id"}, qualificationreport.ReportSchemaID},
		{[]string{"transport_profile", "protocol_data_language"}, "language-neutral-json"},
		{[]string{"transport_profile", "supported_platforms"}, []any{"darwin", "linux"}},
		{[]string{"transport_profile", "unsupported_platform_behavior"}, "fail-closed-before-process-start"},
		{[]string{"transport_profile", "startup_before_harness_input"}, true},
		{[]string{"transport_profile", "startup_before_credential_delivery"}, true},
		{[]string{"transport_profile", "fixed_empty_argv"}, true},
		{[]string{"limits", "max_invocation_bytes"}, float64(MaxInvocationBytes)},
		{[]string{"limits", "max_adapter_output_record_bytes"}, float64(MaxAdapterOutputRecordBytes)},
		{[]string{"limits", "max_adapter_output_records_per_process"}, float64(MaxAdapterOutputRecords)},
		{[]string{"limits", "max_adapter_output_sequence"}, float64(32)},
		{[]string{"limits", "max_adapter_stdout_bytes"}, float64(MaxAdapterStdoutBytes)},
		{[]string{"limits", "max_adapter_stderr_bytes"}, float64(MaxAdapterStderrBytes)},
		{[]string{"limits", "max_credential_channels"}, float64(MaxCredentialChannels)},
		{[]string{"limits", "max_credential_channel_bytes"}, float64(MaxCredentialChannelBytes)},
		{[]string{"limits", "max_credential_total_bytes"}, float64(MaxCredentialTotalBytes)},
		{[]string{"limits", "max_case_seconds"}, float64(120)},
		{[]string{"limits", "max_execution_seconds"}, float64(1800)},
		{[]string{"limits", "max_process_reap_seconds"}, float64(5)},
		{[]string{"codec", "harness_to_adapter_message_types"}, stringsToAny(harnessToAdapterMessageTypes)},
		{[]string{"codec", "adapter_to_harness_message_types"}, stringsToAny(adapterToHarnessMessageTypes)},
		{[]string{"codec", "invocation_framing", "document_count"}, float64(1)},
		{[]string{"codec", "invocation_framing", "eof_required"}, true},
		{[]string{"codec", "invocation_framing", "byte_count"}, "all-wire-bytes-through-eof-including-json-whitespace"},
		{[]string{"codec", "invocation_framing", "empty_input_allowed"}, false},
		{[]string{"codec", "adapter_output_framing", "delimiter"}, "single-lf-byte"},
		{[]string{"codec", "adapter_output_framing", "record_document_bytes_exclude_delimiter"}, true},
		{[]string{"codec", "adapter_output_framing", "stdout_total_bytes_include_delimiters_and_invalid_or_truncated_bytes"}, true},
		{[]string{"codec", "adapter_output_framing", "every_record_requires_delimiter"}, true},
		{[]string{"codec", "adapter_output_framing", "empty_records_allowed"}, false},
		{[]string{"codec", "adapter_output_framing", "carriage_return_bytes_allowed"}, false},
		{[]string{"codec", "adapter_output_framing", "crlf_allowed"}, false},
		{[]string{"codec", "adapter_output_framing", "complete_records_rejected_by_document_validation_count_toward_record_limit"}, true},
		{[]string{"codec", "adapter_output_framing", "record_limit_failure_occurs_on_first_byte_after_max_complete_records"}, true},
		{[]string{"codec", "json", "utf8_required"}, true},
		{[]string{"codec", "json", "duplicate_member_names_allowed"}, false},
		{[]string{"codec", "json", "invalid_unicode_surrogate_escapes_allowed"}, false},
		{[]string{"codec", "json", "multiple_values_per_document_allowed"}, false},
		{[]string{"codec", "json", "schema_validation_required"}, true},
		{[]string{"codec", "json", "unknown_message_fields_allowed"}, false},
		{[]string{"codec", "startup_protocol_digests_must_match_locked_authority"}, true},
		{[]string{"codec", "invocation_failure_precedence"}, []any{"invocation-byte-limit", "stream-io-failure", "json-encoding-or-structure", "schema", "message-direction"}},
		{[]string{"codec", "adapter_output_failure_precedence"}, []any{"stdout-byte-limit", "record-count-limit", "record-byte-limit", "stream-io-failure", "record-framing", "json-encoding-or-structure", "schema", "message-direction", "protocol-authority"}},
		{[]string{"codec", "first_decode_failure_is_terminal"}, true},
		{[]string{"codec", "codec_validates_message_order"}, false},
		{[]string{"codec", "codec_launches_or_supervises_processes"}, false},
		{[]string{"deadline_control", "clock_source"}, "process-supervisor-monotonic-elapsed-time"},
		{[]string{"deadline_control", "reported_wall_clock_timestamps_control_deadlines"}, false},
		{[]string{"deadline_control", "run_execution", "start_anchor"}, "immediately-before-first-preflight-read"},
		{[]string{"deadline_control", "run_execution", "success_end_anchor"}, "immediately-after-final-reached-phase-clean-process-exit-following-terminal-and-stdout-eof"},
		{[]string{"deadline_control", "run_execution", "failure_end_anchor"}, "immediately-upon-terminal-supervisor-failure-classification-before-separate-termination-cleanup"},
		{[]string{"deadline_control", "run_execution", "deadline_policy"}, "minimum-of-locked-run-execution-and-parent-context-deadline"},
		{[]string{"deadline_control", "run_execution", "shared_across_phases"}, true},
		{[]string{"deadline_control", "run_execution", "phase_process_start_resets_deadline"}, false},
		{[]string{"deadline_control", "run_execution", "reconstruction_resets_deadline"}, false},
		{[]string{"deadline_control", "run_execution", "included_waits"}, []any{"startup-identity", "invocation-and-credential-delivery", "adapter-output", "terminal-stdout-eof-and-clean-process-exit"}},
		{[]string{"deadline_control", "case", "start_anchor"}, "immediately-after-supervisor-validates-prior-case-boundary"},
		{[]string{"deadline_control", "case", "first_case_prior_boundary_message_type"}, "invocation_accepted"},
		{[]string{"deadline_control", "case", "later_case_prior_boundary_message_type"}, "scenario_result"},
		{[]string{"deadline_control", "case", "timer_starts_before_waiting_for_expected_case_output"}, true},
		{[]string{"deadline_control", "case", "deadline_policy"}, "minimum-of-locked-case-remaining-run-execution-and-parent-context-deadline"},
		{[]string{"deadline_control", "case", "applies_to_dispositions"}, []any{"completed", "not_executed"}},
		{[]string{"deadline_control", "case", "scenario_started_resets_deadline"}, false},
		{[]string{"deadline_control", "case", "retries_or_transient_outcomes_reset_deadline"}, false},
		{[]string{"deadline_control", "expiry", "effective_deadline_expiry_failure"}, "deadline-exceeded"},
		{[]string{"deadline_control", "expiry", "parent_cancellation_before_effective_deadline_failure"}, "context-canceled"},
		{[]string{"deadline_control", "expiry", "simultaneous_event_policy"}, "deadline-preempts-events-observed-at-or-after-effective-deadline"},
		{[]string{"deadline_control", "termination", "start_anchor"}, "immediately-before-close-supervisor-owned-io"},
		{[]string{"deadline_control", "termination", "scope"}, []any{"close-supervisor-owned-io", "kill-process-group", "bounded-wait-and-reap"}},
		{[]string{"deadline_control", "termination", "deadline_policy"}, "separate-cleanup-context-with-locked-process-reap-limit"},
		{[]string{"deadline_control", "termination", "timeout_result"}, "incomplete"},
		{[]string{"deadline_control", "definition_verifier_claims_runtime_deadline_enforcement"}, false},
		{[]string{"startup_identity", "expected_values_injected_by_harness"}, false},
		{[]string{"startup_identity", "combined_frame_is_caller_owner_assertion"}, true},
		{[]string{"startup_identity", "process_supervisor_must_independently_bind_actual_artifacts_and_processes"}, true},
		{[]string{"invocation", "one_process_invocation_per_phase"}, true},
		{[]string{"invocation", "allowed_harness_fields"}, stringsToAny(allowedHarnessFields)},
		{[]string{"invocation", "forbidden_correlation_fields"}, stringsToAny(forbiddenCorrelationFields)},
		{[]string{"invocation", "location_policy", "path_profile"}, "absolute-clean-posix-portable-filename-v1"},
		{[]string{"invocation", "location_policy", "uri_profile"}, "canonical-secure-uri-v1"},
		{[]string{"invocation", "location_policy", "profile_path_binding"}, "same-read-only-regular-file-opened-without-symlinks-and-verified-as-locked-profile"},
		{[]string{"invocation", "location_policy", "caller_state_root_binding"}, "same-private-directory-opened-without-symlinks-created-empty-before-initial-and-unread-unmodified-unreplaced-by-harness"},
		{[]string{"invocation", "location_policy", "provider_origin_policy"}, "https-origin-without-path-userinfo-query-fragment-percent-encoding-or-explicit-default-port"},
		{[]string{"invocation", "location_policy", "gateway_probe_endpoint_policy"}, "https-or-wss-endpoint-with-required-static-clean-path-without-userinfo-query-fragment-percent-encoding-or-explicit-default-port"},
		{[]string{"invocation", "location_policy", "host_policy"}, "lowercase-ldh-dns-not-ending-in-whatwg-ipv4-number-or-canonical-ip-literal"},
		{[]string{"invocation", "location_policy", "ipv4_policy"}, "four-shortest-decimal-octets"},
		{[]string{"invocation", "location_policy", "ipv6_policy"}, "non-ipv4-mapped-rfc5952-literal"},
		{[]string{"invocation", "location_policy", "port_policy"}, "omitted-or-nondefault-shortest-decimal-1-through-65535"},
		{[]string{"invocation", "location_policy", "gateway_scheme_rewrite_allowed"}, false},
		{[]string{"invocation", "location_policy", "values_source"}, "qualification-operator-and-process-supervisor-static-preflight-only"},
		{[]string{"invocation", "location_policy", "values_commitment"}, "adapter-configuration-digest-finalized"},
		{[]string{"invocation", "location_policy", "values_commitment_configuration_id"}, "adapter_configuration"},
		{[]string{"invocation", "location_policy", "values_commitment_digest_profile"}, "rfc8785-full-document-v1"},
		{[]string{"invocation", "location_policy", "values_frozen_before"}, stringsToAny(locationFreezePrecedes)},
		{[]string{"invocation", "location_policy", "values_identical_across_phases"}, stringsToAny(locationBindingFields)},
		{[]string{"invocation", "location_policy", "values_derived_from_forbidden_correlation"}, false},
		{[]string{"invocation", "location_policy", "values_derived_from_credential_payload"}, false},
		{[]string{"invocation", "location_policy", "derivation_and_order_proof_observer"}, "process_supervisor"},
		{[]string{"invocation", "location_policy", "operator_upstream_non_derivation_is_trusted_input"}, true},
		{[]string{"invocation", "location_policy", "definition_verifier_claims_derivation_or_order_proof"}, false},
		{[]string{"invocation", "location_policy", "location_values_in_sanitized_transcript"}, false},
		{[]string{"invocation", "location_policy", "runtime_binding_observer"}, "process_supervisor"},
		{[]string{"invocation", "location_policy", "runtime_location_overlap_forbidden"}, stringsToAny(runtimeLocationOverlapRules)},
		{[]string{"invocation", "evidence_root_exposed_to_adapter"}, false},
		{[]string{"state_machine", "scope"}, "one-fresh-adapter-process-and-one-phase"},
		{[]string{"state_machine", "initial_state"}, "awaiting-startup"},
		{[]string{"state_machine", "states"}, stringsToAny(stateMachineStates)},
		{[]string{"state_machine", "harness_input_event"}, "validated-invocation-delivered"},
		{[]string{"state_machine", "transition_table"}, lockedStateTransitions()},
		{[]string{"state_machine", "undefined_transition_result"}, "failed"},
		{[]string{"state_machine", "decode_failure_from_nonterminal_result"}, "failed"},
		{[]string{"state_machine", "stdout_eof_before_terminal_result"}, "failed"},
		{[]string{"state_machine", "byte_after_terminal_result"}, "failed"},
		{[]string{"state_machine", "process_exit_event_source"}, "bounded-wait-after-stdout-eof-drain"},
		{[]string{"state_machine", "non_clean_process_exit_result"}, "failed"},
		{[]string{"state_machine", "complete_and_failed_states_are_absorbing"}, true},
		{[]string{"state_machine", "startup_identity_records_per_process"}, float64(1)},
		{[]string{"state_machine", "startup_identity_records_per_complete_run"}, float64(2)},
		{[]string{"state_machine", "startup_identity_cross_phase_equality"}, "rfc8785-canonical-complete-record-identical"},
		{[]string{"state_machine", "report_startup_identity_projection"}, "locked-report-fields-from-both-canonical-equal-startup-records"},
		{[]string{"state_machine", "reconstruction_start_precondition"}, "initial-state-machine-complete-and-initial-process-cleanly-exited"},
		{[]string{"state_machine", "output_binding_reference"}, "single-validated-inbound-invocation-document-for-process"},
		{[]string{"state_machine", "output_binding_message_types"}, stringsToAny(outputBindingMessageTypes)},
		{[]string{"state_machine", "output_invocation_id_binding"}, "byte-identical-to-reference-invocation-id"},
		{[]string{"state_machine", "output_phase_binding"}, "exactly-equal-to-reference-invocation-phase"},
		{[]string{"state_machine", "scenario_case_phase_binding"}, "case-id-prefix-equals-reference-invocation-phase"},
		{[]string{"state_machine", "output_binding_mismatch_behavior"}, "invalid-or-out-of-order-message"},
		{[]string{"state_machine", "protocol_error_binding"}, "branch-selected-by-error-code"},
		{[]string{"state_machine", "definition_verifier_claims_runtime_output_binding"}, false},
		{[]string{"state_machine", "scenario_order_source"}, "locked-profile-phase-order"},
		{[]string{"state_machine", "normal_terminal_requires_exactly_one_result_per_phase_scenario"}, true},
		{[]string{"state_machine", "protocol_error_may_terminate_before_remaining_scenario_results"}, true},
		{[]string{"state_machine", "unreported_scenarios_after_protocol_error_are_not_adapter_not_executed_assertions"}, true},
		{[]string{"state_machine", "result_dispositions"}, []any{"completed", "not_executed"}},
		{[]string{"state_machine", "invocation_finished_completion"}, map[string]any{"completed": "every-phase-scenario-disposition-completed", "stopped": "at-least-one-phase-scenario-disposition-not-executed"}},
		{[]string{"state_machine", "terminal_message_types"}, []any{"invocation_finished", "protocol_error"}},
		{[]string{"state_machine", "exactly_one_terminal_message"}, true},
		{[]string{"state_machine", "output_after_terminal_forbidden"}, true},
		{[]string{"state_machine", "stdout_eof_after_terminal_required"}, true},
		{[]string{"state_machine", "clean_process_exit_after_terminal_required"}, true},
		{[]string{"state_machine", "definition_verifier_claims_runtime_state_machine_enforcement"}, false},
		{[]string{"protocol_error", "branch_selector"}, "error_code"},
		{[]string{"protocol_error", "invocation_id_and_phase_nullability"}, "both-null-or-both-non-null"},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "error_codes"}, []any{"invalid_invocation"}},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "reference_invocation_bound"}, false},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "requires_invocation_accepted"}, false},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "sequence"}, float64(1)},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "invocation_id"}, nil},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "phase"}, nil},
		{[]string{"protocol_error", "pre_binding_invalid_invocation", "prior_post_invocation_output_allowed"}, false},
		{[]string{"protocol_error", "post_binding_failure", "error_codes"}, stringsToAny(postBindingProtocolErrorCodes)},
		{[]string{"protocol_error", "post_binding_failure", "reference_invocation_bound"}, true},
		{[]string{"protocol_error", "post_binding_failure", "requires_invocation_accepted"}, true},
		{[]string{"protocol_error", "post_binding_failure", "sequence"}, "next-contiguous-adapter-output-sequence"},
		{[]string{"protocol_error", "post_binding_failure", "invocation_id"}, "byte-identical-to-reference-invocation-id"},
		{[]string{"protocol_error", "post_binding_failure", "phase"}, "exactly-equal-to-reference-invocation-phase"},
		{[]string{"protocol_error", "post_binding_failure", "prior_post_invocation_output_allowed"}, true},
		{[]string{"protocol_error", "complete_record_required"}, true},
		{[]string{"protocol_error", "output_failed_emission_precondition"}, "no-bytes-of-failed-normal-record-written-and-complete-protocol-error-record-remains-writable"},
		{[]string{"protocol_error", "partial_record_or_write_failure_observation"}, "invalid-or-truncated-output-observed-by-process-supervisor"},
		{[]string{"protocol_error", "terminal"}, true},
		{[]string{"protocol_error", "mutually_exclusive_with_invocation_finished"}, true},
		{[]string{"protocol_error", "output_after_terminal_forbidden"}, true},
		{[]string{"protocol_error", "adapter_assigns_report_status"}, false},
		{[]string{"protocol_error", "adapter_assigns_run_outcome"}, false},
		{[]string{"protocol_error", "definition_verifier_claims_runtime_protocol_error_handling"}, false},
		{[]string{"progress_semantics", "adapter_output_is_caller_owner_assertion"}, true},
		{[]string{"progress_semantics", "adapter_assigns_report_scenario_status"}, false},
		{[]string{"progress_semantics", "adapter_assigns_run_outcome"}, false},
		{[]string{"progress_semantics", "adapter_incomplete_status_allowed"}, false},
		{[]string{"progress_semantics", "missing_required_observation_without_observed_mismatch"}, "incomplete"},
		{[]string{"progress_semantics", "observed_mismatch"}, "failed"},
		{[]string{"process_control", "failure_conditions"}, stringsToAny(processFailureConditions)},
		{[]string{"process_control", "failure_sequence"}, []any{"close-supervisor-owned-io", "kill-process-group", "bounded-wait-and-reap"}},
		{[]string{"process_control", "kill_or_reap_failure_result"}, "incomplete"},
		{[]string{"sanitized_transcript", "projection_schema", "path"}, TranscriptSchemaPath},
		{[]string{"sanitized_transcript", "projection_schema", "digest"}, ExpectedTranscriptSchemaDigest},
		{[]string{"sanitized_transcript", "projection_schema", "digest_profile"}, "sha256-raw-file-bytes-v1"},
		{[]string{"sanitized_transcript", "projection_schema", "schema_id"}, TranscriptSchemaID},
		{[]string{"sanitized_transcript", "digest_subject"}, "complete-projection-document"},
		{[]string{"sanitized_transcript", "digest_profile"}, "rfc8785-full-document-v1"},
		{[]string{"sanitized_transcript", "digest_excluded_from_preimage"}, true},
		{[]string{"sanitized_transcript", "protocol_identity_matches_locked_authority"}, true},
		{[]string{"sanitized_transcript", "projection_presence"}, "only-after-both-phase-streams-reach-valid-terminal-eof-and-clean-exit"},
		{[]string{"sanitized_transcript", "phase_order"}, []any{"initial", "reconstruction"}},
		{[]string{"sanitized_transcript", "invocation_ids_bind_phase_entries"}, true},
		{[]string{"sanitized_transcript", "process_identities_bind_report_phase_processes_by_component"}, true},
		{[]string{"sanitized_transcript", "executable_digests_bind_report_phase_processes_by_component"}, true},
		{[]string{"sanitized_transcript", "configuration_digests_bind_report_phase_processes_by_component"}, true},
		{[]string{"sanitized_transcript", "supplied_field_names"}, stringsToAny(allowedHarnessFields)},
		{[]string{"sanitized_transcript", "credential_channel_roles_order"}, "invocation-descriptor-array-order"},
		{[]string{"sanitized_transcript", "credential_channel_roles_byte_identical_across_phases"}, true},
		{[]string{"sanitized_transcript", "message_types_order"}, "all-complete-decoded-adapter-output-records-in-wire-order-including-startup-and-terminal"},
		{[]string{"sanitized_transcript", "message_counts_derived_from_message_types"}, true},
		{[]string{"sanitized_transcript", "adapter_output_complete_records_equals_message_types_length"}, true},
		{[]string{"sanitized_transcript", "bounded_byte_count_sources"}, lockedTranscriptByteCountSources()},
		{[]string{"sanitized_transcript", "terminal_state_matches_final_message_and_supervisor_eof_exit_observations"}, true},
		{[]string{"sanitized_transcript", "definition_verifier_claims_runtime_transcript_recomputation"}, false},
		{[]string{"sanitized_transcript", "include"}, stringsToAny(sanitizedTranscriptFields)},
		{[]string{"sanitized_transcript", "exclude"}, stringsToAny(sanitizedTranscriptExcludedFields)},
	}
	for _, check := range checks {
		got, ok := nestedValue(value, check.path...)
		if !ok || !reflect.DeepEqual(got, check.want) {
			return fmt.Errorf("adapter protocol semantics field %s does not match the locked value", strings.Join(check.path, "."))
		}
	}
	return nil
}

func validateLockedExamples(schema *jsonschema.Schema) error {
	if schema == nil {
		return errors.New("adapter protocol schema is unavailable")
	}
	release := map[string]any{"kind": "source-revision", "value": strings.Repeat("a", 40), "immutable": true}
	requirement := map[string]any{
		"channel_id": "controller-a-provider",
		"role":       "provider_credentials",
		"actor":      "controller_a",
		"media_type": "application/vnd.example.credentials+json",
		"max_bytes":  float64(4096),
	}
	descriptor := cloneMap(requirement)
	descriptor["file_descriptor"] = float64(3)
	invocationLocations := invocationLocationFields{
		ProfilePath:          "/qualification/profile.json",
		ProviderOrigin:       "https://provider.invalid",
		GatewayProbeEndpoint: "wss://gateway.invalid/terminal",
		CallerStateRoot:      "/caller-state",
	}
	if err := validateInvocationLocationFields(invocationLocations); err != nil {
		return fmt.Errorf("locked adapter invocation locations are invalid: %w", err)
	}
	if err := validateReconstructionLocationBinding(invocationLocations, invocationLocations); err != nil {
		return fmt.Errorf("locked adapter invocation location binding is invalid: %w", err)
	}
	startup := map[string]any{
		"format_version": float64(1), "protocol_id": ProtocolID, "protocol_version": ProtocolVersion,
		"message_type": "startup_identity", "sequence": float64(0),
		"protocol_schema_digest": ExpectedProtocolSchemaDigest, "protocol_semantics_digest": ExpectedProtocolSemanticsDigest,
		"caller_release_identity": release, "adapter_release_identity": release,
		"contract_revision": "22ba6987ea5fbc37d53942720133c0acad199edd", "contract_tree": "c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38",
		"profile_id": qualificationprofile.ProfileID, "profile_version": qualificationprofile.ProfileVersion,
		"profile_digest": qualificationprofile.ExpectedProfileDigest, "expected_values_injected_by_harness": false,
		"credential_channel_requirements": []any{requirement},
	}
	invocation := map[string]any{
		"format_version": float64(1), "protocol_id": ProtocolID, "protocol_version": ProtocolVersion,
		"message_type": "invocation", "invocation_id": "invocation-initial", "phase": "initial",
		"profile_path": invocationLocations.ProfilePath, "provider_origin": invocationLocations.ProviderOrigin,
		"gateway_probe_endpoint": invocationLocations.GatewayProbeEndpoint, "credential_channel_descriptors": []any{descriptor},
		"caller_state_root": invocationLocations.CallerStateRoot,
	}
	boundOutputs := []map[string]any{
		outputExample("invocation_accepted", 1, nil),
		outputExample("scenario_started", 2, map[string]any{"case_id": "initial.locked-capability-discovery"}),
		outputExample("scenario_result", 3, map[string]any{
			"case_id": "initial.locked-capability-discovery", "disposition": "not_executed",
			"interactions": []any{}, "assertions": []any{}, "observation_ids": []any{}, "reason_code": "prerequisite_not_satisfied",
		}),
		outputExample("invocation_finished", 4, map[string]any{"completion": "stopped"}),
	}
	preBindingProtocolError := protocolErrorExample(1, nil, nil, "invalid_invocation")
	postBindingProtocolError := protocolErrorExample(2, "invocation-initial", "initial", "caller_start_failed")
	examples := append([]map[string]any{startup, invocation}, boundOutputs...)
	examples = append(examples, preBindingProtocolError, postBindingProtocolError)
	for _, example := range examples {
		if err := schema.Validate(example); err != nil {
			return fmt.Errorf("locked adapter protocol example %q does not match schema: %w", example["message_type"], err)
		}
	}
	if err := validateOutputBindings(invocation, boundOutputs); err != nil {
		return fmt.Errorf("locked adapter output binding examples are invalid: %w", err)
	}
	if err := validateProtocolErrorBranch(nil, nil, preBindingProtocolError); err != nil {
		return fmt.Errorf("locked pre-binding protocol-error example is invalid: %w", err)
	}
	if err := validateProtocolErrorBranch(invocation, boundOutputs[:1], postBindingProtocolError); err != nil {
		return fmt.Errorf("locked post-binding protocol-error example is invalid: %w", err)
	}
	if err := validateLockedDeadlineExamples(); err != nil {
		return fmt.Errorf("locked adapter deadline examples are invalid: %w", err)
	}
	return nil
}

func validateLockedTranscriptExample(schema *jsonschema.Schema) error {
	if schema == nil {
		return errors.New("adapter transcript schema is unavailable")
	}
	if err := schema.Validate(lockedTranscriptExample()); err != nil {
		return fmt.Errorf("locked adapter transcript example does not match schema: %w", err)
	}
	return nil
}

func lockedTranscriptExample() map[string]any {
	digest := "sha256:" + strings.Repeat("a", 64)
	phase := func(phaseID, invocationID string) map[string]any {
		processIDs := map[string]any{}
		digests := map[string]any{}
		for _, component := range []string{"provider", "external_caller", "qualification_adapter", "caller_gateway"} {
			processIDs[component] = component + "-" + phaseID
			digests[component] = digest
		}
		return map[string]any{
			"phase_id":              phaseID,
			"invocation_id":         invocationID,
			"process_identities":    processIDs,
			"executable_digests":    cloneMap(digests),
			"configuration_digests": cloneMap(digests),
			"supplied_field_names":  stringsToAny(allowedHarnessFields),
			"credential_channel_roles": []any{
				"provider_credentials",
			},
			"message_types": []any{
				"startup_identity",
				"invocation_accepted",
				"scenario_result",
				"invocation_finished",
			},
			"message_counts": map[string]any{
				"startup_identity":    float64(1),
				"invocation_accepted": float64(1),
				"scenario_started":    float64(0),
				"scenario_result":     float64(1),
				"invocation_finished": float64(1),
				"protocol_error":      float64(0),
			},
			"bounded_byte_counts": map[string]any{
				"invocation_wire_bytes":           float64(512),
				"adapter_stdout_wire_bytes":       float64(1024),
				"adapter_stderr_wire_bytes":       float64(0),
				"adapter_output_complete_records": float64(4),
				"credential_channel_count":        float64(1),
				"credential_payload_total_bytes":  float64(4096),
			},
			"terminal_state": map[string]any{
				"terminal_message_type":       "invocation_finished",
				"completion":                  "stopped",
				"error_code":                  nil,
				"stdout_eof_observed":         true,
				"clean_process_exit_observed": true,
			},
		}
	}
	return map[string]any{
		"format_version":            float64(1),
		"transcript_type":           "sandbox-runtime-external-caller-adapter-transcript",
		"transcript_version":        ProtocolVersion,
		"protocol_id":               ProtocolID,
		"protocol_version":          ProtocolVersion,
		"protocol_schema_digest":    ExpectedProtocolSchemaDigest,
		"protocol_semantics_digest": ExpectedProtocolSemanticsDigest,
		"phase_order":               []any{"initial", "reconstruction"},
		"invocation_ids":            []any{"invocation-initial", "invocation-reconstruction"},
		"phases": []any{
			phase("initial", "invocation-initial"),
			phase("reconstruction", "invocation-reconstruction"),
		},
	}
}

type deadlineBudget struct {
	Execution time.Duration
	Case      time.Duration
	Reap      time.Duration
}

// deriveDeadlineBudget models the exact budget clipping that the process
// supervisor independently applies at a case boundary. executionElapsed is measured from
// the single run execution anchor, so reconstruction cannot reset the budget.
func deriveDeadlineBudget(executionElapsed time.Duration, parentRemaining *time.Duration) (deadlineBudget, error) {
	if executionElapsed < 0 {
		return deadlineBudget{}, errors.New("execution elapsed time must not be negative")
	}
	if parentRemaining != nil && *parentRemaining < 0 {
		return deadlineBudget{}, errors.New("parent deadline remaining time must not be negative")
	}

	executionRemaining := maxRunExecutionDuration - executionElapsed
	if executionRemaining < 0 {
		executionRemaining = 0
	}
	if parentRemaining != nil && *parentRemaining < executionRemaining {
		executionRemaining = *parentRemaining
	}
	caseRemaining := min(maxCaseDuration, executionRemaining)

	return deadlineBudget{
		Execution: executionRemaining,
		Case:      caseRemaining,
		Reap:      maxProcessReapDuration,
	}, nil
}

func validateLockedDeadlineExamples() error {
	parentThirtySeconds := 30 * time.Second
	examples := []struct {
		name             string
		executionElapsed time.Duration
		parentRemaining  *time.Duration
		want             deadlineBudget
	}{
		{name: "initial", want: deadlineBudget{Execution: 1800 * time.Second, Case: 120 * time.Second, Reap: 5 * time.Second}},
		{name: "remaining-execution-clips-case", executionElapsed: 1750 * time.Second, want: deadlineBudget{Execution: 50 * time.Second, Case: 50 * time.Second, Reap: 5 * time.Second}},
		{name: "parent-clips-execution-and-case", parentRemaining: &parentThirtySeconds, want: deadlineBudget{Execution: 30 * time.Second, Case: 30 * time.Second, Reap: 5 * time.Second}},
		{name: "expired-execution", executionElapsed: 1800 * time.Second, want: deadlineBudget{Reap: 5 * time.Second}},
	}
	for _, example := range examples {
		got, err := deriveDeadlineBudget(example.executionElapsed, example.parentRemaining)
		if err != nil {
			return fmt.Errorf("%s: %w", example.name, err)
		}
		if got != example.want {
			return fmt.Errorf("%s: got %+v, want %+v", example.name, got, example.want)
		}
	}
	return nil
}

func validateOutputBindings(invocation map[string]any, outputs []map[string]any) error {
	invocationID, ok := invocation["invocation_id"].(string)
	if !ok || invocationID == "" {
		return errors.New("reference invocation_id is unavailable")
	}
	phase, ok := invocation["phase"].(string)
	if !ok || (phase != "initial" && phase != "reconstruction") {
		return errors.New("reference invocation phase is unavailable")
	}
	for index, output := range outputs {
		messageType, ok := output["message_type"].(string)
		if !ok || !containsString(outputBindingMessageTypes, messageType) {
			return fmt.Errorf("output %d is outside the locked output binding message types", index)
		}
		outputInvocationID, ok := output["invocation_id"].(string)
		if !ok || outputInvocationID != invocationID {
			return fmt.Errorf("output %d %s invocation_id is not byte-identical to the reference invocation", index, messageType)
		}
		outputPhase, ok := output["phase"].(string)
		if !ok || outputPhase != phase {
			return fmt.Errorf("output %d %s phase does not equal the reference invocation phase", index, messageType)
		}
		if messageType == "scenario_started" || messageType == "scenario_result" {
			caseID, ok := output["case_id"].(string)
			if !ok || !strings.HasPrefix(caseID, phase+".") {
				return fmt.Errorf("output %d %s case_id is not bound to the reference invocation phase", index, messageType)
			}
		}
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateProtocolErrorBranch(invocation map[string]any, priorOutputs []map[string]any, protocolError map[string]any) error {
	if protocolError["message_type"] != "protocol_error" || protocolError["terminal"] != true {
		return errors.New("protocol_error must be terminal")
	}
	errorCode, ok := protocolError["error_code"].(string)
	if !ok {
		return errors.New("protocol_error error_code is unavailable")
	}
	sequence, ok := protocolError["sequence"].(float64)
	if !ok {
		return errors.New("protocol_error sequence is unavailable")
	}
	if errorCode == "invalid_invocation" {
		if invocation != nil || len(priorOutputs) != 0 {
			return errors.New("invalid_invocation protocol_error must occur before invocation binding")
		}
		if sequence != 1 {
			return errors.New("invalid_invocation protocol_error sequence must be 1")
		}
		if protocolError["invocation_id"] != nil || protocolError["phase"] != nil {
			return errors.New("invalid_invocation protocol_error invocation_id and phase must both be null")
		}
		return nil
	}
	if !containsString(postBindingProtocolErrorCodes, errorCode) {
		return errors.New("protocol_error error_code is outside the locked branches")
	}
	if invocation == nil {
		return errors.New("post-binding protocol_error requires a reference invocation")
	}
	if len(priorOutputs) == 0 || priorOutputs[0]["message_type"] != "invocation_accepted" {
		return errors.New("post-binding protocol_error requires invocation_accepted first")
	}
	if err := validateOutputBindings(invocation, priorOutputs); err != nil {
		return fmt.Errorf("validate output before protocol_error: %w", err)
	}
	for index, output := range priorOutputs {
		if output["message_type"] == "invocation_finished" {
			return errors.New("protocol_error and invocation_finished are mutually exclusive")
		}
		if output["sequence"] != float64(index+1) {
			return errors.New("output before protocol_error does not use contiguous sequence values")
		}
	}
	if sequence != float64(len(priorOutputs)+1) {
		return errors.New("post-binding protocol_error does not use the next contiguous sequence value")
	}
	invocationID, _ := invocation["invocation_id"].(string)
	phase, _ := invocation["phase"].(string)
	if protocolError["invocation_id"] != invocationID || protocolError["phase"] != phase {
		return errors.New("post-binding protocol_error does not bind the reference invocation_id and phase")
	}
	return nil
}

func outputExample(messageType string, sequence int, extra map[string]any) map[string]any {
	value := map[string]any{
		"format_version": float64(1), "protocol_id": ProtocolID, "protocol_version": ProtocolVersion,
		"message_type": messageType, "sequence": float64(sequence), "invocation_id": "invocation-initial", "phase": "initial",
	}
	for key, item := range extra {
		value[key] = item
	}
	return value
}

func protocolErrorExample(sequence int, invocationID, phase any, errorCode string) map[string]any {
	return map[string]any{
		"format_version": float64(1), "protocol_id": ProtocolID, "protocol_version": ProtocolVersion,
		"message_type": "protocol_error", "sequence": float64(sequence), "invocation_id": invocationID, "phase": phase,
		"error_code": errorCode, "terminal": true,
	}
}

func cloneMap(value map[string]any) map[string]any {
	cloned := make(map[string]any, len(value)+1)
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func nestedValue(root map[string]any, path ...string) (any, bool) {
	var current any = root
	for _, part := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func readRepositoryFile(root, relative string, maximum int64) ([]byte, error) {
	if strings.TrimSpace(root) == "" || filepath.IsAbs(relative) || maximum < 1 {
		return nil, errors.New("invalid repository file")
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, errors.New("invalid repository file")
	}
	path := filepath.Join(root, clean)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("repository file must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() != before.Size() {
		return nil, errors.New("repository file changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum || int64(len(content)) != after.Size() {
		return nil, errors.New("read bounded repository file")
	}
	return content, nil
}

func decodeStrictObject(content []byte) (map[string]any, error) {
	value, err := decodeStrictValue(content)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return nil, errors.New("expected JSON object")
	}
	return object, nil
}

func decodeStrictValue(content []byte) (any, error) {
	if len(content) == 0 || !utf8.Valid(content) {
		return nil, errors.New("invalid JSON document encoding")
	}
	if err := validateUnicodeEscapes(content); err != nil {
		return nil, err
	}
	if err := validateUniqueJSONFields(content); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON document has trailing content")
	}
	return value, nil
}

func validateUnicodeEscapes(content []byte) error {
	inString := false
	for index := 0; index < len(content); index++ {
		switch content[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(content) {
				continue
			}
			if content[index+1] != 'u' {
				index++
				continue
			}
			codePoint, ok := decodeHexQuad(content, index+2)
			if !ok {
				continue
			}
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+11 >= len(content) || content[index+6] != '\\' || content[index+7] != 'u' {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				low, ok := decodeHexQuad(content, index+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("JSON contains an invalid Unicode surrogate escape")
				}
				index += 11
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return errors.New("JSON contains an invalid Unicode surrogate escape")
			default:
				index += 5
			}
		}
	}
	return nil
}

func decodeHexQuad(content []byte, start int) (uint16, bool) {
	if start+4 > len(content) {
		return 0, false
	}
	var value uint16
	for _, digit := range content[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func validateUniqueJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return errors.New("JSON document has trailing content")
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object member name is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate JSON object member %q", name)
			}
			seen[name] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

func rawDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
