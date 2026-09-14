package qualificationreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
)

type validatorSemantics struct {
	FormatVersion              int                      `json:"format_version"`
	SemanticsID                string                   `json:"semantics_id"`
	SemanticsVersion           string                   `json:"semantics_version"`
	ReportSchema               authorityIdentity        `json:"report_schema"`
	AdapterProtocol            adapterProtocolAuthority `json:"adapter_protocol"`
	TranscriptProjectionSchema authorityIdentity        `json:"transcript_projection_schema"`
	TranscriptProjectionRules  map[string]any           `json:"transcript_projection"`
	Payloads                   []payloadSemantics       `json:"payloads"`
	TrustedInputs              []trustedInputSemantic   `json:"trusted_inputs"`
	ForbiddenMaterialMarkers   []string                 `json:"forbidden_material_markers"`
	Rules                      semanticsRules           `json:"rules"`
}

type authorityIdentity struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type adapterProtocolAuthority struct {
	ProtocolID      string            `json:"protocol_id"`
	ProtocolVersion string            `json:"protocol_version"`
	Schema          authorityIdentity `json:"schema"`
	Semantics       authorityIdentity `json:"semantics"`
}

type payloadSemantics struct {
	PayloadID          string  `json:"payload_id"`
	Path               string  `json:"path"`
	SchemaRef          string  `json:"schema_ref"`
	ObservationSource  *string `json:"observation_source"`
	InteractionSurface *string `json:"interaction_surface"`
}

type trustedInputSemantic struct {
	ID     string `json:"input_id"`
	Source string `json:"source"`
}

type semanticsRules struct {
	CompleteIdentityRequiresAllPayloads          bool `json:"complete_identity_requires_all_payloads"`
	PassedOrFailedRequiresCompleteIdentity       bool `json:"passed_or_failed_requires_complete_identity"`
	PresentPayloadsMustValidate                  bool `json:"present_payloads_must_validate"`
	ObservationsBindSourcePayloadRawDigest       bool `json:"observations_bind_source_payload_raw_digest"`
	TrustedInputsBindPayloadRawDigest            bool `json:"trusted_inputs_bind_payload_raw_digest"`
	PayloadInventoryAllowsOnlyNamedPayloads      bool `json:"payload_inventory_allows_only_named_payloads"`
	PayloadFilesMustBeSinglyLinked               bool `json:"payload_files_must_be_singly_linked"`
	RuntimeCommitmentBindsReportPayloadsReceipt  bool `json:"runtime_commitment_binds_report_payloads_and_receipt"`
	MutationFlagsFollowProfileCounters           bool `json:"mutation_flags_follow_profile_counters"`
	CleanupRequiredConservative                  bool `json:"cleanup_required_is_conservative_and_implied_by_mutation_observation"`
	ResourceCountsFailClosedOnUnexpected         bool `json:"resource_counts_include_profile_admissions_and_unexpected_resource_mutation_outcomes"`
	CleanupInventoriesBindQueryScopeDigest       bool `json:"cleanup_inventories_bind_query_scope_digest"`
	CleanupQueryScopeBindsSubjectIdentities      bool `json:"cleanup_query_scope_digest_binds_target_namespace_selector_and_inspector"`
	CleanupQueryScopeBindingsAllEmptyOrComplete  bool `json:"cleanup_query_scope_bindings_are_all_empty_or_complete"`
	CleanupTimestampsCoverStabilitySamples       bool `json:"successful_cleanup_timestamps_cover_stability_samples"`
	TransientOutcomesMatchWireAttemptBound       bool `json:"transient_outcomes_match_profile_wire_attempt_bound"`
	ConfigurationsBoundByProcessSupervisor       bool `json:"configuration_identities_are_bound_by_process_supervisor"`
	StartupIdentityBindsAdapterProtocolAuthority bool `json:"startup_identity_binds_adapter_protocol_authority"`
	TranscriptProjectionBindsReport              bool `json:"transcript_projection_is_schema_valid_recomputed_and_bound_to_report"`
	SandboxResourceProjectionBoundByProvider     bool `json:"sandbox_resource_projection_is_bound_by_provider_observer"`
	SandboxResourceProjectionPresentIFFCreate    bool `json:"sandbox_resource_projection_is_present_iff_create_sandbox_is_observed"`
	SandboxResourceProjectionMatchesProfile      bool `json:"sandbox_resource_projection_matches_locked_profile"`
	AbsentPayloadsSuppressOwnedEvidence          bool `json:"absent_payloads_cannot_leave_owned_positive_evidence"`
	AbsentProcessPayloadRequiresNotExecuted      bool `json:"absent_process_supervisor_requires_not_executed_scenarios"`
	AbsentProcessPayloadSuppressesTimings        bool `json:"absent_process_supervisor_suppresses_execution_timings"`
	AbsentProcessPayloadSuppressesShellChallenge bool `json:"absent_process_supervisor_suppresses_shell_continuity_challenge"`
	PresentProcessPayloadRequiresTimings         bool `json:"present_process_supervisor_requires_complete_execution_timings"`
	PassedScenariosRequireAllObservations        bool `json:"passed_scenarios_require_all_required_observations"`
	IncompleteScenariosRequireMissingEvidence    bool `json:"incomplete_scenarios_require_missing_evidence_without_observed_mismatch"`
	AbsentInspectorAllowsUnknownCleanup          bool `json:"absent_resource_inspector_allows_unknown_required_cleanup_without_positive_evidence"`
	ReconstructionProcessIDsMustChange           bool `json:"reconstruction_process_ids_must_change"`
	ScenarioTimestampsFollowProfileOrder         bool `json:"scenario_timestamps_follow_profile_order"`
	SanitizationScansRawAndDecodedJSON           bool `json:"sanitization_scans_raw_and_decoded_json_for_locked_markers"`
	ReceiptStagedBeforeChecksCommittedAfter      bool `json:"receipt_is_staged_before_final_checks_and_committed_after_final_checks"`
	ReceiptBindsSchemaAndSemantics               bool `json:"receipt_binds_schema_and_semantics"`
	ReceiptBindsAdapterProtocolAuthority         bool `json:"receipt_binds_adapter_protocol_authority"`
}

type observerFact struct {
	ID          string `json:"observation_id"`
	Actor       string `json:"actor"`
	Subject     string `json:"subject"`
	Correlation string `json:"correlation"`
	Result      string `json:"result"`
}

type providerObserverPayload struct {
	FormatVersion               int                 `json:"format_version"`
	PayloadType                 string              `json:"payload_type"`
	PayloadVersion              string              `json:"payload_version"`
	InvocationID                string              `json:"invocation_id"`
	RuntimeCommitmentDigest     string              `json:"runtime_commitment_digest"`
	ObserverArtifactDigest      *string             `json:"observer_artifact_digest"`
	ObserverConfigurationDigest *string             `json:"observer_configuration_digest"`
	SandboxResources            *sandboxResources   `json:"sandbox_resources"`
	Interactions                []interactionResult `json:"interactions"`
	Observations                []observerFact      `json:"observations"`
}

type gatewayObserverPayload struct {
	FormatVersion               int                 `json:"format_version"`
	PayloadType                 string              `json:"payload_type"`
	PayloadVersion              string              `json:"payload_version"`
	InvocationID                string              `json:"invocation_id"`
	RuntimeCommitmentDigest     string              `json:"runtime_commitment_digest"`
	ObserverArtifactDigest      *string             `json:"observer_artifact_digest"`
	ObserverConfigurationDigest *string             `json:"observer_configuration_digest"`
	Interactions                []interactionResult `json:"interactions"`
	Observations                []observerFact      `json:"observations"`
	ShellChallenge              *shellChallenge     `json:"shell_continuity_challenge"`
}

type processSupervisorPayload struct {
	FormatVersion                 int                `json:"format_version"`
	PayloadType                   string             `json:"payload_type"`
	PayloadVersion                string             `json:"payload_version"`
	InvocationID                  string             `json:"invocation_id"`
	RuntimeCommitmentDigest       string             `json:"runtime_commitment_digest"`
	SupervisorArtifactDigest      *string            `json:"supervisor_artifact_digest"`
	SupervisorConfigurationDigest *string            `json:"supervisor_configuration_digest"`
	InitialInvocationID           *string            `json:"initial_invocation_id"`
	ReconstructionInvocationID    *string            `json:"reconstruction_invocation_id"`
	StartupIdentity               *startupIdentity   `json:"startup_identity"`
	ArtifactIdentities            []artifactIdentity `json:"artifact_identities"`
	ConfigurationIdentities       []configuration    `json:"configuration_identities"`
	InitialProcesses              []processIdentity  `json:"initial_processes"`
	ReconstructionProcesses       []processIdentity  `json:"reconstruction_processes"`
	AdapterTranscript             *adapterTranscript `json:"adapter_transcript"`
	AdapterTranscriptProjection   map[string]any     `json:"adapter_transcript_projection"`
	RunTimestamps                 timestamps         `json:"run_timestamps"`
	Phases                        []phase            `json:"phases"`
	ScenarioTimings               []scenarioTiming   `json:"scenario_timings"`
	Observations                  []observerFact     `json:"observations"`
}

type resourceInspectorPayload struct {
	FormatVersion                int                `json:"format_version"`
	PayloadType                  string             `json:"payload_type"`
	PayloadVersion               string             `json:"payload_version"`
	InvocationID                 string             `json:"invocation_id"`
	RuntimeCommitmentDigest      string             `json:"runtime_commitment_digest"`
	InspectorArtifactDigest      *string            `json:"inspector_artifact_digest"`
	InspectorConfigurationDigest *string            `json:"inspector_configuration_digest"`
	TargetIdentity               any                `json:"target_identity"`
	ArtifactIdentities           []artifactIdentity `json:"artifact_identities"`
	Cleanup                      cleanup            `json:"cleanup"`
	CleanupTimestamps            cleanupTimestamps  `json:"cleanup_timestamps"`
	Observations                 []observerFact     `json:"observations"`
}

type trustedInputStatement struct {
	ID            string `json:"input_id"`
	Source        string `json:"source"`
	SubjectDigest string `json:"subject_digest"`
}

type trustedInputsPayload struct {
	FormatVersion           int                     `json:"format_version"`
	PayloadType             string                  `json:"payload_type"`
	PayloadVersion          string                  `json:"payload_version"`
	InvocationID            string                  `json:"invocation_id"`
	RuntimeCommitmentDigest string                  `json:"runtime_commitment_digest"`
	TrustedInputs           []trustedInputStatement `json:"trusted_inputs"`
	CallerAssertions        []claimAssertion        `json:"caller_assertions"`
}

type payloadSet struct {
	Provider          *providerObserverPayload
	Gateway           *gatewayObserverPayload
	ProcessSupervisor *processSupervisorPayload
	ResourceInspector *resourceInspectorPayload
	TrustedInputs     *trustedInputsPayload
	RawByPath         map[string][]byte
	DigestByPath      map[string]string
}

func loadValidatorSemantics(sourceRoot string, schemaDigest string) (validatorSemantics, error) {
	document, err := readSourceFile(sourceRoot, ValidatorSemanticsPath, maxReportBytes)
	if err != nil {
		return validatorSemantics{}, fmt.Errorf("read qualification validator semantics: %w", err)
	}
	if got := evidencefiles.RawDigest(document); got != ExpectedValidatorSemanticsDigest {
		return validatorSemantics{}, fmt.Errorf("qualification validator semantics digest %s does not match trust anchor", got)
	}
	var semantics validatorSemantics
	if err := decodeStrictJSON(document, &semantics); err != nil {
		return validatorSemantics{}, fmt.Errorf("decode qualification validator semantics: %w", err)
	}
	if err := validateLockedSemantics(semantics, schemaDigest); err != nil {
		return validatorSemantics{}, err
	}
	return semantics, nil
}

func validateLockedSemantics(actual validatorSemantics, schemaDigest string) error {
	wantPayloads := []payloadSemantics{
		payloadRule("provider_observer", "provider-observer.json", "#/$defs/providerObserverPayload", "provider_observer", "provider_http"),
		payloadRule("gateway_observer", "gateway-observer.json", "#/$defs/gatewayObserverPayload", "gateway_observer", "caller_gateway"),
		payloadRule("process_supervisor", "process-supervisor.json", "#/$defs/processSupervisorPayload", "process_supervisor", ""),
		payloadRule("resource_inspector", "resource-inspector.json", "#/$defs/resourceInspectorPayload", "resource_inspector", ""),
		payloadRule("trusted_inputs", "trusted-inputs.json", "#/$defs/trustedInputsPayload", "", ""),
	}
	wantTrustedInputs := []trustedInputSemantic{
		{ID: "external-caller-ownership", Source: "external_caller_owner"},
		{ID: "source-hosting", Source: "external_caller_owner"},
		{ID: "build-system", Source: "external_caller_owner"},
		{ID: "operating-system", Source: "qualification_operator"},
		{ID: "network-path", Source: "qualification_operator"},
	}
	allRules := actual.Rules.CompleteIdentityRequiresAllPayloads &&
		actual.Rules.PassedOrFailedRequiresCompleteIdentity &&
		actual.Rules.PresentPayloadsMustValidate &&
		actual.Rules.ObservationsBindSourcePayloadRawDigest &&
		actual.Rules.TrustedInputsBindPayloadRawDigest &&
		actual.Rules.PayloadInventoryAllowsOnlyNamedPayloads &&
		actual.Rules.PayloadFilesMustBeSinglyLinked &&
		actual.Rules.RuntimeCommitmentBindsReportPayloadsReceipt &&
		actual.Rules.MutationFlagsFollowProfileCounters &&
		actual.Rules.CleanupRequiredConservative &&
		actual.Rules.ResourceCountsFailClosedOnUnexpected &&
		actual.Rules.CleanupInventoriesBindQueryScopeDigest &&
		actual.Rules.CleanupQueryScopeBindsSubjectIdentities &&
		actual.Rules.CleanupQueryScopeBindingsAllEmptyOrComplete &&
		actual.Rules.CleanupTimestampsCoverStabilitySamples &&
		actual.Rules.TransientOutcomesMatchWireAttemptBound &&
		actual.Rules.ConfigurationsBoundByProcessSupervisor &&
		actual.Rules.StartupIdentityBindsAdapterProtocolAuthority &&
		actual.Rules.TranscriptProjectionBindsReport &&
		actual.Rules.SandboxResourceProjectionBoundByProvider &&
		actual.Rules.SandboxResourceProjectionPresentIFFCreate &&
		actual.Rules.SandboxResourceProjectionMatchesProfile &&
		actual.Rules.AbsentPayloadsSuppressOwnedEvidence &&
		actual.Rules.AbsentProcessPayloadRequiresNotExecuted &&
		actual.Rules.AbsentProcessPayloadSuppressesTimings &&
		actual.Rules.AbsentProcessPayloadSuppressesShellChallenge &&
		actual.Rules.PresentProcessPayloadRequiresTimings &&
		actual.Rules.PassedScenariosRequireAllObservations &&
		actual.Rules.IncompleteScenariosRequireMissingEvidence &&
		actual.Rules.AbsentInspectorAllowsUnknownCleanup &&
		actual.Rules.ReconstructionProcessIDsMustChange &&
		actual.Rules.ScenarioTimestampsFollowProfileOrder &&
		actual.Rules.SanitizationScansRawAndDecodedJSON &&
		actual.Rules.ReceiptStagedBeforeChecksCommittedAfter &&
		actual.Rules.ReceiptBindsSchemaAndSemantics &&
		actual.Rules.ReceiptBindsAdapterProtocolAuthority
	wantAdapterProtocol := lockedAdapterProtocolAuthority()
	if actual.TranscriptProjectionSchema != (authorityIdentity{Path: TranscriptSchemaPath, Digest: ExpectedTranscriptSchemaDigest}) {
		return errors.New("qualification transcript schema authority mismatch")
	}
	if !reflect.DeepEqual(actual.TranscriptProjectionRules, lockedTranscriptProjectionRules()) {
		return errors.New("qualification transcript projection rules mismatch")
	}
	if actual.FormatVersion != 1 || actual.SemanticsID != "sandbox-runtime-external-caller-coding-shell-report-validator-v1" || actual.SemanticsVersion != "1.0.0" || actual.ReportSchema != (authorityIdentity{Path: ReportSchemaPath, Digest: schemaDigest}) || actual.AdapterProtocol != wantAdapterProtocol || !reflect.DeepEqual(actual.Payloads, wantPayloads) || !reflect.DeepEqual(actual.TrustedInputs, wantTrustedInputs) || !reflect.DeepEqual(actual.ForbiddenMaterialMarkers, forbiddenMaterialMarkers()) || !allRules {
		return errors.New("qualification validator semantics do not match the locked v1 rules")
	}
	return nil
}

func lockedAdapterProtocolAuthority() adapterProtocolAuthority {
	return adapterProtocolAuthority{
		ProtocolID:      AdapterProtocolID,
		ProtocolVersion: AdapterProtocolVersion,
		Schema:          authorityIdentity{Path: AdapterProtocolSchemaPath, Digest: ExpectedAdapterProtocolSchemaDigest},
		Semantics:       authorityIdentity{Path: AdapterProtocolSemanticsPath, Digest: ExpectedAdapterProtocolSemanticsDigest},
	}
}

func payloadRule(id, path, schemaRef, source, surface string) payloadSemantics {
	result := payloadSemantics{PayloadID: id, Path: path, SchemaRef: schemaRef}
	if source != "" {
		result.ObservationSource = &source
	}
	if surface != "" {
		result.InteractionSurface = &surface
	}
	return result
}

func loadPayloads(root *evidencefiles.Root, inventory evidencefiles.Inventory, schema []byte, semantics validatorSemantics) (payloadSet, error) {
	result := payloadSet{RawByPath: make(map[string][]byte), DigestByPath: make(map[string]string)}
	byPath := make(map[string]payloadSemantics, len(semantics.Payloads))
	for _, spec := range semantics.Payloads {
		byPath[spec.Path] = spec
	}
	for _, entry := range inventory.Entries {
		spec, ok := byPath[entry.Path]
		if !ok {
			return payloadSet{}, fmt.Errorf("qualification evidence payload %q is not allowed by validator semantics", entry.Path)
		}
		document, err := root.ReadFile(entry.Path, evidencefiles.DefaultMaxFileBytes)
		if err != nil {
			return payloadSet{}, fmt.Errorf("read qualification payload %q: %w", entry.Path, err)
		}
		if got := evidencefiles.RawDigest(document); got != entry.SHA256 || int64(len(document)) != entry.Bytes {
			return payloadSet{}, fmt.Errorf("qualification payload %q changed after inventory", entry.Path)
		}
		var value any
		if err := decodeStrictJSON(document, &value); err != nil {
			return payloadSet{}, fmt.Errorf("decode qualification payload %q: %w", entry.Path, err)
		}
		if err := validateSchemaReference(schema, spec.SchemaRef, value); err != nil {
			return payloadSet{}, fmt.Errorf("validate qualification payload %q: %w", entry.Path, err)
		}
		result.RawByPath[entry.Path] = document
		result.DigestByPath[entry.Path] = entry.SHA256
		switch spec.PayloadID {
		case "provider_observer":
			var payload providerObserverPayload
			if err := json.Unmarshal(document, &payload); err != nil {
				return payloadSet{}, err
			}
			result.Provider = &payload
		case "gateway_observer":
			var payload gatewayObserverPayload
			if err := json.Unmarshal(document, &payload); err != nil {
				return payloadSet{}, err
			}
			result.Gateway = &payload
		case "process_supervisor":
			var payload processSupervisorPayload
			if err := json.Unmarshal(document, &payload); err != nil {
				return payloadSet{}, err
			}
			result.ProcessSupervisor = &payload
		case "resource_inspector":
			var payload resourceInspectorPayload
			if err := json.Unmarshal(document, &payload); err != nil {
				return payloadSet{}, err
			}
			result.ResourceInspector = &payload
		case "trusted_inputs":
			var payload trustedInputsPayload
			if err := json.Unmarshal(document, &payload); err != nil {
				return payloadSet{}, err
			}
			result.TrustedInputs = &payload
		default:
			return payloadSet{}, fmt.Errorf("qualification validator semantics contain unknown payload %q", spec.PayloadID)
		}
	}
	return result, nil
}

func (p payloadSet) complete() bool {
	return p.Provider != nil && p.Gateway != nil && p.ProcessSupervisor != nil && p.ResourceInspector != nil && p.TrustedInputs != nil
}

func validatePayloadBindings(report reportDocument, semantics validatorSemantics, payloads payloadSet) error {
	artifactByID := artifactMap(report.Artifacts)
	configurationByID := configurationMap(report.Configurations)
	providerInteractions, gatewayInteractions := splitInteractions(report.ScenarioResults)
	if err := validateAbsentPayloadClaims(report, payloads, providerInteractions, gatewayInteractions); err != nil {
		return err
	}
	if err := validateProcessTimingEvidence(report, payloads.ProcessSupervisor); err != nil {
		return err
	}
	if err := validateResourceInspectorTimingEvidence(report, payloads.ResourceInspector); err != nil {
		return err
	}
	if payloads.Provider != nil {
		payload := payloads.Provider
		if payload.InvocationID != report.Invocation.InvocationID || payload.RuntimeCommitmentDigest != report.Invocation.RuntimeCommitmentDigest || !equalStringPtr(payload.ObserverArtifactDigest, artifactByID["provider_observer"].Digest) || !equalStringPtr(payload.ObserverConfigurationDigest, configurationByID["observer_configuration"].Digest) || !reflect.DeepEqual(payload.SandboxResources, report.SandboxResources) || !reflect.DeepEqual(payload.Interactions, providerInteractions) {
			return errors.New("provider-observer payload does not bind the reported invocation, identity, and interactions")
		}
	}
	if payloads.Gateway != nil {
		payload := payloads.Gateway
		if payload.InvocationID != report.Invocation.InvocationID || payload.RuntimeCommitmentDigest != report.Invocation.RuntimeCommitmentDigest || !equalStringPtr(payload.ObserverArtifactDigest, artifactByID["gateway_observer"].Digest) || !equalStringPtr(payload.ObserverConfigurationDigest, configurationByID["observer_configuration"].Digest) || !reflect.DeepEqual(payload.Interactions, gatewayInteractions) || !reflect.DeepEqual(payload.ShellChallenge, report.Invocation.ShellChallenge) {
			return errors.New("gateway-observer payload does not bind the reported invocation, identity, interactions, and shell challenge")
		}
	}
	if payloads.ProcessSupervisor != nil {
		payload := payloads.ProcessSupervisor
		if err := validateTranscriptBinding(report, payload); err != nil {
			return err
		}
		if !processSupervisorBindsReport(payload, report, artifactByID, configurationByID) {
			return errors.New("process-supervisor payload does not bind the reported startup, artifact, configuration, process, and transcript identities")
		}
	}
	if payloads.ResourceInspector != nil {
		payload := payloads.ResourceInspector
		if payload.InvocationID != report.Invocation.InvocationID || payload.RuntimeCommitmentDigest != report.Invocation.RuntimeCommitmentDigest || !equalStringPtr(payload.InspectorArtifactDigest, artifactByID["resource_inspector"].Digest) || !equalStringPtr(payload.InspectorConfigurationDigest, configurationByID["inspector_configuration"].Digest) || !reflect.DeepEqual(payload.TargetIdentity, report.Topology["target_identity"]) || !reflect.DeepEqual(payload.ArtifactIdentities, filterArtifacts(report.Artifacts, "resource_inspector")) || !reflect.DeepEqual(payload.Cleanup, report.Cleanup) {
			return errors.New("resource-inspector payload does not bind the reported target, identity, and cleanup evidence")
		}
	}
	if err := validateObservationPayloads(report.Observations, semantics, payloads); err != nil {
		return err
	}
	return validateTrustedInputPayload(report, semantics, payloads)
}

func processSupervisorBindsReport(payload *processSupervisorPayload, report reportDocument, artifactByID map[string]artifactIdentity, configurationByID map[string]configuration) bool {
	return payload != nil &&
		payload.InvocationID == report.Invocation.InvocationID &&
		payload.RuntimeCommitmentDigest == report.Invocation.RuntimeCommitmentDigest &&
		equalStringPtr(payload.SupervisorArtifactDigest, artifactByID["process_supervisor"].Digest) &&
		equalStringPtr(payload.SupervisorConfigurationDigest, configurationByID["observer_configuration"].Digest) &&
		equalStringPtr(payload.InitialInvocationID, report.Invocation.InitialInvocationID) &&
		equalStringPtr(payload.ReconstructionInvocationID, report.Invocation.ReconstructionInvocationID) &&
		reflect.DeepEqual(payload.StartupIdentity, report.Invocation.StartupIdentity) &&
		reflect.DeepEqual(payload.ArtifactIdentities, filterArtifacts(report.Artifacts, "process_supervisor")) &&
		reflect.DeepEqual(payload.ConfigurationIdentities, report.Configurations) &&
		reflect.DeepEqual(payload.InitialProcesses, report.Invocation.InitialProcesses) &&
		reflect.DeepEqual(payload.ReconstructionProcesses, report.Invocation.ReconstructionProcesses) &&
		reflect.DeepEqual(payload.AdapterTranscript, report.Invocation.AdapterTranscript)
}

func projectScenarioTimings(results []scenarioResult) []scenarioTiming {
	projected := make([]scenarioTiming, len(results))
	for index, result := range results {
		projected[index] = scenarioTiming{CaseID: result.CaseID, PhaseID: result.PhaseID, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt}
	}
	return projected
}

func validateProcessTimingEvidence(report reportDocument, payload *processSupervisorPayload) error {
	if payload == nil {
		if !timestampsEmpty(report.Timestamps) {
			return errors.New("qualification report retains run timing evidence without process-supervisor payload")
		}
		for _, phase := range report.Phases {
			if phase.StartedAt != nil || phase.FinishedAt != nil {
				return errors.New("qualification report retains phase timing evidence without process-supervisor payload")
			}
		}
		for _, scenario := range report.ScenarioResults {
			if scenario.StartedAt != nil || scenario.FinishedAt != nil {
				return errors.New("qualification report retains scenario timing evidence without process-supervisor payload")
			}
		}
		return nil
	}

	if !timestampsComplete(report.Timestamps) {
		return errors.New("process-supervisor-backed report requires complete run timing evidence")
	}
	for _, phase := range report.Phases {
		if phase.StartedAt == nil || phase.FinishedAt == nil {
			return errors.New("process-supervisor-backed report requires complete phase timing evidence")
		}
	}
	for _, scenario := range report.ScenarioResults {
		if scenario.StartedAt == nil || scenario.FinishedAt == nil {
			return errors.New("process-supervisor-backed report requires complete scenario timing evidence")
		}
	}
	if !reflect.DeepEqual(payload.RunTimestamps, report.Timestamps) || !reflect.DeepEqual(payload.Phases, report.Phases) || !reflect.DeepEqual(payload.ScenarioTimings, projectScenarioTimings(report.ScenarioResults)) {
		return errors.New("process-supervisor payload does not bind the reported run, phase, and scenario timing evidence")
	}
	return nil
}

func validateResourceInspectorTimingEvidence(report reportDocument, payload *resourceInspectorPayload) error {
	if payload == nil {
		return nil
	}
	want := cleanupTimestamps{StartedAt: report.Timestamps.CleanupStartedAt, FinishedAt: report.Timestamps.CleanupFinishedAt}
	if !reflect.DeepEqual(payload.CleanupTimestamps, want) {
		return errors.New("resource-inspector payload does not bind the reported cleanup timing evidence")
	}
	return nil
}

func validateAbsentPayloadClaims(report reportDocument, payloads payloadSet, providerInteractions, gatewayInteractions []interactionResult) error {
	if payloads.Provider == nil && (len(providerInteractions) != 0 || report.SandboxResources != nil) {
		return errors.New("qualification report retains Provider request evidence without provider-observer payload")
	}
	if payloads.Gateway == nil && (len(gatewayInteractions) != 0 || report.Invocation.ShellChallenge != nil) {
		return errors.New("qualification report retains Gateway evidence without gateway-observer payload")
	}
	if payloads.ProcessSupervisor == nil {
		invocation := report.Invocation
		if invocation.ShellChallenge != nil {
			return errors.New("qualification report retains shell continuity execution evidence without process-supervisor payload")
		}
		if invocation.InitialInvocationID != nil || invocation.ReconstructionInvocationID != nil || invocation.HarnessArtifactDigest != nil || invocation.StartupIdentity != nil || invocation.HarnessReinjected != nil || len(invocation.InitialProcesses) != 0 || len(invocation.ReconstructionProcesses) != 0 || len(invocation.RestartedComponents) != 0 || len(invocation.PreservedStores) != 0 || invocation.AdapterTranscript != nil {
			return errors.New("qualification report retains process evidence without process-supervisor payload")
		}
		for _, artifact := range report.Artifacts {
			if artifact.ObservedBy == "process_supervisor" && (artifact.Digest != nil || artifact.Source != nil) {
				return fmt.Errorf("qualification report retains artifact %q without process-supervisor payload", artifact.ArtifactID)
			}
		}
		for _, configuration := range report.Configurations {
			if configuration.Digest != nil || configuration.Sanitized {
				return fmt.Errorf("qualification report retains configuration %q without process-supervisor payload", configuration.ID)
			}
		}
		for _, scenario := range report.ScenarioResults {
			if scenario.Status != "not_executed" || len(scenario.Interactions) != 0 || len(scenario.ObservationIDs) != 0 {
				return errors.New("qualification report retains executed scenario evidence without process-supervisor payload")
			}
		}
		for _, phase := range report.Phases {
			if phase.Status != "not_executed" {
				return errors.New("qualification report retains execution phase evidence without process-supervisor payload")
			}
		}
		if len(report.Observations) != 0 {
			return errors.New("qualification report retains observations without process-supervisor payload")
		}
	}
	if payloads.ResourceInspector == nil {
		if report.Topology["target_identity"] != nil || report.Cleanup.QueryScope != nil || report.Cleanup.Baseline != nil || report.Cleanup.PostTeardown != nil || report.Cleanup.TeardownAttempts != 0 || report.Cleanup.TeardownCompleted || report.Cleanup.StabilitySamples != 0 || report.Cleanup.StabilityIntervalMS != 0 || report.Cleanup.Outcome == "succeeded" || ((report.Cleanup.CleanupRequired || report.Cleanup.MutationWriteObserved) && report.RunOutcome.CleanupSatisfied) {
			return errors.New("qualification report retains cleanup or target evidence without resource-inspector payload")
		}
		for _, artifact := range report.Artifacts {
			if artifact.ObservedBy == "resource_inspector" && (artifact.Digest != nil || artifact.Source != nil) {
				return fmt.Errorf("qualification report retains artifact %q without resource-inspector payload", artifact.ArtifactID)
			}
		}
	}
	return nil
}

func timestampsEmpty(value timestamps) bool {
	return value.RunStartedAt == nil && value.ExecutionStartedAt == nil && value.ExecutionFinishedAt == nil && value.CleanupStartedAt == nil && value.CleanupFinishedAt == nil && value.RunFinishedAt == nil
}

func timestampsComplete(value timestamps) bool {
	return value.RunStartedAt != nil && value.ExecutionStartedAt != nil && value.ExecutionFinishedAt != nil && value.CleanupStartedAt != nil && value.CleanupFinishedAt != nil && value.RunFinishedAt != nil
}

func validateObservationPayloads(reportObservations []observation, semantics validatorSemantics, payloads payloadSet) error {
	type sourceFacts struct {
		path  string
		facts []observerFact
	}
	bySource := map[string]sourceFacts{}
	if payloads.Provider != nil {
		bySource["provider_observer"] = sourceFacts{path: "provider-observer.json", facts: payloads.Provider.Observations}
	}
	if payloads.Gateway != nil {
		bySource["gateway_observer"] = sourceFacts{path: "gateway-observer.json", facts: payloads.Gateway.Observations}
	}
	if payloads.ProcessSupervisor != nil {
		bySource["process_supervisor"] = sourceFacts{path: "process-supervisor.json", facts: payloads.ProcessSupervisor.Observations}
	}
	if payloads.ResourceInspector != nil {
		bySource["resource_inspector"] = sourceFacts{path: "resource-inspector.json", facts: payloads.ResourceInspector.Observations}
	}
	_ = semantics
	reportByBinding := make(map[string]observation, len(reportObservations))
	for _, item := range reportObservations {
		key := observationKey(profileObservation{ID: item.ID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation})
		if _, duplicate := reportByBinding[key]; duplicate {
			return fmt.Errorf("qualification report duplicates observation binding %q", item.ID)
		}
		reportByBinding[key] = item
	}
	seenFacts := make(map[string]struct{}, len(reportObservations))
	for source, group := range bySource {
		digest := payloads.DigestByPath[group.path]
		expectedFacts := make([]observerFact, 0, len(reportObservations))
		for _, item := range reportObservations {
			if item.Source == source {
				expectedFacts = append(expectedFacts, observerFact{ID: item.ID, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: item.Result})
			}
		}
		if !reflect.DeepEqual(group.facts, expectedFacts) {
			return fmt.Errorf("qualification %s payload observations are not the report's ordered source projection", source)
		}
		for _, fact := range group.facts {
			key := observationKey(profileObservation{ID: fact.ID, Source: source, Actor: fact.Actor, Subject: fact.Subject, Correlation: fact.Correlation})
			if _, duplicate := seenFacts[key]; duplicate {
				return fmt.Errorf("qualification payloads duplicate observation binding %q", fact.ID)
			}
			seenFacts[key] = struct{}{}
			reported, ok := reportByBinding[key]
			if !ok || reported.Source != source || reported.Actor != fact.Actor || reported.Subject != fact.Subject || reported.Correlation != fact.Correlation || reported.Result != fact.Result || reported.EvidenceDigest == nil || *reported.EvidenceDigest != digest {
				return fmt.Errorf("qualification observation %q does not bind its source payload", fact.ID)
			}
		}
	}
	for _, item := range reportObservations {
		key := observationKey(profileObservation{ID: item.ID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation})
		if _, ok := seenFacts[key]; !ok {
			return fmt.Errorf("qualification observation %q has no source payload fact", item.ID)
		}
	}
	return nil
}

func validateTrustedInputPayload(report reportDocument, semantics validatorSemantics, payloads payloadSet) error {
	if payloads.TrustedInputs == nil {
		if len(report.Claims.TrustedInputs) != 0 || len(report.Claims.CallerAssertions) != 0 {
			return errors.New("qualification report claims have no trusted-input payload")
		}
		return nil
	}
	payload := payloads.TrustedInputs
	digest := payloads.DigestByPath["trusted-inputs.json"]
	if payload.InvocationID != report.Invocation.InvocationID || payload.RuntimeCommitmentDigest != report.Invocation.RuntimeCommitmentDigest || !reflect.DeepEqual(payload.CallerAssertions, report.Claims.CallerAssertions) || len(payload.TrustedInputs) != len(report.Claims.TrustedInputs) {
		return errors.New("trusted-input payload does not bind the reported invocation and claims")
	}
	for index, statement := range payload.TrustedInputs {
		reported := report.Claims.TrustedInputs[index]
		if statement.ID != reported.ID || statement.Source != reported.Source || reported.Digest != digest {
			return fmt.Errorf("trusted input %q does not bind trusted-inputs.json", statement.ID)
		}
	}
	if len(payload.TrustedInputs) > len(semantics.TrustedInputs) {
		return errors.New("trusted-input payload has too many statements")
	}
	for index, statement := range payload.TrustedInputs {
		if statement.ID != semantics.TrustedInputs[index].ID || statement.Source != semantics.TrustedInputs[index].Source {
			return fmt.Errorf("trusted input %q is out of locked order", statement.ID)
		}
	}
	return nil
}

func splitInteractions(scenarios []scenarioResult) ([]interactionResult, []interactionResult) {
	provider := make([]interactionResult, 0)
	gateway := make([]interactionResult, 0)
	for _, scenario := range scenarios {
		for _, interaction := range scenario.Interactions {
			if interaction.Surface == "provider_http" {
				provider = append(provider, interaction)
			} else {
				gateway = append(gateway, interaction)
			}
		}
	}
	return provider, gateway
}

func artifactMap(values []artifactIdentity) map[string]artifactIdentity {
	result := make(map[string]artifactIdentity, len(values))
	for _, value := range values {
		result[value.ArtifactID] = value
	}
	return result
}

func configurationMap(values []configuration) map[string]configuration {
	result := make(map[string]configuration, len(values))
	for _, value := range values {
		result[value.ID] = value
	}
	return result
}

func filterArtifacts(values []artifactIdentity, observer string) []artifactIdentity {
	result := make([]artifactIdentity, 0, len(values))
	for _, value := range values {
		if value.ObservedBy == observer {
			result = append(result, value)
		}
	}
	return result
}

func equalStringPtr(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
