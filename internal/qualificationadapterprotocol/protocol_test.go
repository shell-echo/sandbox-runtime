package qualificationadapterprotocol

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

func TestLockedDefinition(t *testing.T) {
	report, err := VerifyDefinition(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	if report.ProtocolID != ProtocolID || report.ProtocolVersion != ProtocolVersion ||
		report.SchemaDigest != ExpectedProtocolSchemaDigest || report.SemanticsDigest != ExpectedProtocolSemanticsDigest ||
		report.TranscriptSchemaDigest != ExpectedTranscriptSchemaDigest {
		t.Fatalf("unexpected verification report: %+v", report)
	}
}

func TestQualificationReportProtocolTrustAnchorsMatch(t *testing.T) {
	if qualificationreport.AdapterProtocolID != ProtocolID ||
		qualificationreport.AdapterProtocolVersion != ProtocolVersion ||
		qualificationreport.AdapterProtocolSchemaPath != ProtocolSchemaPath ||
		qualificationreport.AdapterProtocolSemanticsPath != ProtocolSemanticsPath ||
		qualificationreport.ExpectedAdapterProtocolSchemaDigest != ExpectedProtocolSchemaDigest ||
		qualificationreport.ExpectedAdapterProtocolSemanticsDigest != ExpectedProtocolSemanticsDigest {
		t.Fatal("qualification report and adapter protocol trust anchors differ")
	}
}

func TestVerifyDefinitionHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyDefinition(ctx, "../.."); err == nil {
		t.Fatal("VerifyDefinition accepted canceled context")
	}
}

func TestSchemaRejectsAdapterAssignedQualificationStatus(t *testing.T) {
	protocolDocument, err := readRepositoryFile("../..", ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	reportDocument, err := readRepositoryFile("../..", "qualification/external-caller-coding-shell-v1/report.schema.json", maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		t.Fatal(err)
	}
	message := outputExample("scenario_result", 3, map[string]any{
		"case_id": "initial.locked-capability-discovery", "disposition": "not_executed",
		"interactions": []any{}, "assertions": []any{}, "observation_ids": []any{},
		"reason_code": "prerequisite_not_satisfied", "status": "incomplete",
	})
	if err := schema.Validate(message); err == nil {
		t.Fatal("protocol schema accepted adapter-assigned qualification status")
	}
}

func TestSchemaRejectsCompletedScenarioWithoutInteraction(t *testing.T) {
	protocolDocument, err := readRepositoryFile("../..", ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	reportDocument, err := readRepositoryFile("../..", "qualification/external-caller-coding-shell-v1/report.schema.json", maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		t.Fatal(err)
	}
	message := outputExample("scenario_result", 3, map[string]any{
		"case_id": "initial.locked-capability-discovery", "disposition": "completed",
		"interactions": []any{}, "assertions": []any{}, "observation_ids": []any{}, "reason_code": nil,
	})
	if err := schema.Validate(message); err == nil {
		t.Fatal("protocol schema accepted completed scenario without interactions")
	}
}

func TestSchemaRejectsHarnessInjectedStartupIdentity(t *testing.T) {
	protocolDocument, err := readRepositoryFile("../..", ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	reportDocument, err := readRepositoryFile("../..", "qualification/external-caller-coding-shell-v1/report.schema.json", maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		t.Fatal(err)
	}
	release := map[string]any{"kind": "source-revision", "value": strings.Repeat("a", 40), "immutable": true}
	message := map[string]any{
		"format_version": float64(1), "protocol_id": ProtocolID, "protocol_version": ProtocolVersion,
		"message_type": "startup_identity", "sequence": float64(0),
		"protocol_schema_digest": ExpectedProtocolSchemaDigest, "protocol_semantics_digest": ExpectedProtocolSemanticsDigest,
		"caller_release_identity": release, "adapter_release_identity": release,
		"contract_revision": "22ba6987ea5fbc37d53942720133c0acad199edd", "contract_tree": "c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38",
		"profile_id": "sandbox-runtime-external-caller-coding-shell-v1", "profile_version": "1.0.0",
		"profile_digest":                      "sha256:4effea27fd3d7668b88eeb95c69e19b51556914b7949b1a39ce522b2aec46c14",
		"expected_values_injected_by_harness": true,
		"credential_channel_requirements": []any{map[string]any{
			"channel_id": "provider-a", "role": "provider_credentials", "actor": "controller_a",
			"media_type": "application/example", "max_bytes": float64(1024),
		}},
	}
	if err := schema.Validate(message); err == nil {
		t.Fatal("protocol schema accepted a harness-injected startup identity")
	}
}

func TestInvocationLocationFieldsRejectUnsafeCharacters(t *testing.T) {
	protocolDocument, err := readRepositoryFile("../..", ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	reportDocument, err := readRepositoryFile("../..", qualificationreport.ReportSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		t.Fatal(err)
	}

	fields := map[string]string{
		"profile_path":           "/qualification/profile.json",
		"provider_origin":        "https://provider.invalid",
		"gateway_probe_endpoint": "wss://gateway.invalid/terminal",
		"caller_state_root":      "/caller-state",
	}
	controls := append([]rune{}, []rune("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")...)
	controls = append(controls, []rune("\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f")...)
	for field, valid := range fields {
		baseline := invocationExampleForSchemaTest()
		baseline[field] = valid
		if err := schema.Validate(baseline); err != nil {
			t.Fatalf("canonical %s test value does not match schema: %v", field, err)
		}
		positions := []int{0, len(valid) / 2, len(valid)}
		for _, control := range controls {
			for _, position := range positions {
				message := invocationExampleForSchemaTest()
				message[field] = valid[:position] + string(control) + valid[position:]
				if err := schema.Validate(message); err == nil {
					t.Errorf("schema accepted %s with U+%04X at byte offset %d", field, control, position)
				}
			}
		}
		message := invocationExampleForSchemaTest()
		message[field] = valid[:len(valid)/2] + "\u0080" + valid[len(valid)/2:]
		if err := schema.Validate(message); err == nil {
			t.Errorf("schema accepted %s with non-ASCII U+0080", field)
		}
	}
}

func TestValidateSemanticsRejectsAllowedFieldDrift(t *testing.T) {
	content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeStrictObject(content)
	if err != nil {
		t.Fatal(err)
	}
	invocation := value["invocation"].(map[string]any)
	invocation["allowed_harness_fields"] = append(stringsToAny(allowedHarnessFields), "sandbox_id")
	if err := validateSemantics(value); err == nil || !strings.Contains(err.Error(), "allowed_harness_fields") {
		t.Fatalf("validateSemantics = %v", err)
	}
}

func TestValidateSemanticsRejectsCodecDrift(t *testing.T) {
	tests := map[string]func(map[string]any){
		"record delimiter accounting": func(codec map[string]any) {
			codec["adapter_output_framing"].(map[string]any)["record_document_bytes_exclude_delimiter"] = false
		},
		"truncated byte accounting": func(codec map[string]any) {
			codec["adapter_output_framing"].(map[string]any)["stdout_total_bytes_include_delimiters_and_invalid_or_truncated_bytes"] = false
		},
		"carriage return acceptance": func(codec map[string]any) {
			codec["adapter_output_framing"].(map[string]any)["carriage_return_bytes_allowed"] = true
		},
		"rejected record accounting": func(codec map[string]any) {
			codec["adapter_output_framing"].(map[string]any)["complete_records_rejected_by_document_validation_count_toward_record_limit"] = false
		},
		"invalid surrogate acceptance": func(codec map[string]any) {
			codec["json"].(map[string]any)["invalid_unicode_surrogate_escapes_allowed"] = true
		},
		"startup authority bypass": func(codec map[string]any) {
			codec["startup_protocol_digests_must_match_locked_authority"] = false
		},
		"message order claim": func(codec map[string]any) {
			codec["codec_validates_message_order"] = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeStrictObject(content)
			if err != nil {
				t.Fatal(err)
			}
			mutate(value["codec"].(map[string]any))
			if err := validateSemantics(value); err == nil || !strings.Contains(err.Error(), "codec") {
				t.Fatalf("validateSemantics = %v", err)
			}
		})
	}
}

func TestValidateSemanticsRejectsOutputBindingDrift(t *testing.T) {
	content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeStrictObject(content)
	if err != nil {
		t.Fatal(err)
	}
	stateMachine := value["state_machine"].(map[string]any)
	stateMachine["output_phase_binding"] = "adapter-selected"
	if err := validateSemantics(value); err == nil || !strings.Contains(err.Error(), "output_phase_binding") {
		t.Fatalf("validateSemantics = %v", err)
	}
}

func TestValidateSemanticsRejectsStateTransitionAndTranscriptDrift(t *testing.T) {
	tests := map[string]func(map[string]any){
		"transition target": func(value map[string]any) {
			transitions := value["state_machine"].(map[string]any)["transition_table"].([]any)
			transitions[0].(map[string]any)["to"] = "complete"
		},
		"cross-phase startup": func(value map[string]any) {
			value["state_machine"].(map[string]any)["startup_identity_cross_phase_equality"] = "unchecked"
		},
		"normal terminal inventory": func(value map[string]any) {
			value["state_machine"].(map[string]any)["normal_terminal_requires_exactly_one_result_per_phase_scenario"] = false
		},
		"transcript schema": func(value map[string]any) {
			value["sanitized_transcript"].(map[string]any)["projection_schema"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("f", 64)
		},
		"transcript protocol authority": func(value map[string]any) {
			value["sanitized_transcript"].(map[string]any)["protocol_identity_matches_locked_authority"] = false
		},
		"transcript byte source": func(value map[string]any) {
			value["sanitized_transcript"].(map[string]any)["bounded_byte_count_sources"].(map[string]any)["adapter_stdout_wire_bytes"] = "adapter-reported"
		},
		"transcript exclusion": func(value map[string]any) {
			value["sanitized_transcript"].(map[string]any)["exclude"] = []any{}
		},
		"runtime claim": func(value map[string]any) {
			value["sanitized_transcript"].(map[string]any)["definition_verifier_claims_runtime_transcript_recomputation"] = true
		},
		"process failure condition": func(value map[string]any) {
			value["process_control"].(map[string]any)["failure_conditions"] = []any{"unexpected-process-exit"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeStrictObject(content)
			if err != nil {
				t.Fatal(err)
			}
			mutate(value)
			if err := validateSemantics(value); err == nil {
				t.Fatal("validateSemantics accepted state-machine or transcript drift")
			}
		})
	}
}

func TestTranscriptSchemaRejectsPrivateAndAmbiguousProjection(t *testing.T) {
	document, err := readRepositoryFile("../..", TranscriptSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileTranscriptSchema(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(lockedTranscriptExample()); err != nil {
		t.Fatalf("canonical transcript projection was rejected: %v", err)
	}

	tests := map[string]func(map[string]any){
		"private endpoint": func(value map[string]any) {
			value["provider_origin"] = "https://private.invalid"
		},
		"reversed phase order": func(value map[string]any) {
			value["phase_order"] = []any{"reconstruction", "initial"}
		},
		"reused invocation id": func(value map[string]any) {
			value["invocation_ids"] = []any{"same", "same"}
		},
		"missing process identity": func(value map[string]any) {
			phase := value["phases"].([]any)[0].(map[string]any)
			delete(phase["process_identities"].(map[string]any), "provider")
		},
		"missing startup message": func(value map[string]any) {
			phase := value["phases"].([]any)[0].(map[string]any)
			phase["message_types"].([]any)[0] = "invocation_accepted"
		},
		"duplicate startup message": func(value map[string]any) {
			phase := value["phases"].([]any)[0].(map[string]any)
			phase["message_types"] = append(phase["message_types"].([]any), "startup_identity")
		},
		"missing terminal message": func(value map[string]any) {
			phase := value["phases"].([]any)[0].(map[string]any)
			phase["message_types"] = []any{"startup_identity", "invocation_accepted", "scenario_result"}
		},
		"ambiguous terminal": func(value map[string]any) {
			phase := value["phases"].([]any)[0].(map[string]any)
			phase["terminal_state"].(map[string]any)["completion"] = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := lockedTranscriptExample()
			mutate(value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("transcript schema accepted invalid projection")
			}
		})
	}
}

func TestValidateSemanticsRejectsProtocolErrorBranchDrift(t *testing.T) {
	content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeStrictObject(content)
	if err != nil {
		t.Fatal(err)
	}
	protocolError := value["protocol_error"].(map[string]any)
	postBinding := protocolError["post_binding_failure"].(map[string]any)
	postBinding["requires_invocation_accepted"] = false
	if err := validateSemantics(value); err == nil || !strings.Contains(err.Error(), "requires_invocation_accepted") {
		t.Fatalf("validateSemantics = %v", err)
	}
}

func TestValidateSemanticsRejectsDeadlineControlDrift(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"wall-clock-control": func(value map[string]any) {
			value["clock_source"] = "reported-wall-clock"
		},
		"reconstruction-reset": func(value map[string]any) {
			value["run_execution"].(map[string]any)["reconstruction_resets_deadline"] = true
		},
		"scenario-start-reset": func(value map[string]any) {
			value["case"].(map[string]any)["scenario_started_resets_deadline"] = true
		},
		"late-termination-anchor": func(value map[string]any) {
			value["termination"].(map[string]any)["start_anchor"] = "after-process-group-kill"
		},
		"runtime-claim": func(value map[string]any) {
			value["definition_verifier_claims_runtime_deadline_enforcement"] = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			content, err := readRepositoryFile("../..", ProtocolSemanticsPath, maxDefinitionBytes)
			if err != nil {
				t.Fatal(err)
			}
			value, err := decodeStrictObject(content)
			if err != nil {
				t.Fatal(err)
			}
			deadlineControl := value["deadline_control"].(map[string]any)
			mutate(deadlineControl)
			if err := validateSemantics(value); err == nil || !strings.Contains(err.Error(), "deadline_control") {
				t.Fatalf("validateSemantics = %v", err)
			}
		})
	}
}

func TestDeriveDeadlineBudgetClipsWithoutReset(t *testing.T) {
	parentLonger := 500 * time.Second
	parentShorter := 25 * time.Second
	tests := []struct {
		name             string
		executionElapsed time.Duration
		parentRemaining  *time.Duration
		want             deadlineBudget
	}{
		{
			name: "initial case",
			want: deadlineBudget{
				Execution: 1800 * time.Second,
				Case:      120 * time.Second,
				Reap:      5 * time.Second,
			},
		},
		{
			name:             "reconstruction retains run elapsed time",
			executionElapsed: 1740 * time.Second,
			parentRemaining:  &parentLonger,
			want: deadlineBudget{
				Execution: 60 * time.Second,
				Case:      60 * time.Second,
				Reap:      5 * time.Second,
			},
		},
		{
			name:             "parent deadline preempts profile limits",
			executionElapsed: 100 * time.Second,
			parentRemaining:  &parentShorter,
			want: deadlineBudget{
				Execution: 25 * time.Second,
				Case:      25 * time.Second,
				Reap:      5 * time.Second,
			},
		},
		{
			name:             "expired run keeps only separate reap budget",
			executionElapsed: 1801 * time.Second,
			want:             deadlineBudget{Reap: 5 * time.Second},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := deriveDeadlineBudget(test.executionElapsed, test.parentRemaining)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("deriveDeadlineBudget = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestDeriveDeadlineBudgetRejectsNegativeDurations(t *testing.T) {
	negative := -time.Nanosecond
	if _, err := deriveDeadlineBudget(negative, nil); err == nil {
		t.Fatal("deriveDeadlineBudget accepted negative execution elapsed time")
	}
	if _, err := deriveDeadlineBudget(0, &negative); err == nil {
		t.Fatal("deriveDeadlineBudget accepted negative parent remaining time")
	}
}

func TestOutputRecordsBindToReferenceInvocation(t *testing.T) {
	invocation := invocationExampleForSchemaTest()
	outputs := boundOutputExamplesForTest()
	if err := validateOutputBindings(invocation, outputs); err != nil {
		t.Fatalf("canonical output bindings were rejected: %v", err)
	}

	for index, output := range outputs {
		messageType := output["message_type"].(string)
		t.Run(messageType+"-invocation-id", func(t *testing.T) {
			mutated := cloneOutputExamples(outputs)
			mutated[index]["invocation_id"] = "invocation-reconstruction"
			if err := validateOutputBindings(invocation, mutated); err == nil || !strings.Contains(err.Error(), "invocation_id") {
				t.Fatalf("validateOutputBindings = %v", err)
			}
		})
		t.Run(messageType+"-phase", func(t *testing.T) {
			mutated := cloneOutputExamples(outputs)
			mutated[index]["phase"] = "reconstruction"
			if err := validateOutputBindings(invocation, mutated); err == nil || !strings.Contains(err.Error(), "phase") {
				t.Fatalf("validateOutputBindings = %v", err)
			}
		})
	}
}

func TestOutputRecordsBindToReconstructionInvocation(t *testing.T) {
	invocation := invocationExampleForSchemaTest()
	invocation["invocation_id"] = "invocation-reconstruction"
	invocation["phase"] = "reconstruction"
	outputs := boundOutputExamplesForTest()
	for _, output := range outputs {
		output["invocation_id"] = "invocation-reconstruction"
		output["phase"] = "reconstruction"
		if caseID, ok := output["case_id"].(string); ok {
			output["case_id"] = "reconstruction." + strings.TrimPrefix(caseID, "initial.")
		}
	}
	if err := validateOutputBindings(invocation, outputs); err != nil {
		t.Fatalf("canonical reconstruction output bindings were rejected: %v", err)
	}
}

func TestScenarioCaseIDBindsToReferenceInvocationPhase(t *testing.T) {
	invocation := invocationExampleForSchemaTest()
	for _, messageType := range []string{"scenario_started", "scenario_result"} {
		t.Run(messageType, func(t *testing.T) {
			outputs := boundOutputExamplesForTest()
			for _, output := range outputs {
				if output["message_type"] == messageType {
					output["case_id"] = "reconstruction.locked-capability-discovery"
				}
			}
			if err := validateOutputBindings(invocation, outputs); err == nil || !strings.Contains(err.Error(), "case_id") {
				t.Fatalf("validateOutputBindings = %v", err)
			}
		})
	}
}

func TestProtocolErrorSchemaLocksBindingBranches(t *testing.T) {
	protocolDocument, err := readRepositoryFile("../..", ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	reportDocument, err := readRepositoryFile("../..", qualificationreport.ReportSchemaPath, maxDefinitionBytes)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		t.Fatal(err)
	}
	preBinding := protocolErrorExample(1, nil, nil, "invalid_invocation")
	postBinding := protocolErrorExample(2, "invocation-initial", "initial", "caller_start_failed")
	for name, message := range map[string]map[string]any{
		"pre-binding":  preBinding,
		"post-binding": postBinding,
	} {
		t.Run(name, func(t *testing.T) {
			if err := schema.Validate(message); err != nil {
				t.Fatalf("canonical protocol_error was rejected: %v", err)
			}
		})
	}

	invalid := map[string]map[string]any{}
	invalid["invalid-invocation-bound-pair"] = cloneMap(preBinding)
	invalid["invalid-invocation-bound-pair"]["invocation_id"] = "invocation-initial"
	invalid["invalid-invocation-bound-pair"]["phase"] = "initial"
	invalid["invalid-invocation-mixed-pair"] = cloneMap(preBinding)
	invalid["invalid-invocation-mixed-pair"]["invocation_id"] = "invocation-initial"
	invalid["invalid-invocation-sequence"] = cloneMap(preBinding)
	invalid["invalid-invocation-sequence"]["sequence"] = float64(2)
	invalid["post-binding-null-pair"] = cloneMap(postBinding)
	invalid["post-binding-null-pair"]["invocation_id"] = nil
	invalid["post-binding-null-pair"]["phase"] = nil
	invalid["post-binding-mixed-pair"] = cloneMap(postBinding)
	invalid["post-binding-mixed-pair"]["phase"] = nil
	invalid["post-binding-sequence-one"] = cloneMap(postBinding)
	invalid["post-binding-sequence-one"]["sequence"] = float64(1)
	for name, message := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := schema.Validate(message); err == nil {
				t.Fatal("protocol schema accepted an ambiguous protocol_error branch")
			}
		})
	}
}

func TestProtocolErrorStateBranches(t *testing.T) {
	invocation := invocationExampleForSchemaTest()
	accepted := outputExample("invocation_accepted", 1, nil)
	preBinding := protocolErrorExample(1, nil, nil, "invalid_invocation")
	postBinding := protocolErrorExample(2, "invocation-initial", "initial", "caller_start_failed")
	if err := validateProtocolErrorBranch(nil, nil, preBinding); err != nil {
		t.Fatalf("canonical pre-binding branch was rejected: %v", err)
	}
	if err := validateProtocolErrorBranch(invocation, []map[string]any{accepted}, postBinding); err != nil {
		t.Fatalf("canonical post-binding branch was rejected: %v", err)
	}
	for _, errorCode := range postBindingProtocolErrorCodes {
		message := protocolErrorExample(2, "invocation-initial", "initial", errorCode)
		if err := validateProtocolErrorBranch(invocation, []map[string]any{accepted}, message); err != nil {
			t.Fatalf("canonical %s branch was rejected: %v", errorCode, err)
		}
	}

	tests := []struct {
		name       string
		invocation map[string]any
		prior      []map[string]any
		message    map[string]any
		want       string
	}{
		{name: "pre-binding-with-reference", invocation: invocation, message: preBinding, want: "before invocation binding"},
		{name: "pre-binding-after-output", prior: []map[string]any{accepted}, message: preBinding, want: "before invocation binding"},
		{name: "post-binding-without-reference", prior: []map[string]any{accepted}, message: postBinding, want: "reference invocation"},
		{name: "post-binding-before-acceptance", invocation: invocation, message: postBinding, want: "invocation_accepted"},
		{name: "post-binding-after-finished", invocation: invocation, prior: []map[string]any{accepted, outputExample("invocation_finished", 2, map[string]any{"completion": "stopped"})}, message: protocolErrorExample(3, "invocation-initial", "initial", "internal_failure"), want: "mutually exclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateProtocolErrorBranch(test.invocation, test.prior, test.message); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateProtocolErrorBranch = %v", err)
			}
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"wrong-invocation-id": func(message map[string]any) { message["invocation_id"] = "invocation-reconstruction" },
		"wrong-phase":         func(message map[string]any) { message["phase"] = "reconstruction" },
		"skipped-sequence":    func(message map[string]any) { message["sequence"] = float64(3) },
		"non-terminal":        func(message map[string]any) { message["terminal"] = false },
		"unknown-code":        func(message map[string]any) { message["error_code"] = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			message := cloneMap(postBinding)
			mutate(message)
			if err := validateProtocolErrorBranch(invocation, []map[string]any{accepted}, message); err == nil {
				t.Fatal("validateProtocolErrorBranch accepted invalid post-binding state")
			}
		})
	}
}

func TestDecodeStrictValueRejectsDuplicateAndTrailingJSON(t *testing.T) {
	for name, content := range map[string][]byte{
		"duplicate":     []byte(`{"field":1,"field":2}`),
		"trailing":      []byte(`{} {}`),
		"invalid UTF-8": {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictValue(content); err == nil {
				t.Fatal("decodeStrictValue accepted invalid JSON")
			}
		})
	}
}

func TestReadRepositoryFileRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "definition.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}
	if _, err := readRepositoryFile(root, "definition.json", 1024); err == nil {
		t.Fatal("readRepositoryFile accepted symlink")
	}
}

func invocationExampleForSchemaTest() map[string]any {
	descriptor := map[string]any{
		"channel_id":      "controller-a-provider",
		"role":            "provider_credentials",
		"actor":           "controller_a",
		"media_type":      "application/vnd.example.credentials+json",
		"max_bytes":       float64(4096),
		"file_descriptor": float64(3),
	}
	return map[string]any{
		"format_version":                 float64(1),
		"protocol_id":                    ProtocolID,
		"protocol_version":               ProtocolVersion,
		"message_type":                   "invocation",
		"invocation_id":                  "invocation-initial",
		"phase":                          "initial",
		"profile_path":                   "/qualification/profile.json",
		"provider_origin":                "https://provider.invalid",
		"gateway_probe_endpoint":         "wss://gateway.invalid/terminal",
		"credential_channel_descriptors": []any{descriptor},
		"caller_state_root":              "/caller-state",
	}
}

func boundOutputExamplesForTest() []map[string]any {
	return []map[string]any{
		outputExample("invocation_accepted", 1, nil),
		outputExample("scenario_started", 2, map[string]any{"case_id": "initial.locked-capability-discovery"}),
		outputExample("scenario_result", 3, map[string]any{
			"case_id":     "initial.locked-capability-discovery",
			"disposition": "not_executed", "interactions": []any{}, "assertions": []any{}, "observation_ids": []any{},
			"reason_code": "prerequisite_not_satisfied",
		}),
		outputExample("invocation_finished", 4, map[string]any{"completion": "stopped"}),
	}
}

func cloneOutputExamples(outputs []map[string]any) []map[string]any {
	cloned := make([]map[string]any, len(outputs))
	for index, output := range outputs {
		cloned[index] = cloneMap(output)
	}
	return cloned
}
