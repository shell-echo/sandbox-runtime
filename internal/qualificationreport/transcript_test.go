package qualificationreport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
)

// Synthetic metadata is only fixture data; it does not represent real streams.
func syntheticTranscriptProjection(t *testing.T, report *reportDocument) map[string]any {
	t.Helper()
	if report.Invocation.AdapterTranscript == nil {
		return nil
	}
	phases := []any{}
	for i, phase := range report.Phases {
		processes, executables, configurations := map[string]any{}, map[string]any{}, map[string]any{}
		for _, process := range [][]processIdentity{report.Invocation.InitialProcesses, report.Invocation.ReconstructionProcesses}[i] {
			processes[process.Component] = process.ProcessID
			executables[process.Component] = process.ExecutableDigest
			configurations[process.Component] = process.ConfigurationDigest
		}
		types := []any{"startup_identity", "invocation_accepted"}
		completion := "completed"
		for _, id := range phase.ScenarioIDs {
			executed := true
			for _, result := range report.ScenarioResults {
				if result.CaseID == id && result.Status == "not_executed" {
					executed = false
				}
			}
			if executed {
				types = append(types, "scenario_started")
			} else {
				completion = "stopped"
			}
			types = append(types, "scenario_result")
		}
		types = append(types, "invocation_finished")
		counts := map[string]any{"startup_identity": float64(0), "invocation_accepted": float64(0), "scenario_started": float64(0), "scenario_result": float64(0), "invocation_finished": float64(0), "protocol_error": float64(0)}
		for _, kind := range types {
			counts[kind.(string)] = counts[kind.(string)].(float64) + 1
		}
		phases = append(phases, map[string]any{
			"phase_id": phase.PhaseID, "invocation_id": report.Invocation.AdapterTranscript.InvocationIDs[i],
			"process_identities": processes, "executable_digests": executables, "configuration_digests": configurations,
			"supplied_field_names": report.Invocation.AdapterTranscript.AllowedFields, "credential_channel_roles": []any{"provider_credentials"},
			"message_types": types, "message_counts": counts,
			"bounded_byte_counts": map[string]any{"invocation_wire_bytes": 512, "adapter_stdout_wire_bytes": 16384, "adapter_stderr_wire_bytes": 0, "adapter_output_complete_records": len(types), "credential_channel_count": 1, "credential_payload_total_bytes": 512},
			"terminal_state":      map[string]any{"terminal_message_type": "invocation_finished", "completion": completion, "error_code": nil, "stdout_eof_observed": true, "clean_process_exit_observed": true},
		})
	}
	projection := map[string]any{
		"format_version": 1, "transcript_type": "sandbox-runtime-external-caller-adapter-transcript", "transcript_version": "1.0.0",
		"protocol_id": AdapterProtocolID, "protocol_version": AdapterProtocolVersion, "protocol_schema_digest": ExpectedAdapterProtocolSchemaDigest, "protocol_semantics_digest": ExpectedAdapterProtocolSemanticsDigest,
		"phase_order": []any{"initial", "reconstruction"}, "invocation_ids": report.Invocation.AdapterTranscript.InvocationIDs, "phases": phases,
	}
	bindTranscriptDigest(t, report, projection)
	return projection
}

func bindTranscriptDigest(t *testing.T, report *reportDocument, value map[string]any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		t.Fatal(err)
	}
	report.Invocation.AdapterTranscript.Digest = evidencefiles.RawDigest(canonical)
}

func TestTranscriptValidatorRejectsResignedSemanticTampering(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"protocol authority": func(p map[string]any) { p["protocol_schema_digest"] = testAlternateDigest },
		"invocation":         func(p map[string]any) { p["phases"].([]any)[0].(map[string]any)["invocation_id"] = "substitute" },
		"process": func(p map[string]any) {
			p["phases"].([]any)[0].(map[string]any)["process_identities"].(map[string]any)["external_caller"] = "substitute"
		},
		"executable": func(p map[string]any) {
			p["phases"].([]any)[0].(map[string]any)["executable_digests"].(map[string]any)["provider"] = testAlternateDigest
		},
		"configuration": func(p map[string]any) {
			p["phases"].([]any)[1].(map[string]any)["configuration_digests"].(map[string]any)["qualification_adapter"] = testAlternateDigest
		},
		"channel roles": func(p map[string]any) {
			p["phases"].([]any)[1].(map[string]any)["credential_channel_roles"] = []any{"gateway_credentials"}
		},
		"count": func(p map[string]any) {
			p["phases"].([]any)[0].(map[string]any)["message_counts"].(map[string]any)["scenario_started"] = float64(14)
		},
		"record count": func(p map[string]any) {
			p["phases"].([]any)[0].(map[string]any)["bounded_byte_counts"].(map[string]any)["adapter_output_complete_records"] = 32
		},
		"channel count": func(p map[string]any) {
			p["phases"].([]any)[0].(map[string]any)["bounded_byte_counts"].(map[string]any)["credential_channel_count"] = 2
		},
		"message order": func(p map[string]any) {
			v := p["phases"].([]any)[0].(map[string]any)["message_types"].([]any)
			v[1], v[2] = v[2], v[1]
		},
		"terminal completion": func(p map[string]any) {
			p["phases"].([]any)[0].(map[string]any)["terminal_state"].(map[string]any)["completion"] = "stopped"
		},
	}
	schema, err := os.ReadFile(filepath.Join("../..", ReportSchemaPath))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			report := syntheticPassingReport(loadTestProfile(t))
			projection := syntheticTranscriptProjection(t, &report)
			mutate(projection)
			bindTranscriptDigest(t, &report, projection) // not merely a stale hash rejection
			document, _ := json.Marshal(projection)
			var normalized any
			if err := json.Unmarshal(document, &normalized); err != nil {
				t.Fatal(err)
			}
			if err := validateSchemaReference(schema, "#/$defs/adapterTranscriptProjection", normalized); err != nil {
				t.Fatalf("fixture must be schema-valid: %v", err)
			}
			payload := &processSupervisorPayload{AdapterTranscript: report.Invocation.AdapterTranscript, AdapterTranscriptProjection: projection}
			if err := validateTranscriptBinding(report, payload); err == nil {
				t.Fatal("resigned semantic drift accepted")
			}
		})
	}
}

func TestTranscriptValidatorPresenceDigestAndClosedShape(t *testing.T) {
	report := syntheticPassingReport(loadTestProfile(t))
	projection := syntheticTranscriptProjection(t, &report)
	payload := &processSupervisorPayload{AdapterTranscript: report.Invocation.AdapterTranscript, AdapterTranscriptProjection: projection}
	if err := validateTranscriptBinding(report, payload); err != nil {
		t.Fatal(err)
	}
	report.Invocation.AdapterTranscript.Digest = testAlternateDigest
	if err := validateTranscriptBinding(report, payload); err == nil {
		t.Fatal("opaque digest accepted")
	}
	bindTranscriptDigest(t, &report, projection)
	payload.AdapterTranscriptProjection = nil
	if err := validateTranscriptBinding(report, payload); err == nil {
		t.Fatal("missing preimage accepted")
	}
	payload.AdapterTranscriptProjection = projection
	report.Invocation.AdapterTranscript = nil
	if err := validateTranscriptBinding(report, payload); err == nil {
		t.Fatal("orphan projection accepted")
	}
	payload.AdapterTranscriptProjection = nil
	payload.AdapterTranscript = nil
	if err := validateTranscriptBinding(report, payload); err != nil {
		t.Fatal("honest unavailable projection rejected")
	}
	schema, err := os.ReadFile(filepath.Join("../..", ReportSchemaPath))
	if err != nil {
		t.Fatal(err)
	}
	projection["stderr"] = "private-output"
	document, _ := json.Marshal(projection)
	var normalized any
	if err := json.Unmarshal(document, &normalized); err != nil {
		t.Fatal(err)
	}
	if err := validateSchemaReference(schema, "#/$defs/adapterTranscriptProjection", normalized); err == nil {
		t.Fatal("unlocked private field accepted")
	}
	if err := validateEmbeddedTranscriptAuthority("../..", schema); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsTranscriptTamperBeforeReceipt(t *testing.T) {
	report := syntheticPassingReport(loadTestProfile(t))
	root := t.TempDir()
	writeSyntheticPayloads(t, root, &report)
	path := filepath.Join(root, "process-supervisor.json")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload processSupervisorPayload
	if err := json.Unmarshal(document, &payload); err != nil {
		t.Fatal(err)
	}
	payload.AdapterTranscriptProjection["protocol_semantics_digest"] = testAlternateDigest
	bindTranscriptDigest(t, &report, payload.AdapterTranscriptProjection)
	payload.AdapterTranscript = report.Invocation.AdapterTranscript
	document, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0600); err != nil {
		t.Fatal(err)
	}
	evidence, err := evidencefiles.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer evidence.Close()
	inventory, err := evidence.Read([]string{ReportFileName, ReceiptFileName}, evidencefiles.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	// Refresh all raw digest bindings, so only transcript semantics can reject.
	for i := range report.Observations {
		if report.Observations[i].Source == "process_supervisor" {
			d := evidencefiles.RawDigest(document)
			report.Observations[i].EvidenceDigest = &d
		}
	}
	writeSyntheticReport(t, root, &report, inventory)
	if _, err := Verify(context.Background(), root, "../.."); err == nil || !strings.Contains(err.Error(), "transcript projection or report binding invalid") {
		t.Fatalf("expected transcript-specific rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ReceiptFileName)); !os.IsNotExist(err) {
		t.Fatal("receipt published for invalid transcript")
	}
}

func TestTranscriptErrorBranchesAndStatusConstraints(t *testing.T) {
	for _, branch := range []string{"invalid_invocation", "internal_failure", "started_error", "stopped"} {
		t.Run(branch, func(t *testing.T) {
			report := syntheticPassingReport(loadTestProfile(t))
			projection := syntheticTranscriptProjection(t, &report)
			p := projection["phases"].([]any)[0].(map[string]any)
			types := []any{"startup_identity", "protocol_error"}
			code := "invalid_invocation"
			if branch != "invalid_invocation" {
				types = []any{"startup_identity", "invocation_accepted", "protocol_error"}
				code = "internal_failure"
			}
			if branch == "started_error" {
				types = []any{"startup_identity", "invocation_accepted", "scenario_started", "protocol_error"}
			}
			terminal := p["terminal_state"].(map[string]any)
			terminal["terminal_message_type"], terminal["completion"], terminal["error_code"] = "protocol_error", nil, code
			if branch == "stopped" {
				types = []any{"startup_identity", "invocation_accepted"}
				for range report.Phases[0].ScenarioIDs {
					types = append(types, "scenario_result")
				}
				types = append(types, "invocation_finished")
				terminal["terminal_message_type"], terminal["completion"], terminal["error_code"] = "invocation_finished", "stopped", nil
			}
			p["message_types"] = types
			counts := p["message_counts"].(map[string]any)
			for key := range counts {
				counts[key] = float64(0)
			}
			for _, kind := range types {
				counts[kind.(string)] = counts[kind.(string)].(float64) + 1
			}
			p["bounded_byte_counts"].(map[string]any)["adapter_output_complete_records"] = len(types)
			for i := range report.ScenarioResults {
				if report.ScenarioResults[i].PhaseID == "initial" {
					report.ScenarioResults[i].Status = "not_executed"
				}
			}
			if branch == "started_error" {
				report.ScenarioResults[0].Status = "incomplete"
			}
			bindTranscriptDigest(t, &report, projection)
			payload := &processSupervisorPayload{AdapterTranscript: report.Invocation.AdapterTranscript, AdapterTranscriptProjection: projection}
			if err := validateTranscriptBinding(report, payload); err != nil {
				t.Fatal(err)
			}
			report.ScenarioResults[0].Status = "passed"
			if err := validateTranscriptBinding(report, payload); err == nil {
				t.Fatal("missing completion became passed")
			}
		})
	}
}

func TestTranscriptCanonicalSpellingAndAuthorityDrift(t *testing.T) {
	report := syntheticPassingReport(loadTestProfile(t))
	projection := syntheticTranscriptProjection(t, &report)
	// Pretty-print and equivalent numeric spelling are not digest changes.
	document, err := json.MarshalIndent(projection, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	document = []byte(strings.Replace(string(document), `"format_version": 1`, `"format_version": 1e0`, 1))
	var variant map[string]any
	if err := decodeStrictJSON(document, &variant); err != nil {
		t.Fatal(err)
	}
	if err := validateTranscriptBinding(report, &processSupervisorPayload{AdapterTranscript: report.Invocation.AdapterTranscript, AdapterTranscriptProjection: variant}); err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile(filepath.Join("../..", ReportSchemaPath))
	if err != nil {
		t.Fatal(err)
	}
	var schemaValue map[string]any
	if err := json.Unmarshal(schema, &schemaValue); err != nil {
		t.Fatal(err)
	}
	schemaValue["$defs"].(map[string]any)["adapterTranscriptProjection"].(map[string]any)["additionalProperties"] = true
	changed, err := json.Marshal(schemaValue)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEmbeddedTranscriptAuthority("../..", changed); err == nil {
		t.Fatal("embedded authority drift accepted")
	}
	semantics, err := loadValidatorSemantics("../..", ExpectedReportSchemaDigest)
	if err != nil {
		t.Fatal(err)
	}
	semantics.TranscriptProjectionRules["channel_count_equals_role_count"] = false
	if err := validateLockedSemantics(semantics, ExpectedReportSchemaDigest); err == nil {
		t.Fatal("semantic drift accepted")
	}
}
