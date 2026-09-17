package qualificationreport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
	"github.com/shell-echo/sandbox-runtime/internal/jsonschemaecma"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testAlternateDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func testStringPtr(value string) *string {
	return &value
}

func testBoolPtr(value bool) *bool {
	return &value
}

func testIntPtr(value int) *int {
	return &value
}

func testSemantics() validatorSemantics {
	return validatorSemantics{
		ReportSchema:    authorityIdentity{Path: ReportSchemaPath, Digest: ExpectedReportSchemaDigest},
		AdapterProtocol: lockedAdapterProtocolAuthority(),
	}
}

func loadTestProfile(t *testing.T) profileDocument {
	t.Helper()
	document, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(qualificationprofile.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	var profile profileDocument
	if err := decodeStrictJSON(document, &profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestFrozenHarnessInventoryMatchesReportAuthority(t *testing.T) {
	frozen, err := qualificationharness.Freeze(context.Background(), "../..", qualificationharness.Configuration{
		Architecture: "darwin/arm64", TargetDigest: testDigest, RunNamespaceDigest: testAlternateDigest,
		ComponentConfigurations: qualificationharness.ComponentConfigurationDigests{
			Provider: testDigest, Caller: testDigest, Adapter: testDigest, Gateway: testDigest,
			Observer: testDigest, Inspector: testDigest, Teardown: testDigest,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(frozen.Topology())
	if err != nil {
		t.Fatal(err)
	}
	var topology map[string]any
	if err := decodeStrictJSON(encoded, &topology); err != nil {
		t.Fatal(err)
	}
	profile := loadTestProfile(t)
	if err := validateTopology(topology, profile.Topology); err != nil {
		t.Fatalf("frozen topology does not match report authority: %v", err)
	}
	identities := frozen.ConfigurationExpectations()
	configurations := make([]configuration, len(identities))
	for index, identity := range identities {
		digest := identity.Digest
		configurations[index] = configuration{
			ID: identity.ID, Digest: &digest, DigestProfile: identity.DigestProfile,
			Sanitized: true, ObservedBy: "process_supervisor",
		}
	}
	if err := validateConfigurations(configurations, profile.Evidence); err != nil {
		t.Fatalf("frozen configurations do not match report authority: %v", err)
	}
}

func TestDecodeLockedProfileRejectsUntrustedSecondRead(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(qualificationprofile.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(document), `"execution_mode": "independent-external-caller-black-box"`, `"execution_mode": "resigned-substitute"`, 1)
	if mutated == string(document) {
		t.Fatal("locked profile test mutation did not apply")
	}
	if _, err := decodeLockedProfile([]byte(mutated)); err == nil || !strings.Contains(err.Error(), "changed after definition verification") {
		t.Fatalf("decodeLockedProfile(mutated) error = %v", err)
	}
}

func TestBoundedTextRejectsASCIIControlCharacters(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(ReportSchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	var schemaValue any
	if err := decodeStrictJSON(document, &schemaValue); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschemaecma.NewCompiler()
	if err := compiler.AddResource(ReportSchemaID, schemaValue); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(ReportSchemaID + "#/$defs/boundedText")
	if err != nil {
		t.Fatal(err)
	}

	valid := "bounded-text"
	controls := append([]rune{}, []rune("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")...)
	controls = append(controls, []rune("\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f")...)
	for _, control := range controls {
		for _, position := range []int{0, len(valid) / 2, len(valid)} {
			value := valid[:position] + string(control) + valid[position:]
			if err := schema.Validate(value); err == nil {
				t.Errorf("boundedText accepted U+%04X at byte offset %d", control, position)
			}
		}
	}
	if err := schema.Validate("bounded-\u0080-text"); err != nil {
		t.Fatalf("boundedText rejected non-ASCII U+0080: %v", err)
	}
}

func TestVerifyAcceptsConsistentSyntheticEvidenceAndWritesReceipt(t *testing.T) {
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	schemaBytes, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(ReportSchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	if got := evidencefiles.RawDigest(schemaBytes); got != ExpectedReportSchemaDigest {
		t.Fatalf("locked report schema digest = %s, want %s", got, ExpectedReportSchemaDigest)
	}

	profileBytes, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(qualificationprofile.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	var profile profileDocument
	if err := decodeStrictJSON(profileBytes, &profile); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	report := syntheticPassingReport(profile)
	inventory := writeSyntheticPayloads(t, root, &report)
	var reportBytes []byte
	for attempts := 0; attempts < 8; attempts++ {
		reportBytes, err = json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		reportBytes = append(reportBytes, '\n')
		inventoryWithReport := inventory
		inventoryWithReport.FileCount++
		inventoryWithReport.TotalBytes += int64(len(reportBytes))
		receiptBytes, _, err := makeReceipt(report, reportBytes, inventoryWithReport, testSemantics())
		if err != nil {
			t.Fatal(err)
		}
		want := inventoryWithReport.TotalBytes + int64(len(receiptBytes))
		if report.Evidence.TotalBytes == want {
			break
		}
		report.Evidence.TotalBytes = want
	}
	reportBytes, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportBytes = append(reportBytes, '\n')
	if err := os.WriteFile(filepath.Join(root, ReportFileName), reportBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Verify(context.Background(), root, sourceRoot)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.RunOutcome != "passed" || result.ValidationOutcome != "accepted" || result.FileCount != 7 || result.RuntimeCommitment != report.Invocation.RuntimeCommitmentDigest {
		t.Fatalf("Verify() result = %+v", result)
	}
	receiptBytes, err := os.ReadFile(filepath.Join(root, ReceiptFileName))
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := decodeStrictJSON(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["report_sha256"] != evidencefiles.RawDigest(reportBytes) || receipt["payload_inventory_sha256"] != inventory.Digest || receipt["runtime_commitment_digest"] != report.Invocation.RuntimeCommitmentDigest {
		t.Fatal("receipt does not bind the exact report, runtime commitment, and payload inventory")
	}
	if !reflect.DeepEqual(receipt["report_schema"], map[string]any{"path": ReportSchemaPath, "digest": ExpectedReportSchemaDigest}) || !reflect.DeepEqual(receipt["validator_semantics"], map[string]any{"path": ValidatorSemanticsPath, "digest": ExpectedValidatorSemanticsDigest}) || !reflect.DeepEqual(receipt["adapter_protocol"], map[string]any{
		"protocol_id":      AdapterProtocolID,
		"protocol_version": AdapterProtocolVersion,
		"schema":           map[string]any{"path": AdapterProtocolSchemaPath, "digest": ExpectedAdapterProtocolSchemaDigest},
		"semantics":        map[string]any{"path": AdapterProtocolSemanticsPath, "digest": ExpectedAdapterProtocolSemanticsDigest},
	}) {
		t.Fatal("receipt does not bind the report, validator, and adapter protocol authorities")
	}
	retained, err := VerifyRetained(context.Background(), root, sourceRoot)
	if err != nil {
		t.Fatalf("VerifyRetained() error = %v", err)
	}
	if retained.ReportDigest != result.ReportDigest || retained.PayloadInventory != result.PayloadInventory ||
		retained.RunOutcome != "passed" || retained.ValidationOutcome != "accepted" || retained.FileCount != 7 {
		t.Fatalf("VerifyRetained() result = %+v", retained)
	}
}

func TestVerifyAcceptsHonestNotExecutedReportWithoutPayloads(t *testing.T) {
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	profileBytes, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(qualificationprofile.ProfilePath)))
	if err != nil {
		t.Fatal(err)
	}
	var profile profileDocument
	if err := decodeStrictJSON(profileBytes, &profile); err != nil {
		t.Fatal(err)
	}
	report := syntheticNotExecutedReport(profile)
	root := t.TempDir()
	inventory, err := evidencefiles.Read(root, []string{ReportFileName, ReceiptFileName}, evidencefiles.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	report.Evidence.PayloadInventory = inventory.Entries
	report.Evidence.PayloadInventoryDigest = inventory.Digest
	var reportBytes []byte
	for attempts := 0; attempts < 8; attempts++ {
		reportBytes, err = json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		reportBytes = append(reportBytes, '\n')
		inventoryWithReport := inventory
		inventoryWithReport.FileCount++
		inventoryWithReport.TotalBytes += int64(len(reportBytes))
		receiptBytes, _, err := makeReceipt(report, reportBytes, inventoryWithReport, testSemantics())
		if err != nil {
			t.Fatal(err)
		}
		want := inventoryWithReport.TotalBytes + int64(len(receiptBytes))
		if report.Evidence.TotalBytes == want {
			break
		}
		report.Evidence.TotalBytes = want
	}
	reportBytes, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportBytes = append(reportBytes, '\n')
	if err := os.WriteFile(filepath.Join(root, ReportFileName), reportBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Verify(context.Background(), root, sourceRoot)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.RunOutcome != "not_executed" || result.ValidationOutcome != "accepted" || result.FileCount != 2 {
		t.Fatalf("Verify() result = %+v", result)
	}
}

func TestVerifyAcceptsExecutedIncompleteReportWithMissingObservation(t *testing.T) {
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	lastScenario := len(report.ScenarioResults) - 1
	if lastScenario < 0 || len(report.Observations) == 0 {
		t.Fatal("synthetic report lacks a final scenario observation")
	}
	report.Observations = report.Observations[:len(report.Observations)-1]
	report.ScenarioResults[lastScenario].Status = "incomplete"
	report.Phases[1].Status = "incomplete"
	report.RunOutcome = runOutcome{
		Outcome:            "incomplete",
		ReasonCodes:        []string{"missing_identity_or_evidence"},
		ScenarioCounts:     scenarioCounts{Passed: 19, Incomplete: 1},
		CleanupSatisfied:   true,
		IdentityComplete:   false,
		SanitizationPassed: true,
	}
	allCases := append(append([]profileCase{}, profile.Phases[0].Cases...), profile.Phases[1].Cases...)
	report.Counters, _ = calculateCounters(report.ScenarioResults, report.Observations, allCases)

	root := t.TempDir()
	inventory := writeSyntheticPayloads(t, root, &report)
	writeSyntheticReport(t, root, &report, inventory)
	result, err := Verify(context.Background(), root, sourceRoot)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.RunOutcome != "incomplete" || result.ValidationOutcome != "accepted" || result.FileCount != 7 {
		t.Fatalf("Verify() result = %+v", result)
	}
}

func TestVerifyAcceptsCompleteObservedFailure(t *testing.T) {
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	lastScenario := len(report.ScenarioResults) - 1
	lastObservation := len(report.Observations) - 1
	if lastScenario < 0 || lastObservation < 0 {
		t.Fatal("synthetic report lacks a final scenario observation")
	}
	report.Observations[lastObservation].Result = "contradicted"
	report.ScenarioResults[lastScenario].Status = "failed"
	report.Phases[1].Status = "failed"
	report.RunOutcome = runOutcome{
		Outcome:            "failed",
		ReasonCodes:        []string{"executed_mismatch"},
		ScenarioCounts:     scenarioCounts{Passed: 19, Failed: 1},
		CleanupSatisfied:   true,
		IdentityComplete:   true,
		SanitizationPassed: true,
	}
	allCases := append(append([]profileCase{}, profile.Phases[0].Cases...), profile.Phases[1].Cases...)
	report.Counters, _ = calculateCounters(report.ScenarioResults, report.Observations, allCases)

	root := t.TempDir()
	inventory := writeSyntheticPayloads(t, root, &report)
	writeSyntheticReport(t, root, &report, inventory)
	result, err := Verify(context.Background(), root, sourceRoot)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.RunOutcome != "failed" || result.ValidationOutcome != "accepted" || result.FileCount != 7 {
		t.Fatalf("Verify() result = %+v", result)
	}
}

func TestVerifyAcceptsMutationWithMissingInspectorAsIncomplete(t *testing.T) {
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	createScenario := -1
	for index, scenario := range report.ScenarioResults {
		if scenario.CaseID == "initial.protected-lifecycle-create" {
			createScenario = index
			break
		}
	}
	if createScenario < 0 {
		t.Fatal("synthetic report lacks protected lifecycle create scenario")
	}

	keptObservationBindings := map[string]struct{}{}
	keptAssertionIDs := map[string]struct{}{}
	for index := range report.ScenarioResults {
		scenario := &report.ScenarioResults[index]
		switch {
		case index < createScenario:
			for _, interaction := range scenario.Interactions {
				for _, id := range interaction.ObservationIDs {
					keptObservationBindings[id+"\x00"+interaction.InteractionID] = struct{}{}
				}
			}
			for _, assertion := range scenario.Assertions {
				keptAssertionIDs[assertion.ID] = struct{}{}
			}
		case index == createScenario:
			scenario.Status = "incomplete"
			for _, interaction := range scenario.Interactions {
				for _, id := range interaction.ObservationIDs {
					if id != "run-owned-sandbox-resource-count-one" {
						keptObservationBindings[id+"\x00"+interaction.InteractionID] = struct{}{}
					}
				}
			}
			for _, assertion := range scenario.Assertions {
				keptAssertionIDs[assertion.ID] = struct{}{}
			}
		default:
			scenario.Status = "not_executed"
			scenario.Interactions = []interactionResult{}
			scenario.Assertions = []assertionResult{}
			scenario.ObservationIDs = []string{}
		}
	}
	report.Phases[0].Status = "incomplete"
	report.Phases[1].Status = "not_executed"
	report.Observations = filterObservations(report.Observations, keptObservationBindings)
	report.Claims.CallerAssertions = filterCallerAssertions(report.Claims.CallerAssertions, keptAssertionIDs)
	report.Invocation.ShellChallenge = nil
	report.Topology["target_identity"] = nil
	for index := range report.Artifacts {
		if report.Artifacts[index].ObservedBy == "resource_inspector" {
			report.Artifacts[index].Digest = nil
			report.Artifacts[index].Source = nil
		}
	}
	report.Cleanup = cleanup{Authority: profile.Cleanup.Authority, MutationWriteObserved: true, CleanupRequired: true, Outcome: "unknown"}
	allCases := append(append([]profileCase{}, profile.Phases[0].Cases...), profile.Phases[1].Cases...)
	report.Counters, _ = calculateCounters(report.ScenarioResults, report.Observations, allCases)
	counts := scenarioCounts{}
	for _, scenario := range report.ScenarioResults {
		switch scenario.Status {
		case "passed":
			counts.Passed++
		case "incomplete":
			counts.Incomplete++
		case "not_executed":
			counts.NotExecuted++
		}
	}
	report.RunOutcome = runOutcome{
		Outcome:            "incomplete",
		ReasonCodes:        []string{"cleanup_unknown_or_failed", "missing_identity_or_evidence", "scenario_not_executed"},
		ScenarioCounts:     counts,
		CleanupSatisfied:   false,
		IdentityComplete:   false,
		SanitizationPassed: true,
	}

	root := t.TempDir()
	inventory := writeSyntheticPayloadsExcept(t, root, &report, "resource-inspector.json")
	writeSyntheticReport(t, root, &report, inventory)
	result, err := Verify(context.Background(), root, sourceRoot)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.RunOutcome != "incomplete" || result.ValidationOutcome != "accepted" || result.FileCount != 6 {
		t.Fatalf("Verify() result = %+v", result)
	}
}

func TestValidatePayloadBindingsRejectsShellChallengeWithoutProcessSupervisor(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticNotExecutedReport(profile)
	report.Invocation.ShellChallenge = syntheticPassingReport(profile).Invocation.ShellChallenge
	payloads := payloadSet{
		Gateway: &gatewayObserverPayload{
			InvocationID:   report.Invocation.InvocationID,
			Interactions:   []interactionResult{},
			Observations:   []observerFact{},
			ShellChallenge: report.Invocation.ShellChallenge,
		},
		DigestByPath: map[string]string{},
	}
	if err := validatePayloadBindings(report, validatorSemantics{}, payloads); err == nil || !strings.Contains(err.Error(), "shell continuity execution evidence") {
		t.Fatalf("validatePayloadBindings(shell challenge without process supervisor) error = %v", err)
	}
}

func TestValidateAbsentPayloadClaimsRejectsOwnedPositiveEvidence(t *testing.T) {
	profile := loadTestProfile(t)
	base := syntheticNotExecutedReport(profile)
	cloneReport := func(source reportDocument) reportDocument {
		result := source
		result.Topology = make(map[string]any, len(source.Topology))
		for key, value := range source.Topology {
			result.Topology[key] = value
		}
		result.Artifacts = append([]artifactIdentity(nil), source.Artifacts...)
		result.Configurations = append([]configuration(nil), source.Configurations...)
		result.Phases = append([]phase(nil), source.Phases...)
		result.ScenarioResults = append([]scenarioResult(nil), source.ScenarioResults...)
		result.Observations = append([]observation(nil), source.Observations...)
		return result
	}
	processArtifactIndex := -1
	inspectorArtifactIndex := -1
	for index, artifact := range base.Artifacts {
		switch artifact.ObservedBy {
		case "process_supervisor":
			if processArtifactIndex < 0 {
				processArtifactIndex = index
			}
		case "resource_inspector":
			if inspectorArtifactIndex < 0 {
				inspectorArtifactIndex = index
			}
		}
	}
	if processArtifactIndex < 0 || inspectorArtifactIndex < 0 || len(base.Configurations) == 0 {
		t.Fatal("synthetic report lacks payload-owned identity fields")
	}

	type absenceCase struct {
		name   string
		want   string
		mutate func(*reportDocument, *payloadSet, *[]interactionResult, *[]interactionResult)
	}
	source := &sourceIdentity{Kind: "release-id", Value: "synthetic-release", Immutable: true}
	cases := []absenceCase{
		{"provider interaction", "Provider request evidence", func(_ *reportDocument, _ *payloadSet, provider *[]interactionResult, _ *[]interactionResult) {
			*provider = []interactionResult{{Surface: "provider_http"}}
		}},
		{"provider sandbox resources", "Provider request evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.SandboxResources = &sandboxResources{}
		}},
		{"gateway interaction", "Gateway evidence", func(_ *reportDocument, _ *payloadSet, _ *[]interactionResult, gateway *[]interactionResult) {
			*gateway = []interactionResult{{Surface: "caller_gateway"}}
		}},
		{"gateway shell challenge", "Gateway evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.ShellChallenge = &shellChallenge{}
		}},
		{"process shell challenge", "shell continuity execution evidence", func(report *reportDocument, payloads *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			payloads.Gateway = &gatewayObserverPayload{}
			report.Invocation.ShellChallenge = &shellChallenge{}
		}},
		{"process initial invocation", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.InitialInvocationID = testStringPtr("initial")
		}},
		{"process reconstruction invocation", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.ReconstructionInvocationID = testStringPtr("reconstruction")
		}},
		{"process harness artifact", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.HarnessArtifactDigest = testStringPtr(testDigest)
		}},
		{"process startup identity", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.StartupIdentity = &startupIdentity{}
		}},
		{"process harness reinjection", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.HarnessReinjected = testBoolPtr(false)
		}},
		{"process initial processes", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.InitialProcesses = []processIdentity{{}}
		}},
		{"process reconstruction processes", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.ReconstructionProcesses = []processIdentity{{}}
		}},
		{"process restarted components", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.RestartedComponents = []string{"provider"}
		}},
		{"process preserved stores", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.PreservedStores = []string{"provider_state"}
		}},
		{"process adapter transcript", "process evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Invocation.AdapterTranscript = &adapterTranscript{}
		}},
		{"process artifact digest", "retains artifact", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Artifacts[processArtifactIndex].Digest = testStringPtr(testDigest)
		}},
		{"process artifact source", "retains artifact", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Artifacts[processArtifactIndex].Source = source
		}},
		{"process configuration digest", "retains configuration", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Configurations[0].Digest = testStringPtr(testDigest)
		}},
		{"process sanitized configuration", "retains configuration", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Configurations[0].Sanitized = true
		}},
		{"process scenario status", "executed scenario evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.ScenarioResults[0].Status = "passed"
		}},
		{"process scenario interaction", "executed scenario evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.ScenarioResults[0].Interactions = []interactionResult{{}}
		}},
		{"process scenario observation inventory", "executed scenario evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.ScenarioResults[0].ObservationIDs = []string{"observation"}
		}},
		{"process phase status", "execution phase evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Phases[0].Status = "passed"
		}},
		{"process observation", "retains observations", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Observations = []observation{{ID: "observation"}}
		}},
		{"inspector target", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Topology["target_identity"] = map[string]any{"target_digest": testDigest}
		}},
		{"inspector query scope", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.QueryScope = &queryScope{}
		}},
		{"inspector baseline", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.Baseline = &resourceInventory{}
		}},
		{"inspector post teardown", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.PostTeardown = &resourceInventory{}
		}},
		{"inspector teardown attempts", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.TeardownAttempts = 1
		}},
		{"inspector teardown completed", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.TeardownCompleted = true
		}},
		{"inspector stability samples", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.StabilitySamples = 3
		}},
		{"inspector stability interval", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.StabilityIntervalMS = 1000
		}},
		{"inspector successful outcome", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.Outcome = "succeeded"
		}},
		{"inspector mutation cleanup satisfaction", "cleanup or target evidence", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Cleanup.MutationWriteObserved = true
			report.RunOutcome.CleanupSatisfied = true
		}},
		{"inspector artifact digest", "retains artifact", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Artifacts[inspectorArtifactIndex].Digest = testStringPtr(testDigest)
		}},
		{"inspector artifact source", "retains artifact", func(report *reportDocument, _ *payloadSet, _ *[]interactionResult, _ *[]interactionResult) {
			report.Artifacts[inspectorArtifactIndex].Source = source
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := cloneReport(base)
			payloads := payloadSet{}
			var providerInteractions []interactionResult
			var gatewayInteractions []interactionResult
			tc.mutate(&report, &payloads, &providerInteractions, &gatewayInteractions)
			if err := validateAbsentPayloadClaims(report, payloads, providerInteractions, gatewayInteractions); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateAbsentPayloadClaims(%s) error = %v", tc.name, err)
			}
		})
	}
}

func TestAbsentObservationAndTrustedInputPayloadsRejectOwnedClaims(t *testing.T) {
	for _, source := range []string{"provider_observer", "gateway_observer", "process_supervisor", "resource_inspector"} {
		t.Run(source+" observation", func(t *testing.T) {
			reported := []observation{{ID: "observation", Source: source, Actor: "actor", Subject: "subject", Correlation: "correlation", Result: "observed", EvidenceDigest: testStringPtr(testDigest)}}
			if err := validateObservationPayloads(reported, validatorSemantics{}, payloadSet{}); err == nil || !strings.Contains(err.Error(), "has no source payload fact") {
				t.Fatalf("validateObservationPayloads(%s without payload) error = %v", source, err)
			}
		})
	}

	base := syntheticNotExecutedReport(loadTestProfile(t))
	for _, tc := range []struct {
		name   string
		mutate func(*reportDocument)
	}{
		{"trusted input", func(report *reportDocument) {
			report.Claims.TrustedInputs = []trustedInput{{ID: "external-caller-ownership", Source: "external_caller_owner", Digest: testDigest}}
		}},
		{"caller assertion", func(report *reportDocument) {
			report.Claims.CallerAssertions = []claimAssertion{{ID: "assertion", Owner: "external_caller_owner", Result: "asserted"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := base
			tc.mutate(&report)
			if err := validateTrustedInputPayload(report, validatorSemantics{}, payloadSet{}); err == nil || !strings.Contains(err.Error(), "claims have no trusted-input payload") {
				t.Fatalf("validateTrustedInputPayload(%s without payload) error = %v", tc.name, err)
			}
		})
	}
}

func TestVerifyRejectsPayloadChangedAfterReportInventory(t *testing.T) {
	sourceRoot := filepath.Clean(filepath.Join("..", ".."))
	report := syntheticPassingReport(loadTestProfile(t))
	root := t.TempDir()
	inventory := writeSyntheticPayloads(t, root, &report)
	var reportBytes []byte
	for attempts := 0; attempts < 8; attempts++ {
		var err error
		reportBytes, err = json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		reportBytes = append(reportBytes, '\n')
		inventoryWithReport := inventory
		inventoryWithReport.FileCount++
		inventoryWithReport.TotalBytes += int64(len(reportBytes))
		receiptBytes, _, err := makeReceipt(report, reportBytes, inventoryWithReport, testSemantics())
		if err != nil {
			t.Fatal(err)
		}
		want := inventoryWithReport.TotalBytes + int64(len(receiptBytes))
		if report.Evidence.TotalBytes == want {
			break
		}
		report.Evidence.TotalBytes = want
	}
	reportBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ReportFileName), append(reportBytes, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(root, "provider-observer.json")
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, append(payload, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), root, sourceRoot); err == nil {
		t.Fatal("Verify() accepted payload content that no longer matched the report inventory and bindings")
	}
}

func syntheticPassingReport(profile profileDocument) reportDocument {
	contract := contractIdentity{
		Namespace: profile.Contract.Namespace, Version: profile.Contract.Version, Revision: profile.Contract.Revision,
		Tree: profile.Contract.Tree, ManifestDigest: profile.Contract.ManifestDigest, OpenAPIDigest: profile.Contract.OpenAPIDigest,
		SemanticRulesDigest: profile.Contract.SemanticRulesDigest,
		LocalSuite:          syntheticSuite(profile.Contract.LocalSuite),
		RemoteSuite:         syntheticSuite(profile.Contract.RemoteSuite),
	}
	topology := make(map[string]any, len(profile.Topology)+1)
	for key, value := range profile.Topology {
		topology[key] = value
	}
	topology["distinct_tenants"] = topology["distinct_tenants_required"]
	delete(topology, "distinct_tenants_required")
	topology["target_identity"] = map[string]any{
		"target_digest": testDigest, "target_digest_profile": "sha256-canonical-target-description-v1",
		"architecture": "linux-amd64", "run_namespace_digest": testDigest, "run_namespace_digest_profile": "sha256-run-namespace-v1",
	}

	artifacts := make([]artifactIdentity, len(profile.Artifacts))
	artifactByID := map[string]artifactIdentity{}
	for index, expected := range profile.Artifacts {
		artifact := artifactIdentity{ArtifactID: expected.ID, Owner: expected.Owner, TrustDomain: expected.TrustDomain, DigestSubject: expected.DigestSubject, Digest: testStringPtr(testDigest), ObservedBy: expected.ObservedBy, Source: &sourceIdentity{Kind: "release-id", Value: expected.ID + "-release", Immutable: true}}
		artifacts[index] = artifact
		artifactByID[artifact.ArtifactID] = artifact
	}
	configurations := make([]configuration, len(profile.Evidence.RequiredInventories))
	configurationByID := map[string]configuration{}
	for index, id := range profile.Evidence.RequiredInventories {
		item := configuration{ID: id, Digest: testStringPtr(testDigest), DigestProfile: profile.Evidence.ConfigurationDigestProfile, Sanitized: true, ObservedBy: "process_supervisor"}
		configurations[index] = item
		configurationByID[id] = item
	}
	components := []string{"provider", "external_caller", "qualification_adapter", "caller_gateway"}
	configurationID := map[string]string{"provider": "provider_configuration", "external_caller": "caller_configuration", "qualification_adapter": "adapter_configuration", "caller_gateway": "gateway_configuration"}
	processes := func(prefix string) []processIdentity {
		result := make([]processIdentity, len(components))
		for index, component := range components {
			result[index] = processIdentity{Component: component, ProcessID: prefix + "-" + component, ExecutableDigest: *artifactByID[component].Digest, ConfigurationDigest: *configurationByID[configurationID[component]].Digest, ObservedBy: "process_supervisor"}
		}
		return result
	}

	base := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	phases := make([]phase, len(profile.Phases))
	scenarios := make([]scenarioResult, 0, 20)
	observations := make([]observation, 0, 91)
	callerAssertions := make([]claimAssertion, 0, 29)
	allCases := make([]profileCase, 0, 20)
	for phaseIndex, expectedPhase := range profile.Phases {
		allCases = append(allCases, expectedPhase.Cases...)
		caseIDs := make([]string, len(expectedPhase.Cases))
		phaseStart := base.Add(time.Duration(phaseIndex*16+1) * time.Second)
		phaseFinish := phaseStart.Add(time.Duration(len(expectedPhase.Cases)) * time.Second)
		for caseIndex, expectedCase := range expectedPhase.Cases {
			caseIDs[caseIndex] = expectedCase.CaseID
			interactions := make([]interactionResult, len(expectedCase.Interactions))
			scenarioObservationIDs := make([]string, 0)
			for interactionIndex, expectedInteraction := range expectedCase.Interactions {
				observationIDs := make([]string, len(expectedInteraction.Observations))
				for observationIndex, expectedObservation := range expectedInteraction.Observations {
					observationIDs[observationIndex] = expectedObservation.ID
					scenarioObservationIDs = append(scenarioObservationIDs, expectedObservation.ID)
					observations = append(observations, observation{ID: expectedObservation.ID, Source: expectedObservation.Source, Actor: expectedObservation.Actor, Subject: expectedObservation.Subject, Correlation: expectedObservation.Correlation, Result: "observed", EvidenceDigest: testStringPtr(testDigest)})
				}
				interactions[interactionIndex] = syntheticInteraction(expectedInteraction, observationIDs)
			}
			assertions := make([]assertionResult, len(expectedCase.Assertions))
			for assertionIndex, id := range expectedCase.Assertions {
				assertions[assertionIndex] = assertionResult{ID: id, Result: "asserted"}
				callerAssertions = append(callerAssertions, claimAssertion{ID: id, Owner: "external_caller_owner", Result: "asserted"})
			}
			scenarioStart := phaseStart.Add(time.Duration(caseIndex) * time.Second)
			scenarios = append(scenarios, scenarioResult{CaseID: expectedCase.CaseID, PhaseID: expectedPhase.PhaseID, Status: "passed", StartedAt: testStringPtr(scenarioStart.Format(time.RFC3339Nano)), FinishedAt: testStringPtr(scenarioStart.Add(time.Second).Format(time.RFC3339Nano)), Interactions: interactions, Assertions: assertions, ObservationIDs: scenarioObservationIDs})
		}
		phases[phaseIndex] = phase{PhaseID: expectedPhase.PhaseID, Status: "passed", ScenarioIDs: caseIDs, StartedAt: testStringPtr(phaseStart.Format(time.RFC3339Nano)), FinishedAt: testStringPtr(phaseFinish.Format(time.RFC3339Nano))}
	}

	report := reportDocument{
		FormatVersion: 1, ReportType: "sandbox-runtime-external-caller-qualification-report", ReportVersion: "1.0.0", ReportID: "synthetic-validator-test",
		Profile:  profileIdentity{ProfileID: qualificationprofile.ProfileID, ProfileVersion: qualificationprofile.ProfileVersion, ProfileDigest: qualificationprofile.ExpectedProfileDigest, SchemaDigest: qualificationprofile.ExpectedSchemaDigest, SchemaDigestProfile: evidencefiles.FileDigestProfile},
		Contract: contract, Capability: profile.CapabilitySelection, SandboxResources: &sandboxResources{CPUMillis: profile.Limits.SandboxCPUMillis, MemoryBytes: profile.Limits.SandboxMemoryBytes, EphemeralStorageBytes: profile.Limits.SandboxEphemeralStorageBytes, PIDs: profile.Limits.SandboxPIDs}, Topology: topology, Artifacts: artifacts, Configurations: configurations,
		Invocation: invocation{InvocationID: "synthetic-invocation", RuntimeCommitmentDigest: testDigest, InitialInvocationID: testStringPtr("initial-invocation"), ReconstructionInvocationID: testStringPtr("reconstruction-invocation"), HarnessArtifactDigest: artifactByID["qualification_harness"].Digest, StartupIdentity: &startupIdentity{CallerRelease: artifactByID["external_caller"].Source, AdapterRelease: artifactByID["qualification_adapter"].Source, ContractRevision: contract.Revision, ContractTree: contract.Tree, ProfileID: qualificationprofile.ProfileID, ProfileDigest: qualificationprofile.ExpectedProfileDigest, AdapterProtocolID: AdapterProtocolID, AdapterProtocolVersion: AdapterProtocolVersion, AdapterProtocolSchemaDigest: ExpectedAdapterProtocolSchemaDigest, AdapterProtocolSemanticsDigest: ExpectedAdapterProtocolSemanticsDigest}, InitialProcesses: processes("initial"), ReconstructionProcesses: processes("reconstruction"), RestartedComponents: profile.Reconstruction.RestartComponents, PreservedStores: profile.Reconstruction.PreserveStores, HarnessReinjected: testBoolPtr(false), AdapterTranscript: &adapterTranscript{Digest: testDigest, DigestProfile: "rfc8785-full-document-v1", InvocationIDs: []string{"initial-invocation", "reconstruction-invocation"}, AllowedFields: profile.Reconstruction.AdapterInvocation.AllowedFields, ForbiddenFields: profile.Reconstruction.ReinjectionForbidden, Sanitized: true, ObservedBy: "process_supervisor"}, ShellChallenge: &shellChallenge{Digest: testDigest, DigestProfile: "sha256-raw-challenge-bytes-v1", EstablishedInCase: profile.Reconstruction.ShellChallenge.Established, VerifiedInCase: profile.Reconstruction.ShellChallenge.Verified}},
		Phases:     phases, ScenarioResults: scenarios, Observations: observations,
		Cleanup:  cleanup{Authority: profile.Cleanup.Authority, MutationWriteObserved: true, CleanupRequired: true, QueryScope: &queryScope{DigestProfile: profile.Cleanup.QueryDigestProfile, TargetDigest: testStringPtr(testDigest), RunNamespaceDigest: testStringPtr(testDigest), OwnershipSelectorDigest: testStringPtr(testDigest), ResourceKinds: profile.Cleanup.InspectorScope, InspectorArtifactDigest: artifactByID["resource_inspector"].Digest, InspectorConfigurationDigest: configurationByID["inspector_configuration"].Digest, ExcludesHarnessControlPlane: true}, Baseline: &resourceInventory{DigestProfile: profile.Cleanup.InventoryDigestProfile, Stable: true}, TeardownAttempts: 1, TeardownCompleted: true, PostTeardown: &resourceInventory{DigestProfile: profile.Cleanup.InventoryDigestProfile, Stable: true}, StabilitySamples: profile.Cleanup.StabilitySamples, StabilityIntervalMS: profile.Cleanup.StabilityIntervalMS, Outcome: "succeeded"},
		Evidence: evidence{RootRelative: ".", PayloadInventoryDigestProfile: evidencefiles.DigestProfile, FileCount: 7, Sanitization: sanitization{Required: true, Status: "passed", ScannerIdentity: ExpectedValidatorSemanticsDigest}, Boundary: "sanitized-evidence-payload-excludes-private-material"},
		Claims: claims{CallerAssertions: callerAssertions, TrustedInputs: []trustedInput{
			{ID: "external-caller-ownership", Source: "external_caller_owner"},
			{ID: "source-hosting", Source: "external_caller_owner"},
			{ID: "build-system", Source: "external_caller_owner"},
			{ID: "operating-system", Source: "qualification_operator"},
			{ID: "network-path", Source: "qualification_operator"},
		}, NonClaims: profile.RequiredNonClaims},
		RunOutcome: runOutcome{Outcome: "passed", ReasonCodes: []string{}, ScenarioCounts: scenarioCounts{Passed: 20}, CleanupSatisfied: true, IdentityComplete: true, SanitizationPassed: true},
		Timestamps: timestamps{RunStartedAt: testStringPtr(base.Format(time.RFC3339Nano)), ExecutionStartedAt: testStringPtr(base.Format(time.RFC3339Nano)), ExecutionFinishedAt: testStringPtr(base.Add(25 * time.Second).Format(time.RFC3339Nano)), CleanupStartedAt: testStringPtr(base.Add(25 * time.Second).Format(time.RFC3339Nano)), CleanupFinishedAt: testStringPtr(base.Add(28 * time.Second).Format(time.RFC3339Nano)), RunFinishedAt: testStringPtr(base.Add(29 * time.Second).Format(time.RFC3339Nano))},
	}
	scopeDigest, err := queryScopeDigest(*report.Cleanup.QueryScope)
	if err != nil {
		panic(err)
	}
	report.Cleanup.QueryScope.Digest = &scopeDigest
	report.Cleanup.Baseline.QueryScopeDigest = &scopeDigest
	report.Cleanup.Baseline.Digest = testStringPtr(testDigest)
	report.Cleanup.Baseline.SampledAt = []string{base.Add(time.Nanosecond).Format(time.RFC3339Nano)}
	report.Cleanup.PostTeardown.QueryScopeDigest = &scopeDigest
	report.Cleanup.PostTeardown.Digest = testStringPtr(testDigest)
	report.Cleanup.PostTeardown.SampledAt = []string{base.Add(25 * time.Second).Format(time.RFC3339Nano), base.Add(26 * time.Second).Format(time.RFC3339Nano), base.Add(27 * time.Second).Format(time.RFC3339Nano)}
	report.Counters, _ = calculateCounters(report.ScenarioResults, report.Observations, allCases)
	return report
}

func syntheticNotExecutedReport(profile profileDocument) reportDocument {
	report := syntheticPassingReport(profile)
	report.SandboxResources = nil
	report.Topology["target_identity"] = nil
	for index := range report.Artifacts {
		report.Artifacts[index].Digest = nil
		report.Artifacts[index].Source = nil
	}
	for index := range report.Configurations {
		report.Configurations[index].Digest = nil
		report.Configurations[index].Sanitized = false
	}
	report.Invocation.InitialInvocationID = nil
	report.Invocation.ReconstructionInvocationID = nil
	report.Invocation.HarnessArtifactDigest = nil
	report.Invocation.StartupIdentity = nil
	report.Invocation.InitialProcesses = []processIdentity{}
	report.Invocation.ReconstructionProcesses = []processIdentity{}
	report.Invocation.RestartedComponents = []string{}
	report.Invocation.PreservedStores = []string{}
	report.Invocation.HarnessReinjected = nil
	report.Invocation.AdapterTranscript = nil
	report.Invocation.ShellChallenge = nil
	for index := range report.Phases {
		report.Phases[index].Status = "not_executed"
		report.Phases[index].StartedAt = nil
		report.Phases[index].FinishedAt = nil
	}
	for index := range report.ScenarioResults {
		report.ScenarioResults[index].Status = "not_executed"
		report.ScenarioResults[index].StartedAt = nil
		report.ScenarioResults[index].FinishedAt = nil
		report.ScenarioResults[index].Interactions = []interactionResult{}
		report.ScenarioResults[index].Assertions = []assertionResult{}
		report.ScenarioResults[index].ObservationIDs = []string{}
	}
	report.Observations = []observation{}
	report.Counters = counters{}
	report.Cleanup = cleanup{Authority: profile.Cleanup.Authority, Outcome: "not_required"}
	report.Evidence.PayloadInventory = []evidencefiles.Entry{}
	report.Evidence.FileCount = 2
	report.Claims.CallerAssertions = []claimAssertion{}
	report.Claims.TrustedInputs = []trustedInput{}
	report.RunOutcome = runOutcome{
		Outcome:            "not_executed",
		ReasonCodes:        []string{"prerequisite_unavailable", "scenario_not_executed", "missing_identity_or_evidence"},
		ScenarioCounts:     scenarioCounts{NotExecuted: 20},
		CleanupSatisfied:   true,
		IdentityComplete:   false,
		SanitizationPassed: true,
	}
	report.Timestamps = timestamps{}
	return report
}

func writeSyntheticPayloads(t *testing.T, root string, report *reportDocument) evidencefiles.Inventory {
	t.Helper()
	return writeSyntheticPayloadsExcept(t, root, report, "")
}

func writeSyntheticPayloadsExcept(t *testing.T, root string, report *reportDocument, omittedPath string) evidencefiles.Inventory {
	t.Helper()
	projection := syntheticTranscriptProjection(t, report)
	artifactByID := artifactMap(report.Artifacts)
	configurationByID := configurationMap(report.Configurations)
	providerInteractions, gatewayInteractions := splitInteractions(report.ScenarioResults)
	if providerInteractions == nil {
		providerInteractions = []interactionResult{}
	}
	if gatewayInteractions == nil {
		gatewayInteractions = []interactionResult{}
	}
	factsBySource := make(map[string][]observerFact)
	for _, item := range report.Observations {
		factsBySource[item.Source] = append(factsBySource[item.Source], observerFact{ID: item.ID, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: item.Result})
	}
	for _, source := range []string{"provider_observer", "gateway_observer", "process_supervisor", "resource_inspector"} {
		if factsBySource[source] == nil {
			factsBySource[source] = []observerFact{}
		}
	}
	trustedStatements := make([]trustedInputStatement, len(report.Claims.TrustedInputs))
	for index, item := range report.Claims.TrustedInputs {
		trustedStatements[index] = trustedInputStatement{ID: item.ID, Source: item.Source, SubjectDigest: testDigest}
	}
	payloads := map[string]any{
		"provider-observer.json": providerObserverPayload{
			FormatVersion: 1, PayloadType: "sandbox-runtime-provider-observer-evidence", PayloadVersion: "1.0.0",
			InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ObserverArtifactDigest: artifactByID["provider_observer"].Digest, ObserverConfigurationDigest: configurationByID["observer_configuration"].Digest,
			SandboxResources: report.SandboxResources, Interactions: providerInteractions, Observations: factsBySource["provider_observer"],
		},
		"gateway-observer.json": gatewayObserverPayload{
			FormatVersion: 1, PayloadType: "sandbox-runtime-gateway-observer-evidence", PayloadVersion: "1.0.0",
			InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ObserverArtifactDigest: artifactByID["gateway_observer"].Digest, ObserverConfigurationDigest: configurationByID["observer_configuration"].Digest,
			Interactions: gatewayInteractions, Observations: factsBySource["gateway_observer"], ShellChallenge: report.Invocation.ShellChallenge,
		},
		"process-supervisor.json": processSupervisorPayload{
			AdapterTranscriptProjection: projection,
			FormatVersion:               1, PayloadType: "sandbox-runtime-process-supervisor-evidence", PayloadVersion: "1.0.0",
			InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, SupervisorArtifactDigest: artifactByID["process_supervisor"].Digest, SupervisorConfigurationDigest: configurationByID["observer_configuration"].Digest,
			InitialInvocationID: report.Invocation.InitialInvocationID, ReconstructionInvocationID: report.Invocation.ReconstructionInvocationID, StartupIdentity: report.Invocation.StartupIdentity,
			ArtifactIdentities: filterArtifacts(report.Artifacts, "process_supervisor"), ConfigurationIdentities: report.Configurations, InitialProcesses: report.Invocation.InitialProcesses, ReconstructionProcesses: report.Invocation.ReconstructionProcesses,
			AdapterTranscript: report.Invocation.AdapterTranscript, RunTimestamps: report.Timestamps, Phases: report.Phases, ScenarioTimings: projectScenarioTimings(report.ScenarioResults), Observations: factsBySource["process_supervisor"],
		},
		"resource-inspector.json": resourceInspectorPayload{
			FormatVersion: 1, PayloadType: "sandbox-runtime-resource-inspector-evidence", PayloadVersion: "1.0.0",
			InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, InspectorArtifactDigest: artifactByID["resource_inspector"].Digest, InspectorConfigurationDigest: configurationByID["inspector_configuration"].Digest,
			TargetIdentity: report.Topology["target_identity"], ArtifactIdentities: filterArtifacts(report.Artifacts, "resource_inspector"), Cleanup: report.Cleanup, CleanupTimestamps: cleanupTimestamps{StartedAt: report.Timestamps.CleanupStartedAt, FinishedAt: report.Timestamps.CleanupFinishedAt}, Observations: factsBySource["resource_inspector"],
		},
		"trusted-inputs.json": trustedInputsPayload{
			FormatVersion: 1, PayloadType: "sandbox-runtime-trusted-input-evidence", PayloadVersion: "1.0.0", InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest,
			TrustedInputs: trustedStatements, CallerAssertions: report.Claims.CallerAssertions,
		},
	}
	for path, payload := range payloads {
		if path == omittedPath {
			continue
		}
		contents, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal %s: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(root, path), append(contents, '\n'), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	inventory, err := evidencefiles.Read(root, []string{ReportFileName, ReceiptFileName}, evidencefiles.DefaultOptions())
	if err != nil {
		t.Fatalf("inventory synthetic payloads: %v", err)
	}
	digestByPath := make(map[string]string, len(inventory.Entries))
	for _, entry := range inventory.Entries {
		digestByPath[entry.Path] = entry.SHA256
	}
	pathBySource := map[string]string{
		"provider_observer":  "provider-observer.json",
		"gateway_observer":   "gateway-observer.json",
		"process_supervisor": "process-supervisor.json",
		"resource_inspector": "resource-inspector.json",
	}
	for index := range report.Observations {
		report.Observations[index].EvidenceDigest = testStringPtr(digestByPath[pathBySource[report.Observations[index].Source]])
	}
	for index := range report.Claims.TrustedInputs {
		report.Claims.TrustedInputs[index].Digest = digestByPath["trusted-inputs.json"]
	}
	report.Evidence.PayloadInventory = inventory.Entries
	report.Evidence.PayloadInventoryDigest = inventory.Digest
	return inventory
}

func writeSyntheticReport(t *testing.T, root string, report *reportDocument, inventory evidencefiles.Inventory) {
	t.Helper()
	report.Evidence.FileCount = inventory.FileCount + 2
	var reportBytes []byte
	for attempts := 0; attempts < 8; attempts++ {
		var err error
		reportBytes, err = json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		reportBytes = append(reportBytes, '\n')
		inventoryWithReport := inventory
		inventoryWithReport.FileCount++
		inventoryWithReport.TotalBytes += int64(len(reportBytes))
		receiptBytes, _, err := makeReceipt(*report, reportBytes, inventoryWithReport, testSemantics())
		if err != nil {
			t.Fatal(err)
		}
		want := inventoryWithReport.TotalBytes + int64(len(receiptBytes))
		if report.Evidence.TotalBytes == want {
			break
		}
		report.Evidence.TotalBytes = want
	}
	if err := os.WriteFile(filepath.Join(root, ReportFileName), reportBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func filterObservations(items []observation, allowedBindings map[string]struct{}) []observation {
	result := make([]observation, 0, len(items))
	for _, item := range items {
		if _, ok := allowedBindings[item.ID+"\x00"+item.Subject]; ok {
			result = append(result, item)
		}
	}
	return result
}

func filterCallerAssertions(items []claimAssertion, allowedIDs map[string]struct{}) []claimAssertion {
	result := make([]claimAssertion, 0, len(items))
	for _, item := range items {
		if _, ok := allowedIDs[item.ID]; ok {
			result = append(result, item)
		}
	}
	return result
}

func syntheticSuite(expected profileSuite) suiteIdentity {
	return suiteIdentity{SuiteID: expected.SuiteID, SuiteVersion: expected.SuiteVersion, SuiteDigest: expected.SuiteDigest, SuiteDigestProfile: expected.SuiteDigestProfile, ProfileID: expected.ProfileID, CaseCount: expected.CaseCount, Outcome: "not_executed"}
}

func syntheticOutcome(outcome profileOutcome) reportOutcome {
	actual := reportOutcome{Transport: outcome.Transport, StatusCode: outcome.StatusCode}
	if outcome.Retryable != nil {
		actual.Retryable = *outcome.Retryable
	}
	if outcome.RetryAfter != nil {
		actual.RetryAfterPresent = *outcome.RetryAfter
	}
	if (outcome.ErrorPolicy == "exact" || outcome.ErrorPolicy == "one-of-exact") && len(outcome.ErrorCodes) > 0 {
		actual.ErrorCode = &outcome.ErrorCodes[0]
	}
	return actual
}

func syntheticInteraction(expected profileInteraction, observationIDs []string) interactionResult {
	actual := syntheticOutcome(expected.Outcomes[0])
	return interactionResult{InteractionID: expected.ID, Surface: expected.Surface, Actor: expected.Actor, Method: expected.Method, RouteTemplate: expected.Route, LogicalRequestID: expected.Logical, ReplayOf: expected.Replay, WireAttempts: 1, TransientOutcomes: []reportOutcome{}, FinalOutcome: actual, MutationWriteObserved: (expected.Surface == "provider_http" && expected.Method == "POST") || expected.Method == "CONTROL", ObservationIDs: observationIDs}
}

func TestDecodeStrictJSONRejectsDuplicateTrailingAndInvalidUTF8(t *testing.T) {
	tests := []struct {
		name string
		doc  []byte
	}{
		{name: "duplicate member", doc: []byte(`{"a":1,"a":2}`)},
		{name: "multiple values", doc: []byte(`{"a":1} {"b":2}`)},
		{name: "trailing data", doc: []byte(`{"a":1} trailing`)},
		{name: "invalid utf8", doc: []byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'}},
		{name: "invalid surrogate", doc: []byte(`{"a":"\ud800"}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var value any
			if err := decodeStrictJSON(test.doc, &value); err == nil {
				t.Fatalf("decodeStrictJSON(%q) accepted malformed JSON", test.doc)
			}
		})
	}
}

func TestSourceRevisionRequiresFullGitOrSHA256Identity(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(ReportSchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	short := map[string]any{"kind": "source-revision", "value": "abcdef1", "immutable": true}
	if err := validateSchemaReference(schema, "#/$defs/sourceIdentity", short); err == nil {
		t.Fatal("sourceIdentity schema accepted an abbreviated source revision")
	}
	full := map[string]any{"kind": "source-revision", "value": strings.Repeat("a", 40), "immutable": true}
	if err := validateSchemaReference(schema, "#/$defs/sourceIdentity", full); err != nil {
		t.Fatalf("sourceIdentity schema rejected a full Git revision: %v", err)
	}
}

func TestValidateObservationPayloadsUsesFullBindingAndOrderedProjection(t *testing.T) {
	digest := testDigest
	reported := []observation{
		{ID: "operation-succeeded", Source: "provider_observer", Actor: "controller_a", Subject: "operation-a", Correlation: "request-a", Result: "observed", EvidenceDigest: &digest},
		{ID: "operation-succeeded", Source: "provider_observer", Actor: "controller_a", Subject: "operation-b", Correlation: "request-b", Result: "observed", EvidenceDigest: &digest},
	}
	facts := []observerFact{
		{ID: "operation-succeeded", Actor: "controller_a", Subject: "operation-a", Correlation: "request-a", Result: "observed"},
		{ID: "operation-succeeded", Actor: "controller_a", Subject: "operation-b", Correlation: "request-b", Result: "observed"},
	}
	payloads := payloadSet{Provider: &providerObserverPayload{Observations: facts}, DigestByPath: map[string]string{"provider-observer.json": digest}}
	if err := validateObservationPayloads(reported, validatorSemantics{}, payloads); err != nil {
		t.Fatalf("validateObservationPayloads() rejected distinct bindings sharing one ID: %v", err)
	}
	payloads.Provider.Observations[0], payloads.Provider.Observations[1] = payloads.Provider.Observations[1], payloads.Provider.Observations[0]
	if err := validateObservationPayloads(reported, validatorSemantics{}, payloads); err == nil || !strings.Contains(err.Error(), "ordered source projection") {
		t.Fatalf("validateObservationPayloads() reorder error = %v", err)
	}
}

func TestValidateInvocationRejectsProcessOrderDrift(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	report.Invocation.InitialProcesses[0], report.Invocation.InitialProcesses[1] = report.Invocation.InitialProcesses[1], report.Invocation.InitialProcesses[0]
	if err := validateInvocation(report, profile.Reconstruction, true); err == nil || !strings.Contains(err.Error(), "locked reconstruction order") {
		t.Fatalf("validateInvocation() process-order error = %v", err)
	}
}

func TestValidateInvocationRejectsAdapterProtocolIdentityDrift(t *testing.T) {
	profile := loadTestProfile(t)
	for name, mutate := range map[string]func(*startupIdentity){
		"protocol id":      func(identity *startupIdentity) { identity.AdapterProtocolID = "substitute-protocol" },
		"protocol version": func(identity *startupIdentity) { identity.AdapterProtocolVersion = "9.9.9" },
		"schema digest":    func(identity *startupIdentity) { identity.AdapterProtocolSchemaDigest = testAlternateDigest },
		"semantics digest": func(identity *startupIdentity) { identity.AdapterProtocolSemanticsDigest = testAlternateDigest },
	} {
		t.Run(name, func(t *testing.T) {
			report := syntheticPassingReport(profile)
			mutate(report.Invocation.StartupIdentity)
			if err := validateInvocation(report, profile.Reconstruction, true); err == nil || !strings.Contains(err.Error(), "artifacts and locks") {
				t.Fatalf("validateInvocation() error = %v", err)
			}
			payloads := payloadSet{Provider: &providerObserverPayload{}, Gateway: &gatewayObserverPayload{}, ProcessSupervisor: &processSupervisorPayload{}, ResourceInspector: &resourceInspectorPayload{}, TrustedInputs: &trustedInputsPayload{}}
			if hasCompleteIdentity(report, testSemantics(), payloads) {
				t.Fatal("hasCompleteIdentity accepted drifted adapter protocol authority")
			}
		})
	}
}

func TestStartupIdentitySchemaRequiresAdapterProtocolAuthority(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(ReportSchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	profile := loadTestProfile(t)
	encoded, err := json.Marshal(syntheticPassingReport(profile).Invocation.StartupIdentity)
	if err != nil {
		t.Fatal(err)
	}
	var identity map[string]any
	if err := decodeStrictJSON(encoded, &identity); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"adapter_protocol_id", "adapter_protocol_version", "adapter_protocol_schema_digest", "adapter_protocol_semantics_digest"} {
		t.Run(field, func(t *testing.T) {
			candidate := make(map[string]any, len(identity))
			for key, value := range identity {
				candidate[key] = value
			}
			delete(candidate, field)
			if err := validateSchemaReference(schema, "#/$defs/startupIdentity", candidate); err == nil {
				t.Fatalf("startupIdentity schema accepted missing %s", field)
			}
		})
	}
}

func TestValidateLockedSemanticsRejectsAdapterProtocolAuthorityDrift(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(ValidatorSemanticsPath)))
	if err != nil {
		t.Fatal(err)
	}
	var semantics validatorSemantics
	if err := decodeStrictJSON(document, &semantics); err != nil {
		t.Fatal(err)
	}
	if err := validateLockedSemantics(semantics, ExpectedReportSchemaDigest); err != nil {
		t.Fatalf("locked semantics rejected: %v", err)
	}
	semantics.AdapterProtocol.Semantics.Digest = testAlternateDigest
	if err := validateLockedSemantics(semantics, ExpectedReportSchemaDigest); err == nil {
		t.Fatal("validator semantics accepted adapter protocol authority drift")
	}
}

func TestProcessSupervisorBindingRejectsAdapterProtocolIdentityDrift(t *testing.T) {
	report := syntheticPassingReport(loadTestProfile(t))
	artifactByID := artifactMap(report.Artifacts)
	configurationByID := configurationMap(report.Configurations)
	startup := *report.Invocation.StartupIdentity
	payload := &processSupervisorPayload{
		InvocationID:                  report.Invocation.InvocationID,
		RuntimeCommitmentDigest:       report.Invocation.RuntimeCommitmentDigest,
		SupervisorArtifactDigest:      artifactByID["process_supervisor"].Digest,
		SupervisorConfigurationDigest: configurationByID["observer_configuration"].Digest,
		InitialInvocationID:           report.Invocation.InitialInvocationID,
		ReconstructionInvocationID:    report.Invocation.ReconstructionInvocationID,
		StartupIdentity:               &startup,
		ArtifactIdentities:            filterArtifacts(report.Artifacts, "process_supervisor"),
		ConfigurationIdentities:       report.Configurations,
		InitialProcesses:              report.Invocation.InitialProcesses,
		ReconstructionProcesses:       report.Invocation.ReconstructionProcesses,
		AdapterTranscript:             report.Invocation.AdapterTranscript,
	}
	if !processSupervisorBindsReport(payload, report, artifactByID, configurationByID) {
		t.Fatal("process supervisor did not bind the matching report")
	}
	payload.StartupIdentity.AdapterProtocolSemanticsDigest = testAlternateDigest
	if processSupervisorBindsReport(payload, report, artifactByID, configurationByID) {
		t.Fatal("process supervisor binding accepted adapter protocol identity drift")
	}
}

func TestValidateReportSchemaRejectsUnknownField(t *testing.T) {
	schema := []byte(`{
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "$id":"urn:test:qualification-report",
                "type":"object",
                "additionalProperties":false,
                "required":["name"],
                "properties":{"name":{"type":"string"}}
        }`)
	var value any
	if err := decodeStrictJSON([]byte(`{"name":"ok","unknown":true}`), &value); err != nil {
		t.Fatalf("decodeStrictJSON() error = %v", err)
	}
	if err := validateReportSchema(schema, value); err == nil || !strings.Contains(err.Error(), "schema validation failed") {
		t.Fatalf("validateReportSchema() error = %v, want unknown-field rejection", err)
	}
}

func TestValidateReportSchemaAcceptsNotExecutedNullTimings(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticNotExecutedReport(profile)
	report.Evidence.PayloadInventoryDigest = testDigest
	report.Evidence.TotalBytes = 1
	document, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := decodeStrictJSON(document, &value); err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(ReportSchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateReportSchema(schema, value); err != nil {
		t.Fatalf("validateReportSchema() rejected not-executed null timings: %v", err)
	}
}

func TestValidateSuiteRejectsIdentityMismatch(t *testing.T) {
	valid := suiteIdentity{
		SuiteID:            "sandbox-provider",
		SuiteVersion:       "1.0.0",
		SuiteDigest:        "sha256:" + strings.Repeat("a", 64),
		SuiteDigestProfile: "rfc8785-full-document-excluding-suite-digest-v1",
		ProfileID:          "sandbox-runtime-provider-v1",
		CaseCount:          50,
		Outcome:            "not_executed",
	}
	expected := profileSuite{SuiteID: valid.SuiteID, SuiteVersion: valid.SuiteVersion, SuiteDigest: valid.SuiteDigest, SuiteDigestProfile: valid.SuiteDigestProfile, ProfileID: valid.ProfileID, CaseCount: valid.CaseCount}
	if err := validateSuite(valid, expected); err != nil {
		t.Fatalf("validateSuite(valid) error = %v", err)
	}
	for name, mutate := range map[string]func(*suiteIdentity){
		"wrong suite id":   func(value *suiteIdentity) { value.SuiteID = "other" },
		"wrong profile id": func(value *suiteIdentity) { value.ProfileID = "other" },
		"wrong case count": func(value *suiteIdentity) { value.CaseCount = 49 },
		"missing digest":   func(value *suiteIdentity) { value.SuiteDigest = "" },
		"missing outcome":  func(value *suiteIdentity) { value.Outcome = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateSuite(candidate, expected); err == nil {
				t.Fatal("validateSuite() accepted mismatched identity")
			}
		})
	}
}

func TestValidateSandboxResourcesBindsCreateInteractionAndProfile(t *testing.T) {
	profile := loadTestProfile(t)
	passing := syntheticPassingReport(profile)
	cloneReport := func(source reportDocument) reportDocument {
		result := source
		result.ScenarioResults = make([]scenarioResult, len(source.ScenarioResults))
		for index, scenario := range source.ScenarioResults {
			result.ScenarioResults[index] = scenario
			result.ScenarioResults[index].Interactions = append([]interactionResult(nil), scenario.Interactions...)
		}
		if source.SandboxResources != nil {
			resources := *source.SandboxResources
			result.SandboxResources = &resources
		}
		return result
	}
	if err := validateSandboxResources(passing, profile.Limits); err != nil {
		t.Fatalf("validateSandboxResources(valid) error = %v", err)
	}

	missingResources := cloneReport(passing)
	missingResources.SandboxResources = nil
	if err := validateSandboxResources(missingResources, profile.Limits); err == nil || !strings.Contains(err.Error(), "present iff create-sandbox") {
		t.Fatalf("validateSandboxResources(create without resources) error = %v", err)
	}

	withoutCreate := cloneReport(passing)
	for scenarioIndex := range withoutCreate.ScenarioResults {
		interactions := withoutCreate.ScenarioResults[scenarioIndex].Interactions
		for interactionIndex, interaction := range interactions {
			if interaction.InteractionID == "create-sandbox" {
				withoutCreate.ScenarioResults[scenarioIndex].Interactions = append(interactions[:interactionIndex], interactions[interactionIndex+1:]...)
			}
		}
	}
	if err := validateSandboxResources(withoutCreate, profile.Limits); err == nil || !strings.Contains(err.Error(), "present iff create-sandbox") {
		t.Fatalf("validateSandboxResources(resources without create) error = %v", err)
	}
	withoutCreate.SandboxResources = nil
	if err := validateSandboxResources(withoutCreate, profile.Limits); err != nil {
		t.Fatalf("validateSandboxResources(no create and no resources) error = %v", err)
	}

	duplicateCreate := cloneReport(passing)
	for scenarioIndex := range duplicateCreate.ScenarioResults {
		for _, interaction := range duplicateCreate.ScenarioResults[scenarioIndex].Interactions {
			if interaction.InteractionID == "create-sandbox" {
				duplicateCreate.ScenarioResults[scenarioIndex].Interactions = append(duplicateCreate.ScenarioResults[scenarioIndex].Interactions, interaction)
			}
		}
	}
	if err := validateSandboxResources(duplicateCreate, profile.Limits); err == nil || !strings.Contains(err.Error(), "duplicate create-sandbox") {
		t.Fatalf("validateSandboxResources(duplicate create) error = %v", err)
	}

	failedCreate := cloneReport(passing)
	for scenarioIndex := range failedCreate.ScenarioResults {
		for interactionIndex := range failedCreate.ScenarioResults[scenarioIndex].Interactions {
			interaction := &failedCreate.ScenarioResults[scenarioIndex].Interactions[interactionIndex]
			if interaction.InteractionID == "create-sandbox" {
				interaction.FinalOutcome = reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}
			}
		}
	}
	if err := validateSandboxResources(failedCreate, profile.Limits); err != nil {
		t.Fatalf("validateSandboxResources(failed create with request projection) error = %v", err)
	}
	failedCreate.SandboxResources = nil
	if err := validateSandboxResources(failedCreate, profile.Limits); err == nil || !strings.Contains(err.Error(), "present iff create-sandbox") {
		t.Fatalf("validateSandboxResources(failed create without request projection) error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*sandboxResources)
	}{
		{"cpu", func(value *sandboxResources) { value.CPUMillis++ }},
		{"memory", func(value *sandboxResources) { value.MemoryBytes++ }},
		{"ephemeral storage", func(value *sandboxResources) { value.EphemeralStorageBytes++ }},
		{"pids", func(value *sandboxResources) { value.PIDs++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneReport(passing)
			tc.mutate(candidate.SandboxResources)
			if err := validateSandboxResources(candidate, profile.Limits); err == nil || !strings.Contains(err.Error(), "locked profile") {
				t.Fatalf("validateSandboxResources(tampered %s) error = %v", tc.name, err)
			}
		})
	}
}

func TestProviderPayloadBindsSandboxResourcesBidirectionally(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticNotExecutedReport(profile)
	payload := &providerObserverPayload{
		InvocationID:            report.Invocation.InvocationID,
		RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest,
		Interactions:            []interactionResult{},
		Observations:            []observerFact{},
	}
	payloads := payloadSet{Provider: payload, DigestByPath: map[string]string{}}
	if err := validatePayloadBindings(report, validatorSemantics{}, payloads); err != nil {
		t.Fatalf("validatePayloadBindings(matching null resources) error = %v", err)
	}
	payload.RuntimeCommitmentDigest = testAlternateDigest
	if err := validatePayloadBindings(report, validatorSemantics{}, payloads); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("validatePayloadBindings(runtime commitment drift) error = %v", err)
	}
	payload.RuntimeCommitmentDigest = report.Invocation.RuntimeCommitmentDigest

	expected := sandboxResources{CPUMillis: profile.Limits.SandboxCPUMillis, MemoryBytes: profile.Limits.SandboxMemoryBytes, EphemeralStorageBytes: profile.Limits.SandboxEphemeralStorageBytes, PIDs: profile.Limits.SandboxPIDs}
	report.SandboxResources = &expected
	if err := validatePayloadBindings(report, validatorSemantics{}, payloads); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("validatePayloadBindings(report-only resources) error = %v", err)
	}
	payload.SandboxResources = &expected
	if err := validatePayloadBindings(report, validatorSemantics{}, payloads); err != nil {
		t.Fatalf("validatePayloadBindings(matching resources) error = %v", err)
	}
	report.SandboxResources = nil
	if err := validatePayloadBindings(report, validatorSemantics{}, payloads); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("validatePayloadBindings(payload-only resources) error = %v", err)
	}
}

func TestValidateArtifactsRejectsUnknownAndDuplicateArtifacts(t *testing.T) {
	want := []profileArtifact{{ID: "provider", Owner: "provider", TrustDomain: "release", DigestSubject: "executable_raw_bytes", ObservedBy: "process_supervisor", SourceRequired: true}}
	valid := []artifactIdentity{{
		ArtifactID:    "provider",
		Owner:         "provider",
		TrustDomain:   "release",
		DigestSubject: "executable_raw_bytes",
		Digest:        testStringPtr("sha256:" + strings.Repeat("a", 64)),
		ObservedBy:    "process_supervisor",
		Source:        &sourceIdentity{Kind: "release-id", Value: "provider-1", Immutable: true},
	}}
	if err := validateArtifacts(valid, want); err != nil {
		t.Fatalf("validateArtifacts(valid) error = %v", err)
	}
	unknown := append([]artifactIdentity(nil), valid...)
	unknown[0].ArtifactID = "unknown"
	if err := validateArtifacts(unknown, want); err == nil {
		t.Fatal("validateArtifacts() accepted unknown artifact")
	}
	duplicate := append(append([]artifactIdentity(nil), valid...), valid[0])
	if err := validateArtifacts(duplicate, append(want, want[0])); err == nil {
		t.Fatal("validateArtifacts() accepted duplicate artifact")
	}
}

func TestValidateInteractionRejectsWrongRouteAndOutcome(t *testing.T) {
	status := 202
	expected := profileInteraction{
		ID: "create", Surface: "provider_http", Actor: "controller_a", Method: "POST",
		Route: "/v1/sandboxes", Logical: "create", MaxWireAttempts: 1,
		Outcomes: []profileOutcome{{Transport: "http", StatusCode: &status, ErrorPolicy: "none"}}, Counts: []string{"provider_mutation_write_attempts"},
	}
	actual := interactionResult{
		InteractionID: "create", Surface: "provider_http", Actor: "controller_a", Method: "POST",
		RouteTemplate: "/v1/wrong", LogicalRequestID: "create", WireAttempts: 1,
		FinalOutcome: reportOutcome{Transport: "http", StatusCode: &status}, MutationWriteObserved: true, ObservationIDs: []string{},
	}
	if _, err := validateInteraction(actual, expected); err == nil {
		t.Fatal("validateInteraction() accepted wrong route")
	}
	actual.RouteTemplate = expected.Route
	actual.FinalOutcome.StatusCode = nil
	if matched, err := validateInteraction(actual, expected); err != nil || matched {
		t.Fatalf("validateInteraction() result = (%t, %v), want recorded behavioral mismatch", matched, err)
	}
}

func TestValidateInteractionRejectsMutationFlagBypass(t *testing.T) {
	status := 202
	expected := profileInteraction{
		ID: "create", Surface: "provider_http", Actor: "controller_a", Method: "POST", Route: "/v1/sandboxes", Logical: "create", MaxWireAttempts: 1,
		Outcomes: []profileOutcome{{Transport: "http-response", StatusCode: &status, ErrorPolicy: "none"}}, Counts: []string{"provider_http_requests", "provider_mutation_write_attempts"},
	}
	actual := interactionResult{
		InteractionID: "create", Surface: expected.Surface, Actor: expected.Actor, Method: expected.Method, RouteTemplate: expected.Route, LogicalRequestID: expected.Logical,
		WireAttempts: 1, FinalOutcome: reportOutcome{Transport: "http-response", StatusCode: &status}, MutationWriteObserved: false, ObservationIDs: []string{},
	}
	if _, err := validateInteraction(actual, expected); err == nil || !strings.Contains(err.Error(), "mutation-write flag") {
		t.Fatalf("validateInteraction() mutation bypass error = %v", err)
	}
	expected.Counts = []string{"provider_http_requests"}
	actual.MutationWriteObserved = true
	if _, err := validateInteraction(actual, expected); err == nil || !strings.Contains(err.Error(), "mutation-write flag") {
		t.Fatalf("validateInteraction() false mutation claim error = %v", err)
	}
}

func TestInteractionWireAttemptBoundsMatchReportAndProfile(t *testing.T) {
	profile := loadTestProfile(t)
	var expected64, expected2 profileInteraction
	for _, phase := range profile.Phases {
		for _, candidate := range phase.Cases {
			for _, interaction := range candidate.Interactions {
				switch {
				case interaction.MaxWireAttempts == 64 && expected64.ID == "":
					expected64 = interaction
				case interaction.MaxWireAttempts == 2 && expected2.ID == "":
					expected2 = interaction
				}
			}
		}
	}
	if expected64.ID == "" || expected2.ID == "" || len(expected64.Transient) == 0 || len(expected2.Transient) == 0 {
		t.Fatal("locked profile lacks expected wire-attempt boundary fixtures")
	}
	observationIDs := func(expected profileInteraction) []string {
		result := make([]string, len(expected.Observations))
		for index, item := range expected.Observations {
			result[index] = item.ID
		}
		return result
	}
	withAttempts := func(expected profileInteraction, transientCount, wireAttempts int) interactionResult {
		result := syntheticInteraction(expected, observationIDs(expected))
		result.WireAttempts = wireAttempts
		result.TransientOutcomes = make([]reportOutcome, transientCount)
		for index := range result.TransientOutcomes {
			result.TransientOutcomes[index] = syntheticOutcome(expected.Transient[0])
		}
		return result
	}

	maximum := withAttempts(expected64, 63, 64)
	if matched, err := validateInteraction(maximum, expected64); err != nil || !matched {
		t.Fatalf("validateInteraction(63 transient + final) = (%t, %v)", matched, err)
	}
	for _, tc := range []struct {
		name     string
		actual   interactionResult
		expected profileInteraction
	}{
		{"transient count exceeds wire relation", withAttempts(expected64, 64, 64), expected64},
		{"wire attempts exceed report maximum", withAttempts(expected64, 63, 65), expected64},
		{"wire attempts exceed profile maximum", withAttempts(expected2, 2, 3), expected2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateInteraction(tc.actual, tc.expected); err == nil || !strings.Contains(err.Error(), "wire-attempt count") {
				t.Fatalf("validateInteraction() error = %v", err)
			}
		})
	}
}

func TestValidateInteractionAcceptsLockedNonRetryablePollingTransient(t *testing.T) {
	profile := loadTestProfile(t)
	var expected profileInteraction
	for _, phase := range profile.Phases {
		for _, candidate := range phase.Cases {
			for _, interaction := range candidate.Interactions {
				if interaction.ID == "read-create-operation" {
					expected = interaction
				}
			}
		}
	}
	var polling *profileOutcome
	for index := range expected.Transient {
		candidate := &expected.Transient[index]
		if candidate.StatusCode != nil && *candidate.StatusCode == 200 && candidate.Retryable != nil && !*candidate.Retryable {
			polling = candidate
			break
		}
	}
	if expected.ID == "" || polling == nil {
		t.Fatal("locked lifecycle interaction lacks a non-retryable 200 polling transient")
	}
	observationIDs := make([]string, len(expected.Observations))
	observations := make(map[string]observation, len(expected.Observations))
	for index, item := range expected.Observations {
		observationIDs[index] = item.ID
		digest := testDigest
		observations[observationKey(item)] = observation{ID: item.ID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: "observed", EvidenceDigest: &digest}
	}
	actual := syntheticInteraction(expected, observationIDs)
	actual.WireAttempts = 2
	actual.TransientOutcomes = []reportOutcome{syntheticOutcome(*polling)}
	if matched, err := validateInteraction(actual, expected); err != nil || !matched {
		t.Fatalf("validateInteraction(non-retryable polling transient) = (%t, %v)", matched, err)
	}
	if !interactionMatchesExpectedEvidence(actual, expected, observations) {
		t.Fatal("resource accounting rejected the locked non-retryable polling transient")
	}
}

func TestReportSchemaEnforcesTransientAndWireAttemptBounds(t *testing.T) {
	profile := loadTestProfile(t)
	schema, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(ReportSchemaPath)))
	if err != nil {
		t.Fatal(err)
	}
	validate := func(t *testing.T, transientCount, wireAttempts int) error {
		t.Helper()
		report := syntheticPassingReport(profile)
		found := false
		for scenarioIndex := range report.ScenarioResults {
			for interactionIndex := range report.ScenarioResults[scenarioIndex].Interactions {
				interaction := &report.ScenarioResults[scenarioIndex].Interactions[interactionIndex]
				if interaction.InteractionID != "controller-a-capabilities" {
					continue
				}
				interaction.WireAttempts = wireAttempts
				interaction.TransientOutcomes = make([]reportOutcome, transientCount)
				for index := range interaction.TransientOutcomes {
					interaction.TransientOutcomes[index] = reportOutcome{Transport: "http-response", StatusCode: testIntPtr(503), Retryable: true}
				}
				found = true
			}
		}
		if !found {
			t.Fatal("synthetic report lacks controller-a-capabilities")
		}
		report.Evidence.PayloadInventoryDigest = testDigest
		report.Evidence.PayloadInventory = []evidencefiles.Entry{}
		report.Evidence.TotalBytes = 1
		for index := range report.Claims.TrustedInputs {
			report.Claims.TrustedInputs[index].Digest = testDigest
		}
		document, err := json.Marshal(report)
		if err != nil {
			return err
		}
		var value any
		if err := decodeStrictJSON(document, &value); err != nil {
			return err
		}
		return validateReportSchema(schema, value)
	}

	if err := validate(t, 63, 64); err != nil {
		t.Fatalf("report schema rejected 63 transient outcomes plus final: %v", err)
	}
	for name, test := range map[string]struct {
		transientCount int
		wireAttempts   int
	}{
		"64 transient outcomes": {transientCount: 64, wireAttempts: 64},
		"65 wire attempts":      {transientCount: 63, wireAttempts: 65},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validate(t, test.transientCount, test.wireAttempts); err == nil || !strings.Contains(err.Error(), "schema validation failed") {
				t.Fatalf("validateReportSchema() error = %v", err)
			}
		})
	}
}

func TestValidateScenarioRejectsExtraInteraction(t *testing.T) {
	actual := scenarioResult{
		CaseID: "initial.empty", PhaseID: "initial", Status: "passed",
		Interactions: []interactionResult{{InteractionID: "unexpected"}},
	}
	expected := profileCase{CaseID: "initial.empty"}
	if err := validateScenario(actual, expected, map[string]observation{}, map[string]struct{}{}, true); err == nil || !strings.Contains(err.Error(), "extra interactions") {
		t.Fatalf("validateScenario() error = %v, want extra-interaction rejection", err)
	}
}

func TestValidateScenarioAcceptsRecordedBehavioralFailure(t *testing.T) {
	wantStatus := 202
	gotStatus := 500
	expected := profileCase{CaseID: "initial.failure", Assertions: []string{"expected-behavior"}, Interactions: []profileInteraction{{
		ID: "request", Surface: "provider_http", Actor: "controller_a", Method: "GET", Route: "/v1/capabilities", Logical: "request", MaxWireAttempts: 1,
		Outcomes: []profileOutcome{{Transport: "http-response", StatusCode: &wantStatus, ErrorPolicy: "none"}},
	}}}
	actual := scenarioResult{CaseID: expected.CaseID, PhaseID: "initial", Status: "failed", Assertions: []assertionResult{{ID: "expected-behavior", Result: "asserted"}}, Interactions: []interactionResult{{
		InteractionID: "request", Surface: "provider_http", Actor: "controller_a", Method: "GET", RouteTemplate: "/v1/capabilities", LogicalRequestID: "request", WireAttempts: 1,
		TransientOutcomes: []reportOutcome{}, FinalOutcome: reportOutcome{Transport: "http-response", StatusCode: &gotStatus}, ObservationIDs: []string{},
	}}, ObservationIDs: []string{}}
	if err := validateScenario(actual, expected, map[string]observation{}, map[string]struct{}{}, true); err != nil {
		t.Fatalf("validateScenario() rejected a coherent behavioral failure: %v", err)
	}
}

func TestValidateScenarioRejectsMissingInteractionAsExecutedFailure(t *testing.T) {
	expected := profileCase{CaseID: "initial.failure", Interactions: []profileInteraction{{ID: "request"}}}
	actual := scenarioResult{CaseID: expected.CaseID, PhaseID: "initial", Status: "failed", Interactions: []interactionResult{}, Assertions: []assertionResult{}, ObservationIDs: []string{}}
	if err := validateScenario(actual, expected, map[string]observation{}, map[string]struct{}{}, false); err == nil || !strings.Contains(err.Error(), "no observed mismatch") {
		t.Fatalf("validateScenario() missing-interaction failure error = %v", err)
	}
}

func TestValidateScenarioRejectsPassedCaseWithMissingRequiredObservation(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	const caseID = "initial.protected-lifecycle-create"
	var expected profileCase
	var actual scenarioResult
	for _, candidate := range profile.Phases[0].Cases {
		if candidate.CaseID == caseID {
			expected = candidate
			break
		}
	}
	for _, candidate := range report.ScenarioResults {
		if candidate.CaseID == caseID {
			actual = candidate
			break
		}
	}
	if expected.CaseID == "" || actual.CaseID == "" {
		t.Fatal("synthetic profile or report lacks protected lifecycle create case")
	}

	allObservations := make(map[string]observation, len(report.Observations))
	for _, item := range report.Observations {
		item.EvidenceDigest = testStringPtr(testDigest)
		allObservations[observationKey(profileObservation{ID: item.ID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation})] = item
	}
	var inspectorObservation profileObservation
	for _, interaction := range expected.Interactions {
		for _, item := range interaction.Observations {
			if item.ID == "run-owned-sandbox-resource-count-one" {
				inspectorObservation = item
			}
		}
	}
	if inspectorObservation.ID == "" {
		t.Fatal("profile lacks run-owned sandbox resource observation")
	}
	inspectorKey := observationKey(inspectorObservation)
	if err := validateScenario(actual, expected, allObservations, map[string]struct{}{}, false); err != nil {
		t.Fatalf("validateScenario(passed with all required observations) error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]observation)
	}{
		{"absent", func(items map[string]observation) { delete(items, inspectorKey) }},
		{"reported missing", func(items map[string]observation) {
			item := items[inspectorKey]
			item.Result = "missing"
			items[inspectorKey] = item
		}},
		{"without evidence digest", func(items map[string]observation) {
			item := items[inspectorKey]
			item.EvidenceDigest = nil
			items[inspectorKey] = item
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observations := make(map[string]observation, len(allObservations))
			for key, item := range allObservations {
				observations[key] = item
			}
			tc.mutate(observations)
			if err := validateScenario(actual, expected, observations, map[string]struct{}{}, false); err == nil || !strings.Contains(err.Error(), "has an unmet expectation") {
				t.Fatalf("validateScenario(passed with %s required observation) error = %v", tc.name, err)
			}
			incomplete := actual
			incomplete.Status = "incomplete"
			if err := validateScenario(incomplete, expected, observations, map[string]struct{}{}, false); err != nil {
				t.Fatalf("validateScenario(incomplete with %s required observation) error = %v", tc.name, err)
			}
		})
	}
	incomplete := actual
	incomplete.Status = "incomplete"
	if err := validateScenario(incomplete, expected, allObservations, map[string]struct{}{}, false); err == nil || !strings.Contains(err.Error(), "must contain missing evidence") {
		t.Fatalf("validateScenario(complete evidence marked incomplete) error = %v", err)
	}
}

func TestValidateCleanupRejectsUnstableOrIncompleteTeardown(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := cleanup{
		Authority:             "operator-owned-run-namespace-teardown-within-disposable-target",
		MutationWriteObserved: false,
		CleanupRequired:       false,
		QueryScope:            &queryScope{Digest: testStringPtr(digest), DigestProfile: "rfc8785-full-document-v1", ResourceKinds: []string{"runtime_allocations", "compute_resources", "network_resources", "storage_resources", "run_owned_processes"}, ExcludesHarnessControlPlane: true},
		Baseline:              &resourceInventory{QueryScopeDigest: testStringPtr(digest), Digest: testStringPtr(digest), DigestProfile: "rfc8785-full-document-v1", Stable: true},
		PostTeardown:          &resourceInventory{QueryScopeDigest: testStringPtr(digest), Digest: testStringPtr(digest), DigestProfile: "rfc8785-full-document-v1", Stable: true},
		StabilitySamples:      3,
		StabilityIntervalMS:   1000,
		Outcome:               "not_required",
	}
	expected := profileCleanup{Authority: valid.Authority, QueryDigestProfile: valid.QueryScope.DigestProfile, ExcludesControlPlane: true, InspectorScope: valid.QueryScope.ResourceKinds, InventoryDigestProfile: valid.Baseline.DigestProfile, StabilitySamples: 3, StabilityIntervalMS: 1000}
	valid.QueryScope.TargetDigest = testStringPtr(digest)
	valid.QueryScope.RunNamespaceDigest = testStringPtr(digest)
	valid.QueryScope.OwnershipSelectorDigest = testStringPtr(digest)
	valid.QueryScope.InspectorArtifactDigest = testStringPtr(digest)
	valid.QueryScope.InspectorConfigurationDigest = testStringPtr(digest)
	validScopeDigest, _ := queryScopeDigest(*valid.QueryScope)
	valid.QueryScope.Digest = testStringPtr(validScopeDigest)
	*valid.Baseline.QueryScopeDigest = validScopeDigest
	*valid.PostTeardown.QueryScopeDigest = validScopeDigest
	if satisfied, err := validateCleanup(valid, expected, false); err != nil || !satisfied {
		t.Fatalf("validateCleanup(valid) error = %v", err)
	}
	unstable := valid
	unstableBaseline := *valid.Baseline
	unstableBaseline.Stable = false
	unstable.Baseline = &unstableBaseline
	if _, err := validateCleanup(unstable, expected, false); err == nil {
		t.Fatal("validateCleanup() accepted unstable baseline")
	}
	incomplete := valid
	incomplete.MutationWriteObserved = true
	incomplete.CleanupRequired = true
	incomplete.Outcome = "failed"
	incomplete.TeardownAttempts = 1
	if satisfied, err := validateCleanup(incomplete, expected, true); err != nil || satisfied {
		t.Fatalf("validateCleanup() result = (%t, %v), want coherent incomplete cleanup", satisfied, err)
	}
	unknownWithoutInspector := cleanup{Authority: valid.Authority, MutationWriteObserved: true, CleanupRequired: true, Outcome: "unknown"}
	if satisfied, err := validateCleanup(unknownWithoutInspector, expected, true); err != nil || satisfied {
		t.Fatalf("validateCleanup(unknown without inspector) result = (%t, %v), want coherent incomplete cleanup", satisfied, err)
	}
	if err := validateAbsentPayloadClaims(reportDocument{Cleanup: unknownWithoutInspector}, payloadSet{Provider: &providerObserverPayload{}, Gateway: &gatewayObserverPayload{}, ProcessSupervisor: &processSupervisorPayload{}, TrustedInputs: &trustedInputsPayload{}}, nil, nil); err != nil {
		t.Fatalf("validateAbsentPayloadClaims(unknown cleanup without inspector) error = %v", err)
	}
}

func TestValidateCleanupRejectsNilDigestAsSuccessfulRestoration(t *testing.T) {
	digest := testStringPtr(testDigest)
	actual := cleanup{
		Authority: "operator-owned-run-namespace-teardown-within-disposable-target", MutationWriteObserved: true, CleanupRequired: true,
		QueryScope: &queryScope{DigestProfile: "rfc8785-full-document-v1", TargetDigest: digest, RunNamespaceDigest: digest, OwnershipSelectorDigest: digest, ResourceKinds: []string{"runtime_allocations"}, InspectorArtifactDigest: digest, InspectorConfigurationDigest: digest, ExcludesHarnessControlPlane: true},
		Baseline:   &resourceInventory{QueryScopeDigest: digest, Digest: digest, DigestProfile: "rfc8785-full-document-v1", Stable: true}, TeardownAttempts: 1, TeardownCompleted: true,
		PostTeardown: &resourceInventory{QueryScopeDigest: digest, Digest: digest, DigestProfile: "rfc8785-full-document-v1", Stable: true}, StabilitySamples: 3, StabilityIntervalMS: 1000, Outcome: "succeeded",
	}
	expected := profileCleanup{Authority: actual.Authority, QueryDigestProfile: "rfc8785-full-document-v1", ExcludesControlPlane: true, InspectorScope: []string{"runtime_allocations"}, InventoryDigestProfile: "rfc8785-full-document-v1", StabilitySamples: 3, StabilityIntervalMS: 1000}
	actualScopeDigest, _ := queryScopeDigest(*actual.QueryScope)
	actual.QueryScope.Digest = testStringPtr(actualScopeDigest)
	actual.Baseline.QueryScopeDigest = testStringPtr(actualScopeDigest)
	actual.PostTeardown.QueryScopeDigest = testStringPtr(actualScopeDigest)
	if satisfied, err := validateCleanup(actual, expected, true); err != nil || !satisfied {
		t.Fatalf("validateCleanup(valid) = (%t, %v)", satisfied, err)
	}
	for name, mutate := range map[string]func(*cleanup){
		"scope digest":          func(item *cleanup) { copy := *item.QueryScope; copy.Digest = nil; item.QueryScope = &copy },
		"baseline scope digest": func(item *cleanup) { copy := *item.Baseline; copy.QueryScopeDigest = nil; item.Baseline = &copy },
		"baseline digest":       func(item *cleanup) { copy := *item.Baseline; copy.Digest = nil; item.Baseline = &copy },
		"post scope digest": func(item *cleanup) {
			copy := *item.PostTeardown
			copy.QueryScopeDigest = nil
			item.PostTeardown = &copy
		},
		"post digest": func(item *cleanup) { copy := *item.PostTeardown; copy.Digest = nil; item.PostTeardown = &copy },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := actual
			mutate(&candidate)
			if satisfied, err := validateCleanup(candidate, expected, true); err == nil || satisfied {
				t.Fatalf("validateCleanup(nil %s) = (%t, %v)", name, satisfied, err)
			}
		})
	}
	mismatched := actual
	mismatched.PostTeardown = &resourceInventory{QueryScopeDigest: testStringPtr("sha256:" + strings.Repeat("b", 64)), Digest: digest, DigestProfile: "rfc8785-full-document-v1", Stable: true}
	if satisfied, err := validateCleanup(mismatched, expected, true); err == nil || satisfied {
		t.Fatalf("validateCleanup(mismatched query scope) = (%t, %v)", satisfied, err)
	}
}

func TestValidateCleanupRejectsQueryScopeIdentityTamperingAndPartialBindings(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	cloneCleanup := func(source cleanup) cleanup {
		result := source
		scope := *source.QueryScope
		baseline := *source.Baseline
		post := *source.PostTeardown
		result.QueryScope = &scope
		result.Baseline = &baseline
		result.PostTeardown = &post
		return result
	}
	rebind := func(t *testing.T, value *cleanup) {
		t.Helper()
		digest, err := queryScopeDigest(*value.QueryScope)
		if err != nil {
			t.Fatal(err)
		}
		value.QueryScope.Digest = testStringPtr(digest)
		value.Baseline.QueryScopeDigest = testStringPtr(digest)
		value.PostTeardown.QueryScopeDigest = testStringPtr(digest)
	}
	fields := []struct {
		name   string
		clear  func(*queryScope)
		tamper func(*queryScope)
	}{
		{"target", func(scope *queryScope) { scope.TargetDigest = nil }, func(scope *queryScope) { scope.TargetDigest = testStringPtr(testAlternateDigest) }},
		{"run namespace", func(scope *queryScope) { scope.RunNamespaceDigest = nil }, func(scope *queryScope) { scope.RunNamespaceDigest = testStringPtr(testAlternateDigest) }},
		{"ownership selector", func(scope *queryScope) { scope.OwnershipSelectorDigest = nil }, func(scope *queryScope) { scope.OwnershipSelectorDigest = testStringPtr(testAlternateDigest) }},
		{"inspector artifact", func(scope *queryScope) { scope.InspectorArtifactDigest = nil }, func(scope *queryScope) { scope.InspectorArtifactDigest = testStringPtr(testAlternateDigest) }},
		{"inspector configuration", func(scope *queryScope) { scope.InspectorConfigurationDigest = nil }, func(scope *queryScope) { scope.InspectorConfigurationDigest = testStringPtr(testAlternateDigest) }},
	}
	for _, tc := range fields {
		t.Run("partial "+tc.name, func(t *testing.T) {
			candidate := cloneCleanup(report.Cleanup)
			tc.clear(candidate.QueryScope)
			if satisfied, err := validateCleanup(candidate, profile.Cleanup, true); err == nil || satisfied || !strings.Contains(err.Error(), "all empty or all complete") {
				t.Fatalf("validateCleanup(partial %s) = (%t, %v)", tc.name, satisfied, err)
			}
		})
		t.Run("digest tamper "+tc.name, func(t *testing.T) {
			candidate := cloneCleanup(report.Cleanup)
			tc.tamper(candidate.QueryScope)
			if satisfied, err := validateCleanup(candidate, profile.Cleanup, true); err == nil || satisfied || !strings.Contains(err.Error(), "digest does not match") {
				t.Fatalf("validateCleanup(tampered %s) = (%t, %v)", tc.name, satisfied, err)
			}
		})
	}

	t.Run("all empty bindings", func(t *testing.T) {
		candidate := cleanup{
			Authority: profile.Cleanup.Authority,
			QueryScope: &queryScope{
				DigestProfile:               profile.Cleanup.QueryDigestProfile,
				ResourceKinds:               profile.Cleanup.InspectorScope,
				ExcludesHarnessControlPlane: profile.Cleanup.ExcludesControlPlane,
			},
			Outcome: "not_required",
		}
		if satisfied, err := validateCleanup(candidate, profile.Cleanup, false); err != nil || !satisfied {
			t.Fatalf("validateCleanup(all-empty query scope) = (%t, %v)", satisfied, err)
		}
		if err := validateCleanupScopeBindings(reportDocument{Cleanup: candidate}); err != nil {
			t.Fatalf("validateCleanupScopeBindings(all-empty query scope) error = %v", err)
		}
	})

	t.Run("digest without bindings", func(t *testing.T) {
		candidate := cleanup{
			Authority: profile.Cleanup.Authority,
			QueryScope: &queryScope{
				Digest:                      testStringPtr(testDigest),
				DigestProfile:               profile.Cleanup.QueryDigestProfile,
				ResourceKinds:               profile.Cleanup.InspectorScope,
				ExcludesHarnessControlPlane: profile.Cleanup.ExcludesControlPlane,
			},
			Outcome: "not_required",
		}
		if satisfied, err := validateCleanup(candidate, profile.Cleanup, false); err == nil || satisfied || !strings.Contains(err.Error(), "all empty or all complete") {
			t.Fatalf("validateCleanup(query scope digest without bindings) = (%t, %v)", satisfied, err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*queryScope)
	}{
		{"target", fields[0].tamper},
		{"run namespace", fields[1].tamper},
		{"inspector artifact", fields[3].tamper},
		{"inspector configuration", fields[4].tamper},
	} {
		t.Run("cross binding "+tc.name, func(t *testing.T) {
			candidate := report
			candidate.Cleanup = cloneCleanup(report.Cleanup)
			tc.mutate(candidate.Cleanup.QueryScope)
			rebind(t, &candidate.Cleanup)
			if satisfied, err := validateCleanup(candidate.Cleanup, profile.Cleanup, true); err != nil || !satisfied {
				t.Fatalf("validateCleanup(rebound %s) = (%t, %v)", tc.name, satisfied, err)
			}
			if err := validateCleanupScopeBindings(candidate); err == nil {
				t.Fatalf("validateCleanupScopeBindings() accepted rebound %s", tc.name)
			}
		})
	}
}

func TestValidateCleanupTimingRejectsBaselineAndPostSampleAnomalies(t *testing.T) {
	profile := loadTestProfile(t)
	baseReport := syntheticPassingReport(profile)
	cases := make([]profileCase, 0, len(baseReport.ScenarioResults))
	for _, phase := range profile.Phases {
		cases = append(cases, phase.Cases...)
	}
	cloneReport := func(source reportDocument) reportDocument {
		result := source
		baseline := *source.Cleanup.Baseline
		baseline.SampledAt = append([]string(nil), source.Cleanup.Baseline.SampledAt...)
		post := *source.Cleanup.PostTeardown
		post.SampledAt = append([]string(nil), source.Cleanup.PostTeardown.SampledAt...)
		result.Cleanup.Baseline = &baseline
		result.Cleanup.PostTeardown = &post
		result.ScenarioResults = append([]scenarioResult(nil), source.ScenarioResults...)
		return result
	}
	if err := validateCleanupTiming(baseReport, cases); err != nil {
		t.Fatalf("validateCleanupTiming(valid) error = %v", err)
	}
	if err := validateCleanupTiming(syntheticNotExecutedReport(profile), cases); err != nil {
		t.Fatalf("validateCleanupTiming(no samples) error = %v", err)
	}
	firstMutation, ok := firstMutationScenarioStart(baseReport.ScenarioResults, cases)
	if !ok {
		t.Fatal("synthetic report lacks first mutation time")
	}
	executionStarted, err := parseUTCTimestamp(baseReport.Timestamps.ExecutionStartedAt)
	if err != nil {
		t.Fatal(err)
	}
	baselineAtExecutionStart := cloneReport(baseReport)
	baselineAtExecutionStart.Cleanup.Baseline.SampledAt[0] = executionStarted.Format(time.RFC3339Nano)
	if err := validateCleanupTiming(baselineAtExecutionStart, cases); err != nil {
		t.Fatalf("validateCleanupTiming(baseline at execution start) error = %v", err)
	}
	cleanupStarted, err := parseUTCTimestamp(baseReport.Timestamps.CleanupStartedAt)
	if err != nil {
		t.Fatal(err)
	}
	cleanupFinished, err := parseUTCTimestamp(baseReport.Timestamps.CleanupFinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		want   string
		mutate func(*reportDocument)
	}{
		{"missing baseline sample", "required baseline", func(report *reportDocument) { report.Cleanup.Baseline.SampledAt = []string{} }},
		{"extra baseline sample", "required baseline", func(report *reportDocument) {
			report.Cleanup.Baseline.SampledAt = append(report.Cleanup.Baseline.SampledAt, executionStarted.Format(time.RFC3339Nano))
		}},
		{"invalid baseline sample", "baseline sample time is invalid", func(report *reportDocument) { report.Cleanup.Baseline.SampledAt[0] = "invalid" }},
		{"baseline before execution", "execution start", func(report *reportDocument) {
			report.Cleanup.Baseline.SampledAt[0] = executionStarted.Add(-time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"baseline at first mutation", "before the first mutation", func(report *reportDocument) {
			report.Cleanup.Baseline.SampledAt[0] = firstMutation.Format(time.RFC3339Nano)
		}},
		{"baseline after first mutation", "before the first mutation", func(report *reportDocument) {
			report.Cleanup.Baseline.SampledAt[0] = firstMutation.Add(time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"mutation without timing boundary", "no observed mutation boundary", func(report *reportDocument) {
			for index := range report.ScenarioResults {
				started, err := parseUTCTimestamp(report.ScenarioResults[index].StartedAt)
				if err == nil && started.Equal(firstMutation) {
					report.ScenarioResults[index].StartedAt = nil
					return
				}
			}
		}},
		{"missing post sample", "claimed post-teardown sample count", func(report *reportDocument) {
			report.Cleanup.PostTeardown.SampledAt = report.Cleanup.PostTeardown.SampledAt[:2]
		}},
		{"zero stability samples do not bypass an invalid baseline", "execution start", func(report *reportDocument) {
			report.Cleanup.Outcome = "failed"
			report.Cleanup.StabilitySamples = 0
			report.Cleanup.StabilityIntervalMS = 0
			report.Cleanup.PostTeardown.SampledAt = nil
			report.Cleanup.Baseline.SampledAt[0] = executionStarted.Add(-time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"sample before cleanup", "cleanup window and interval", func(report *reportDocument) {
			report.Cleanup.PostTeardown.SampledAt[0] = cleanupStarted.Add(-time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"sample after cleanup", "cleanup window and interval", func(report *reportDocument) {
			report.Cleanup.PostTeardown.SampledAt[2] = cleanupFinished.Add(time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"samples too close", "cleanup window and interval", func(report *reportDocument) {
			report.Cleanup.PostTeardown.SampledAt[1] = cleanupStarted.Add(500 * time.Millisecond).Format(time.RFC3339Nano)
		}},
		{"samples out of order", "cleanup window and interval", func(report *reportDocument) {
			report.Cleanup.PostTeardown.SampledAt[1], report.Cleanup.PostTeardown.SampledAt[2] = report.Cleanup.PostTeardown.SampledAt[2], report.Cleanup.PostTeardown.SampledAt[1]
		}},
		{"cleanup window too short", "cannot contain", func(report *reportDocument) {
			report.Timestamps.CleanupFinishedAt = testStringPtr(cleanupStarted.Add(time.Second).Format(time.RFC3339Nano))
		}},
		{"zero sample interval", "cannot contain", func(report *reportDocument) { report.Cleanup.StabilityIntervalMS = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := cloneReport(baseReport)
			tc.mutate(&report)
			if err := validateCleanupTiming(report, cases); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateCleanupTiming() error = %v", err)
			}
		})
	}
}

func TestHasCompleteIdentityRejectsNotAssertedRequiredAssertion(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	for index := range report.Observations {
		report.Observations[index].EvidenceDigest = testStringPtr(testDigest)
	}
	semantics := validatorSemantics{TrustedInputs: make([]trustedInputSemantic, 5)}
	payloads := payloadSet{Provider: &providerObserverPayload{}, Gateway: &gatewayObserverPayload{}, ProcessSupervisor: &processSupervisorPayload{}, ResourceInspector: &resourceInspectorPayload{}, TrustedInputs: &trustedInputsPayload{}}
	if !hasCompleteIdentity(report, semantics, payloads) {
		t.Fatal("hasCompleteIdentity() rejected complete synthetic identity")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*payloadSet)
	}{
		{"provider observer", func(value *payloadSet) { value.Provider = nil }},
		{"gateway observer", func(value *payloadSet) { value.Gateway = nil }},
		{"process supervisor", func(value *payloadSet) { value.ProcessSupervisor = nil }},
		{"resource inspector", func(value *payloadSet) { value.ResourceInspector = nil }},
		{"trusted inputs", func(value *payloadSet) { value.TrustedInputs = nil }},
	} {
		t.Run("missing "+tc.name, func(t *testing.T) {
			candidate := payloads
			tc.mutate(&candidate)
			if hasCompleteIdentity(report, semantics, candidate) {
				t.Fatalf("hasCompleteIdentity() accepted missing %s payload", tc.name)
			}
		})
	}
	report.Claims.CallerAssertions[0].Result = "not_asserted"
	if hasCompleteIdentity(report, semantics, payloads) {
		t.Fatal("hasCompleteIdentity() accepted a required not_asserted assertion")
	}
}

func TestValidateEvidenceRejectsInventoryMismatch(t *testing.T) {
	entry := evidencefiles.Entry{Path: "payload.json", Bytes: 1, SHA256: "sha256:" + strings.Repeat("a", 64)}
	inventory := evidencefiles.Inventory{Entries: []evidencefiles.Entry{entry}, Digest: "sha256:" + strings.Repeat("b", 64), FileCount: 1, TotalBytes: 1}
	report := reportDocument{}
	if err := validateEvidence(report, inventory, []byte("{}"), 1); err == nil {
		t.Fatal("validateEvidence() accepted an inventory mismatch")
	}
}

func TestValidateRunOutcomeRejectsCountAndPrecedenceMismatch(t *testing.T) {
	report := reportDocument{RunOutcome: runOutcome{
		Outcome:            "passed",
		CleanupSatisfied:   true,
		IdentityComplete:   true,
		SanitizationPassed: true,
	}}
	report.RunOutcome.ScenarioCounts.Passed = 20
	counts := map[string]int{"passed": 20, "failed": 0, "incomplete": 0, "not_executed": 0}
	if err := validateRunOutcome(report, counts, true); err != nil {
		t.Fatalf("validateRunOutcome(valid) error = %v", err)
	}

	wrongCounts := report
	wrongCounts.RunOutcome.ScenarioCounts.Passed = 19
	if err := validateRunOutcome(wrongCounts, counts, true); err == nil || !strings.Contains(err.Error(), "scenario counts") {
		t.Fatalf("validateRunOutcome(wrong counts) error = %v", err)
	}

	wrongPrecedence := report
	wrongPrecedence.RunOutcome.Outcome = "passed"
	wrongPrecedence.RunOutcome.ReasonCodes = []string{"executed_mismatch"}
	wrongPrecedence.RunOutcome.ScenarioCounts.Passed = 19
	wrongPrecedence.RunOutcome.ScenarioCounts.Failed = 1
	failedCounts := map[string]int{"passed": 19, "failed": 1, "incomplete": 0, "not_executed": 0}
	if err := validateRunOutcome(wrongPrecedence, failedCounts, true); err == nil || !strings.Contains(err.Error(), "precedence") {
		t.Fatalf("validateRunOutcome(wrong precedence) error = %v", err)
	}

	incompleteFailure := report
	incompleteFailure.RunOutcome.Outcome = "incomplete"
	incompleteFailure.RunOutcome.IdentityComplete = false
	incompleteFailure.RunOutcome.ScenarioCounts = scenarioCounts{Passed: 19, Failed: 1}
	incompleteFailure.RunOutcome.ReasonCodes = []string{"missing_identity_or_evidence"}
	if err := validateRunOutcome(incompleteFailure, failedCounts, true); err == nil || !strings.Contains(err.Error(), "executed_mismatch") {
		t.Fatalf("validateRunOutcome(incomplete failure) error = %v", err)
	}

	incompleteScenario := report
	incompleteScenario.RunOutcome.Outcome = "incomplete"
	incompleteScenario.RunOutcome.IdentityComplete = false
	incompleteScenario.RunOutcome.ScenarioCounts = scenarioCounts{Passed: 19, Incomplete: 1}
	incompleteScenario.RunOutcome.ReasonCodes = []string{"missing_identity_or_evidence"}
	incompleteCounts := map[string]int{"passed": 19, "failed": 0, "incomplete": 1, "not_executed": 0}
	if err := validateRunOutcome(incompleteScenario, incompleteCounts, true); err != nil {
		t.Fatalf("validateRunOutcome(incomplete scenario) error = %v", err)
	}

	conflictingReason := report
	conflictingReason.RunOutcome.ReasonCodes = []string{"scenario_not_executed"}
	if err := validateRunOutcome(conflictingReason, counts, true); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("validateRunOutcome(conflicting reason) error = %v", err)
	}
}

func TestValidateSanitizedBytesRejectsForbiddenMarker(t *testing.T) {
	for _, marker := range []string{"-----BEGIN PRIVATE KEY-----", "Bearer secret", `"client_secret":"secret"`, "Authorization:", "ref:session:raw", "wss://private.example"} {
		document, err := json.Marshal(map[string]string{"report_id": "payload " + marker})
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSanitizedBytes(document); err == nil {
			t.Errorf("validateSanitizedBytes() accepted marker %q", marker)
		}
	}
	for _, escaped := range [][]byte{
		[]byte(`{"report_id":"\u0072ef:session:raw"}`),
		[]byte(`{"report_id":"https:\/\/private.example"}`),
	} {
		if err := validateSanitizedBytes(escaped); err == nil {
			t.Errorf("validateSanitizedBytes() accepted escaped marker in %s", escaped)
		}
	}
	if err := validateSanitizedBytes([]byte(`{"assertion_id":"no-raw-handoff-reference-or-admission-context-or-command-output"}`)); err != nil {
		t.Fatalf("validateSanitizedBytes() rejected a schema-defined semantic label: %v", err)
	}
}

func TestValidateTimestampsRejectsNonUTCAndExcessiveDuration(t *testing.T) {
	base := time.Date(2026, 9, 8, 1, 0, 0, 0, time.UTC)
	valid := timestamps{
		RunStartedAt:        testStringPtr(base.Format(time.RFC3339Nano)),
		ExecutionStartedAt:  testStringPtr(base.Add(time.Second).Format(time.RFC3339Nano)),
		ExecutionFinishedAt: testStringPtr(base.Add(2 * time.Second).Format(time.RFC3339Nano)),
		CleanupStartedAt:    testStringPtr(base.Add(3 * time.Second).Format(time.RFC3339Nano)),
		CleanupFinishedAt:   testStringPtr(base.Add(4 * time.Second).Format(time.RFC3339Nano)),
		RunFinishedAt:       testStringPtr(base.Add(5 * time.Second).Format(time.RFC3339Nano)),
	}
	limits := profileLimits{MaxExecutionSeconds: 10, MaxCleanupSeconds: 10, MaxTotalWallClockSeconds: 20}
	if err := validateTimestamps(valid, limits); err != nil {
		t.Fatalf("validateTimestamps(valid) error = %v", err)
	}
	if err := validateTimestamps(timestamps{}, limits); err != nil {
		t.Fatalf("validateTimestamps(all null) error = %v", err)
	}
	partial := timestamps{RunStartedAt: valid.RunStartedAt}
	if err := validateTimestamps(partial, limits); err == nil || !strings.Contains(err.Error(), "all null or all present") {
		t.Fatalf("validateTimestamps(partial) error = %v", err)
	}
	offset := valid
	offset.RunStartedAt = testStringPtr(base.In(time.FixedZone("offset", 3600)).Format(time.RFC3339Nano))
	if err := validateTimestamps(offset, limits); err == nil {
		t.Fatal("validateTimestamps() accepted non-UTC timestamp")
	}
	long := valid
	long.ExecutionFinishedAt = testStringPtr(base.Add(11 * time.Second).Format(time.RFC3339Nano))
	if err := validateTimestamps(long, limits); err == nil {
		t.Fatal("validateTimestamps() accepted excessive execution duration")
	}
}

func TestValidateProcessTimingEvidenceRequiresOwnershipAndCompleteBindings(t *testing.T) {
	profile := loadTestProfile(t)
	passing := syntheticPassingReport(profile)
	cloneReport := func(source reportDocument) reportDocument {
		result := source
		result.Phases = append([]phase(nil), source.Phases...)
		result.ScenarioResults = append([]scenarioResult(nil), source.ScenarioResults...)
		return result
	}
	payloadFor := func(report reportDocument) *processSupervisorPayload {
		return &processSupervisorPayload{
			RunTimestamps:   report.Timestamps,
			Phases:          append([]phase(nil), report.Phases...),
			ScenarioTimings: projectScenarioTimings(report.ScenarioResults),
		}
	}
	validPayload := payloadFor(passing)
	if err := validateProcessTimingEvidence(passing, validPayload); err != nil {
		t.Fatalf("validateProcessTimingEvidence(valid) error = %v", err)
	}

	notExecuted := syntheticNotExecutedReport(profile)
	if err := validateProcessTimingEvidence(notExecuted, nil); err != nil {
		t.Fatalf("validateProcessTimingEvidence(absent supervisor) error = %v", err)
	}

	residualCases := []struct {
		name   string
		mutate func(*reportDocument)
	}{
		{"run started", func(report *reportDocument) { report.Timestamps.RunStartedAt = passing.Timestamps.RunStartedAt }},
		{"execution started", func(report *reportDocument) {
			report.Timestamps.ExecutionStartedAt = passing.Timestamps.ExecutionStartedAt
		}},
		{"execution finished", func(report *reportDocument) {
			report.Timestamps.ExecutionFinishedAt = passing.Timestamps.ExecutionFinishedAt
		}},
		{"cleanup started", func(report *reportDocument) { report.Timestamps.CleanupStartedAt = passing.Timestamps.CleanupStartedAt }},
		{"cleanup finished", func(report *reportDocument) {
			report.Timestamps.CleanupFinishedAt = passing.Timestamps.CleanupFinishedAt
		}},
		{"run finished", func(report *reportDocument) { report.Timestamps.RunFinishedAt = passing.Timestamps.RunFinishedAt }},
		{"phase started", func(report *reportDocument) { report.Phases[0].StartedAt = passing.Phases[0].StartedAt }},
		{"phase finished", func(report *reportDocument) { report.Phases[0].FinishedAt = passing.Phases[0].FinishedAt }},
		{"scenario started", func(report *reportDocument) {
			report.ScenarioResults[0].StartedAt = passing.ScenarioResults[0].StartedAt
		}},
		{"scenario finished", func(report *reportDocument) {
			report.ScenarioResults[0].FinishedAt = passing.ScenarioResults[0].FinishedAt
		}},
	}
	for _, tc := range residualCases {
		t.Run("absent supervisor rejects "+tc.name, func(t *testing.T) {
			candidate := cloneReport(notExecuted)
			tc.mutate(&candidate)
			if err := validateProcessTimingEvidence(candidate, nil); err == nil {
				t.Fatalf("validateProcessTimingEvidence() accepted %s without process supervisor", tc.name)
			}
		})
	}

	missingCases := []struct {
		name   string
		want   string
		mutate func(*reportDocument)
	}{
		{"run started", "complete run", func(report *reportDocument) { report.Timestamps.RunStartedAt = nil }},
		{"execution started", "complete run", func(report *reportDocument) { report.Timestamps.ExecutionStartedAt = nil }},
		{"execution finished", "complete run", func(report *reportDocument) { report.Timestamps.ExecutionFinishedAt = nil }},
		{"cleanup started", "complete run", func(report *reportDocument) { report.Timestamps.CleanupStartedAt = nil }},
		{"cleanup finished", "complete run", func(report *reportDocument) { report.Timestamps.CleanupFinishedAt = nil }},
		{"run finished", "complete run", func(report *reportDocument) { report.Timestamps.RunFinishedAt = nil }},
		{"phase started", "complete phase", func(report *reportDocument) { report.Phases[0].StartedAt = nil }},
		{"phase finished", "complete phase", func(report *reportDocument) { report.Phases[0].FinishedAt = nil }},
		{"scenario started", "complete scenario", func(report *reportDocument) { report.ScenarioResults[0].StartedAt = nil }},
		{"scenario finished", "complete scenario", func(report *reportDocument) { report.ScenarioResults[0].FinishedAt = nil }},
	}
	for _, tc := range missingCases {
		t.Run("present supervisor requires "+tc.name, func(t *testing.T) {
			candidate := cloneReport(passing)
			tc.mutate(&candidate)
			if err := validateProcessTimingEvidence(candidate, payloadFor(candidate)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateProcessTimingEvidence(missing %s) error = %v", tc.name, err)
			}
		})
	}

	alternate := testStringPtr("2026-09-08T02:00:00Z")
	mismatchCases := []struct {
		name   string
		mutate func(*processSupervisorPayload)
	}{
		{"run started", func(payload *processSupervisorPayload) { payload.RunTimestamps.RunStartedAt = alternate }},
		{"execution started", func(payload *processSupervisorPayload) { payload.RunTimestamps.ExecutionStartedAt = alternate }},
		{"execution finished", func(payload *processSupervisorPayload) { payload.RunTimestamps.ExecutionFinishedAt = alternate }},
		{"cleanup started", func(payload *processSupervisorPayload) { payload.RunTimestamps.CleanupStartedAt = alternate }},
		{"cleanup finished", func(payload *processSupervisorPayload) { payload.RunTimestamps.CleanupFinishedAt = alternate }},
		{"run finished", func(payload *processSupervisorPayload) { payload.RunTimestamps.RunFinishedAt = alternate }},
		{"phase started", func(payload *processSupervisorPayload) { payload.Phases[0].StartedAt = alternate }},
		{"phase finished", func(payload *processSupervisorPayload) { payload.Phases[0].FinishedAt = alternate }},
		{"scenario started", func(payload *processSupervisorPayload) { payload.ScenarioTimings[0].StartedAt = alternate }},
		{"scenario finished", func(payload *processSupervisorPayload) { payload.ScenarioTimings[0].FinishedAt = alternate }},
	}
	for _, tc := range mismatchCases {
		t.Run("rejects payload mismatch "+tc.name, func(t *testing.T) {
			payload := payloadFor(passing)
			tc.mutate(payload)
			if err := validateProcessTimingEvidence(passing, payload); err == nil || !strings.Contains(err.Error(), "does not bind") {
				t.Fatalf("validateProcessTimingEvidence(mismatched %s) error = %v", tc.name, err)
			}
		})
	}
}

func TestValidateResourceInspectorTimingEvidenceBindsCleanupWindow(t *testing.T) {
	report := syntheticPassingReport(loadTestProfile(t))
	want := cleanupTimestamps{StartedAt: report.Timestamps.CleanupStartedAt, FinishedAt: report.Timestamps.CleanupFinishedAt}
	if err := validateResourceInspectorTimingEvidence(report, &resourceInspectorPayload{CleanupTimestamps: want}); err != nil {
		t.Fatalf("validateResourceInspectorTimingEvidence(valid) error = %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*cleanupTimestamps)
	}{
		{"started", func(value *cleanupTimestamps) { value.StartedAt = report.Timestamps.RunStartedAt }},
		{"finished", func(value *cleanupTimestamps) { value.FinishedAt = report.Timestamps.RunFinishedAt }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := want
			tc.mutate(&candidate)
			if err := validateResourceInspectorTimingEvidence(report, &resourceInspectorPayload{CleanupTimestamps: candidate}); err == nil || !strings.Contains(err.Error(), "does not bind") {
				t.Fatalf("validateResourceInspectorTimingEvidence(%s mismatch) error = %v", tc.name, err)
			}
		})
	}
}

func TestValidateScenarioTimestampsRejectsOverlap(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	cases := make([]profileCase, 0, len(report.ScenarioResults))
	for _, phase := range profile.Phases {
		cases = append(cases, phase.Cases...)
	}
	report.ScenarioResults[1].StartedAt = report.ScenarioResults[0].StartedAt
	if err := validateScenarioTimestamps(report, cases); err == nil || !strings.Contains(err.Error(), "overlaps or precedes") {
		t.Fatalf("validateScenarioTimestamps() overlap error = %v", err)
	}
}

func TestCalculateCountersCountsUnexpectedResourceMutationOutcomes(t *testing.T) {
	profile := loadTestProfile(t)
	cases := make([]profileCase, 0, 20)
	for _, phase := range profile.Phases {
		cases = append(cases, phase.Cases...)
	}
	findInteraction := func(t *testing.T, report *reportDocument, id string) *interactionResult {
		t.Helper()
		for scenarioIndex := range report.ScenarioResults {
			for interactionIndex := range report.ScenarioResults[scenarioIndex].Interactions {
				interaction := &report.ScenarioResults[scenarioIndex].Interactions[interactionIndex]
				if interaction.InteractionID == id {
					return interaction
				}
			}
		}
		t.Fatalf("synthetic report lacks interaction %q", id)
		return nil
	}
	findExpected := func(t *testing.T, id string) profileInteraction {
		t.Helper()
		for _, candidate := range cases {
			for _, interaction := range candidate.Interactions {
				if interaction.ID == id {
					return interaction
				}
			}
		}
		t.Fatalf("profile lacks interaction %q", id)
		return profileInteraction{}
	}
	contradictObservation := func(t *testing.T, report *reportDocument, interactionID string) {
		t.Helper()
		interaction := findInteraction(t, report, interactionID)
		if len(interaction.ObservationIDs) == 0 {
			t.Fatalf("interaction %q lacks observations", interactionID)
		}
		for index := range report.Observations {
			if report.Observations[index].ID == interaction.ObservationIDs[0] {
				report.Observations[index].Result = "contradicted"
				return
			}
		}
		t.Fatalf("synthetic report lacks observation for interaction %q", interactionID)
	}
	assertResources := func(t *testing.T, report reportDocument, sandboxes, execs, terminals, artifacts int) {
		t.Helper()
		counts, _ := calculateCounters(report.ScenarioResults, report.Observations, cases)
		if counts.Sandboxes != sandboxes || counts.AdmittedExecOperations != execs || counts.TerminalSessions != terminals || counts.AdmittedArtifactOperations != artifacts {
			t.Fatalf("calculateCounters() resources = %+v, want sandboxes=%d execs=%d terminals=%d artifacts=%d", counts, sandboxes, execs, terminals, artifacts)
		}
	}

	base := syntheticPassingReport(profile)
	assertResources(t, base, 1, 2, 1, 1)

	allowedIdempotencyReplay := syntheticPassingReport(profile)
	assertResources(t, allowedIdempotencyReplay, 1, 2, 1, 1)

	for _, tc := range []struct {
		name          string
		interactionID string
		outcome       reportOutcome
		sandboxes     int
		execs         int
		artifacts     int
	}{
		{"create 500", "create-sandbox", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 1, 2, 1},
		{"output exec 500", "start-output-exec", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 1, 2, 1},
		{"terminal deadline", "open-terminal-session", reportOutcome{Transport: "deadline-exceeded"}, 1, 2, 1},
		{"artifact 500", "stage-artifact", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 1, 2, 1},
		{"exact JTI unexpected 202", "exact-jti-replay", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(202)}, 2, 2, 1},
		{"exact JTI 500", "exact-jti-replay", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 2, 2, 1},
		{"exact JTI deadline", "exact-jti-replay", reportOutcome{Transport: "deadline-exceeded"}, 2, 2, 1},
		{"new JTI replay 500", "new-jti-idempotency-replay", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 2, 2, 1},
		{"stale fence 500", "start-stale-fence-exec", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 1, 3, 1},
		{"stale fence deadline", "start-stale-fence-exec", reportOutcome{Transport: "deadline-exceeded"}, 1, 3, 1},
		{"cross tenant artifact 500", "cross-tenant-stage-artifact", reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)}, 1, 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := syntheticPassingReport(profile)
			findInteraction(t, &report, tc.interactionID).FinalOutcome = tc.outcome
			assertResources(t, report, tc.sandboxes, tc.execs, 1, tc.artifacts)
		})
	}

	for _, tc := range []struct {
		interactionID string
		sandboxes     int
		execs         int
		artifacts     int
	}{
		{"create-sandbox", 1, 2, 1},
		{"start-output-exec", 1, 2, 1},
		{"open-terminal-session", 1, 2, 1},
		{"stage-artifact", 1, 2, 1},
		{"exact-jti-replay", 2, 2, 1},
		{"new-jti-idempotency-replay", 2, 2, 1},
		{"start-stale-fence-exec", 1, 3, 1},
		{"cross-tenant-stage-artifact", 1, 2, 2},
	} {
		t.Run(tc.interactionID+" observation mismatch", func(t *testing.T) {
			report := syntheticPassingReport(profile)
			contradictObservation(t, &report, tc.interactionID)
			assertResources(t, report, tc.sandboxes, tc.execs, 1, tc.artifacts)
		})
	}

	for _, tc := range []struct {
		name                 string
		transient            reportOutcome
		final                reportOutcome
		wantInteractionMatch bool
	}{
		{
			name:                 "allowed transient with unexpected final",
			transient:            syntheticOutcome(findExpected(t, "start-stale-fence-exec").Transient[0]),
			final:                reportOutcome{Transport: "http-response", StatusCode: testIntPtr(500)},
			wantInteractionMatch: false,
		},
		{
			name:                 "unexpected transient with allowed final",
			transient:            reportOutcome{Transport: "deadline-exceeded", Retryable: true},
			final:                syntheticOutcome(findExpected(t, "start-stale-fence-exec").Outcomes[0]),
			wantInteractionMatch: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := syntheticPassingReport(profile)
			interaction := findInteraction(t, &report, "start-stale-fence-exec")
			interaction.WireAttempts = 2
			interaction.TransientOutcomes = []reportOutcome{tc.transient}
			interaction.FinalOutcome = tc.final
			matched, err := validateInteraction(*interaction, findExpected(t, interaction.InteractionID))
			if err != nil || matched != tc.wantInteractionMatch {
				t.Fatalf("validateInteraction() = (%t, %v)", matched, err)
			}
			assertResources(t, report, 1, 4, 1, 1)
		})
	}

	underreported := syntheticPassingReport(profile)
	findInteraction(t, &underreported, "start-stale-fence-exec").FinalOutcome = reportOutcome{Transport: "deadline-exceeded"}
	if err := validateOutcomeAndCleanup(underreported, profile, cases); err == nil || !strings.Contains(err.Error(), "counters do not match") {
		t.Fatalf("validateOutcomeAndCleanup(underreported potential resource) error = %v", err)
	}

	overLimit := syntheticPassingReport(profile)
	overLimitInteraction := findInteraction(t, &overLimit, "start-stale-fence-exec")
	overLimitInteraction.WireAttempts = 2
	overLimitInteraction.TransientOutcomes = []reportOutcome{{Transport: "deadline-exceeded", Retryable: true}}
	overLimit.Counters, _ = calculateCounters(overLimit.ScenarioResults, overLimit.Observations, cases)
	if err := validateOutcomeAndCleanup(overLimit, profile, cases); err == nil || !strings.Contains(err.Error(), "exceeds a locked resource limit") {
		t.Fatalf("validateOutcomeAndCleanup(over-limit potential resources) error = %v", err)
	}
}

func TestVerifyNeverOverwritesExistingReceipt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ReceiptFileName)
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), root, filepath.Clean(filepath.Join("..", ".."))); err == nil || !strings.Contains(err.Error(), "already contains receipt.json") {
		t.Fatalf("Verify() existing receipt error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "original" {
		t.Fatalf("existing receipt changed to %q", contents)
	}
}

func TestCommitQualificationReceiptHonorsCancellationAndReportsCleanupFailure(t *testing.T) {
	for _, tc := range []struct {
		name              string
		replaceStaging    bool
		wantCleanupFailed bool
	}{
		{name: "clean staging"},
		{name: "replaced staging", replaceStaging: true, wantCleanupFailed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootPath := t.TempDir()
			root, err := evidencefiles.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			const staging = ".receipt.pending-canceled"
			publication, err := root.Publish(staging, []byte("candidate"), 100)
			if err != nil {
				t.Fatal(err)
			}
			if tc.replaceStaging {
				if err := os.Remove(filepath.Join(rootPath, staging)); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(rootPath, staging), []byte("replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err = commitQualificationReceipt(ctx, publication)
			if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "staging cleanup failed") != tc.wantCleanupFailed {
				t.Fatalf("commitQualificationReceipt() error = %v", err)
			}
			if _, err := os.Lstat(filepath.Join(rootPath, "receipt.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("receipt committed after cancellation: %v", err)
			}
			_, statErr := os.Lstat(filepath.Join(rootPath, staging))
			if tc.replaceStaging {
				if statErr != nil {
					t.Fatalf("replacement staging entry was removed: %v", statErr)
				}
			} else if !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("owned staging entry remains after cancellation: %v", statErr)
			}
		})
	}
}

func TestCommitQualificationReceiptPreservesCompetingDestinationAndError(t *testing.T) {
	rootPath := t.TempDir()
	root, err := evidencefiles.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	const staging = ".receipt.pending-competing-destination"
	publication, err := root.Publish(staging, []byte("candidate"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootPath, ReceiptFileName), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = commitQualificationReceipt(context.Background(), publication)
	if err == nil || !strings.Contains(err.Error(), "cannot be committed") || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("commitQualificationReceipt(competing destination) error = %v", err)
	}
	contents, readErr := os.ReadFile(filepath.Join(rootPath, ReceiptFileName))
	if readErr != nil || string(contents) != "existing" {
		t.Fatalf("competing receipt = %q, %v", contents, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(rootPath, staging)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("owned staging entry remains after commit rejection: %v", statErr)
	}
}

func TestMakeReceiptUsesRawReportDigestAndPayloadInventory(t *testing.T) {
	reportBytes := []byte(`{"report_id":"r"}`)
	inventory := evidencefiles.Inventory{Digest: "sha256:" + strings.Repeat("b", 64)}
	report := reportDocument{Profile: profileIdentity{ProfileID: "profile"}, Invocation: invocation{InvocationID: "invocation"}, RunOutcome: runOutcome{Outcome: "failed"}}
	receiptBytes, receipt, err := makeReceipt(report, reportBytes, inventory, testSemantics())
	if err != nil {
		t.Fatal(err)
	}
	if len(receiptBytes) == 0 {
		t.Fatal("makeReceipt() returned empty bytes")
	}
	if got, want := receipt["report_sha256"], evidencefiles.RawDigest(reportBytes); got != want {
		t.Fatalf("receipt report digest = %v, want %v", got, want)
	}
	if got, want := receipt["payload_inventory_sha256"], inventory.Digest; got != want {
		t.Fatalf("receipt inventory digest = %v, want %v", got, want)
	}
	if got, want := receipt["adapter_protocol"], lockedAdapterProtocolAuthority(); !reflect.DeepEqual(got, want) {
		t.Fatalf("receipt adapter protocol authority = %#v, want %#v", got, want)
	}
	if strings.Contains(string(receiptBytes), ReceiptFileName) {
		t.Fatal("receipt appears to hash or identify itself")
	}
	var decoded map[string]any
	if err := json.Unmarshal(receiptBytes, &decoded); err != nil {
		t.Fatalf("receipt is not JSON: %v", err)
	}
}
