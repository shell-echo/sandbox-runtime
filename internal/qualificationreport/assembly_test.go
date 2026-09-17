package qualificationreport

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

func TestRootAssemblerPublishesClosedEvidenceAndVerifierReceipt(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	shiftSyntheticTimes(t, &report, time.Now().UTC().Add(-time.Minute))
	projection := syntheticTranscriptProjection(t, &report)
	projectionBytes, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := syntheticEvidenceSnapshot(t, report)
	input := syntheticAssemblyInput(report, projectionBytes)
	root := t.TempDir()
	var stages []string
	assembler := RootAssembler{SourceRoot: "../..", EvidenceRoot: root, Input: input, StageObserver: func(stage string) {
		stages = append(stages, stage)
	}}

	result, err := assembler.AssembleAndVerify(context.Background(), snapshot)
	if err != nil {
		t.Fatalf("AssembleAndVerify() error = %v", err)
	}
	if result.RunOutcome != "passed" || result.ValidationOutcome != "accepted" || result.FileCount != 7 || result.RuntimeCommitmentDigest != snapshot.RuntimeCommitmentDigest || result.InitialInvocationID != snapshot.Reconstruction.InitialInvocationID || result.ReconstructionInvocationID != snapshot.Reconstruction.ReconstructionInvocationID {
		t.Fatalf("AssembleAndVerify() result = %+v", result)
	}
	if len(stages) == 0 || stages[len(stages)-1] != "completed" {
		t.Fatalf("safe assembly stages = %v", stages)
	}
	for _, name := range []string{"provider-observer.json", "gateway-observer.json", "process-supervisor.json", "resource-inspector.json", "trusted-inputs.json", ReportFileName, ReceiptFileName} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", name, info.Mode())
		}
	}

	if _, err := assembler.AssembleAndVerify(context.Background(), snapshot); err == nil {
		t.Fatal("second assembly unexpectedly accepted a non-empty evidence root")
	}
	if _, err := os.Stat(filepath.Join(root, ReceiptFileName)); err != nil {
		t.Fatal("failed repeat assembly removed accepted evidence")
	}
}

func TestRootAssemblerRejectsTranscriptBeforePublishing(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	shiftSyntheticTimes(t, &report, time.Now().UTC().Add(-time.Minute))
	projection := syntheticTranscriptProjection(t, &report)
	projection["protocol_id"] = "substitute"
	projectionBytes, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	assembler := RootAssembler{SourceRoot: "../..", EvidenceRoot: root, Input: syntheticAssemblyInput(report, projectionBytes)}
	if _, err := assembler.AssembleAndVerify(context.Background(), syntheticEvidenceSnapshot(t, report)); err == nil {
		t.Fatal("assembly accepted a tampered transcript projection")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("pre-publication rejection left %d files", len(entries))
	}
}

func TestRootAssemblerDerivesCallerContradictionAsFailed(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	shiftSyntheticTimes(t, &report, time.Now().UTC().Add(-time.Minute))
	projection := syntheticTranscriptProjection(t, &report)
	projectionBytes, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	input := syntheticAssemblyInput(report, projectionBytes)
	input.CallerAssertions[len(input.CallerAssertions)-1].Result = "contradicted"
	assembler := RootAssembler{SourceRoot: "../..", EvidenceRoot: t.TempDir(), Input: input}
	result, err := assembler.AssembleAndVerify(context.Background(), syntheticEvidenceSnapshot(t, report))
	if err != nil {
		t.Fatalf("AssembleAndVerify(contradicted assertion) error = %v", err)
	}
	if result.RunOutcome != "failed" || result.ValidationOutcome != "accepted" {
		t.Fatalf("contradicted assertion result = %+v", result)
	}
}

func TestRootAssemblerRemovesItsPayloadsAfterPreHandoffSemanticFailure(t *testing.T) {
	profile := loadTestProfile(t)
	report := syntheticPassingReport(profile)
	shiftSyntheticTimes(t, &report, time.Now().UTC().Add(-time.Minute))
	projection := syntheticTranscriptProjection(t, &report)
	projectionBytes, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := syntheticEvidenceSnapshot(t, report)
	if len(snapshot.Observation.Scenarios[0].ObservationIDs) == 0 {
		t.Fatal("fixture lacks scenario observations")
	}
	snapshot.Observation.Scenarios[0].ObservationIDs[0] = "substitute"
	root := t.TempDir()
	assembler := RootAssembler{SourceRoot: "../..", EvidenceRoot: root, Input: syntheticAssemblyInput(report, projectionBytes)}
	if _, err := assembler.AssembleAndVerify(context.Background(), snapshot); err == nil {
		t.Fatal("assembly accepted a semantically inconsistent d1-d6 snapshot")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("pre-handoff rejection left %d files", len(entries))
	}
}

func syntheticAssemblyInput(report reportDocument, projection []byte) AssemblyInput {
	timings := make([]ScenarioTimingInput, len(report.ScenarioResults))
	for index, scenario := range report.ScenarioResults {
		timings[index] = ScenarioTimingInput{CaseID: scenario.CaseID, PhaseID: scenario.PhaseID, StartedAt: mustTestTime(*scenario.StartedAt), FinishedAt: mustTestTime(*scenario.FinishedAt)}
	}
	assertions := make([]CallerAssertionInput, len(report.Claims.CallerAssertions))
	for index, item := range report.Claims.CallerAssertions {
		assertions[index] = CallerAssertionInput{AssertionID: item.ID, Result: item.Result}
	}
	trusted := make([]TrustedInputStatementInput, len(report.Claims.TrustedInputs))
	for index, item := range report.Claims.TrustedInputs {
		trusted[index] = TrustedInputStatementInput{InputID: item.ID, Source: item.Source, SubjectDigest: testDigest}
	}
	return AssemblyInput{AdapterTranscriptProjection: projection, ScenarioTimings: timings, CallerAssertions: assertions, TrustedInputs: trusted}
}

func syntheticEvidenceSnapshot(t *testing.T, report reportDocument) qualificationharness.EvidenceSnapshot {
	t.Helper()
	definition, err := qualificationprofile.VerifyCodingShellV1(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make([]qualificationharness.ArtifactObservation, len(report.Artifacts))
	for index, item := range report.Artifacts {
		artifacts[index] = qualificationharness.ArtifactObservation{ArtifactID: item.ArtifactID, Owner: item.Owner, TrustDomain: item.TrustDomain, DigestSubject: item.DigestSubject, Digest: *item.Digest, ObservedBy: item.ObservedBy, Source: &qualificationharness.SourceIdentity{Kind: item.Source.Kind, Value: item.Source.Value, Immutable: item.Source.Immutable}}
	}
	configurations := make([]qualificationharness.ConfigurationObservation, len(report.Configurations))
	for index, item := range report.Configurations {
		configurations[index] = qualificationharness.ConfigurationObservation{ID: item.ID, Digest: *item.Digest, DigestProfile: item.DigestProfile, Sanitized: item.Sanitized, ObservedBy: item.ObservedBy}
	}
	processes := func(source []processIdentity) []qualificationharness.ProcessIdentityObservation {
		result := make([]qualificationharness.ProcessIdentityObservation, len(source))
		for index, item := range source {
			result[index] = qualificationharness.ProcessIdentityObservation{Component: item.Component, ProcessID: item.ProcessID, ExecutableDigest: item.ExecutableDigest, ConfigurationDigest: item.ConfigurationDigest, ObservedBy: item.ObservedBy}
		}
		return result
	}
	interactions := func(source []interactionResult) []qualificationharness.ObservedInteraction {
		result := make([]qualificationharness.ObservedInteraction, len(source))
		for index, item := range source {
			transient := make([]qualificationharness.ObservedOutcome, len(item.TransientOutcomes))
			for outcomeIndex, outcome := range item.TransientOutcomes {
				transient[outcomeIndex] = harnessOutcome(outcome)
			}
			result[index] = qualificationharness.ObservedInteraction{InteractionID: item.InteractionID, Surface: item.Surface, Actor: item.Actor, Method: item.Method, RouteTemplate: item.RouteTemplate, LogicalRequestID: item.LogicalRequestID, ReplayOf: item.ReplayOf, WireAttempts: item.WireAttempts, TransientOutcomes: transient, FinalOutcome: harnessOutcome(item.FinalOutcome), MutationWriteObserved: item.MutationWriteObserved}
		}
		return result
	}
	providerInteractions, gatewayInteractions := splitInteractions(report.ScenarioResults)
	facts := map[string][]qualificationharness.ObserverFact{}
	bound := make([]qualificationharness.BoundObservation, len(report.Observations))
	for index, item := range report.Observations {
		fact := qualificationharness.ObserverFact{ObservationID: item.ID, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: item.Result}
		facts[item.Source] = append(facts[item.Source], fact)
		bound[index] = qualificationharness.BoundObservation{ObservationID: item.ID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: item.Result}
	}
	scenarios := make([]qualificationharness.DerivedScenario, len(report.ScenarioResults))
	initialProgress := make([]qualificationharness.ScenarioProgress, 0, 15)
	reconstructionProgress := make([]qualificationharness.ScenarioProgress, 0, 5)
	for index, item := range report.ScenarioResults {
		observed := interactions(item.Interactions)
		scenarios[index] = qualificationharness.DerivedScenario{CaseID: item.CaseID, PhaseID: item.PhaseID, Status: item.Status, Interactions: observed, ObservationIDs: append([]string(nil), item.ObservationIDs...)}
		progress := qualificationharness.ScenarioProgress{CaseID: item.CaseID, Disposition: qualificationharness.ScenarioCompleted}
		for _, interaction := range item.Interactions {
			progress.Interactions = append(progress.Interactions, qualificationharness.InteractionProgress{InteractionID: interaction.InteractionID, WireAttempts: interaction.WireAttempts})
		}
		if item.PhaseID == "initial" {
			initialProgress = append(initialProgress, progress)
		} else {
			reconstructionProgress = append(reconstructionProgress, progress)
		}
	}
	artifactsByID, configurationsByID := artifactMap(report.Artifacts), configurationMap(report.Configurations)
	query := harnessQueryScope(*report.Cleanup.QueryScope)
	baseline := harnessCleanupInventory(*report.Cleanup.Baseline)
	post := harnessCleanupInventory(*report.Cleanup.PostTeardown)
	resourceTarget := qualificationharness.TargetIdentity{TargetDigest: testDigest, TargetDigestProfile: "sha256-canonical-target-description-v1", Architecture: "linux-amd64", RunNamespaceDigest: testDigest, RunNamespaceDigestProfile: "sha256-run-namespace-v1"}
	challenge := report.Invocation.ShellChallenge
	resources := report.SandboxResources
	start := mustTestTime(*report.Timestamps.ExecutionStartedAt)
	return qualificationharness.EvidenceSnapshot{
		RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ProfileID: report.Profile.ProfileID, ProfileVersion: report.Profile.ProfileVersion, ProfileDigest: report.Profile.ProfileDigest,
		Runtime:              qualificationharness.RuntimeObservation{DedicatedDisposableTarget: true, RunUniqueNamespace: true, Target: resourceTarget, Artifacts: artifacts, Configurations: configurations},
		ReconstructionPolicy: definition.Reconstruction(), QueryScope: query, Baseline: qualificationharness.ResourceBaseline{QueryScopeDigest: baseline.QueryScopeDigest, InventoryDigest: baseline.InventoryDigest, DigestProfile: baseline.DigestProfile, RunOwnedCount: baseline.RunOwnedCount, Stable: baseline.Stable, SampledAt: baseline.SampledAt[0]},
		ExecutionStartedAt: start, ExecutionDeadlineAt: start.Add(30 * time.Minute), TotalDeadlineAt: start.Add(35 * time.Minute),
		Initial:        qualificationharness.InitialPhaseResult{PhaseID: "initial", OrchestrationStartedAt: mustTestTime(*report.Phases[0].StartedAt), OrchestrationFinishedAt: mustTestTime(*report.Phases[0].FinishedAt), Scenarios: initialProgress, Completion: "completed", TerminalObserved: true, CleanupRequired: true},
		Reconstruction: qualificationharness.ReconstructionPhaseResult{PhaseID: "reconstruction", OrchestrationStartedAt: mustTestTime(*report.Phases[1].StartedAt), OrchestrationFinishedAt: mustTestTime(*report.Phases[1].FinishedAt), InitialInvocationID: *report.Invocation.InitialInvocationID, ReconstructionInvocationID: *report.Invocation.ReconstructionInvocationID, Scenarios: reconstructionProgress, Completion: "completed", TerminalObserved: true, CleanupRequired: true},
		Observation: qualificationharness.ExecutionObservationResult{
			Scenarios: scenarios, Observations: bound,
			Provider:   qualificationharness.ProviderExecutionObservation{RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ObserverArtifactDigest: *artifactsByID["provider_observer"].Digest, ObserverConfigurationDigest: *configurationsByID["observer_configuration"].Digest, SandboxResources: &qualificationharness.SandboxResourceObservation{CPUMillis: resources.CPUMillis, MemoryBytes: resources.MemoryBytes, EphemeralStorageBytes: resources.EphemeralStorageBytes, PIDs: resources.PIDs}, Interactions: interactions(providerInteractions), Facts: facts["provider_observer"]},
			Gateway:    qualificationharness.GatewayExecutionObservation{RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ObserverArtifactDigest: *artifactsByID["gateway_observer"].Digest, ObserverConfigurationDigest: *configurationsByID["observer_configuration"].Digest, Interactions: interactions(gatewayInteractions), ShellChallenge: &qualificationharness.ShellContinuityObservation{Digest: challenge.Digest, DigestProfile: challenge.DigestProfile, EstablishedInCase: challenge.EstablishedInCase, VerifiedInCase: challenge.VerifiedInCase, RawChallengeInEvidence: challenge.RawChallengeInEvidence}, Facts: facts["gateway_observer"]},
			Processes:  qualificationharness.ProcessExecutionObservation{RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, SupervisorArtifactDigest: *artifactsByID["process_supervisor"].Digest, SupervisorConfigurationDigest: *configurationsByID["observer_configuration"].Digest, InitialInvocationID: *report.Invocation.InitialInvocationID, ReconstructionInvocationID: *report.Invocation.ReconstructionInvocationID, Artifacts: artifacts, Configurations: configurations, InitialProcesses: processes(report.Invocation.InitialProcesses), ReconstructionProcesses: processes(report.Invocation.ReconstructionProcesses), HarnessReinjectedForbiddenBindings: false, AdapterTranscript: qualificationharness.AdapterTranscriptObservation{Digest: report.Invocation.AdapterTranscript.Digest, DigestProfile: report.Invocation.AdapterTranscript.DigestProfile, InvocationIDs: report.Invocation.AdapterTranscript.InvocationIDs, AllowedFields: report.Invocation.AdapterTranscript.AllowedFields, ForbiddenFields: report.Invocation.AdapterTranscript.ForbiddenFields, Sanitized: true, ObservedBy: "process_supervisor"}, Facts: facts["process_supervisor"]},
			Resources:  qualificationharness.ResourceExecutionObservation{RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, InspectorArtifactDigest: *artifactsByID["resource_inspector"].Digest, InspectorConfigurationDigest: *configurationsByID["inspector_configuration"].Digest, Target: resourceTarget, Artifacts: artifacts, Facts: facts["resource_inspector"]},
			ObservedAt: mustTestTime(*report.Timestamps.ExecutionFinishedAt), CleanupRequired: true,
		},
		Cleanup: qualificationharness.CleanupResult{Authority: report.Cleanup.Authority, MutationWriteObserved: report.Cleanup.MutationWriteObserved, CleanupRequired: report.Cleanup.CleanupRequired, QueryScope: query, Baseline: baseline, TeardownAttempts: report.Cleanup.TeardownAttempts, TeardownCompleted: report.Cleanup.TeardownCompleted, PostTeardown: &post, StabilitySamples: report.Cleanup.StabilitySamples, StabilityIntervalMilliseconds: report.Cleanup.StabilityIntervalMS, Outcome: report.Cleanup.Outcome, CleanupStartedAt: mustTestTime(*report.Timestamps.CleanupStartedAt), CleanupFinishedAt: mustTestTime(*report.Timestamps.CleanupFinishedAt)},
	}
}

func harnessOutcome(source reportOutcome) qualificationharness.ObservedOutcome {
	return qualificationharness.ObservedOutcome{Transport: source.Transport, StatusCode: source.StatusCode, ErrorCode: source.ErrorCode, Retryable: source.Retryable, RetryAfterPresent: source.RetryAfterPresent}
}

func harnessQueryScope(source queryScope) qualificationharness.QueryScope {
	return qualificationharness.QueryScope{Digest: *source.Digest, DigestProfile: source.DigestProfile, TargetDigest: *source.TargetDigest, RunNamespaceDigest: *source.RunNamespaceDigest, OwnershipSelectorDigest: *source.OwnershipSelectorDigest, ResourceKinds: source.ResourceKinds, InspectorArtifactDigest: *source.InspectorArtifactDigest, InspectorConfigurationDigest: *source.InspectorConfigurationDigest, ExcludesHarnessControlPlane: source.ExcludesHarnessControlPlane}
}

func harnessCleanupInventory(source resourceInventory) qualificationharness.CleanupInventory {
	sampled := make([]time.Time, len(source.SampledAt))
	for index, value := range source.SampledAt {
		sampled[index] = mustTestTime(value)
	}
	return qualificationharness.CleanupInventory{QueryScopeDigest: *source.QueryScopeDigest, InventoryDigest: *source.Digest, DigestProfile: source.DigestProfile, RunOwnedCount: source.RunOwnedCount, Stable: source.Stable, SampledAt: sampled}
}

func shiftSyntheticTimes(t *testing.T, report *reportDocument, newStart time.Time) {
	t.Helper()
	oldStart := mustTestTime(*report.Timestamps.RunStartedAt)
	delta := newStart.Sub(oldStart)
	shift := func(value **string) {
		if *value == nil {
			return
		}
		shifted := mustTestTime(**value).Add(delta).UTC().Format(time.RFC3339Nano)
		*value = &shifted
	}
	for _, value := range []**string{&report.Timestamps.RunStartedAt, &report.Timestamps.ExecutionStartedAt, &report.Timestamps.ExecutionFinishedAt, &report.Timestamps.CleanupStartedAt, &report.Timestamps.CleanupFinishedAt, &report.Timestamps.RunFinishedAt} {
		shift(value)
	}
	for index := range report.Phases {
		shift(&report.Phases[index].StartedAt)
		shift(&report.Phases[index].FinishedAt)
	}
	for index := range report.ScenarioResults {
		shift(&report.ScenarioResults[index].StartedAt)
		shift(&report.ScenarioResults[index].FinishedAt)
	}
	for index, value := range report.Cleanup.Baseline.SampledAt {
		report.Cleanup.Baseline.SampledAt[index] = mustTestTime(value).Add(delta).UTC().Format(time.RFC3339Nano)
	}
	for index, value := range report.Cleanup.PostTeardown.SampledAt {
		report.Cleanup.PostTeardown.SampledAt[index] = mustTestTime(value).Add(delta).UTC().Format(time.RFC3339Nano)
	}
}

func mustTestTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		panic(err)
	}
	return parsed
}
