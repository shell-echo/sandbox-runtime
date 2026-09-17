package qualificationreport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/evidencefiles"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

var ErrEvidenceAssembly = errors.New("qualification evidence assembly failed")

var assemblyDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ScenarioTimingInput is a process-supervisor observation. The assembler
// accepts only the locked case identity and its bounded UTC interval.
type ScenarioTimingInput struct {
	CaseID     string
	PhaseID    string
	StartedAt  time.Time
	FinishedAt time.Time
}

// CallerAssertionInput is caller-owner evidence, not an independent runtime
// observation. The report validator cross-binds it to the exact profile case.
type CallerAssertionInput struct {
	AssertionID string
	Result      string
}

// TrustedInputStatementInput binds one locked provenance statement to a
// digest. Its external provenance is evaluated only by the P2.7e gate.
type TrustedInputStatementInput struct {
	InputID       string
	Source        string
	SubjectDigest string
}

// AssemblyInput contains the only d7 data not already present in the d1-d6
// snapshot. It deliberately excludes paths other than the evidence root,
// endpoints, credentials, requests, responses, and raw correlation values.
type AssemblyInput struct {
	AdapterTranscriptProjection []byte
	ScenarioTimings             []ScenarioTimingInput
	CallerAssertions            []CallerAssertionInput
	TrustedInputs               []TrustedInputStatementInput
}

// RootAssembler publishes the five locked payloads and report through a
// descriptor-pinned evidence root, closes its writer, then invokes Verify.
// The caller must ensure no external writer remains active before invocation.
type RootAssembler struct {
	SourceRoot   string
	EvidenceRoot string
	Input        AssemblyInput
	// StageObserver receives only a fixed, non-sensitive stage identifier. It
	// exists so an outer operator can diagnose a failed hosted finalization
	// without exposing the assembler's underlying error or evidence content.
	StageObserver func(string)
}

// AssembleAndVerify implements qualificationharness.EvidenceAssembler. A
// failed validator run intentionally leaves the assembled root for diagnosis;
// failures before writer handoff remove only files created by this invocation.
func (a RootAssembler) AssembleAndVerify(ctx context.Context, snapshot qualificationharness.EvidenceSnapshot) (qualificationharness.EvidenceFinalizationResult, error) {
	a.observeStage("preflight")
	if ctx == nil || a.SourceRoot == "" || a.EvidenceRoot == "" {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	if err := ctx.Err(); err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, errors.Join(ErrEvidenceAssembly, err)
	}

	a.observeStage("definition-lock")
	definition, err := qualificationprofile.VerifyCodingShellV1(ctx, a.SourceRoot)
	if err != nil || definition.ProfileDigest != qualificationprofile.ExpectedProfileDigest {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	profileBytes, err := readSourceFile(a.SourceRoot, qualificationprofile.ProfilePath, maxReportBytes)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	profile, err := decodeLockedProfile(profileBytes)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	schemaBytes, err := readSourceFile(a.SourceRoot, ReportSchemaPath, maxReportBytes)
	if err != nil || evidencefiles.RawDigest(schemaBytes) != ExpectedReportSchemaDigest {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	semantics, err := loadValidatorSemantics(a.SourceRoot, ExpectedReportSchemaDigest)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}

	a.observeStage("input-normalization")
	projection, timings, assertions, trusted, err := normalizeAssemblyInput(a.Input, snapshot, profile, schemaBytes, semantics)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	a.observeStage("report-model")
	reportID, err := randomEvidenceID("qualification-report-")
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	invocationID, err := randomEvidenceID("qualification-run-")
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	report, err := assembleReport(snapshot, profile, reportID, invocationID, timings, assertions, trusted)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	a.observeStage("payload-model")
	payloadDocuments, payloadModels, err := assemblePayloads(report, projection, trusted)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}

	a.observeStage("evidence-root")
	root, err := evidencefiles.OpenRoot(a.EvidenceRoot)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	publications := make([]*evidencefiles.Publication, 0, len(payloadDocuments)+1)
	handedOff := false
	defer func() {
		if !handedOff {
			for index := len(publications) - 1; index >= 0; index-- {
				_ = publications[index].Remove()
			}
		}
		_ = root.Close()
	}()
	empty, err := root.Read(nil, evidencefiles.DefaultOptions())
	if err != nil || empty.FileCount != 0 || empty.TotalBytes != 0 || len(empty.Entries) != 0 {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	a.observeStage("payload-publication")
	for _, path := range []string{"provider-observer.json", "gateway-observer.json", "process-supervisor.json", "resource-inspector.json", "trusted-inputs.json"} {
		document := payloadDocuments[path]
		if len(document) == 0 || validateSanitizedBytes(document) != nil {
			return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
		}
		publication, err := root.Publish(path, document, evidencefiles.DefaultMaxFileBytes)
		if err != nil {
			return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
		}
		publications = append(publications, publication)
	}
	if err := ctx.Err(); err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, errors.Join(ErrEvidenceAssembly, err)
	}
	inventory, err := root.Read([]string{ReportFileName, ReceiptFileName}, evidencefiles.DefaultOptions())
	if err != nil || inventory.FileCount != 5 || len(inventory.Entries) != 5 {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	payloadModels.RawByPath = make(map[string][]byte, len(payloadDocuments))
	payloadModels.DigestByPath = make(map[string]string, len(inventory.Entries))
	for _, entry := range inventory.Entries {
		payloadModels.RawByPath[entry.Path] = append([]byte(nil), payloadDocuments[entry.Path]...)
		payloadModels.DigestByPath[entry.Path] = entry.SHA256
	}
	bindPayloadDigests(&report, inventory)
	report.Counters, _ = calculateCounters(report.ScenarioResults, report.Observations, orderedProfileCases(profile))
	report.Evidence.PayloadInventory = append([]evidencefiles.Entry(nil), inventory.Entries...)
	report.Evidence.PayloadInventoryDigest = inventory.Digest
	report.Evidence.FileCount = inventory.FileCount + 2
	report.RunOutcome.IdentityComplete = hasCompleteIdentity(report, semantics, payloadModels)
	report.RunOutcome = deriveRunOutcome(report, profile, report.RunOutcome.IdentityComplete)
	a.observeStage("semantic-validation")
	if err := validateSemantic(report, profile, definition, semantics, payloadModels); err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}

	a.observeStage("report-finalization")
	reportBytes, err := finalizeReportBytes(report, inventory, semantics)
	if err != nil || validateSanitizedBytes(reportBytes) != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	var reportValue any
	if decodeStrictJSON(reportBytes, &reportValue) != nil || validateReportSchema(schemaBytes, reportValue) != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	a.observeStage("report-publication")
	publication, err := root.Publish(ReportFileName, reportBytes, maxReportBytes)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	publications = append(publications, publication)
	if err := root.Close(); err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	handedOff = true

	a.observeStage("receipt-validation")
	verified, err := Verify(ctx, a.EvidenceRoot, a.SourceRoot)
	if err != nil {
		return qualificationharness.EvidenceFinalizationResult{}, ErrEvidenceAssembly
	}
	a.observeStage("completed")
	return qualificationharness.EvidenceFinalizationResult{
		ReportID: verified.ReportID, InvocationID: verified.InvocationID, RuntimeCommitmentDigest: verified.RuntimeCommitment,
		ProfileID: snapshot.ProfileID, ProfileVersion: snapshot.ProfileVersion, ProfileDigest: snapshot.ProfileDigest,
		InitialInvocationID: snapshot.Reconstruction.InitialInvocationID, ReconstructionInvocationID: snapshot.Reconstruction.ReconstructionInvocationID,
		ReportDigest: verified.ReportDigest, PayloadInventoryDigest: verified.PayloadInventory, ReceiptFile: verified.ReceiptFile,
		RunOutcome: verified.RunOutcome, ValidationOutcome: verified.ValidationOutcome, FileCount: verified.FileCount, TotalBytes: verified.TotalBytes,
	}, nil
}

func (a RootAssembler) observeStage(stage string) {
	if a.StageObserver != nil {
		a.StageObserver(stage)
	}
}

func normalizeAssemblyInput(input AssemblyInput, snapshot qualificationharness.EvidenceSnapshot, profile profileDocument, schema []byte, semantics validatorSemantics) (map[string]any, []scenarioTiming, []claimAssertion, []trustedInputStatement, error) {
	if !validEvidenceSnapshot(snapshot, profile) || len(input.AdapterTranscriptProjection) == 0 || int64(len(input.AdapterTranscriptProjection)) > evidencefiles.DefaultMaxFileBytes {
		return nil, nil, nil, nil, ErrEvidenceAssembly
	}
	var projection map[string]any
	if decodeStrictJSON(input.AdapterTranscriptProjection, &projection) != nil || validateSchemaReference(schema, "#/$defs/adapterTranscriptProjection", projection) != nil {
		return nil, nil, nil, nil, ErrEvidenceAssembly
	}
	projectionDigest, err := canonicalDigest(projection)
	if err != nil || projectionDigest != snapshot.Observation.Processes.AdapterTranscript.Digest {
		return nil, nil, nil, nil, ErrEvidenceAssembly
	}

	cases := orderedProfileCases(profile)
	if len(cases) != 20 || len(input.ScenarioTimings) != len(cases) {
		return nil, nil, nil, nil, ErrEvidenceAssembly
	}
	timings := make([]scenarioTiming, len(cases))
	for index, expected := range cases {
		actual := input.ScenarioTimings[index]
		if actual.CaseID != expected.CaseID || actual.PhaseID != expected.PhaseID() || !validUTCInterval(actual.StartedAt, actual.FinishedAt) || actual.FinishedAt.Sub(actual.StartedAt) > time.Duration(expected.TimeoutSeconds)*time.Second {
			return nil, nil, nil, nil, ErrEvidenceAssembly
		}
		started, finished := formatTime(actual.StartedAt), formatTime(actual.FinishedAt)
		timings[index] = scenarioTiming{CaseID: actual.CaseID, PhaseID: actual.PhaseID, StartedAt: &started, FinishedAt: &finished}
	}

	expectedAssertions := make([]string, 0, 29)
	for _, current := range cases {
		expectedAssertions = append(expectedAssertions, current.Assertions...)
	}
	if len(expectedAssertions) != 29 || len(input.CallerAssertions) != len(expectedAssertions) {
		return nil, nil, nil, nil, ErrEvidenceAssembly
	}
	assertions := make([]claimAssertion, len(expectedAssertions))
	for index, id := range expectedAssertions {
		actual := input.CallerAssertions[index]
		if actual.AssertionID != id || !oneOf(actual.Result, "asserted", "not_asserted", "contradicted") {
			return nil, nil, nil, nil, ErrEvidenceAssembly
		}
		assertions[index] = claimAssertion{ID: id, Owner: "external_caller_owner", Result: actual.Result}
	}

	if len(input.TrustedInputs) != len(semantics.TrustedInputs) {
		return nil, nil, nil, nil, ErrEvidenceAssembly
	}
	trusted := make([]trustedInputStatement, len(input.TrustedInputs))
	for index, expected := range semantics.TrustedInputs {
		actual := input.TrustedInputs[index]
		if actual.InputID != expected.ID || actual.Source != expected.Source || !assemblyDigestPattern.MatchString(actual.SubjectDigest) {
			return nil, nil, nil, nil, ErrEvidenceAssembly
		}
		trusted[index] = trustedInputStatement{ID: actual.InputID, Source: actual.Source, SubjectDigest: actual.SubjectDigest}
	}
	return projection, timings, assertions, trusted, nil
}

func validEvidenceSnapshot(snapshot qualificationharness.EvidenceSnapshot, profile profileDocument) bool {
	if !assemblyDigestPattern.MatchString(snapshot.RuntimeCommitmentDigest) || snapshot.ProfileID != qualificationprofile.ProfileID || snapshot.ProfileVersion != qualificationprofile.ProfileVersion || snapshot.ProfileDigest != qualificationprofile.ExpectedProfileDigest ||
		!snapshot.Runtime.DedicatedDisposableTarget || !snapshot.Runtime.RunUniqueNamespace || len(snapshot.Runtime.Artifacts) != len(profile.Artifacts) || len(snapshot.Runtime.Configurations) != len(profile.Evidence.RequiredInventories) ||
		len(snapshot.Initial.Scenarios) != 15 || len(snapshot.Reconstruction.Scenarios) != 5 || len(snapshot.Observation.Scenarios) != 20 || len(snapshot.Observation.Observations) != 91 || snapshot.Initial.PhaseID != "initial" || snapshot.Reconstruction.PhaseID != "reconstruction" ||
		!snapshot.Initial.TerminalObserved || !snapshot.Reconstruction.TerminalObserved || snapshot.Reconstruction.InitialInvocationID == "" || snapshot.Reconstruction.ReconstructionInvocationID == "" || snapshot.Reconstruction.InitialInvocationID == snapshot.Reconstruction.ReconstructionInvocationID ||
		!validUTCInterval(snapshot.ExecutionStartedAt, snapshot.Observation.ObservedAt) || !validUTCInterval(snapshot.Cleanup.CleanupStartedAt, snapshot.Cleanup.CleanupFinishedAt) || snapshot.Cleanup.CleanupStartedAt.Before(snapshot.Observation.ObservedAt) || snapshot.Cleanup.CleanupFinishedAt.After(snapshot.TotalDeadlineAt) ||
		snapshot.Cleanup.Outcome == qualificationharness.CleanupOutcomeNotRequired {
		return false
	}
	if snapshot.Observation.Processes.RuntimeCommitmentDigest != snapshot.RuntimeCommitmentDigest || snapshot.Observation.Provider.RuntimeCommitmentDigest != snapshot.RuntimeCommitmentDigest || snapshot.Observation.Gateway.RuntimeCommitmentDigest != snapshot.RuntimeCommitmentDigest || snapshot.Observation.Resources.RuntimeCommitmentDigest != snapshot.RuntimeCommitmentDigest {
		return false
	}
	return true
}

func assembleReport(snapshot qualificationharness.EvidenceSnapshot, profile profileDocument, reportID, invocationID string, timings []scenarioTiming, assertions []claimAssertion, trustedStatements []trustedInputStatement) (reportDocument, error) {
	contract := contractIdentity{
		Namespace: profile.Contract.Namespace, Version: profile.Contract.Version, Revision: profile.Contract.Revision, Tree: profile.Contract.Tree,
		ManifestDigest: profile.Contract.ManifestDigest, OpenAPIDigest: profile.Contract.OpenAPIDigest, SemanticRulesDigest: profile.Contract.SemanticRulesDigest,
		LocalSuite: suiteFromProfile(profile.Contract.LocalSuite), RemoteSuite: suiteFromProfile(profile.Contract.RemoteSuite),
	}
	topology := make(map[string]any, len(profile.Topology)+1)
	for key, value := range profile.Topology {
		topology[key] = value
	}
	topology["distinct_tenants"] = topology["distinct_tenants_required"]
	delete(topology, "distinct_tenants_required")
	topology["target_identity"] = map[string]any{
		"target_digest": snapshot.Runtime.Target.TargetDigest, "target_digest_profile": snapshot.Runtime.Target.TargetDigestProfile,
		"architecture": snapshot.Runtime.Target.Architecture, "run_namespace_digest": snapshot.Runtime.Target.RunNamespaceDigest,
		"run_namespace_digest_profile": snapshot.Runtime.Target.RunNamespaceDigestProfile,
	}
	artifacts := make([]artifactIdentity, len(snapshot.Runtime.Artifacts))
	for index, item := range snapshot.Runtime.Artifacts {
		digest := item.Digest
		artifacts[index] = artifactIdentity{ArtifactID: item.ArtifactID, Owner: item.Owner, TrustDomain: item.TrustDomain, DigestSubject: item.DigestSubject, Digest: &digest, ObservedBy: item.ObservedBy, Source: sourceFromHarness(item.Source)}
	}
	configurations := make([]configuration, len(snapshot.Runtime.Configurations))
	for index, item := range snapshot.Runtime.Configurations {
		digest := item.Digest
		configurations[index] = configuration{ID: item.ID, Digest: &digest, DigestProfile: item.DigestProfile, Sanitized: item.Sanitized, ObservedBy: item.ObservedBy}
	}
	artifactByID := artifactMap(artifacts)
	caller := artifactByID["external_caller"].Source
	adapter := artifactByID["qualification_adapter"].Source
	initialID, reconstructionID := snapshot.Reconstruction.InitialInvocationID, snapshot.Reconstruction.ReconstructionInvocationID
	harnessReinjected := snapshot.Observation.Processes.HarnessReinjectedForbiddenBindings

	reportScenarios, phases, err := assembleScenarios(snapshot, profile, timings, assertions)
	if err != nil {
		return reportDocument{}, err
	}
	observations := make([]observation, len(snapshot.Observation.Observations))
	for index, item := range snapshot.Observation.Observations {
		observations[index] = observation{ID: item.ObservationID, Source: item.Source, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: item.Result}
	}
	claimsTrusted := make([]trustedInput, len(trustedStatements))
	for index, item := range trustedStatements {
		claimsTrusted[index] = trustedInput{ID: item.ID, Source: item.Source}
	}

	result := reportDocument{
		FormatVersion: 1, ReportType: "sandbox-runtime-external-caller-qualification-report", ReportVersion: "1.0.0", ReportID: reportID,
		Profile:  profileIdentity{ProfileID: snapshot.ProfileID, ProfileVersion: snapshot.ProfileVersion, ProfileDigest: snapshot.ProfileDigest, SchemaDigest: qualificationprofile.ExpectedSchemaDigest, SchemaDigestProfile: evidencefiles.FileDigestProfile},
		Contract: contract, Capability: profile.CapabilitySelection, Topology: topology, Artifacts: artifacts, Configurations: configurations,
		Invocation: invocation{
			InvocationID: invocationID, RuntimeCommitmentDigest: snapshot.RuntimeCommitmentDigest, InitialInvocationID: &initialID, ReconstructionInvocationID: &reconstructionID,
			HarnessArtifactDigest: artifactByID["qualification_harness"].Digest,
			StartupIdentity:       &startupIdentity{CallerRelease: caller, AdapterRelease: adapter, ContractRevision: contract.Revision, ContractTree: contract.Tree, ProfileID: snapshot.ProfileID, ProfileDigest: snapshot.ProfileDigest, AdapterProtocolID: AdapterProtocolID, AdapterProtocolVersion: AdapterProtocolVersion, AdapterProtocolSchemaDigest: ExpectedAdapterProtocolSchemaDigest, AdapterProtocolSemanticsDigest: ExpectedAdapterProtocolSemanticsDigest},
			InitialProcesses:      processIdentities(snapshot.Observation.Processes.InitialProcesses), ReconstructionProcesses: processIdentities(snapshot.Observation.Processes.ReconstructionProcesses),
			RestartedComponents: append([]string(nil), snapshot.ReconstructionPolicy.RestartComponents...), PreservedStores: append([]string(nil), snapshot.ReconstructionPolicy.PreserveStores...), HarnessReinjected: &harnessReinjected,
			AdapterTranscript: transcriptFromHarness(snapshot.Observation.Processes.AdapterTranscript), ShellChallenge: challengeFromHarness(snapshot.Observation.Gateway.ShellChallenge),
		},
		Phases: phases, ScenarioResults: reportScenarios, Observations: observations, Cleanup: cleanupFromHarness(snapshot.Cleanup),
		Evidence:   evidence{RootRelative: ".", PayloadInventoryDigestProfile: evidencefiles.DigestProfile, Sanitization: sanitization{Required: true, Status: "passed", ScannerIdentity: ExpectedValidatorSemanticsDigest}, Boundary: "sanitized-evidence-payload-excludes-private-material"},
		Claims:     claims{CallerAssertions: assertions, TrustedInputs: claimsTrusted, NonClaims: append([]string(nil), profile.RequiredNonClaims...)},
		Timestamps: timestampsFromSnapshot(snapshot),
	}
	for _, scenario := range result.ScenarioResults {
		for _, interaction := range scenario.Interactions {
			if interaction.InteractionID == "create-sandbox" {
				resources := snapshot.Observation.Provider.SandboxResources
				if resources != nil {
					result.SandboxResources = &sandboxResources{CPUMillis: resources.CPUMillis, MemoryBytes: resources.MemoryBytes, EphemeralStorageBytes: resources.EphemeralStorageBytes, PIDs: resources.PIDs}
				}
			}
		}
	}
	allCases := orderedProfileCases(profile)
	result.Counters, _ = calculateCounters(result.ScenarioResults, result.Observations, allCases)
	return result, nil
}

func assembleScenarios(snapshot qualificationharness.EvidenceSnapshot, profile profileDocument, timings []scenarioTiming, callerAssertions []claimAssertion) ([]scenarioResult, []phase, error) {
	cases := orderedProfileCases(profile)
	if len(cases) != len(snapshot.Observation.Scenarios) || len(cases) != len(timings) {
		return nil, nil, ErrEvidenceAssembly
	}
	assertionByID := make(map[string]claimAssertion, len(callerAssertions))
	for _, item := range callerAssertions {
		assertionByID[item.ID] = item
	}
	result := make([]scenarioResult, len(cases))
	for index, expected := range cases {
		observed := snapshot.Observation.Scenarios[index]
		if observed.CaseID != expected.CaseID || observed.PhaseID != expected.PhaseID() || !oneOf(observed.Status, "passed", "failed", "incomplete", "not_executed") {
			return nil, nil, ErrEvidenceAssembly
		}
		interactions := make([]interactionResult, len(observed.Interactions))
		if len(observed.Interactions) > len(expected.Interactions) {
			return nil, nil, ErrEvidenceAssembly
		}
		for interactionIndex, item := range observed.Interactions {
			expectedInteraction := expected.Interactions[interactionIndex]
			if item.InteractionID != expectedInteraction.ID {
				return nil, nil, ErrEvidenceAssembly
			}
			observationIDs := make([]string, len(expectedInteraction.Observations))
			for observationIndex, expectedObservation := range expectedInteraction.Observations {
				observationIDs[observationIndex] = expectedObservation.ID
			}
			interactions[interactionIndex] = interactionFromHarness(item, observationIDs)
		}
		assertions := make([]assertionResult, len(expected.Assertions))
		assertionContradicted := false
		for assertionIndex, id := range expected.Assertions {
			claim, ok := assertionByID[id]
			if !ok || (observed.Status == "not_executed" && claim.Result != "not_asserted") {
				return nil, nil, ErrEvidenceAssembly
			}
			assertions[assertionIndex] = assertionResult{ID: id, Result: claim.Result}
			assertionContradicted = assertionContradicted || claim.Result == "contradicted"
		}
		if observed.Status == "not_executed" {
			interactions = []interactionResult{}
		}
		status := observed.Status
		if status != "not_executed" && assertionContradicted {
			status = "failed"
		}
		result[index] = scenarioResult{CaseID: expected.CaseID, PhaseID: expected.PhaseID(), Status: status, StartedAt: timings[index].StartedAt, FinishedAt: timings[index].FinishedAt, Interactions: interactions, Assertions: assertions, ObservationIDs: append([]string(nil), observed.ObservationIDs...)}
	}
	phases := make([]phase, len(profile.Phases))
	offset := 0
	for index, expected := range profile.Phases {
		caseIDs := make([]string, len(expected.Cases))
		statuses := make([]string, len(expected.Cases))
		for caseIndex, current := range expected.Cases {
			caseIDs[caseIndex] = current.CaseID
			statuses[caseIndex] = result[offset+caseIndex].Status
		}
		started, finished := snapshot.Initial.OrchestrationStartedAt, snapshot.Initial.OrchestrationFinishedAt
		if expected.PhaseID == "reconstruction" {
			started, finished = snapshot.Reconstruction.OrchestrationStartedAt, snapshot.Reconstruction.OrchestrationFinishedAt
		}
		startedText, finishedText := formatTime(started), formatTime(finished)
		phases[index] = phase{PhaseID: expected.PhaseID, Status: derivePhaseStatus(statuses), ScenarioIDs: caseIDs, StartedAt: &startedText, FinishedAt: &finishedText}
		offset += len(expected.Cases)
	}
	return result, phases, nil
}

func assemblePayloads(report reportDocument, projection map[string]any, trusted []trustedInputStatement) (map[string][]byte, payloadSet, error) {
	artifactByID, configurationByID := artifactMap(report.Artifacts), configurationMap(report.Configurations)
	providerInteractions, gatewayInteractions := splitInteractions(report.ScenarioResults)
	facts := make(map[string][]observerFact)
	for _, item := range report.Observations {
		facts[item.Source] = append(facts[item.Source], observerFact{ID: item.ID, Actor: item.Actor, Subject: item.Subject, Correlation: item.Correlation, Result: item.Result})
	}
	for _, source := range []string{"provider_observer", "gateway_observer", "process_supervisor", "resource_inspector"} {
		if facts[source] == nil {
			facts[source] = []observerFact{}
		}
	}
	provider := &providerObserverPayload{FormatVersion: 1, PayloadType: "sandbox-runtime-provider-observer-evidence", PayloadVersion: "1.0.0", InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ObserverArtifactDigest: artifactByID["provider_observer"].Digest, ObserverConfigurationDigest: configurationByID["observer_configuration"].Digest, SandboxResources: report.SandboxResources, Interactions: providerInteractions, Observations: facts["provider_observer"]}
	gateway := &gatewayObserverPayload{FormatVersion: 1, PayloadType: "sandbox-runtime-gateway-observer-evidence", PayloadVersion: "1.0.0", InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, ObserverArtifactDigest: artifactByID["gateway_observer"].Digest, ObserverConfigurationDigest: configurationByID["observer_configuration"].Digest, Interactions: gatewayInteractions, Observations: facts["gateway_observer"], ShellChallenge: report.Invocation.ShellChallenge}
	process := &processSupervisorPayload{FormatVersion: 1, PayloadType: "sandbox-runtime-process-supervisor-evidence", PayloadVersion: "1.0.0", InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, SupervisorArtifactDigest: artifactByID["process_supervisor"].Digest, SupervisorConfigurationDigest: configurationByID["observer_configuration"].Digest, InitialInvocationID: report.Invocation.InitialInvocationID, ReconstructionInvocationID: report.Invocation.ReconstructionInvocationID, StartupIdentity: report.Invocation.StartupIdentity, ArtifactIdentities: filterArtifacts(report.Artifacts, "process_supervisor"), ConfigurationIdentities: report.Configurations, InitialProcesses: report.Invocation.InitialProcesses, ReconstructionProcesses: report.Invocation.ReconstructionProcesses, AdapterTranscript: report.Invocation.AdapterTranscript, AdapterTranscriptProjection: projection, RunTimestamps: report.Timestamps, Phases: report.Phases, ScenarioTimings: projectScenarioTimings(report.ScenarioResults), Observations: facts["process_supervisor"]}
	resource := &resourceInspectorPayload{FormatVersion: 1, PayloadType: "sandbox-runtime-resource-inspector-evidence", PayloadVersion: "1.0.0", InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, InspectorArtifactDigest: artifactByID["resource_inspector"].Digest, InspectorConfigurationDigest: configurationByID["inspector_configuration"].Digest, TargetIdentity: report.Topology["target_identity"], ArtifactIdentities: filterArtifacts(report.Artifacts, "resource_inspector"), Cleanup: report.Cleanup, CleanupTimestamps: cleanupTimestamps{StartedAt: report.Timestamps.CleanupStartedAt, FinishedAt: report.Timestamps.CleanupFinishedAt}, Observations: facts["resource_inspector"]}
	trustedPayload := &trustedInputsPayload{FormatVersion: 1, PayloadType: "sandbox-runtime-trusted-input-evidence", PayloadVersion: "1.0.0", InvocationID: report.Invocation.InvocationID, RuntimeCommitmentDigest: report.Invocation.RuntimeCommitmentDigest, TrustedInputs: trusted, CallerAssertions: report.Claims.CallerAssertions}
	models := payloadSet{Provider: provider, Gateway: gateway, ProcessSupervisor: process, ResourceInspector: resource, TrustedInputs: trustedPayload}
	documents := map[string][]byte{}
	for path, value := range map[string]any{"provider-observer.json": provider, "gateway-observer.json": gateway, "process-supervisor.json": process, "resource-inspector.json": resource, "trusted-inputs.json": trustedPayload} {
		document, err := marshalEvidenceJSON(value)
		if err != nil {
			return nil, payloadSet{}, err
		}
		documents[path] = document
	}
	return documents, models, nil
}

func bindPayloadDigests(report *reportDocument, inventory evidencefiles.Inventory) {
	digestByPath := make(map[string]string, len(inventory.Entries))
	for _, entry := range inventory.Entries {
		digestByPath[entry.Path] = entry.SHA256
	}
	pathBySource := map[string]string{"provider_observer": "provider-observer.json", "gateway_observer": "gateway-observer.json", "process_supervisor": "process-supervisor.json", "resource_inspector": "resource-inspector.json"}
	for index := range report.Observations {
		digest := digestByPath[pathBySource[report.Observations[index].Source]]
		report.Observations[index].EvidenceDigest = &digest
	}
	for index := range report.Claims.TrustedInputs {
		report.Claims.TrustedInputs[index].Digest = digestByPath["trusted-inputs.json"]
	}
}

func deriveRunOutcome(report reportDocument, profile profileDocument, identityComplete bool) runOutcome {
	counts := scenarioCounts{}
	for _, scenario := range report.ScenarioResults {
		switch scenario.Status {
		case "passed":
			counts.Passed++
		case "failed":
			counts.Failed++
		case "incomplete":
			counts.Incomplete++
		case "not_executed":
			counts.NotExecuted++
		}
	}
	allCases := orderedProfileCases(profile)
	_, anyMutation := calculateCounters(report.ScenarioResults, report.Observations, allCases)
	cleanupSatisfied, err := validateCleanup(report.Cleanup, profile.Cleanup, anyMutation)
	if err != nil {
		cleanupSatisfied = false
	}
	reasons := make([]string, 0, 4)
	if counts.Failed > 0 {
		reasons = append(reasons, "executed_mismatch")
	}
	if !cleanupSatisfied {
		reasons = append(reasons, "cleanup_unknown_or_failed")
	}
	if !identityComplete {
		reasons = append(reasons, "missing_identity_or_evidence")
	}
	if counts.NotExecuted > 0 {
		reasons = append(reasons, "scenario_not_executed")
	}
	outcome := "incomplete"
	switch {
	case counts.NotExecuted == 20:
		outcome = "not_executed"
	case !cleanupSatisfied || !identityComplete || counts.Incomplete > 0 || counts.NotExecuted > 0:
		outcome = "incomplete"
	case counts.Failed > 0:
		outcome = "failed"
	case counts.Passed == 20:
		outcome = "passed"
	}
	return runOutcome{Outcome: outcome, ReasonCodes: reasons, ScenarioCounts: counts, CleanupSatisfied: cleanupSatisfied, IdentityComplete: identityComplete, SanitizationPassed: true}
}

func finalizeReportBytes(report reportDocument, inventory evidencefiles.Inventory, semantics validatorSemantics) ([]byte, error) {
	for attempts := 0; attempts < 8; attempts++ {
		document, err := marshalEvidenceJSON(report)
		if err != nil {
			return nil, err
		}
		withReport := inventory
		withReport.FileCount++
		withReport.TotalBytes += int64(len(document))
		receipt, _, err := makeReceipt(report, document, withReport, semantics)
		if err != nil {
			return nil, err
		}
		want := withReport.TotalBytes + int64(len(receipt))
		if report.Evidence.TotalBytes == want {
			return document, nil
		}
		report.Evidence.TotalBytes = want
	}
	return nil, errors.New("qualification evidence size did not converge")
}

func orderedProfileCases(profile profileDocument) []profileCase {
	result := make([]profileCase, 0, 20)
	for _, phase := range profile.Phases {
		result = append(result, phase.Cases...)
	}
	return result
}

func suiteFromProfile(expected profileSuite) suiteIdentity {
	return suiteIdentity{SuiteID: expected.SuiteID, SuiteVersion: expected.SuiteVersion, SuiteDigest: expected.SuiteDigest, SuiteDigestProfile: expected.SuiteDigestProfile, ProfileID: expected.ProfileID, CaseCount: expected.CaseCount, Outcome: "not_executed"}
}

func sourceFromHarness(source *qualificationharness.SourceIdentity) *sourceIdentity {
	if source == nil {
		return nil
	}
	return &sourceIdentity{Kind: source.Kind, Value: source.Value, Immutable: source.Immutable}
}

func processIdentities(source []qualificationharness.ProcessIdentityObservation) []processIdentity {
	result := make([]processIdentity, len(source))
	for index, item := range source {
		result[index] = processIdentity{Component: item.Component, ProcessID: item.ProcessID, ExecutableDigest: item.ExecutableDigest, ConfigurationDigest: item.ConfigurationDigest, ObservedBy: item.ObservedBy}
	}
	return result
}

func transcriptFromHarness(source qualificationharness.AdapterTranscriptObservation) *adapterTranscript {
	return &adapterTranscript{Digest: source.Digest, DigestProfile: source.DigestProfile, InvocationIDs: append([]string(nil), source.InvocationIDs...), AllowedFields: append([]string(nil), source.AllowedFields...), ForbiddenFields: append([]string(nil), source.ForbiddenFields...), Sanitized: source.Sanitized, ObservedBy: source.ObservedBy}
}

func challengeFromHarness(source *qualificationharness.ShellContinuityObservation) *shellChallenge {
	if source == nil {
		return nil
	}
	return &shellChallenge{Digest: source.Digest, DigestProfile: source.DigestProfile, EstablishedInCase: source.EstablishedInCase, VerifiedInCase: source.VerifiedInCase, RawChallengeInEvidence: source.RawChallengeInEvidence}
}

func interactionFromHarness(source qualificationharness.ObservedInteraction, observationIDs []string) interactionResult {
	transient := make([]reportOutcome, len(source.TransientOutcomes))
	for index, item := range source.TransientOutcomes {
		transient[index] = outcomeFromHarness(item)
	}
	return interactionResult{InteractionID: source.InteractionID, Surface: source.Surface, Actor: source.Actor, Method: source.Method, RouteTemplate: source.RouteTemplate, LogicalRequestID: source.LogicalRequestID, ReplayOf: source.ReplayOf, WireAttempts: source.WireAttempts, TransientOutcomes: transient, FinalOutcome: outcomeFromHarness(source.FinalOutcome), MutationWriteObserved: source.MutationWriteObserved, ObservationIDs: observationIDs}
}

func outcomeFromHarness(source qualificationharness.ObservedOutcome) reportOutcome {
	return reportOutcome{Transport: source.Transport, StatusCode: source.StatusCode, ErrorCode: source.ErrorCode, Retryable: source.Retryable, RetryAfterPresent: source.RetryAfterPresent}
}

func cleanupFromHarness(source qualificationharness.CleanupResult) cleanup {
	result := cleanup{Authority: source.Authority, MutationWriteObserved: source.MutationWriteObserved, CleanupRequired: source.CleanupRequired, QueryScope: queryScopeFromHarness(source.QueryScope), Baseline: cleanupInventoryFromHarness(source.Baseline), TeardownAttempts: source.TeardownAttempts, TeardownCompleted: source.TeardownCompleted, PostTeardown: cleanupInventoryFromHarnessPointer(source.PostTeardown), StabilitySamples: source.StabilitySamples, StabilityIntervalMS: source.StabilityIntervalMilliseconds, Outcome: source.Outcome}
	return result
}

func queryScopeFromHarness(source qualificationharness.QueryScope) *queryScope {
	digest, target, namespace, selector, artifact, configuration := source.Digest, source.TargetDigest, source.RunNamespaceDigest, source.OwnershipSelectorDigest, source.InspectorArtifactDigest, source.InspectorConfigurationDigest
	return &queryScope{Digest: &digest, DigestProfile: source.DigestProfile, TargetDigest: &target, RunNamespaceDigest: &namespace, OwnershipSelectorDigest: &selector, ResourceKinds: append([]string(nil), source.ResourceKinds...), InspectorArtifactDigest: &artifact, InspectorConfigurationDigest: &configuration, ExcludesHarnessControlPlane: source.ExcludesHarnessControlPlane}
}

func cleanupInventoryFromHarness(source qualificationharness.CleanupInventory) *resourceInventory {
	digest, scope := source.InventoryDigest, source.QueryScopeDigest
	sampled := make([]string, len(source.SampledAt))
	for index, value := range source.SampledAt {
		sampled[index] = formatTime(value)
	}
	return &resourceInventory{QueryScopeDigest: &scope, Digest: &digest, DigestProfile: source.DigestProfile, RunOwnedCount: source.RunOwnedCount, Stable: source.Stable, SampledAt: sampled}
}

func cleanupInventoryFromHarnessPointer(source *qualificationharness.CleanupInventory) *resourceInventory {
	if source == nil {
		return nil
	}
	return cleanupInventoryFromHarness(*source)
}

func timestampsFromSnapshot(snapshot qualificationharness.EvidenceSnapshot) timestamps {
	runStart, executionStart, executionFinish := formatTime(snapshot.ExecutionStartedAt), formatTime(snapshot.ExecutionStartedAt), formatTime(snapshot.Observation.ObservedAt)
	cleanupStart, cleanupFinish := formatTime(snapshot.Cleanup.CleanupStartedAt), formatTime(snapshot.Cleanup.CleanupFinishedAt)
	runFinish := formatTime(time.Now().UTC())
	return timestamps{RunStartedAt: &runStart, ExecutionStartedAt: &executionStart, ExecutionFinishedAt: &executionFinish, CleanupStartedAt: &cleanupStart, CleanupFinishedAt: &cleanupFinish, RunFinishedAt: &runFinish}
}

func derivePhaseStatus(statuses []string) string {
	counts := map[string]int{}
	for _, status := range statuses {
		counts[status]++
	}
	switch {
	case counts["passed"] == len(statuses):
		return "passed"
	case counts["not_executed"] == len(statuses):
		return "not_executed"
	case counts["incomplete"] > 0 || counts["not_executed"] > 0:
		return "incomplete"
	case counts["failed"] > 0:
		return "failed"
	default:
		return "incomplete"
	}
}

func randomEvidenceID(prefix string) (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(nonce[:]), nil
}

func marshalEvidenceJSON(value any) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(document, '\n'), nil
}

func validUTCInterval(started, finished time.Time) bool {
	return !started.IsZero() && !finished.IsZero() && started.Location() == time.UTC && finished.Location() == time.UTC && !finished.Before(started)
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

var _ qualificationharness.EvidenceAssembler = RootAssembler{}
