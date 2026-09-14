package qualificationharness

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

type providerExecutionObserverFunc func(context.Context, ObservationDirective) (ProviderExecutionObservation, error)

func (f providerExecutionObserverFunc) ObserveProvider(ctx context.Context, directive ObservationDirective) (ProviderExecutionObservation, error) {
	return f(ctx, directive)
}

type gatewayExecutionObserverFunc func(context.Context, ObservationDirective) (GatewayExecutionObservation, error)

func (f gatewayExecutionObserverFunc) ObserveGateway(ctx context.Context, directive ObservationDirective) (GatewayExecutionObservation, error) {
	return f(ctx, directive)
}

type processExecutionObserverFunc func(context.Context, ObservationDirective) (ProcessExecutionObservation, error)

func (f processExecutionObserverFunc) ObserveProcesses(ctx context.Context, directive ObservationDirective) (ProcessExecutionObservation, error) {
	return f(ctx, directive)
}

type resourceExecutionObserverFunc func(context.Context, ObservationDirective, QueryScope) (ResourceExecutionObservation, error)

func (f resourceExecutionObserverFunc) ObserveResources(ctx context.Context, directive ObservationDirective, scope QueryScope) (ResourceExecutionObservation, error) {
	return f(ctx, directive, scope)
}

type executionObservationFixture struct {
	provider  ProviderExecutionObservation
	gateway   GatewayExecutionObservation
	processes ProcessExecutionObservation
	resources ResourceExecutionObservation
}

func runObservationPhases(t *testing.T, prepared *PreparedRuntime, stopped bool) {
	t.Helper()
	runInitialForReconstruction(t, prepared, stopped)
	plan, _, ok := prepared.reconstructionOrchestrationPlan()
	if !ok {
		t.Fatal("missing reconstruction plan")
	}
	progress := completedInitialProgress(plan, nil)
	if stopped {
		caseIDs := make([]string, len(plan.Cases))
		for index, scenario := range plan.Cases {
			caseIDs[index] = scenario.CaseID
		}
		progress = stoppedReconstructionProgress(len(plan.Cases), caseIDs)
	}
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return &scriptedInitialSession{progress: progress}, reconstructionStartFixture(), nil
	}))
	if err != nil || !result.TerminalObserved {
		t.Fatalf("RunReconstruction() = %+v, %v", result, err)
	}
}

func runObservationPhasesStoppedAfterInitialCase(t *testing.T, prepared *PreparedRuntime, lastCompleted int) {
	t.Helper()
	initialPlan, ok := prepared.initialOrchestrationPlan()
	if !ok || lastCompleted < 0 || lastCompleted >= len(initialPlan.Cases) {
		t.Fatal("invalid initial stop fixture")
	}
	initialProgress := completedInitialProgress(initialPlan, nil)
	for index := lastCompleted + 1; index < len(initialProgress); index++ {
		reason := "prerequisite_not_satisfied"
		initialProgress[index] = ScenarioProgress{CaseID: initialPlan.Cases[index].CaseID, Disposition: ScenarioNotExecuted, ReasonCode: &reason, Interactions: []InteractionProgress{}}
	}
	initial, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return &scriptedInitialSession{progress: initialProgress}, nil
	}))
	if err != nil || !initial.TerminalObserved || initial.Completion != InitialCompletionStopped {
		t.Fatalf("RunInitial(stopped after case) = %+v, %v", initial, err)
	}
	reconstructionPlan, _, ok := prepared.reconstructionOrchestrationPlan()
	if !ok {
		t.Fatal("missing reconstruction plan")
	}
	caseIDs := make([]string, len(reconstructionPlan.Cases))
	for index, scenario := range reconstructionPlan.Cases {
		caseIDs[index] = scenario.CaseID
	}
	reconstruction, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return &scriptedInitialSession{progress: stoppedReconstructionProgress(len(caseIDs), caseIDs)}, reconstructionStartFixture(), nil
	}))
	if err != nil || !reconstruction.TerminalObserved || reconstruction.Completion != ReconstructionCompletionStopped {
		t.Fatalf("RunReconstruction(stopped after case) = %+v, %v", reconstruction, err)
	}
}

func observedOutcomeFixture(requirement qualificationprofile.OutcomeRequirement) ObservedOutcome {
	result := ObservedOutcome{
		Transport: requirement.Transport, StatusCode: cloneIntPointer(requirement.StatusCode),
	}
	if requirement.Retryable != nil {
		result.Retryable = *requirement.Retryable
	}
	if requirement.RetryAfterRequired != nil {
		result.RetryAfterPresent = *requirement.RetryAfterRequired
	}
	if (requirement.ErrorCodePolicy == "exact" || requirement.ErrorCodePolicy == "one-of-exact") && len(requirement.ErrorCodes) != 0 {
		value := requirement.ErrorCodes[0]
		result.ErrorCode = &value
	}
	return result
}

func cloneIntPointer(source *int) *int {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

func observationFixture(t *testing.T, prepared *PreparedRuntime) executionObservationFixture {
	t.Helper()
	initial, ok := prepared.InitialResult()
	if !ok {
		t.Fatal("missing initial result")
	}
	reconstruction, ok := prepared.ReconstructionResult()
	if !ok {
		t.Fatal("missing reconstruction result")
	}
	progress := make(map[string]ScenarioProgress, 20)
	for _, scenario := range append(initial.Scenarios, reconstruction.Scenarios...) {
		progress[scenario.CaseID] = scenario
	}
	commitment := prepared.Digest()
	observation := prepared.Observation()
	artifacts := make(map[string]ArtifactObservation, len(observation.Artifacts))
	for _, artifact := range observation.Artifacts {
		artifacts[artifact.ArtifactID] = artifact
	}
	configurations := make(map[string]ConfigurationObservation, len(observation.Configurations))
	for _, configuration := range observation.Configurations {
		configurations[configuration.ID] = configuration
	}
	fixture := executionObservationFixture{
		provider: ProviderExecutionObservation{
			RuntimeCommitmentDigest: commitment, ObserverArtifactDigest: artifacts[ProviderObserverSource].Digest,
			ObserverConfigurationDigest: configurations["observer_configuration"].Digest,
			Interactions:                []ObservedInteraction{}, Facts: []ObserverFact{},
		},
		gateway: GatewayExecutionObservation{
			RuntimeCommitmentDigest: commitment, ObserverArtifactDigest: artifacts[GatewayObserverSource].Digest,
			ObserverConfigurationDigest: configurations["observer_configuration"].Digest,
			Interactions:                []ObservedInteraction{}, Facts: []ObserverFact{},
		},
		processes: ProcessExecutionObservation{
			RuntimeCommitmentDigest: commitment, SupervisorArtifactDigest: artifacts[ProcessSupervisorSource].Digest,
			SupervisorConfigurationDigest: configurations["observer_configuration"].Digest,
			InitialInvocationID:           reconstruction.InitialInvocationID, ReconstructionInvocationID: reconstruction.ReconstructionInvocationID,
			Artifacts: filterArtifactsByObserver(observation.Artifacts, ProcessSupervisorSource), Configurations: observation.Configurations,
			InitialProcesses: []ProcessIdentityObservation{}, ReconstructionProcesses: []ProcessIdentityObservation{}, Facts: []ObserverFact{},
		},
		resources: ResourceExecutionObservation{
			RuntimeCommitmentDigest: commitment, InspectorArtifactDigest: artifacts[ResourceInspectorSource].Digest,
			InspectorConfigurationDigest: configurations["inspector_configuration"].Digest, Target: observation.Target,
			Artifacts: filterArtifactsByObserver(observation.Artifacts, ResourceInspectorSource), Facts: []ObserverFact{},
		},
	}
	policy := prepared.reconstruction
	fixture.processes.AdapterTranscript = AdapterTranscriptObservation{
		Digest: digestOf("a"), DigestProfile: policy.AdapterInvocation.TranscriptDigestProfile,
		InvocationIDs: []string{reconstruction.InitialInvocationID, reconstruction.ReconstructionInvocationID},
		AllowedFields: append([]string(nil), policy.AdapterInvocation.AllowedHarnessFields...), ForbiddenFields: append([]string(nil), policy.ReinjectionForbidden...),
		Sanitized: true, ObservedBy: ProcessSupervisorSource,
	}
	configurationID := map[string]string{"provider": "provider_configuration", "external_caller": "caller_configuration", "qualification_adapter": "adapter_configuration", "caller_gateway": "gateway_configuration"}
	for _, replacement := range reconstruction.ProcessReplacements {
		fixture.processes.InitialProcesses = append(fixture.processes.InitialProcesses, ProcessIdentityObservation{
			Component: replacement.Component, ProcessID: replacement.InitialProcessIdentity, ExecutableDigest: artifacts[replacement.Component].Digest,
			ConfigurationDigest: configurations[configurationID[replacement.Component]].Digest, ObservedBy: ProcessSupervisorSource,
		})
		fixture.processes.ReconstructionProcesses = append(fixture.processes.ReconstructionProcesses, ProcessIdentityObservation{
			Component: replacement.Component, ProcessID: replacement.ReconstructionProcessIdentity, ExecutableDigest: artifacts[replacement.Component].Digest,
			ConfigurationDigest: configurations[configurationID[replacement.Component]].Digest, ObservedBy: ProcessSupervisorSource,
		})
	}
	for _, phase := range prepared.observationPlan {
		for _, scenario := range phase.Cases {
			disposition := progress[scenario.CaseID].Disposition
			for _, interaction := range scenario.Interactions {
				if disposition == ScenarioCompleted {
					actual := ObservedInteraction{
						InteractionID: interaction.InteractionID, Surface: interaction.Surface, Actor: interaction.Actor, Method: interaction.Method,
						RouteTemplate: interaction.RouteTemplate, LogicalRequestID: interaction.LogicalRequestID, ReplayOf: cloneStringPointer(interaction.ReplayOf),
						WireAttempts: 1, TransientOutcomes: []ObservedOutcome{}, FinalOutcome: observedOutcomeFixture(interaction.Outcomes[0]),
						MutationWriteObserved: containsCounter(interaction.CountsToward, "provider_mutation_write_attempts") || containsCounter(interaction.CountsToward, "gateway_mutation_write_attempts"),
					}
					if interaction.Surface == "provider_http" {
						fixture.provider.Interactions = append(fixture.provider.Interactions, actual)
					} else {
						fixture.gateway.Interactions = append(fixture.gateway.Interactions, actual)
					}
				}
				for _, requirement := range interaction.RequiredObservations {
					factResult := "observed"
					if disposition == ScenarioNotExecuted {
						factResult = "missing"
					}
					fact := ObserverFact{ObservationID: requirement.ObservationID, Actor: requirement.Actor, Subject: requirement.Subject, Correlation: requirement.Correlation, Result: factResult}
					switch requirement.Source {
					case ProviderObserverSource:
						fixture.provider.Facts = append(fixture.provider.Facts, fact)
					case GatewayObserverSource:
						fixture.gateway.Facts = append(fixture.gateway.Facts, fact)
					case ProcessSupervisorSource:
						fixture.processes.Facts = append(fixture.processes.Facts, fact)
					case ResourceInspectorSource:
						fixture.resources.Facts = append(fixture.resources.Facts, fact)
					}
				}
			}
		}
	}
	if interactionObserved(fixture.provider.Interactions, fixture.gateway.Interactions, "create-sandbox") {
		limits := prepared.RuntimeLimits()
		fixture.provider.SandboxResources = &SandboxResourceObservation{CPUMillis: limits.SandboxCPUMillis, MemoryBytes: limits.SandboxMemoryBytes, EphemeralStorageBytes: limits.SandboxEphemeralStorageBytes, PIDs: limits.SandboxPIDs}
		fixture.resources.Inspection = Inspection{QueryScopeDigest: prepared.QueryScope().Digest, Complete: true, Entries: []ResourceEntry{{ResourceKind: "runtime_allocations", StableObserverID: "run-sandbox-allocation", IdentityDigest: digestOf("b")}}}
	} else {
		fixture.resources.Inspection = Inspection{QueryScopeDigest: prepared.QueryScope().Digest, Complete: true, Entries: []ResourceEntry{}}
	}
	if interactionObserved(fixture.provider.Interactions, fixture.gateway.Interactions, "gateway-terminal-round-trip") {
		challenge := policy.ShellContinuityChallenge
		fixture.gateway.ShellChallenge = &ShellContinuityObservation{Digest: digestOf("c"), DigestProfile: challenge.ChallengeDigestProfile, EstablishedInCase: challenge.EstablishedInCase, VerifiedInCase: challenge.VerifiedInCase}
	}
	return fixture
}

func cloneStringPointer(source *string) *string {
	if source == nil {
		return nil
	}
	value := *source
	return &value
}

func fixedExecutionObservers(fixture executionObservationFixture, directives *[]ObservationDirective) ExecutionObservers {
	return ExecutionObservers{
		Provider: providerExecutionObserverFunc(func(_ context.Context, directive ObservationDirective) (ProviderExecutionObservation, error) {
			*directives = append(*directives, directive)
			return cloneProviderExecutionObservation(fixture.provider), nil
		}),
		Gateway: gatewayExecutionObserverFunc(func(_ context.Context, directive ObservationDirective) (GatewayExecutionObservation, error) {
			*directives = append(*directives, directive)
			return cloneGatewayExecutionObservation(fixture.gateway), nil
		}),
		Processes: processExecutionObserverFunc(func(_ context.Context, directive ObservationDirective) (ProcessExecutionObservation, error) {
			*directives = append(*directives, directive)
			return cloneProcessExecutionObservation(fixture.processes), nil
		}),
		Resources: resourceExecutionObserverFunc(func(_ context.Context, directive ObservationDirective, scope QueryScope) (ResourceExecutionObservation, error) {
			*directives = append(*directives, directive)
			if scope.Digest != directive.QueryScopeDigest {
				return ResourceExecutionObservation{}, errors.New("scope mismatch")
			}
			return cloneResourceExecutionObservation(fixture.resources), nil
		}),
	}
}

func TestObserveExecutionCrossBindsFourSourcesAndDerivesStatusesAndAdmissions(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhases(t, prepared, false)
	fixture := observationFixture(t, prepared)
	directives := []ObservationDirective{}
	result, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives))
	if err != nil {
		t.Fatal(err)
	}
	if len(directives) != 4 {
		t.Fatalf("observer directive count = %d, want 4", len(directives))
	}
	for _, directive := range directives {
		if directive.RuntimeCommitmentDigest != prepared.Digest() || directive.ProfileID == "" || directive.ProfileVersion == "" || directive.ProfileDigest == "" ||
			directive.InitialInvocationID != "initial-invocation" || directive.ReconstructionInvocationID != "reconstruction-invocation" || directive.QueryScopeDigest != prepared.QueryScope().Digest {
			t.Fatalf("unexpected observer directive: %+v", directive)
		}
	}
	statusCounts := map[string]int{}
	interactionCount := 0
	for _, scenario := range result.Scenarios {
		statusCounts[scenario.Status]++
		interactionCount += len(scenario.Interactions)
	}
	wantUsage := ObservedUsage{
		ProviderHTTPRequests: 34, ProviderMutationWriteAttempts: 10, DistinctProviderMutations: 8, Sandboxes: 1,
		ExecRequests: 3, AdmittedExecOperations: 2, TerminalSessions: 1, ArtifactRequests: 2, AdmittedArtifactOperations: 1,
		GatewayConnectionAttempts: 6, GatewayMutationWriteAttempts: 1,
	}
	if len(result.Scenarios) != 20 || statusCounts[DerivedPassed] != 20 || interactionCount != 41 || len(result.Observations) != 91 || result.Usage != wantUsage ||
		result.CurrentInventory.RunOwnedCount != 1 || result.CurrentInventory.QueryScopeDigest != prepared.QueryScope().Digest || result.ObservedAt.IsZero() || !result.CleanupRequired {
		t.Fatalf("unexpected observation result: statuses=%v interactions=%d observations=%d usage=%+v inventory=%+v", statusCounts, interactionCount, len(result.Observations), result.Usage, result.CurrentInventory)
	}
	sourceCounts := map[string]int{}
	for _, fact := range result.Observations {
		sourceCounts[fact.Source]++
		if fact.Result != "observed" {
			t.Fatalf("unexpected fact: %+v", fact)
		}
	}
	if !reflect.DeepEqual(sourceCounts, map[string]int{ProviderObserverSource: 66, GatewayObserverSource: 17, ProcessSupervisorSource: 7, ResourceInspectorSource: 1}) {
		t.Fatalf("source counts = %v", sourceCounts)
	}
	result.Provider.Interactions[0].InteractionID = "changed"
	result.Processes.InitialProcesses[0].ProcessID = "changed"
	result.Resources.Inspection.Entries[0].StableObserverID = "changed"
	stored, ok := prepared.ExecutionObservation()
	if !ok || stored.Provider.Interactions[0].InteractionID == "changed" || stored.Processes.InitialProcesses[0].ProcessID == "changed" || stored.Resources.Inspection.Entries[0].StableObserverID == "changed" {
		t.Fatal("stored observation result was mutable")
	}
	if _, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives)); !errors.Is(err, ErrExecutionObservation) {
		t.Fatalf("second ObserveExecution() error = %v", err)
	}
}

func TestObserveExecutionDerivesIncompleteAndFailedFromIndependentFacts(t *testing.T) {
	for _, test := range []struct {
		name          string
		factResult    string
		outcomeFailed bool
		wantStatus    string
	}{
		{name: "missing", factResult: "missing", wantStatus: DerivedIncomplete},
		{name: "contradicted", factResult: "contradicted", wantStatus: DerivedFailed},
		{name: "outcome_mismatch", factResult: "observed", outcomeFailed: true, wantStatus: DerivedFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			runObservationPhases(t, prepared, false)
			fixture := observationFixture(t, prepared)
			fixture.processes.Facts[len(fixture.processes.Facts)-1].Result = test.factResult
			if test.outcomeFailed {
				fixture.gateway.Interactions[len(fixture.gateway.Interactions)-1].FinalOutcome = ObservedOutcome{Transport: "transport-unavailable"}
			}
			directives := []ObservationDirective{}
			result, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives))
			if err != nil {
				t.Fatal(err)
			}
			if got := result.Scenarios[len(result.Scenarios)-1].Status; got != test.wantStatus {
				t.Fatalf("last scenario status = %q, want %q", got, test.wantStatus)
			}
		})
	}
}

func TestObserveExecutionPreservesNotExecutedWithoutInventingEvidence(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhases(t, prepared, true)
	fixture := observationFixture(t, prepared)
	directives := []ObservationDirective{}
	result, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range result.Scenarios {
		if scenario.Status != DerivedNotExecuted || len(scenario.Interactions) != 0 || len(scenario.ObservationIDs) != 0 {
			t.Fatalf("not-executed scenario contains evidence: %+v", scenario)
		}
	}
	for _, fact := range result.Observations {
		if fact.Result != "missing" {
			t.Fatalf("not-executed fact = %+v", fact)
		}
	}
	if result.Usage != (ObservedUsage{}) || result.CurrentInventory.RunOwnedCount != 0 || result.Provider.SandboxResources != nil || result.Gateway.ShellChallenge != nil {
		t.Fatalf("not-executed result invented evidence: %+v", result)
	}
}

func TestObserveExecutionCorroboratesFailedPredecessorBeforeDependentStop(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhasesStoppedAfterInitialCase(t, prepared, 1)
	fixture := observationFixture(t, prepared)
	changed := false
	for index := range fixture.provider.Facts {
		if fixture.provider.Facts[index].Subject == "create-sandbox" {
			fixture.provider.Facts[index].Result = "contradicted"
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("missing create-sandbox fact")
	}
	directives := []ObservationDirective{}
	result, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives))
	if err != nil {
		t.Fatal(err)
	}
	if result.Scenarios[0].Status != DerivedPassed || result.Scenarios[1].Status != DerivedFailed {
		t.Fatalf("leading statuses = %q, %q", result.Scenarios[0].Status, result.Scenarios[1].Status)
	}
	for index := 2; index < len(result.Scenarios); index++ {
		if result.Scenarios[index].Status != DerivedNotExecuted {
			t.Fatalf("scenario %d status = %q", index, result.Scenarios[index].Status)
		}
	}
}

func TestObserveExecutionRejectsCallerOnlyPrerequisiteStop(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhasesStoppedAfterInitialCase(t, prepared, 0)
	fixture := observationFixture(t, prepared)
	directives := []ObservationDirective{}
	if _, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives)); !errors.Is(err, ErrExecutionObservation) {
		t.Fatalf("uncorroborated dependency stop error = %v", err)
	}
}

func TestObserveExecutionRejectsUnboundOrInconsistentObserverData(t *testing.T) {
	tests := map[string]func(*executionObservationFixture){
		"wrong_commitment":        func(fixture *executionObservationFixture) { fixture.provider.RuntimeCommitmentDigest = digestOf("f") },
		"wrong_observer_identity": func(fixture *executionObservationFixture) { fixture.gateway.ObserverArtifactDigest = digestOf("f") },
		"interaction_order": func(fixture *executionObservationFixture) {
			fixture.provider.Interactions[0], fixture.provider.Interactions[1] = fixture.provider.Interactions[1], fixture.provider.Interactions[0]
		},
		"fact_binding": func(fixture *executionObservationFixture) { fixture.provider.Facts[0].Actor = "controller_b" },
		"process_replacement": func(fixture *executionObservationFixture) {
			fixture.processes.ReconstructionProcesses[0].ProcessID = fixture.processes.InitialProcesses[0].ProcessID
		},
		"harness_reinjection": func(fixture *executionObservationFixture) {
			fixture.processes.HarnessReinjectedForbiddenBindings = true
		},
		"transcript_fields": func(fixture *executionObservationFixture) {
			fixture.processes.AdapterTranscript.AllowedFields[0] = "sandbox_id"
		},
		"resource_scope": func(fixture *executionObservationFixture) {
			fixture.resources.Inspection.QueryScopeDigest = digestOf("f")
		},
		"resource_fact_mismatch": func(fixture *executionObservationFixture) { fixture.resources.Inspection.Entries = []ResourceEntry{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			runObservationPhases(t, prepared, false)
			fixture := observationFixture(t, prepared)
			mutate(&fixture)
			directives := []ObservationDirective{}
			if _, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives)); !errors.Is(err, ErrExecutionObservation) {
				t.Fatalf("ObserveExecution() error = %v", err)
			}
		})
	}
}

func TestObservedUsageFailsClosedOnPotentialUnexpectedAdmission(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhases(t, prepared, false)
	fixture := observationFixture(t, prepared)
	directives := []ObservationDirective{}
	result, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives))
	if err != nil {
		t.Fatal(err)
	}
	scenarios := cloneDerivedScenarios(result.Scenarios)
	changed := false
	for scenarioIndex := range scenarios {
		for interactionIndex := range scenarios[scenarioIndex].Interactions {
			if scenarios[scenarioIndex].Interactions[interactionIndex].InteractionID == "start-stale-fence-exec" {
				status := 202
				scenarios[scenarioIndex].Interactions[interactionIndex].FinalOutcome = ObservedOutcome{Transport: "http-response", StatusCode: &status}
				changed = true
			}
		}
	}
	if !changed {
		t.Fatal("missing negative exec interaction")
	}
	facts := make(map[string]BoundObservation, len(result.Observations))
	for _, fact := range result.Observations {
		facts[boundObservationKey(fact)] = fact
	}
	usage := deriveObservedUsage(scenarios, prepared.observationPlan, facts)
	if usage.AdmittedExecOperations != 3 || observedUsageWithinLimits(usage, prepared.limits) {
		t.Fatalf("potential unexpected admission usage = %+v", usage)
	}
}

func TestObserveExecutionRejectsEarlyNilCanceledAndObserverFailure(t *testing.T) {
	_, _, _, early := prepareRuntimeFixture(t)
	called := false
	observers := ExecutionObservers{Provider: providerExecutionObserverFunc(func(context.Context, ObservationDirective) (ProviderExecutionObservation, error) {
		called = true
		return ProviderExecutionObservation{}, nil
	})}
	if _, err := ObserveExecution(context.Background(), early, observers); !errors.Is(err, ErrExecutionObservation) || called {
		t.Fatalf("early ObserveExecution() = %v, called=%t", err, called)
	}

	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhases(t, prepared, false)
	fixture := observationFixture(t, prepared)
	var nilProvider *nilProviderExecutionObserver
	observers = fixedExecutionObservers(fixture, &[]ObservationDirective{})
	observers.Provider = nilProvider
	if _, err := ObserveExecution(context.Background(), prepared, observers); !errors.Is(err, ErrExecutionObservation) {
		t.Fatalf("typed-nil ObserveExecution() error = %v", err)
	}

	_, _, _, canceledPrepared := prepareRuntimeFixture(t)
	runObservationPhases(t, canceledPrepared, false)
	canceledFixture := observationFixture(t, canceledPrepared)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveExecution(canceled, canceledPrepared, fixedExecutionObservers(canceledFixture, &[]ObservationDirective{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled ObserveExecution() error = %v", err)
	}

	_, _, _, failedPrepared := prepareRuntimeFixture(t)
	runObservationPhases(t, failedPrepared, false)
	failedFixture := observationFixture(t, failedPrepared)
	failedObservers := fixedExecutionObservers(failedFixture, &[]ObservationDirective{})
	failedObservers.Provider = providerExecutionObserverFunc(func(context.Context, ObservationDirective) (ProviderExecutionObservation, error) {
		return ProviderExecutionObservation{}, errors.New("credential /private/provider-log")
	})
	if _, err := ObserveExecution(context.Background(), failedPrepared, failedObservers); !errors.Is(err, ErrExecutionObservation) || strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "/private") {
		t.Fatalf("observer failure leaked diagnostics: %v", err)
	}
}

type nilProviderExecutionObserver struct{}

func (*nilProviderExecutionObserver) ObserveProvider(context.Context, ObservationDirective) (ProviderExecutionObservation, error) {
	return ProviderExecutionObservation{}, nil
}

func TestObservationDirectiveHasNoRequestCredentialOrPathSurface(t *testing.T) {
	typeOf := reflect.TypeOf(ObservationDirective{})
	if typeOf.NumField() != 7 {
		t.Fatalf("directive field count = %d, want 7", typeOf.NumField())
	}
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		identity := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"path", "route", "method", "request", "payload", "body", "credential", "secret", "signature", "endpoint", "origin", "sandbox_id", "operation_id", "attempt_id", "idempotency_key", "fencing_token", "runtime_session_id", "handoff_reference"} {
			if strings.Contains(identity, forbidden) {
				t.Fatalf("directive exposes forbidden %q field: %s", forbidden, field.Name)
			}
		}
	}
	if _, exists := reflect.TypeOf(ExecutionObservationResult{}).FieldByName("RunOutcome"); exists {
		t.Fatal("d5 result must not assign a final run outcome")
	}
}
