package qualificationharness

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	ProviderObserverSource  = "provider_observer"
	GatewayObserverSource   = "gateway_observer"
	ProcessSupervisorSource = "process_supervisor"
	ResourceInspectorSource = "resource_inspector"

	DerivedPassed      = "passed"
	DerivedFailed      = "failed"
	DerivedIncomplete  = "incomplete"
	DerivedNotExecuted = "not_executed"
)

var (
	ErrExecutionObservation = errors.New("qualification execution observation failed")
	errorCodePattern        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,99}$`)
)

// ObservationDirective is the complete harness-to-observer input. It binds
// four separately configured observers to one prepared runtime and the two
// adapter invocations without exposing endpoints, credentials, payloads,
// concrete requests, host paths, or caller-owned correlation values.
type ObservationDirective struct {
	RuntimeCommitmentDigest    string `json:"runtime_commitment_digest"`
	ProfileID                  string `json:"profile_id"`
	ProfileVersion             string `json:"profile_version"`
	ProfileDigest              string `json:"profile_digest"`
	InitialInvocationID        string `json:"initial_invocation_id"`
	ReconstructionInvocationID string `json:"reconstruction_invocation_id"`
	QueryScopeDigest           string `json:"query_scope_digest"`
}

// ObservedOutcome is a closed, sanitized transport result. It deliberately
// excludes response bodies and headers other than the presence of Retry-After.
type ObservedOutcome struct {
	Transport         string  `json:"transport"`
	StatusCode        *int    `json:"status_code"`
	ErrorCode         *string `json:"error_code"`
	Retryable         bool    `json:"retryable"`
	RetryAfterPresent bool    `json:"retry_after_present"`
}

// ObservedInteraction is the Provider/Gateway observer projection later used
// by the evidence assembler. Concrete origins and request material are absent.
type ObservedInteraction struct {
	InteractionID         string            `json:"interaction_id"`
	Surface               string            `json:"surface"`
	Actor                 string            `json:"actor"`
	Method                string            `json:"method"`
	RouteTemplate         string            `json:"route_template"`
	LogicalRequestID      string            `json:"logical_request_id"`
	ReplayOf              *string           `json:"replay_of"`
	WireAttempts          int               `json:"wire_attempts"`
	TransientOutcomes     []ObservedOutcome `json:"transient_outcomes"`
	FinalOutcome          ObservedOutcome   `json:"final_outcome"`
	MutationWriteObserved bool              `json:"mutation_write_observed"`
}

// ObserverFact excludes a source field because the observer port itself owns
// that source. ObserveExecution adds the structural source when it forms the
// aggregate result; external process/control-domain independence remains an
// evidence and provenance obligation.
type ObserverFact struct {
	ObservationID string `json:"observation_id"`
	Actor         string `json:"actor"`
	Subject       string `json:"subject"`
	Correlation   string `json:"correlation"`
	Result        string `json:"result"`
}

// BoundObservation is an exact profile binding plus its structural source.
// Evidence digests are intentionally deferred until d7 writes payload files.
type BoundObservation struct {
	ObservationID string `json:"observation_id"`
	Source        string `json:"source"`
	Actor         string `json:"actor"`
	Subject       string `json:"subject"`
	Correlation   string `json:"correlation"`
	Result        string `json:"result"`
}

type SandboxResourceObservation struct {
	CPUMillis             int `json:"cpu_millis"`
	MemoryBytes           int `json:"memory_bytes"`
	EphemeralStorageBytes int `json:"ephemeral_storage_bytes"`
	PIDs                  int `json:"pids"`
}

type ProviderExecutionObservation struct {
	RuntimeCommitmentDigest     string                      `json:"runtime_commitment_digest"`
	ObserverArtifactDigest      string                      `json:"observer_artifact_digest"`
	ObserverConfigurationDigest string                      `json:"observer_configuration_digest"`
	SandboxResources            *SandboxResourceObservation `json:"sandbox_resources"`
	Interactions                []ObservedInteraction       `json:"interactions"`
	Facts                       []ObserverFact              `json:"observations"`
}

type ShellContinuityObservation struct {
	Digest                 string `json:"digest"`
	DigestProfile          string `json:"digest_profile"`
	EstablishedInCase      string `json:"established_in_case"`
	VerifiedInCase         string `json:"verified_in_case"`
	RawChallengeInEvidence bool   `json:"raw_challenge_in_evidence"`
}

type GatewayExecutionObservation struct {
	RuntimeCommitmentDigest     string                      `json:"runtime_commitment_digest"`
	ObserverArtifactDigest      string                      `json:"observer_artifact_digest"`
	ObserverConfigurationDigest string                      `json:"observer_configuration_digest"`
	Interactions                []ObservedInteraction       `json:"interactions"`
	ShellChallenge              *ShellContinuityObservation `json:"shell_continuity_challenge"`
	Facts                       []ObserverFact              `json:"observations"`
}

type ProcessIdentityObservation struct {
	Component           string `json:"component"`
	ProcessID           string `json:"process_id"`
	ExecutableDigest    string `json:"executable_digest"`
	ConfigurationDigest string `json:"configuration_digest"`
	ObservedBy          string `json:"observed_by"`
}

type AdapterTranscriptObservation struct {
	Digest          string   `json:"digest"`
	DigestProfile   string   `json:"digest_profile"`
	InvocationIDs   []string `json:"invocation_ids"`
	AllowedFields   []string `json:"allowed_fields"`
	ForbiddenFields []string `json:"forbidden_fields"`
	Sanitized       bool     `json:"sanitized"`
	ObservedBy      string   `json:"observed_by"`
}

type ProcessExecutionObservation struct {
	RuntimeCommitmentDigest            string                       `json:"runtime_commitment_digest"`
	SupervisorArtifactDigest           string                       `json:"supervisor_artifact_digest"`
	SupervisorConfigurationDigest      string                       `json:"supervisor_configuration_digest"`
	InitialInvocationID                string                       `json:"initial_invocation_id"`
	ReconstructionInvocationID         string                       `json:"reconstruction_invocation_id"`
	Artifacts                          []ArtifactObservation        `json:"artifact_identities"`
	Configurations                     []ConfigurationObservation   `json:"configuration_identities"`
	InitialProcesses                   []ProcessIdentityObservation `json:"initial_processes"`
	ReconstructionProcesses            []ProcessIdentityObservation `json:"reconstruction_processes"`
	HarnessReinjectedForbiddenBindings bool                         `json:"harness_reinjected_forbidden_bindings"`
	AdapterTranscript                  AdapterTranscriptObservation `json:"adapter_transcript"`
	Facts                              []ObserverFact               `json:"observations"`
}

type ResourceExecutionObservation struct {
	RuntimeCommitmentDigest      string                `json:"runtime_commitment_digest"`
	InspectorArtifactDigest      string                `json:"inspector_artifact_digest"`
	InspectorConfigurationDigest string                `json:"inspector_configuration_digest"`
	Target                       TargetIdentity        `json:"target_identity"`
	Artifacts                    []ArtifactObservation `json:"artifact_identities"`
	Inspection                   Inspection            `json:"inspection"`
	Facts                        []ObserverFact        `json:"observations"`
}

type ProviderExecutionObserver interface {
	ObserveProvider(context.Context, ObservationDirective) (ProviderExecutionObservation, error)
}

type GatewayExecutionObserver interface {
	ObserveGateway(context.Context, ObservationDirective) (GatewayExecutionObservation, error)
}

type ProcessExecutionObserver interface {
	ObserveProcesses(context.Context, ObservationDirective) (ProcessExecutionObservation, error)
}

type ResourceExecutionObserver interface {
	ObserveResources(context.Context, ObservationDirective, QueryScope) (ResourceExecutionObservation, error)
}

// ExecutionObservers keeps the four evidence sources explicit. Caller-owned
// progress is not accepted as any one of these sources.
type ExecutionObservers struct {
	Provider  ProviderExecutionObserver
	Gateway   GatewayExecutionObserver
	Processes ProcessExecutionObserver
	Resources ResourceExecutionObserver
}

type DerivedScenario struct {
	CaseID         string                `json:"case_id"`
	PhaseID        string                `json:"phase_id"`
	Status         string                `json:"status"`
	Interactions   []ObservedInteraction `json:"interactions"`
	ObservationIDs []string              `json:"observation_ids"`
}

// ObservedUsage combines progress-based attempt counters with admission counts
// derived from independently observed outcomes and facts.
type ObservedUsage struct {
	ProviderHTTPRequests          int `json:"provider_http_requests"`
	ProviderMutationWriteAttempts int `json:"provider_mutation_write_attempts"`
	DistinctProviderMutations     int `json:"distinct_provider_mutations"`
	Sandboxes                     int `json:"sandboxes"`
	ExecRequests                  int `json:"exec_requests"`
	AdmittedExecOperations        int `json:"admitted_exec_operations"`
	TerminalSessions              int `json:"terminal_sessions"`
	ArtifactRequests              int `json:"artifact_requests"`
	AdmittedArtifactOperations    int `json:"admitted_artifact_operations"`
	GatewayConnectionAttempts     int `json:"gateway_connection_attempts"`
	GatewayMutationWriteAttempts  int `json:"gateway_mutation_write_attempts"`
}

// ExecutionObservationResult is a sanitized local derivation, not a final run
// outcome or an external-caller qualification claim. d6 still owns cleanup and
// d7 still owns evidence files, payload digests, assertions, and final outcome.
type ExecutionObservationResult struct {
	Scenarios        []DerivedScenario            `json:"scenarios"`
	Observations     []BoundObservation           `json:"observations"`
	Usage            ObservedUsage                `json:"observed_usage"`
	CurrentInventory ResourceBaseline             `json:"current_inventory"`
	Provider         ProviderExecutionObservation `json:"provider_observer"`
	Gateway          GatewayExecutionObservation  `json:"gateway_observer"`
	Processes        ProcessExecutionObservation  `json:"process_supervisor"`
	Resources        ResourceExecutionObservation `json:"resource_inspector"`
	ObservedAt       time.Time                    `json:"observed_at"`
	CleanupRequired  bool                         `json:"cleanup_required"`
}

// ObserveExecution retrieves four independently sourced, already-sanitized
// snapshots, cross-binds them to d2/d3/d4 state, and derives scenario and
// admission facts. It performs no Provider/Gateway request and no teardown.
func ObserveExecution(ctx context.Context, prepared *PreparedRuntime, observers ExecutionObservers) (result ExecutionObservationResult, resultErr error) {
	if ctx == nil || prepared == nil || nilPort(observers.Provider) || nilPort(observers.Gateway) || nilPort(observers.Processes) || nilPort(observers.Resources) {
		return ExecutionObservationResult{}, ErrExecutionObservation
	}
	if err := ctx.Err(); err != nil {
		return ExecutionObservationResult{}, errors.Join(ErrExecutionObservation, err)
	}
	initial, reconstruction, plan, ok := prepared.beginObservation()
	if !ok || !validObservationPlan(plan) {
		return ExecutionObservationResult{}, ErrExecutionObservation
	}
	defer func() {
		result.ObservedAt = time.Now().UTC()
		result.CleanupRequired = prepared.CleanupRequired()
		prepared.finishObservation(result)
	}()

	operationContext, cancel := context.WithDeadline(ctx, prepared.executionDeadline)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return result, observationContextError(operationContext)
	}
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, observationContextError(operationContext)
	}
	directive := ObservationDirective{
		RuntimeCommitmentDigest: prepared.digest, ProfileID: prepared.profileID, ProfileVersion: prepared.profileVersion,
		ProfileDigest: prepared.profileDigest, InitialInvocationID: reconstruction.InitialInvocationID,
		ReconstructionInvocationID: reconstruction.ReconstructionInvocationID, QueryScopeDigest: prepared.queryScope.Digest,
	}

	provider, err := observers.Provider.ObserveProvider(operationContext, directive)
	if err != nil || operationContext.Err() != nil {
		if operationContext.Err() == nil {
			return result, observationStage("provider-observer")
		}
		return result, observationContextError(operationContext)
	}
	provider = cloneProviderExecutionObservation(provider)
	gateway, err := observers.Gateway.ObserveGateway(operationContext, directive)
	if err != nil || operationContext.Err() != nil {
		if operationContext.Err() == nil {
			return result, observationStage("gateway-observer")
		}
		return result, observationContextError(operationContext)
	}
	gateway = cloneGatewayExecutionObservation(gateway)
	processes, err := observers.Processes.ObserveProcesses(operationContext, directive)
	if err != nil || operationContext.Err() != nil {
		if operationContext.Err() == nil {
			return result, observationStage("process-observer")
		}
		return result, observationContextError(operationContext)
	}
	processes = cloneProcessExecutionObservation(processes)
	resources, err := observers.Resources.ObserveResources(operationContext, directive, cloneQueryScope(prepared.queryScope))
	if err != nil || operationContext.Err() != nil {
		if operationContext.Err() == nil {
			return result, observationStage("resource-observer")
		}
		return result, observationContextError(operationContext)
	}
	resources = cloneResourceExecutionObservation(resources)
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, observationContextError(operationContext)
	}

	if err := validateObserverIdentities(prepared, directive, provider, gateway, processes, resources, reconstruction); err != nil {
		return result, observationStage("observer-identities")
	}

	progressByCase, err := observationProgress(initial, reconstruction, plan)
	if err != nil {
		return result, observationStage("scenario-progress")
	}
	executedBySurface := expectedExecutedInteractions(plan, progressByCase)
	providerByID, providerMatched, err := validateObservedInteractions(ProviderObserverSource, "provider_http", executedBySurface["provider_http"], provider.Interactions, progressByCase)
	if err != nil {
		return result, observationStage("provider-interactions")
	}
	gatewayByID, gatewayMatched, err := validateObservedInteractions(GatewayObserverSource, "caller_gateway", executedBySurface["caller_gateway"], gateway.Interactions, progressByCase)
	if err != nil {
		return result, observationStage("gateway-interactions")
	}
	factsByKey, observations, err := validateObserverFacts(plan, provider.Facts, gateway.Facts, processes.Facts, resources.Facts)
	if err != nil {
		return result, observationStage("observer-facts")
	}

	scenarios, err := deriveScenarios(plan, progressByCase, providerByID, gatewayByID, providerMatched, gatewayMatched, factsByKey)
	if err != nil {
		// deriveScenarios only names immutable public profile case and
		// interaction identifiers; retaining that bounded cause makes a failed
		// qualification diagnosable without exposing payloads or credentials.
		return result, fmt.Errorf("%w: scenario-derivation: %v", ErrExecutionObservation, err)
	}
	usage := deriveObservedUsage(scenarios, plan, factsByKey)
	if !observedUsageWithinLimits(usage, prepared.limits) {
		return result, observationStage("observed-usage")
	}
	currentInventory, err := validateCurrentResourceObservation(prepared, resources, factsByKey, progressByCase)
	if err != nil {
		return result, observationStage("resource-inventory")
	}

	result = ExecutionObservationResult{
		Scenarios: scenarios, Observations: observations, Usage: usage, CurrentInventory: currentInventory,
		Provider: provider, Gateway: gateway, Processes: processes, Resources: resources,
	}
	return result, nil
}

func observationStage(stage string) error {
	return fmt.Errorf("%w: %s", ErrExecutionObservation, stage)
}

func validObservationPlan(plan []qualificationprofile.PhaseObservationPlan) bool {
	if len(plan) != 2 || plan[0].PhaseID != InitialPhaseID || plan[1].PhaseID != ReconstructionPhaseID || len(plan[0].Cases) != 15 || len(plan[1].Cases) != 5 {
		return false
	}
	interactions, observations := 0, 0
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			if scenario.CaseID == "" {
				return false
			}
			for _, interaction := range scenario.Interactions {
				interactions++
				observations += len(interaction.RequiredObservations)
			}
		}
	}
	return interactions == 41 && observations == 91
}

func observationProgress(initial InitialPhaseResult, reconstruction ReconstructionPhaseResult, plan []qualificationprofile.PhaseObservationPlan) (map[string]ScenarioProgress, error) {
	all := append(append([]ScenarioProgress(nil), initial.Scenarios...), reconstruction.Scenarios...)
	if len(all) != 20 || len(plan) != 2 {
		return nil, ErrExecutionObservation
	}
	result := make(map[string]ScenarioProgress, len(all))
	index := 0
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			actual := all[index]
			if actual.CaseID != scenario.CaseID {
				return nil, ErrExecutionObservation
			}
			result[actual.CaseID] = cloneScenarioProgress(actual)
			index++
		}
	}
	return result, nil
}

func expectedExecutedInteractions(plan []qualificationprofile.PhaseObservationPlan, progress map[string]ScenarioProgress) map[string][]qualificationprofile.InteractionObservationRequirement {
	result := map[string][]qualificationprofile.InteractionObservationRequirement{"provider_http": {}, "caller_gateway": {}}
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			if progress[scenario.CaseID].Disposition != ScenarioCompleted {
				continue
			}
			for _, interaction := range scenario.Interactions {
				result[interaction.Surface] = append(result[interaction.Surface], interaction)
			}
		}
	}
	return result
}

func validateObservedInteractions(source, surface string, expected []qualificationprofile.InteractionObservationRequirement, actual []ObservedInteraction, progress map[string]ScenarioProgress) (map[string]ObservedInteraction, map[string]bool, error) {
	if len(actual) != len(expected) {
		return nil, nil, fmt.Errorf("%s interaction cardinality differs from completed progress", source)
	}
	progressByInteraction := make(map[string]InteractionProgress)
	for _, scenario := range progress {
		for _, interaction := range scenario.Interactions {
			progressByInteraction[interaction.InteractionID] = interaction
		}
	}
	byID := make(map[string]ObservedInteraction, len(actual))
	matched := make(map[string]bool, len(actual))
	for index, candidate := range actual {
		want := expected[index]
		if candidate.InteractionID != want.InteractionID || candidate.Surface != surface || candidate.Actor != want.Actor || candidate.Method != want.Method ||
			candidate.RouteTemplate != want.RouteTemplate || candidate.LogicalRequestID != want.LogicalRequestID || !equalStringPointers(candidate.ReplayOf, want.ReplayOf) ||
			candidate.WireAttempts != progressByInteraction[want.InteractionID].WireAttempts || candidate.WireAttempts < 1 || candidate.WireAttempts > want.MaxWireAttempts ||
			candidate.WireAttempts != len(candidate.TransientOutcomes)+1 || candidate.MutationWriteObserved != (containsCounter(want.CountsToward, "provider_mutation_write_attempts") || containsCounter(want.CountsToward, "gateway_mutation_write_attempts")) {
			return nil, nil, fmt.Errorf("%s interaction %q is not bound to profile and progress", source, candidate.InteractionID)
		}
		if !validObservedOutcome(candidate.FinalOutcome) {
			return nil, nil, fmt.Errorf("%s interaction %q has an invalid final outcome", source, candidate.InteractionID)
		}
		outcomesMatch := observedOutcomeAllowed(candidate.FinalOutcome, want.Outcomes)
		for _, transient := range candidate.TransientOutcomes {
			if !validObservedOutcome(transient) {
				return nil, nil, fmt.Errorf("%s interaction %q has an invalid transient outcome", source, candidate.InteractionID)
			}
			outcomesMatch = outcomesMatch && transient.Retryable && observedOutcomeAllowed(transient, want.TransientOutcomes)
		}
		if _, duplicate := byID[candidate.InteractionID]; duplicate {
			return nil, nil, fmt.Errorf("%s duplicates interaction %q", source, candidate.InteractionID)
		}
		byID[candidate.InteractionID] = cloneObservedInteraction(candidate)
		matched[candidate.InteractionID] = outcomesMatch
	}
	return byID, matched, nil
}

func validObservedOutcome(outcome ObservedOutcome) bool {
	validTransport := map[string]struct{}{
		"http-response": {}, "tls-rejected": {}, "authorized-byte-round-trip": {}, "gateway-upgrade-rejected": {},
		"gateway-closed-before-data": {}, "gateway-closed-at-grant-expiry": {}, "revocation-acknowledged": {},
		"transport-unavailable": {}, "deadline-exceeded": {},
	}
	if _, ok := validTransport[outcome.Transport]; !ok || (outcome.StatusCode != nil && (*outcome.StatusCode < 100 || *outcome.StatusCode > 599)) ||
		(outcome.ErrorCode != nil && !errorCodePattern.MatchString(*outcome.ErrorCode)) {
		return false
	}
	return true
}

func observedOutcomeAllowed(actual ObservedOutcome, allowed []qualificationprofile.OutcomeRequirement) bool {
	for _, expected := range allowed {
		if actual.Transport != expected.Transport || !equalIntPointers(actual.StatusCode, expected.StatusCode) ||
			(expected.Retryable != nil && actual.Retryable != *expected.Retryable) ||
			(expected.RetryAfterRequired != nil && actual.RetryAfterPresent != *expected.RetryAfterRequired) {
			continue
		}
		switch expected.ErrorCodePolicy {
		case "exact", "one-of-exact":
			if actual.ErrorCode == nil || !slices.Contains(expected.ErrorCodes, *actual.ErrorCode) {
				continue
			}
		case "none":
			if actual.ErrorCode != nil {
				continue
			}
		}
		return true
	}
	return false
}

func validateObserverFacts(plan []qualificationprofile.PhaseObservationPlan, provider, gateway, processes, resources []ObserverFact) (map[string]BoundObservation, []BoundObservation, error) {
	actualBySource := map[string][]ObserverFact{
		ProviderObserverSource: provider, GatewayObserverSource: gateway, ProcessSupervisorSource: processes, ResourceInspectorSource: resources,
	}
	expectedBySource := map[string][]qualificationprofile.ObservationRequirement{
		ProviderObserverSource: {}, GatewayObserverSource: {}, ProcessSupervisorSource: {}, ResourceInspectorSource: {},
	}
	ordered := make([]qualificationprofile.ObservationRequirement, 0, 91)
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			for _, interaction := range scenario.Interactions {
				for _, fact := range interaction.RequiredObservations {
					expectedBySource[fact.Source] = append(expectedBySource[fact.Source], fact)
					ordered = append(ordered, fact)
				}
			}
		}
	}
	byKey := make(map[string]BoundObservation, len(ordered))
	for _, source := range []string{ProviderObserverSource, GatewayObserverSource, ProcessSupervisorSource, ResourceInspectorSource} {
		expected := expectedBySource[source]
		actual := actualBySource[source]
		if len(actual) != len(expected) {
			return nil, nil, fmt.Errorf("%s fact cardinality differs from profile", source)
		}
		for index, candidate := range actual {
			want := expected[index]
			if candidate.ObservationID != want.ObservationID || candidate.Actor != want.Actor || candidate.Subject != want.Subject || candidate.Correlation != want.Correlation ||
				(candidate.Result != "observed" && candidate.Result != "missing" && candidate.Result != "contradicted") {
				return nil, nil, fmt.Errorf("%s fact %q differs from profile", source, candidate.ObservationID)
			}
			bound := BoundObservation{ObservationID: candidate.ObservationID, Source: source, Actor: candidate.Actor, Subject: candidate.Subject, Correlation: candidate.Correlation, Result: candidate.Result}
			key := boundObservationKey(bound)
			if _, duplicate := byKey[key]; duplicate {
				return nil, nil, fmt.Errorf("duplicate fact binding %q", candidate.ObservationID)
			}
			byKey[key] = bound
		}
	}
	result := make([]BoundObservation, len(ordered))
	for index, want := range ordered {
		bound, ok := byKey[requirementObservationKey(want)]
		if !ok {
			return nil, nil, ErrExecutionObservation
		}
		result[index] = bound
	}
	return byKey, result, nil
}

func deriveScenarios(plan []qualificationprofile.PhaseObservationPlan, progress map[string]ScenarioProgress, providerByID, gatewayByID map[string]ObservedInteraction, providerMatched, gatewayMatched map[string]bool, facts map[string]BoundObservation) ([]DerivedScenario, error) {
	result := make([]DerivedScenario, 0, 20)
	statusByCase := make(map[string]string, 20)
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			actualProgress := progress[scenario.CaseID]
			dependenciesPassed := true
			for _, dependency := range scenario.DependsOn {
				dependenciesPassed = dependenciesPassed && statusByCase[dependency] == DerivedPassed
			}
			if !dependenciesPassed {
				if actualProgress.Disposition != ScenarioNotExecuted || actualProgress.ReasonCode == nil || *actualProgress.ReasonCode != "prerequisite_not_satisfied" {
					return nil, fmt.Errorf("scenario %q executed after an independently unpassed dependency", scenario.CaseID)
				}
			} else if actualProgress.Disposition == ScenarioNotExecuted && actualProgress.ReasonCode != nil && *actualProgress.ReasonCode == "prerequisite_not_satisfied" {
				return nil, fmt.Errorf("scenario %q claimed an independently satisfied dependency was unavailable", scenario.CaseID)
			}
			derived := DerivedScenario{CaseID: scenario.CaseID, PhaseID: phase.PhaseID, Interactions: []ObservedInteraction{}, ObservationIDs: []string{}}
			if actualProgress.Disposition == ScenarioNotExecuted {
				derived.Status = DerivedNotExecuted
				for _, interaction := range scenario.Interactions {
					for _, requirement := range interaction.RequiredObservations {
						if facts[requirementObservationKey(requirement)].Result != "missing" {
							return nil, fmt.Errorf("not-executed scenario %q contains non-missing observation", scenario.CaseID)
						}
					}
				}
				result = append(result, derived)
				statusByCase[scenario.CaseID] = derived.Status
				continue
			}

			matched, contradicted, missing := true, false, false
			for _, interaction := range scenario.Interactions {
				observed, ok := providerByID[interaction.InteractionID]
				outcomeMatched := providerMatched[interaction.InteractionID]
				if interaction.Surface == "caller_gateway" {
					observed, ok = gatewayByID[interaction.InteractionID]
					outcomeMatched = gatewayMatched[interaction.InteractionID]
				}
				if !ok {
					return nil, fmt.Errorf("completed scenario %q has no independently observed interaction %q", scenario.CaseID, interaction.InteractionID)
				}
				derived.Interactions = append(derived.Interactions, cloneObservedInteraction(observed))
				if !outcomeMatched {
					matched = false
					contradicted = true
				}
				for _, requirement := range interaction.RequiredObservations {
					fact := facts[requirementObservationKey(requirement)]
					derived.ObservationIDs = append(derived.ObservationIDs, requirement.ObservationID)
					switch fact.Result {
					case "missing":
						matched = false
						missing = true
					case "contradicted":
						matched = false
						contradicted = true
					}
				}
			}
			switch {
			case matched:
				derived.Status = DerivedPassed
			case contradicted:
				derived.Status = DerivedFailed
			case missing:
				derived.Status = DerivedIncomplete
			default:
				return nil, ErrExecutionObservation
			}
			result = append(result, derived)
			statusByCase[scenario.CaseID] = derived.Status
		}
	}
	return result, nil
}

func deriveObservedUsage(scenarios []DerivedScenario, plan []qualificationprofile.PhaseObservationPlan, facts map[string]BoundObservation) ObservedUsage {
	result := ObservedUsage{}
	expectedByID := make(map[string]qualificationprofile.InteractionObservationRequirement, 41)
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			for _, interaction := range scenario.Interactions {
				expectedByID[interaction.InteractionID] = interaction
			}
		}
	}
	distinctMutations := make(map[string]struct{})
	sandboxes := make(map[string]struct{})
	execs := make(map[string]struct{})
	terminals := make(map[string]struct{})
	artifacts := make(map[string]struct{})
	for _, scenario := range scenarios {
		for _, interaction := range scenario.Interactions {
			expected := expectedByID[interaction.InteractionID]
			for _, counter := range expected.CountsToward {
				switch counter {
				case "provider_http_requests":
					result.ProviderHTTPRequests += interaction.WireAttempts
				case "provider_mutation_write_attempts":
					result.ProviderMutationWriteAttempts += interaction.WireAttempts
				case "gateway_connection_attempts":
					result.GatewayConnectionAttempts += interaction.WireAttempts
				case "gateway_mutation_write_attempts":
					result.GatewayMutationWriteAttempts += interaction.WireAttempts
				case "distinct_provider_mutations":
					distinctMutations[interaction.LogicalRequestID] = struct{}{}
				case "exec_requests":
					result.ExecRequests++
				case "artifact_requests":
					result.ArtifactRequests++
				}
			}
			keys := []string{interaction.LogicalRequestID}
			expectedResource := containsAnyCounter(expected.CountsToward, "sandboxes", "admitted_exec_operations", "terminal_sessions", "admitted_artifact_operations")
			evidenceMatches := observedInteractionMatchesEvidence(interaction, expected, facts)
			admissionObserved := evidenceMatches && interaction.FinalOutcome.StatusCode != nil && *interaction.FinalOutcome.StatusCode == 202
			if admissionObserved {
				if !expectedResource {
					continue
				}
			} else {
				if evidenceMatches || !containsCounter(expected.CountsToward, "provider_mutation_write_attempts") {
					continue
				}
				keys = make([]string, interaction.WireAttempts)
				for index := range keys {
					keys[index] = fmt.Sprintf("potential-unexpected-admission:%s:%d", interaction.InteractionID, index+1)
				}
			}
			for _, key := range keys {
				switch interaction.RouteTemplate {
				case "/v1/sandboxes":
					sandboxes[key] = struct{}{}
				case "/v1/sandboxes/{sandbox_id}/exec":
					execs[key] = struct{}{}
				case "/v1/sandboxes/{sandbox_id}/runtime-sessions":
					terminals[key] = struct{}{}
				case "/v1/sandboxes/{sandbox_id}/artifacts:stage":
					artifacts[key] = struct{}{}
				}
			}
		}
	}
	result.DistinctProviderMutations = len(distinctMutations)
	result.Sandboxes = len(sandboxes)
	result.AdmittedExecOperations = len(execs)
	result.TerminalSessions = len(terminals)
	result.AdmittedArtifactOperations = len(artifacts)
	return result
}

func observedInteractionMatchesEvidence(actual ObservedInteraction, expected qualificationprofile.InteractionObservationRequirement, facts map[string]BoundObservation) bool {
	if !observedOutcomeAllowed(actual.FinalOutcome, expected.Outcomes) {
		return false
	}
	for _, outcome := range actual.TransientOutcomes {
		if !outcome.Retryable || !observedOutcomeAllowed(outcome, expected.TransientOutcomes) {
			return false
		}
	}
	for _, requirement := range expected.RequiredObservations {
		if facts[requirementObservationKey(requirement)].Result != "observed" {
			return false
		}
	}
	return true
}

func observedUsageWithinLimits(actual ObservedUsage, limits qualificationprofile.RuntimeLimits) bool {
	return actual.ProviderHTTPRequests <= limits.MaxProviderHTTPRequests && actual.ProviderMutationWriteAttempts <= limits.MaxProviderMutationWriteAttempts &&
		actual.DistinctProviderMutations <= limits.MaxDistinctProviderMutations && actual.Sandboxes <= limits.MaxSandboxes &&
		actual.ExecRequests <= limits.MaxExecRequests && actual.AdmittedExecOperations <= limits.MaxAdmittedExecOperations &&
		actual.TerminalSessions <= limits.MaxTerminalSessions && actual.ArtifactRequests <= limits.MaxArtifactRequests &&
		actual.AdmittedArtifactOperations <= limits.MaxAdmittedArtifactOperations && actual.GatewayConnectionAttempts <= limits.MaxGatewayConnectionAttempts &&
		actual.GatewayMutationWriteAttempts <= limits.MaxGatewayMutationWriteAttempts
}

func validateObserverIdentities(prepared *PreparedRuntime, directive ObservationDirective, provider ProviderExecutionObservation, gateway GatewayExecutionObservation, processes ProcessExecutionObservation, resources ResourceExecutionObservation, reconstruction ReconstructionPhaseResult) error {
	for _, commitment := range []string{provider.RuntimeCommitmentDigest, gateway.RuntimeCommitmentDigest, processes.RuntimeCommitmentDigest, resources.RuntimeCommitmentDigest} {
		if commitment != directive.RuntimeCommitmentDigest {
			return ErrExecutionObservation
		}
	}
	artifactByID := make(map[string]ArtifactObservation, len(prepared.observation.Artifacts))
	for _, artifact := range prepared.observation.Artifacts {
		artifactByID[artifact.ArtifactID] = artifact
	}
	configurationByID := make(map[string]ConfigurationObservation, len(prepared.observation.Configurations))
	for _, configuration := range prepared.observation.Configurations {
		configurationByID[configuration.ID] = configuration
	}
	if provider.ObserverArtifactDigest != artifactByID[ProviderObserverSource].Digest || provider.ObserverConfigurationDigest != configurationByID["observer_configuration"].Digest ||
		gateway.ObserverArtifactDigest != artifactByID[GatewayObserverSource].Digest || gateway.ObserverConfigurationDigest != configurationByID["observer_configuration"].Digest ||
		processes.SupervisorArtifactDigest != artifactByID[ProcessSupervisorSource].Digest || processes.SupervisorConfigurationDigest != configurationByID["observer_configuration"].Digest ||
		resources.InspectorArtifactDigest != artifactByID[ResourceInspectorSource].Digest || resources.InspectorConfigurationDigest != configurationByID["inspector_configuration"].Digest || resources.Target != prepared.observation.Target {
		return ErrExecutionObservation
	}
	if !reflect.DeepEqual(processes.Artifacts, filterArtifactsByObserver(prepared.observation.Artifacts, ProcessSupervisorSource)) ||
		!reflect.DeepEqual(resources.Artifacts, filterArtifactsByObserver(prepared.observation.Artifacts, ResourceInspectorSource)) ||
		!reflect.DeepEqual(processes.Configurations, prepared.observation.Configurations) {
		return ErrExecutionObservation
	}
	if processes.InitialInvocationID != reconstruction.InitialInvocationID || processes.ReconstructionInvocationID != reconstruction.ReconstructionInvocationID ||
		processes.HarnessReinjectedForbiddenBindings || len(processes.InitialProcesses) != 4 || len(processes.ReconstructionProcesses) != 4 {
		return ErrExecutionObservation
	}
	components := []string{"provider", "external_caller", "qualification_adapter", "caller_gateway"}
	configurationID := map[string]string{"provider": "provider_configuration", "external_caller": "caller_configuration", "qualification_adapter": "adapter_configuration", "caller_gateway": "gateway_configuration"}
	for index, component := range components {
		initial := processes.InitialProcesses[index]
		restarted := processes.ReconstructionProcesses[index]
		progress := reconstruction.ProcessReplacements[index]
		for _, candidate := range []ProcessIdentityObservation{initial, restarted} {
			if candidate.Component != component || candidate.ExecutableDigest != artifactByID[component].Digest || candidate.ConfigurationDigest != configurationByID[configurationID[component]].Digest || candidate.ObservedBy != ProcessSupervisorSource {
				return ErrExecutionObservation
			}
		}
		if initial.ProcessID != progress.InitialProcessIdentity || restarted.ProcessID != progress.ReconstructionProcessIdentity || initial.ProcessID == restarted.ProcessID {
			return ErrExecutionObservation
		}
	}
	policy := prepared.reconstruction
	transcript := processes.AdapterTranscript
	if transcript.Digest == "" || !digestPattern.MatchString(transcript.Digest) || transcript.DigestProfile != policy.AdapterInvocation.TranscriptDigestProfile ||
		!reflect.DeepEqual(transcript.InvocationIDs, []string{reconstruction.InitialInvocationID, reconstruction.ReconstructionInvocationID}) ||
		!reflect.DeepEqual(transcript.AllowedFields, policy.AdapterInvocation.AllowedHarnessFields) || !reflect.DeepEqual(transcript.ForbiddenFields, policy.ReinjectionForbidden) ||
		!transcript.Sanitized || transcript.ObservedBy != ProcessSupervisorSource || !policy.AdapterInvocation.SanitizedTranscriptRequired {
		return ErrExecutionObservation
	}
	challengeExpected := interactionObserved(provider.Interactions, gateway.Interactions, "gateway-terminal-round-trip")
	if challengeExpected != (gateway.ShellChallenge != nil) {
		return ErrExecutionObservation
	}
	if gateway.ShellChallenge != nil {
		challenge := gateway.ShellChallenge
		want := policy.ShellContinuityChallenge
		if !digestPattern.MatchString(challenge.Digest) || challenge.DigestProfile != want.ChallengeDigestProfile || challenge.EstablishedInCase != want.EstablishedInCase ||
			challenge.VerifiedInCase != want.VerifiedInCase || challenge.RawChallengeInEvidence || want.RawChallengeInEvidence || want.GeneratedBy != GatewayObserverSource {
			return ErrExecutionObservation
		}
	}
	wantResources := SandboxResourceObservation{CPUMillis: prepared.limits.SandboxCPUMillis, MemoryBytes: prepared.limits.SandboxMemoryBytes, EphemeralStorageBytes: prepared.limits.SandboxEphemeralStorageBytes, PIDs: prepared.limits.SandboxPIDs}
	createObserved := interactionObserved(provider.Interactions, gateway.Interactions, "create-sandbox")
	if createObserved != (provider.SandboxResources != nil) || (provider.SandboxResources != nil && *provider.SandboxResources != wantResources) {
		return ErrExecutionObservation
	}
	return nil
}

func validateCurrentResourceObservation(prepared *PreparedRuntime, observation ResourceExecutionObservation, facts map[string]BoundObservation, progress map[string]ScenarioProgress) (ResourceBaseline, error) {
	if !validInspection(prepared.queryScope, prepared.cleanup, observation.Inspection) {
		return ResourceBaseline{}, ErrExecutionObservation
	}
	runtimeAllocations := 0
	for _, entry := range observation.Inspection.Entries {
		if entry.ResourceKind == "runtime_allocations" {
			runtimeAllocations++
		}
	}
	requirement := qualificationprofile.ObservationRequirement{ObservationID: "run-owned-sandbox-resource-count-one", Source: ResourceInspectorSource, Actor: "controller_a", Subject: "create-sandbox", Correlation: "create-sandbox"}
	fact := facts[requirementObservationKey(requirement)]
	switch fact.Result {
	case "observed":
		if runtimeAllocations != 1 {
			return ResourceBaseline{}, ErrExecutionObservation
		}
	case "contradicted":
		if runtimeAllocations == 1 {
			return ResourceBaseline{}, ErrExecutionObservation
		}
	case "missing":
		if progress["initial.protected-lifecycle-create"].Disposition == ScenarioNotExecuted && runtimeAllocations != 0 {
			return ResourceBaseline{}, ErrExecutionObservation
		}
	}
	digest, err := canonicalDigest(inventoryDocument{FormatVersion: 1, QueryScopeDigest: prepared.queryScope.Digest, Entries: observation.Inspection.Entries})
	if err != nil {
		return ResourceBaseline{}, ErrExecutionObservation
	}
	return ResourceBaseline{QueryScopeDigest: prepared.queryScope.Digest, InventoryDigest: digest, DigestProfile: prepared.cleanup.InventoryDigestProfile, RunOwnedCount: len(observation.Inspection.Entries), Stable: true, SampledAt: time.Now().UTC()}, nil
}

func filterArtifactsByObserver(source []ArtifactObservation, observer string) []ArtifactObservation {
	result := make([]ArtifactObservation, 0, len(source))
	for _, artifact := range source {
		if artifact.ObservedBy == observer {
			result = append(result, cloneArtifactObservation(artifact))
		}
	}
	return result
}

func interactionObserved(provider, gateway []ObservedInteraction, interactionID string) bool {
	for _, group := range [][]ObservedInteraction{provider, gateway} {
		for _, interaction := range group {
			if interaction.InteractionID == interactionID {
				return true
			}
		}
	}
	return false
}

func requirementObservationKey(item qualificationprofile.ObservationRequirement) string {
	return strings.Join([]string{item.ObservationID, item.Source, item.Actor, item.Subject, item.Correlation}, "\x00")
}

func boundObservationKey(item BoundObservation) string {
	return strings.Join([]string{item.ObservationID, item.Source, item.Actor, item.Subject, item.Correlation}, "\x00")
}

func equalStringPointers(left, right *string) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func equalIntPointers(left, right *int) bool {
	return (left == nil && right == nil) || (left != nil && right != nil && *left == *right)
}

func containsAnyCounter(values []string, targets ...string) bool {
	for _, target := range targets {
		if containsCounter(values, target) {
			return true
		}
	}
	return false
}

func cloneObservedOutcome(source ObservedOutcome) ObservedOutcome {
	result := source
	if source.StatusCode != nil {
		value := *source.StatusCode
		result.StatusCode = &value
	}
	if source.ErrorCode != nil {
		value := *source.ErrorCode
		result.ErrorCode = &value
	}
	return result
}

func cloneObservedInteraction(source ObservedInteraction) ObservedInteraction {
	result := source
	if source.ReplayOf != nil {
		value := *source.ReplayOf
		result.ReplayOf = &value
	}
	result.TransientOutcomes = make([]ObservedOutcome, len(source.TransientOutcomes))
	for index, outcome := range source.TransientOutcomes {
		result.TransientOutcomes[index] = cloneObservedOutcome(outcome)
	}
	result.FinalOutcome = cloneObservedOutcome(source.FinalOutcome)
	return result
}

func cloneObserverFacts(source []ObserverFact) []ObserverFact {
	return append([]ObserverFact(nil), source...)
}

func cloneProviderExecutionObservation(source ProviderExecutionObservation) ProviderExecutionObservation {
	result := source
	if source.SandboxResources != nil {
		resources := *source.SandboxResources
		result.SandboxResources = &resources
	}
	result.Interactions = make([]ObservedInteraction, len(source.Interactions))
	for index, interaction := range source.Interactions {
		result.Interactions[index] = cloneObservedInteraction(interaction)
	}
	result.Facts = cloneObserverFacts(source.Facts)
	return result
}

func cloneGatewayExecutionObservation(source GatewayExecutionObservation) GatewayExecutionObservation {
	result := source
	if source.ShellChallenge != nil {
		challenge := *source.ShellChallenge
		result.ShellChallenge = &challenge
	}
	result.Interactions = make([]ObservedInteraction, len(source.Interactions))
	for index, interaction := range source.Interactions {
		result.Interactions[index] = cloneObservedInteraction(interaction)
	}
	result.Facts = cloneObserverFacts(source.Facts)
	return result
}

func cloneProcessIdentities(source []ProcessIdentityObservation) []ProcessIdentityObservation {
	return append([]ProcessIdentityObservation(nil), source...)
}

func cloneProcessExecutionObservation(source ProcessExecutionObservation) ProcessExecutionObservation {
	result := source
	result.Artifacts = make([]ArtifactObservation, len(source.Artifacts))
	for index, artifact := range source.Artifacts {
		result.Artifacts[index] = cloneArtifactObservation(artifact)
	}
	result.Configurations = append([]ConfigurationObservation(nil), source.Configurations...)
	result.InitialProcesses = cloneProcessIdentities(source.InitialProcesses)
	result.ReconstructionProcesses = cloneProcessIdentities(source.ReconstructionProcesses)
	result.AdapterTranscript.InvocationIDs = append([]string(nil), source.AdapterTranscript.InvocationIDs...)
	result.AdapterTranscript.AllowedFields = append([]string(nil), source.AdapterTranscript.AllowedFields...)
	result.AdapterTranscript.ForbiddenFields = append([]string(nil), source.AdapterTranscript.ForbiddenFields...)
	result.Facts = cloneObserverFacts(source.Facts)
	return result
}

func cloneResourceExecutionObservation(source ResourceExecutionObservation) ResourceExecutionObservation {
	result := source
	result.Artifacts = make([]ArtifactObservation, len(source.Artifacts))
	for index, artifact := range source.Artifacts {
		result.Artifacts[index] = cloneArtifactObservation(artifact)
	}
	if source.Inspection.Entries != nil {
		result.Inspection.Entries = make([]ResourceEntry, len(source.Inspection.Entries))
		copy(result.Inspection.Entries, source.Inspection.Entries)
	}
	result.Facts = cloneObserverFacts(source.Facts)
	return result
}

func cloneDerivedScenarios(source []DerivedScenario) []DerivedScenario {
	result := make([]DerivedScenario, len(source))
	for index, scenario := range source {
		result[index] = scenario
		result[index].Interactions = make([]ObservedInteraction, len(scenario.Interactions))
		for interactionIndex, interaction := range scenario.Interactions {
			result[index].Interactions[interactionIndex] = cloneObservedInteraction(interaction)
		}
		result[index].ObservationIDs = append([]string(nil), scenario.ObservationIDs...)
	}
	return result
}

func cloneExecutionObservationResult(source ExecutionObservationResult) ExecutionObservationResult {
	result := source
	result.Scenarios = cloneDerivedScenarios(source.Scenarios)
	result.Observations = append([]BoundObservation(nil), source.Observations...)
	result.Provider = cloneProviderExecutionObservation(source.Provider)
	result.Gateway = cloneGatewayExecutionObservation(source.Gateway)
	result.Processes = cloneProcessExecutionObservation(source.Processes)
	result.Resources = cloneResourceExecutionObservation(source.Resources)
	return result
}

func observationContextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrExecutionObservation, ctx.Err())
	}
	return ErrExecutionObservation
}

func (r *PreparedRuntime) beginObservation() (InitialPhaseResult, ReconstructionPhaseResult, []qualificationprofile.PhaseObservationPlan, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleanupAttempted || r.cleanupActive || r.initialActive || r.reconstructionActive || r.observationAttempted || r.observationActive || !r.cleanupRequired ||
		r.initialResult == nil || r.reconstructionResult == nil || !r.initialResult.TerminalObserved || !r.reconstructionResult.TerminalObserved {
		return InitialPhaseResult{}, ReconstructionPhaseResult{}, nil, false
	}
	r.observationAttempted = true
	r.observationActive = true
	return cloneInitialResult(*r.initialResult), cloneReconstructionResult(*r.reconstructionResult), cloneObservationPlan(r.observationPlan), true
}

func (r *PreparedRuntime) finishObservation(result ExecutionObservationResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := cloneExecutionObservationResult(result)
	r.executionObservation = &copy
	r.observationActive = false
}

// ExecutionObservation returns the immutable d5 snapshot after its one-shot
// attempt finishes. A non-empty partial result is diagnostic component state,
// not qualification evidence.
func (r *PreparedRuntime) ExecutionObservation() (ExecutionObservationResult, bool) {
	if r == nil {
		return ExecutionObservationResult{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.observationActive || r.executionObservation == nil {
		return ExecutionObservationResult{}, false
	}
	return cloneExecutionObservationResult(*r.executionObservation), true
}
