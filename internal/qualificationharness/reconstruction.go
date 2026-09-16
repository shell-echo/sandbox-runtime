package qualificationharness

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	ReconstructionPhaseID = "reconstruction"

	ReconstructionCompletionCompleted = "completed"
	ReconstructionCompletionStopped   = "stopped"
)

var (
	ErrReconstructionPhase = errors.New("qualification reconstruction phase orchestration failed")
	opaqueProcessPatterns  = map[string]*regexp.Regexp{
		"provider":              regexp.MustCompile(`^provider-process-[0-9a-f]{32}$`),
		"external_caller":       regexp.MustCompile(`^caller-process-[0-9a-f]{32}$`),
		"qualification_adapter": regexp.MustCompile(`^adapter-process-[0-9a-f]{32}$`),
		"caller_gateway":        regexp.MustCompile(`^gateway-process-[0-9a-f]{32}$`),
	}
)

// ReconstructionPhaseDirective is the complete harness-to-executor input for
// the second phase. Symbolic component/store names request replacement and
// preservation policy without exposing a path or any caller-owned correlation
// value. Request construction, signing, endpoints, and credentials remain the
// executor's private responsibility.
type ReconstructionPhaseDirective struct {
	RuntimeCommitmentDigest string   `json:"runtime_commitment_digest"`
	ProfileID               string   `json:"profile_id"`
	ProfileVersion          string   `json:"profile_version"`
	ProfileDigest           string   `json:"profile_digest"`
	PhaseID                 string   `json:"phase_id"`
	CaseIDs                 []string `json:"case_ids"`
	RestartComponents       []string `json:"restart_components"`
	PreservedStoreIDs       []string `json:"preserved_store_ids"`
}

// ProcessReplacementProgress is a sanitized executor/supervisor assertion that
// d5 must corroborate independently before it can become report evidence. The
// accepted identities are opaque labels, never OS PIDs or backend identifiers.
type ProcessReplacementProgress struct {
	Component                     string `json:"component"`
	InitialProcessIdentity        string `json:"initial_process_identity"`
	ReconstructionProcessIdentity string `json:"reconstruction_process_identity"`
}

// ReconstructionStartProgress binds two distinct invocation labels and the
// exact four provisional process replacements. It deliberately contains no
// caller state, path, endpoint, credential, request, or reinjection claim.
type ReconstructionStartProgress struct {
	InitialInvocationID        string                       `json:"initial_invocation_id"`
	ReconstructionInvocationID string                       `json:"reconstruction_invocation_id"`
	ProcessReplacements        []ProcessReplacementProgress `json:"process_replacements"`
}

// ReconstructionPhaseResult is a sanitized local orchestration result. Its
// start progress and scenario progress remain assertions until d5 observers
// corroborate them; Completion is not a qualification status.
type ReconstructionPhaseResult struct {
	PhaseID                    string                       `json:"phase_id"`
	OrchestrationStartedAt     time.Time                    `json:"orchestration_started_at"`
	OrchestrationFinishedAt    time.Time                    `json:"orchestration_finished_at"`
	InitialInvocationID        string                       `json:"initial_invocation_id"`
	ReconstructionInvocationID string                       `json:"reconstruction_invocation_id"`
	ProcessReplacements        []ProcessReplacementProgress `json:"process_replacements"`
	Scenarios                  []ScenarioProgress           `json:"scenarios"`
	PhaseUsage                 ProvisionalUsage             `json:"phase_provisional_usage"`
	CumulativeUsage            ProvisionalUsage             `json:"cumulative_provisional_usage"`
	Completion                 string                       `json:"completion"`
	TerminalObserved           bool                         `json:"terminal_observed"`
	CleanupRequired            bool                         `json:"cleanup_required"`
}

// ReconstructionPhaseExecutor owns the stop/start operation for the Provider,
// external caller, adapter, and caller Gateway. The returned progress is a
// provisional supervisor assertion; d5 independently verifies process truth.
type ReconstructionPhaseExecutor interface {
	StartReconstruction(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error)
}

// ReconstructionPhaseSession returns exactly one result per NextScenario call
// in locked order. Finish owns the terminal, stdout-EOF, clean-exit gate for the
// fresh adapter invocation. Close stops/reaps unfinished work.
type ReconstructionPhaseSession interface {
	NextScenario(context.Context) (ScenarioProgress, error)
	Finish(context.Context) error
	Close() error
}

// RunReconstruction performs the one-shot second phase after a terminal initial
// phase. It rechecks only persistent-store metadata and supplies no initial
// correlation values, so recovery must come from caller-owned durable state.
func RunReconstruction(ctx context.Context, prepared *PreparedRuntime, executor ReconstructionPhaseExecutor) (result ReconstructionPhaseResult, resultErr error) {
	if ctx == nil || prepared == nil || nilPort(executor) {
		return ReconstructionPhaseResult{}, ErrReconstructionPhase
	}
	if err := ctx.Err(); err != nil {
		return ReconstructionPhaseResult{}, errors.Join(ErrReconstructionPhase, err)
	}
	plan, policy, ok := prepared.reconstructionOrchestrationPlan()
	if !ok || !validReconstructionOrchestration(plan, policy, prepared.limits) {
		return ReconstructionPhaseResult{}, ErrReconstructionPhase
	}
	initial, ok := prepared.beginReconstruction()
	if !ok {
		return ReconstructionPhaseResult{}, ErrReconstructionPhase
	}
	result.PhaseID = ReconstructionPhaseID
	result.CumulativeUsage = initial.Usage
	defer func() {
		result.OrchestrationFinishedAt = time.Now().UTC()
		result.CleanupRequired = prepared.CleanupRequired()
		prepared.finishReconstruction(result)
	}()

	operationContext, cancel := context.WithDeadline(ctx, prepared.executionDeadline)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return result, errors.Join(ErrReconstructionPhase, err)
	}
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, reconstructionContextError(operationContext)
	}
	startedAt := time.Now().UTC()
	if startedAt.Before(initial.OrchestrationFinishedAt) {
		return result, ErrReconstructionPhase
	}
	result.OrchestrationStartedAt = startedAt
	directive := reconstructionDirective(prepared, plan, policy)
	session, startProgress, err := executor.StartReconstruction(operationContext, cloneReconstructionDirective(directive))
	if err != nil || nilPort(session) || operationContext.Err() != nil {
		if !nilPort(session) {
			_ = session.Close()
		}
		return result, reconstructionContextError(operationContext)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			result.TerminalObserved = false
			result.Completion = ""
			if resultErr == nil {
				resultErr = ErrReconstructionPhase
			}
		}
	}()

	startProgress = cloneReconstructionStartProgress(startProgress)
	if !validReconstructionStartProgress(startProgress, policy.RestartComponents) {
		return result, ErrReconstructionPhase
	}
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, reconstructionContextError(operationContext)
	}
	result.InitialInvocationID = startProgress.InitialInvocationID
	result.ReconstructionInvocationID = startProgress.ReconstructionInvocationID
	result.ProcessReplacements = append([]ProcessReplacementProgress(nil), startProgress.ProcessReplacements...)

	dispositions := make(map[string]string, len(initial.Scenarios)+len(plan.Cases))
	for _, progress := range initial.Scenarios {
		dispositions[progress.CaseID] = progress.Disposition
	}
	distinctMutations := make(map[string]struct{})
	for _, expected := range plan.Cases {
		caseContext, caseCancel, caseDeadline := initialCaseContext(operationContext, expected.TimeoutSeconds)
		progress, nextErr := session.NextScenario(caseContext)
		observedAt := time.Now().UTC()
		deadlineErr := initialDeadlineError(caseContext, caseDeadline, observedAt)
		caseCancel()
		if nextErr != nil || deadlineErr != nil {
			return result, reconstructionContextErrorWithDeadline(operationContext, deadlineErr)
		}
		progress = cloneScenarioProgress(progress)
		if !validScenarioProgress(expected, progress, dispositions) {
			return result, ErrReconstructionPhase
		}
		candidatePhaseUsage, valid := applyProgressUsage(result.PhaseUsage, expected, progress, distinctMutations, prepared.limits)
		if !valid {
			return result, ErrReconstructionPhase
		}
		candidateCumulativeUsage := addProvisionalUsage(initial.Usage, candidatePhaseUsage)
		if !usageWithinLimits(candidateCumulativeUsage, prepared.limits) {
			return result, ErrReconstructionPhase
		}
		result.PhaseUsage = candidatePhaseUsage
		result.CumulativeUsage = candidateCumulativeUsage
		result.Scenarios = append(result.Scenarios, progress)
		dispositions[progress.CaseID] = progress.Disposition
	}
	if err := operationContext.Err(); err != nil {
		return result, errors.Join(ErrReconstructionPhase, err)
	}
	if err := session.Finish(operationContext); err != nil || operationContext.Err() != nil {
		return result, reconstructionContextError(operationContext)
	}
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, reconstructionContextError(operationContext)
	}
	result.TerminalObserved = true
	result.Completion = ReconstructionCompletionCompleted
	for _, progress := range result.Scenarios {
		if progress.Disposition == ScenarioNotExecuted {
			result.Completion = ReconstructionCompletionStopped
			break
		}
	}
	return result, nil
}

func (r *PreparedRuntime) reconstructionOrchestrationPlan() (qualificationprofile.PhaseOrchestration, qualificationprofile.ReconstructionRequirements, bool) {
	if r == nil {
		return qualificationprofile.PhaseOrchestration{}, qualificationprofile.ReconstructionRequirements{}, false
	}
	plan, ok := r.orchestration[ReconstructionPhaseID]
	if !ok {
		return qualificationprofile.PhaseOrchestration{}, qualificationprofile.ReconstructionRequirements{}, false
	}
	return clonePhaseOrchestration(plan), cloneReconstructionRequirements(r.reconstruction), true
}

func reconstructionDirective(prepared *PreparedRuntime, plan qualificationprofile.PhaseOrchestration, policy qualificationprofile.ReconstructionRequirements) ReconstructionPhaseDirective {
	profileID, profileVersion, profileDigest := prepared.profileIdentity()
	caseIDs := make([]string, len(plan.Cases))
	for index, scenario := range plan.Cases {
		caseIDs[index] = scenario.CaseID
	}
	return ReconstructionPhaseDirective{
		RuntimeCommitmentDigest: prepared.digest, ProfileID: profileID, ProfileVersion: profileVersion,
		ProfileDigest: profileDigest, PhaseID: ReconstructionPhaseID, CaseIDs: caseIDs,
		RestartComponents: append([]string(nil), policy.RestartComponents...),
		PreservedStoreIDs: append([]string(nil), policy.PreserveStores...),
	}
}

func validReconstructionOrchestration(plan qualificationprofile.PhaseOrchestration, policy qualificationprofile.ReconstructionRequirements, limits qualificationprofile.RuntimeLimits) bool {
	if plan.PhaseID != ReconstructionPhaseID || plan.DependsOnPhase == nil || *plan.DependsOnPhase != InitialPhaseID || len(plan.Cases) != 5 ||
		!slices.Equal(policy.RestartComponents, []string{"provider", "external_caller", "qualification_adapter", "caller_gateway"}) ||
		!slices.Equal(policy.PreserveStores, persistentStoreIDs()) || policy.CallerStateOwner != "external_caller" ||
		!slices.Equal(policy.ReinjectionForbidden, []string{"sandbox_id", "operation_id", "attempt_id", "idempotency_key", "fencing_token", "runtime_session_id", "handoff_reference"}) {
		return false
	}
	seenInteractions := make(map[string]struct{})
	previousCaseID := "initial.provider-mtls-caller-binding-rejection"
	for _, scenario := range plan.Cases {
		if scenario.CaseID == "" || scenario.TimeoutSeconds <= 0 || scenario.TimeoutSeconds > limits.MaxCaseSeconds || len(scenario.DependsOn) != 1 ||
			scenario.DependsOn[0] != previousCaseID || len(scenario.Interactions) == 0 {
			return false
		}
		for _, interaction := range scenario.Interactions {
			if interaction.InteractionID == "" || interaction.LogicalRequestID == "" || interaction.MaxWireAttempts <= 0 || interaction.MaxWireAttempts > 64 {
				return false
			}
			if _, duplicate := seenInteractions[interaction.InteractionID]; duplicate {
				return false
			}
			seenInteractions[interaction.InteractionID] = struct{}{}
			for _, counter := range interaction.CountsToward {
				if counter != "provider_http_requests" && counter != "gateway_connection_attempts" {
					return false
				}
			}
		}
		previousCaseID = scenario.CaseID
	}
	return len(seenInteractions) == 8
}

func validReconstructionStartProgress(progress ReconstructionStartProgress, components []string) bool {
	if !observerIDPattern.MatchString(progress.InitialInvocationID) || !observerIDPattern.MatchString(progress.ReconstructionInvocationID) ||
		progress.InitialInvocationID == progress.ReconstructionInvocationID || len(progress.ProcessReplacements) != len(components) {
		return false
	}
	seen := make(map[string]struct{}, len(components)*2)
	for index, replacement := range progress.ProcessReplacements {
		pattern := opaqueProcessPatterns[replacement.Component]
		if replacement.Component != components[index] || pattern == nil || !pattern.MatchString(replacement.InitialProcessIdentity) ||
			!pattern.MatchString(replacement.ReconstructionProcessIdentity) || replacement.InitialProcessIdentity == replacement.ReconstructionProcessIdentity {
			return false
		}
		for _, identity := range []string{replacement.InitialProcessIdentity, replacement.ReconstructionProcessIdentity} {
			if _, duplicate := seen[identity]; duplicate {
				return false
			}
			seen[identity] = struct{}{}
		}
	}
	return true
}

func addProvisionalUsage(left, right ProvisionalUsage) ProvisionalUsage {
	return ProvisionalUsage{
		ExecRequests: left.ExecRequests + right.ExecRequests, ArtifactRequests: left.ArtifactRequests + right.ArtifactRequests,
		DistinctProviderMutations:     left.DistinctProviderMutations + right.DistinctProviderMutations,
		ProviderMutationWriteAttempts: left.ProviderMutationWriteAttempts + right.ProviderMutationWriteAttempts,
		GatewayMutationWriteAttempts:  left.GatewayMutationWriteAttempts + right.GatewayMutationWriteAttempts,
		ProviderHTTPRequests:          left.ProviderHTTPRequests + right.ProviderHTTPRequests,
		GatewayConnectionAttempts:     left.GatewayConnectionAttempts + right.GatewayConnectionAttempts,
	}
}

func cloneReconstructionDirective(source ReconstructionPhaseDirective) ReconstructionPhaseDirective {
	result := source
	result.CaseIDs = append([]string(nil), source.CaseIDs...)
	result.RestartComponents = append([]string(nil), source.RestartComponents...)
	result.PreservedStoreIDs = append([]string(nil), source.PreservedStoreIDs...)
	return result
}

func cloneReconstructionStartProgress(source ReconstructionStartProgress) ReconstructionStartProgress {
	result := source
	result.ProcessReplacements = append([]ProcessReplacementProgress(nil), source.ProcessReplacements...)
	return result
}

func cloneReconstructionResult(source ReconstructionPhaseResult) ReconstructionPhaseResult {
	result := source
	result.ProcessReplacements = append([]ProcessReplacementProgress(nil), source.ProcessReplacements...)
	result.Scenarios = make([]ScenarioProgress, len(source.Scenarios))
	for index, scenario := range source.Scenarios {
		result.Scenarios[index] = cloneScenarioProgress(scenario)
	}
	return result
}

func reconstructionContextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrReconstructionPhase, ctx.Err())
	}
	return ErrReconstructionPhase
}

func reconstructionContextErrorWithDeadline(ctx context.Context, deadlineErr error) error {
	if deadlineErr != nil {
		return errors.Join(ErrReconstructionPhase, deadlineErr)
	}
	return reconstructionContextError(ctx)
}

func (r *PreparedRuntime) beginReconstruction() (InitialPhaseResult, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleanupAttempted || r.cleanupActive || r.initialActive || r.reconstructionAttempted || r.reconstructionActive || !r.cleanupRequired || r.initialResult == nil ||
		!r.initialResult.TerminalObserved || (r.initialResult.Completion != InitialCompletionCompleted && r.initialResult.Completion != InitialCompletionStopped) ||
		len(r.initialResult.Scenarios) != 15 || r.initialResult.OrchestrationFinishedAt.IsZero() {
		return InitialPhaseResult{}, false
	}
	r.reconstructionAttempted = true
	r.reconstructionActive = true
	return cloneInitialResult(*r.initialResult), true
}

func (r *PreparedRuntime) finishReconstruction(result ReconstructionPhaseResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := cloneReconstructionResult(result)
	r.reconstructionResult = &copy
	r.reconstructionActive = false
}

// ReconstructionResult returns the immutable second-phase snapshot after its
// one-shot attempt finishes, including partial progress after failure.
func (r *PreparedRuntime) ReconstructionResult() (ReconstructionPhaseResult, bool) {
	if r == nil {
		return ReconstructionPhaseResult{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reconstructionActive || r.reconstructionResult == nil {
		return ReconstructionPhaseResult{}, false
	}
	return cloneReconstructionResult(*r.reconstructionResult), true
}
