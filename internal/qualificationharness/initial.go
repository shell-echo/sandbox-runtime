package qualificationharness

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	InitialPhaseID = "initial"

	ScenarioCompleted   = "completed"
	ScenarioNotExecuted = "not_executed"

	InitialCompletionCompleted = "completed"
	InitialCompletionStopped   = "stopped"
)

var ErrInitialPhase = errors.New("qualification initial phase orchestration failed")

var initialReasonCodes = map[string]struct{}{
	"prerequisite_not_satisfied": {},
	"invocation_canceled":        {},
	"time_budget_exhausted":      {},
	"adapter_unavailable":        {},
}

// InitialPhaseDirective is the entire value passed from the harness to the
// initial-phase executor. It contains only immutable identities and ordered
// case IDs. There is deliberately no route, method, payload, endpoint,
// credential, authorization, correlation, request, or signing field.
type InitialPhaseDirective struct {
	RuntimeCommitmentDigest string   `json:"runtime_commitment_digest"`
	ProfileID               string   `json:"profile_id"`
	ProfileVersion          string   `json:"profile_version"`
	ProfileDigest           string   `json:"profile_digest"`
	PhaseID                 string   `json:"phase_id"`
	CaseIDs                 []string `json:"case_ids"`
}

// InteractionProgress is a reduced caller/adapter progress projection used
// only for fail-closed orchestration accounting. It is not an independent
// observation and cannot by itself establish an interaction outcome.
type InteractionProgress struct {
	InteractionID string `json:"interaction_id"`
	WireAttempts  int    `json:"wire_attempts"`
}

// ScenarioProgress carries only adapter progress and bounded accounting. It
// deliberately has no passed/failed/incomplete status; d5 observations and
// the report validator determine those later.
type ScenarioProgress struct {
	CaseID       string                `json:"case_id"`
	Disposition  string                `json:"disposition"`
	ReasonCode   *string               `json:"reason_code"`
	Interactions []InteractionProgress `json:"interactions"`
}

// ProvisionalUsage is derived from completed progress using the verified
// profile. It enforces counters that do not require an admission outcome.
// Resource/admission counts remain unknown until d5 independent observation.
type ProvisionalUsage struct {
	ExecRequests                  int `json:"exec_requests"`
	ArtifactRequests              int `json:"artifact_requests"`
	DistinctProviderMutations     int `json:"distinct_provider_mutations"`
	ProviderMutationWriteAttempts int `json:"provider_mutation_write_attempts"`
	GatewayMutationWriteAttempts  int `json:"gateway_mutation_write_attempts"`
	ProviderHTTPRequests          int `json:"provider_http_requests"`
	GatewayConnectionAttempts     int `json:"gateway_connection_attempts"`
}

// InitialPhaseResult is a sanitized component result. TerminalObserved means
// the execution port supplied its terminal/EOF/clean-exit gate; it is not a
// qualification status or independent external-caller evidence.
type InitialPhaseResult struct {
	PhaseID                 string             `json:"phase_id"`
	OrchestrationStartedAt  time.Time          `json:"orchestration_started_at"`
	OrchestrationFinishedAt time.Time          `json:"orchestration_finished_at"`
	Scenarios               []ScenarioProgress `json:"scenarios"`
	Usage                   ProvisionalUsage   `json:"provisional_usage"`
	Completion              string             `json:"completion"`
	TerminalObserved        bool               `json:"terminal_observed"`
	CleanupRequired         bool               `json:"cleanup_required"`
}

// InitialPhaseExecutor owns all request construction, signing, credentials,
// endpoints, caller state, and adapter/supervisor composition. StartInitial
// must return a session after invocation acceptance and before consuming the
// first scenario result. The directive is the only harness-supplied value.
type InitialPhaseExecutor interface {
	StartInitial(context.Context, InitialPhaseDirective) (InitialPhaseSession, error)
}

// InitialPhaseSession returns exactly one result per NextScenario call in the
// locked order. Finish owns the terminal, stdout-EOF, and clean-exit gate.
// Close must stop/reap unfinished work and release local resources.
type InitialPhaseSession interface {
	NextScenario(context.Context) (ScenarioProgress, error)
	Finish(context.Context) error
	Close() error
}

// RunInitial performs the one-shot initial phase. It releases mutation
// capability only after the d2 state and baseline recheck, then conservatively
// retains a cleanup obligation even if StartInitial returns an unknown outcome.
// It never constructs or signs a Provider or Gateway request.
func RunInitial(ctx context.Context, prepared *PreparedRuntime, executor InitialPhaseExecutor) (result InitialPhaseResult, resultErr error) {
	if ctx == nil || prepared == nil || nilPort(executor) {
		return InitialPhaseResult{}, ErrInitialPhase
	}
	if err := ctx.Err(); err != nil {
		return InitialPhaseResult{}, errors.Join(ErrInitialPhase, err)
	}
	plan, ok := prepared.initialOrchestrationPlan()
	if !ok || !validInitialOrchestration(plan, prepared.limits) || !prepared.beginInitial() {
		return InitialPhaseResult{}, ErrInitialPhase
	}
	result.PhaseID = InitialPhaseID
	defer func() {
		result.OrchestrationFinishedAt = time.Now().UTC()
		result.CleanupRequired = prepared.CleanupRequired()
		prepared.finishInitial(result)
	}()

	operationContext, cancel := context.WithDeadline(ctx, prepared.executionDeadline)
	defer cancel()
	if err := operationContext.Err(); err != nil {
		return result, errors.Join(ErrInitialPhase, err)
	}
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, initialContextError(operationContext)
	}

	startedAt := time.Now().UTC()
	if !prepared.baseline.SampledAt.Before(startedAt) || !prepared.releaseMutationCapability() {
		return result, ErrInitialPhase
	}
	result.OrchestrationStartedAt = startedAt
	directive := initialDirective(prepared, plan)
	session, err := executor.StartInitial(operationContext, cloneInitialDirective(directive))
	if err != nil || nilPort(session) || operationContext.Err() != nil {
		if !nilPort(session) {
			_ = session.Close()
		}
		return result, initialContextError(operationContext)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			result.TerminalObserved = false
			result.Completion = ""
			if resultErr == nil {
				resultErr = ErrInitialPhase
			}
		}
	}()

	dispositions := make(map[string]string, len(plan.Cases))
	distinctMutations := make(map[string]struct{})
	for _, expected := range plan.Cases {
		caseContext, caseCancel, caseDeadline := initialCaseContext(operationContext, expected.TimeoutSeconds)
		progress, nextErr := session.NextScenario(caseContext)
		observedAt := time.Now().UTC()
		deadlineErr := initialDeadlineError(caseContext, caseDeadline, observedAt)
		caseCancel()
		if nextErr != nil || deadlineErr != nil {
			return result, initialContextErrorWithDeadline(operationContext, deadlineErr)
		}
		progress = cloneScenarioProgress(progress)
		if !validScenarioProgress(expected, progress, dispositions) {
			return result, ErrInitialPhase
		}
		candidateUsage, valid := applyProgressUsage(result.Usage, expected, progress, distinctMutations, prepared.limits)
		if !valid {
			return result, ErrInitialPhase
		}
		result.Usage = candidateUsage
		result.Scenarios = append(result.Scenarios, progress)
		dispositions[progress.CaseID] = progress.Disposition
	}
	if err := operationContext.Err(); err != nil {
		return result, errors.Join(ErrInitialPhase, err)
	}
	if err := session.Finish(operationContext); err != nil || operationContext.Err() != nil {
		return result, initialContextError(operationContext)
	}
	if err := prepared.RecheckPersistentState(operationContext); err != nil {
		return result, initialContextError(operationContext)
	}
	result.TerminalObserved = true
	result.Completion = InitialCompletionCompleted
	for _, progress := range result.Scenarios {
		if progress.Disposition == ScenarioNotExecuted {
			result.Completion = InitialCompletionStopped
			break
		}
	}
	return result, nil
}

func (r *PreparedRuntime) initialOrchestrationPlan() (qualificationprofile.PhaseOrchestration, bool) {
	if r == nil {
		return qualificationprofile.PhaseOrchestration{}, false
	}
	// The d1 object is intentionally not retained by d2. Reconstruct the
	// minimal immutable plan from the exact scenario inventory is insufficient
	// for counters, so d2 retains it privately at construction time.
	return clonePhaseOrchestration(r.orchestration[InitialPhaseID]), len(r.orchestration[InitialPhaseID].Cases) != 0
}

func initialDirective(prepared *PreparedRuntime, plan qualificationprofile.PhaseOrchestration) InitialPhaseDirective {
	profileID, profileVersion, profileDigest := prepared.profileIdentity()
	caseIDs := make([]string, len(plan.Cases))
	for index, scenario := range plan.Cases {
		caseIDs[index] = scenario.CaseID
	}
	return InitialPhaseDirective{
		RuntimeCommitmentDigest: prepared.digest, ProfileID: profileID, ProfileVersion: profileVersion,
		ProfileDigest: profileDigest, PhaseID: InitialPhaseID, CaseIDs: caseIDs,
	}
}

func validInitialOrchestration(plan qualificationprofile.PhaseOrchestration, limits qualificationprofile.RuntimeLimits) bool {
	if plan.PhaseID != InitialPhaseID || plan.DependsOnPhase != nil || len(plan.Cases) != 15 {
		return false
	}
	seenCases := make(map[string]struct{}, len(plan.Cases))
	seenInteractions := make(map[string]struct{})
	mutationCapable := false
	for _, scenario := range plan.Cases {
		if scenario.CaseID == "" || scenario.TimeoutSeconds <= 0 || scenario.TimeoutSeconds > limits.MaxCaseSeconds || len(scenario.Interactions) == 0 {
			return false
		}
		if _, exists := seenCases[scenario.CaseID]; exists {
			return false
		}
		for _, dependency := range scenario.DependsOn {
			if _, exists := seenCases[dependency]; !exists {
				return false
			}
		}
		for _, interaction := range scenario.Interactions {
			if interaction.InteractionID == "" || interaction.LogicalRequestID == "" || interaction.MaxWireAttempts <= 0 || interaction.MaxWireAttempts > 64 {
				return false
			}
			if _, exists := seenInteractions[interaction.InteractionID]; exists {
				return false
			}
			seenInteractions[interaction.InteractionID] = struct{}{}
			if containsCounter(interaction.CountsToward, "provider_mutation_write_attempts") || containsCounter(interaction.CountsToward, "gateway_mutation_write_attempts") {
				mutationCapable = true
			}
		}
		seenCases[scenario.CaseID] = struct{}{}
	}
	return mutationCapable
}

func validScenarioProgress(expected qualificationprofile.CaseOrchestration, actual ScenarioProgress, dispositions map[string]string) bool {
	if actual.CaseID != expected.CaseID {
		return false
	}
	dependencyMissing := false
	for _, dependency := range expected.DependsOn {
		if dispositions[dependency] != ScenarioCompleted {
			dependencyMissing = true
		}
	}
	switch actual.Disposition {
	case ScenarioCompleted:
		if actual.ReasonCode != nil || dependencyMissing || len(actual.Interactions) != len(expected.Interactions) {
			return false
		}
		for index, interaction := range actual.Interactions {
			if interaction.InteractionID != expected.Interactions[index].InteractionID || interaction.WireAttempts < 1 || interaction.WireAttempts > expected.Interactions[index].MaxWireAttempts {
				return false
			}
		}
		return true
	case ScenarioNotExecuted:
		if actual.ReasonCode == nil || len(actual.Interactions) != 0 {
			return false
		}
		if _, ok := initialReasonCodes[*actual.ReasonCode]; !ok {
			return false
		}
		if dependencyMissing {
			return *actual.ReasonCode == "prerequisite_not_satisfied"
		}
		// A completed adapter disposition is not a pass. Permit the caller to
		// provisionally stop a dependent case after an executed predecessor;
		// d5 must then prove that predecessor independently failed or was
		// incomplete. The first case cannot use this dependency reason.
		return *actual.ReasonCode != "prerequisite_not_satisfied" || len(expected.DependsOn) != 0
	default:
		return false
	}
}

func applyProgressUsage(current ProvisionalUsage, expected qualificationprofile.CaseOrchestration, actual ScenarioProgress, distinct map[string]struct{}, limits qualificationprofile.RuntimeLimits) (ProvisionalUsage, bool) {
	if actual.Disposition == ScenarioNotExecuted {
		return current, true
	}
	for index, progress := range actual.Interactions {
		requirement := expected.Interactions[index]
		for _, counter := range requirement.CountsToward {
			switch counter {
			case "provider_http_requests":
				current.ProviderHTTPRequests += progress.WireAttempts
			case "provider_mutation_write_attempts":
				current.ProviderMutationWriteAttempts += progress.WireAttempts
			case "gateway_connection_attempts":
				current.GatewayConnectionAttempts += progress.WireAttempts
			case "gateway_mutation_write_attempts":
				current.GatewayMutationWriteAttempts += progress.WireAttempts
			case "distinct_provider_mutations":
				distinct[requirement.LogicalRequestID] = struct{}{}
			case "exec_requests":
				current.ExecRequests++
			case "artifact_requests":
				current.ArtifactRequests++
			}
		}
		current.DistinctProviderMutations = len(distinct)
		if !usageWithinLimits(current, limits) {
			return ProvisionalUsage{}, false
		}
	}
	return current, true
}

func usageWithinLimits(usage ProvisionalUsage, limits qualificationprofile.RuntimeLimits) bool {
	return usage.ExecRequests <= limits.MaxExecRequests && usage.ArtifactRequests <= limits.MaxArtifactRequests &&
		usage.DistinctProviderMutations <= limits.MaxDistinctProviderMutations &&
		usage.ProviderMutationWriteAttempts <= limits.MaxProviderMutationWriteAttempts &&
		usage.GatewayMutationWriteAttempts <= limits.MaxGatewayMutationWriteAttempts &&
		usage.ProviderHTTPRequests <= limits.MaxProviderHTTPRequests &&
		usage.GatewayConnectionAttempts <= limits.MaxGatewayConnectionAttempts
}

func containsCounter(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func initialCaseContext(parent context.Context, timeoutSeconds int) (context.Context, context.CancelFunc, time.Time) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel, deadline
}

func initialDeadlineError(ctx context.Context, deadline, observedAt time.Time) error {
	if !deadline.IsZero() && !observedAt.Before(deadline) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}

func initialContextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrInitialPhase, ctx.Err())
	}
	return ErrInitialPhase
}

func initialContextErrorWithDeadline(ctx context.Context, deadlineErr error) error {
	if deadlineErr != nil {
		return errors.Join(ErrInitialPhase, deadlineErr)
	}
	return initialContextError(ctx)
}

func cloneInitialDirective(source InitialPhaseDirective) InitialPhaseDirective {
	result := source
	result.CaseIDs = append([]string(nil), source.CaseIDs...)
	return result
}

func cloneScenarioProgress(source ScenarioProgress) ScenarioProgress {
	result := source
	if source.ReasonCode != nil {
		value := *source.ReasonCode
		result.ReasonCode = &value
	}
	result.Interactions = append([]InteractionProgress(nil), source.Interactions...)
	return result
}

func cloneInitialResult(source InitialPhaseResult) InitialPhaseResult {
	result := source
	result.Scenarios = make([]ScenarioProgress, len(source.Scenarios))
	for index, scenario := range source.Scenarios {
		result.Scenarios[index] = cloneScenarioProgress(scenario)
	}
	return result
}

func (r *PreparedRuntime) profileIdentity() (string, string, string) {
	if r == nil {
		return "", "", ""
	}
	return r.profileID, r.profileVersion, r.profileDigest
}

func (r *PreparedRuntime) beginInitial() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleanupAttempted || r.cleanupActive || r.initialAttempted || r.initialActive {
		return false
	}
	r.initialAttempted = true
	r.initialActive = true
	return true
}

func (r *PreparedRuntime) releaseMutationCapability() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || !r.initialActive {
		return false
	}
	r.cleanupRequired = true
	return true
}

func (r *PreparedRuntime) finishInitial(result InitialPhaseResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := cloneInitialResult(result)
	r.initialResult = &copy
	r.initialActive = false
}

// CleanupRequired reports the conservative persistent teardown obligation.
// True means mutation capability was released, not that a mutation succeeded.
func (r *PreparedRuntime) CleanupRequired() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleanupRequired
}

// InitialResult returns the latest immutable orchestration snapshot after the
// one-shot attempt finishes, including partial progress after a failure.
func (r *PreparedRuntime) InitialResult() (InitialPhaseResult, bool) {
	if r == nil {
		return InitialPhaseResult{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.initialActive || r.initialResult == nil {
		return InitialPhaseResult{}, false
	}
	return cloneInitialResult(*r.initialResult), true
}
