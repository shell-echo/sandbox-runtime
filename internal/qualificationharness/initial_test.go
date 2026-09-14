package qualificationharness

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

type initialExecutorFunc func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error)

func (f initialExecutorFunc) StartInitial(ctx context.Context, directive InitialPhaseDirective) (InitialPhaseSession, error) {
	return f(ctx, directive)
}

type scriptedInitialSession struct {
	progress    []ScenarioProgress
	nextIndex   int
	finishCalls int
	closeCalls  int
	nextHook    func(context.Context, int)
	finishHook  func(context.Context)
	finishErr   error
	closeErr    error
}

func (s *scriptedInitialSession) NextScenario(ctx context.Context) (ScenarioProgress, error) {
	if s.nextHook != nil {
		s.nextHook(ctx, s.nextIndex)
	}
	if s.nextIndex >= len(s.progress) {
		return ScenarioProgress{}, errors.New("unexpected extra scenario read")
	}
	result := cloneScenarioProgress(s.progress[s.nextIndex])
	s.nextIndex++
	return result, nil
}

func (s *scriptedInitialSession) Finish(ctx context.Context) error {
	s.finishCalls++
	if s.finishHook != nil {
		s.finishHook(ctx)
	}
	return s.finishErr
}

func (s *scriptedInitialSession) Close() error {
	s.closeCalls++
	return s.closeErr
}

func completedInitialProgress(plan qualificationprofile.PhaseOrchestration, attempts func(qualificationprofile.InteractionAccountingRequirement) int) []ScenarioProgress {
	result := make([]ScenarioProgress, len(plan.Cases))
	for caseIndex, scenario := range plan.Cases {
		interactions := make([]InteractionProgress, len(scenario.Interactions))
		for interactionIndex, interaction := range scenario.Interactions {
			count := 1
			if attempts != nil {
				count = attempts(interaction)
			}
			interactions[interactionIndex] = InteractionProgress{InteractionID: interaction.InteractionID, WireAttempts: count}
		}
		result[caseIndex] = ScenarioProgress{CaseID: scenario.CaseID, Disposition: ScenarioCompleted, Interactions: interactions}
	}
	return result
}

func stoppedInitialProgress(plan qualificationprofile.PhaseOrchestration) []ScenarioProgress {
	result := make([]ScenarioProgress, len(plan.Cases))
	for index, scenario := range plan.Cases {
		reason := "prerequisite_not_satisfied"
		if index == 0 {
			reason = "adapter_unavailable"
		}
		result[index] = ScenarioProgress{CaseID: scenario.CaseID, Disposition: ScenarioNotExecuted, ReasonCode: &reason, Interactions: []InteractionProgress{}}
	}
	return result
}

func TestRunInitialOrchestratesExactCasesAndProvisionalBudgets(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	plan, ok := prepared.initialOrchestrationPlan()
	if !ok {
		t.Fatal("missing initial orchestration plan")
	}
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	var directive InitialPhaseDirective
	var startDeadline, firstCaseDeadline time.Time
	executor := initialExecutorFunc(func(ctx context.Context, supplied InitialPhaseDirective) (InitialPhaseSession, error) {
		directive = cloneInitialDirective(supplied)
		startDeadline, _ = ctx.Deadline()
		supplied.CaseIDs[0] = "executor-mutation"
		session.nextHook = func(caseContext context.Context, index int) {
			if index == 0 {
				firstCaseDeadline, _ = caseContext.Deadline()
			}
		}
		return session, nil
	})
	result, err := RunInitial(context.Background(), prepared, executor)
	if err != nil {
		t.Fatal(err)
	}
	profileID, profileVersion, profileDigest := prepared.profileIdentity()
	if directive.RuntimeCommitmentDigest != prepared.Digest() || directive.ProfileID != profileID || directive.ProfileVersion != profileVersion ||
		directive.ProfileDigest != profileDigest || directive.PhaseID != InitialPhaseID || len(directive.CaseIDs) != 15 ||
		directive.CaseIDs[0] != "initial.locked-capability-discovery" || directive.CaseIDs[14] != "initial.provider-mtls-caller-binding-rejection" {
		t.Fatalf("unexpected directive: %+v", directive)
	}
	_, executionDeadline, _ := prepared.Deadlines()
	if !startDeadline.Equal(executionDeadline) || time.Until(firstCaseDeadline) < 119*time.Second || time.Until(firstCaseDeadline) > 121*time.Second {
		t.Fatalf("unexpected deadlines: start=%v execution=%v case=%v", startDeadline, executionDeadline, firstCaseDeadline)
	}
	wantUsage := ProvisionalUsage{
		ExecRequests: 3, ArtifactRequests: 2, DistinctProviderMutations: 8,
		ProviderMutationWriteAttempts: 10, GatewayMutationWriteAttempts: 1,
		ProviderHTTPRequests: 27, GatewayConnectionAttempts: 5,
	}
	if result.PhaseID != InitialPhaseID || len(result.Scenarios) != 15 || result.Usage != wantUsage ||
		result.Completion != InitialCompletionCompleted || !result.TerminalObserved || !result.CleanupRequired ||
		result.OrchestrationStartedAt.IsZero() || result.OrchestrationFinishedAt.Before(result.OrchestrationStartedAt) ||
		session.nextIndex != 15 || session.finishCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("unexpected initial result=%+v session=%+v", result, session)
	}
	if !prepared.Baseline().SampledAt.Before(result.OrchestrationStartedAt) || !prepared.CleanupRequired() {
		t.Fatal("baseline/cleanup ordering was not retained")
	}
	result.Scenarios[0].CaseID = "changed"
	stored, ok := prepared.InitialResult()
	if !ok || stored.Scenarios[0].CaseID != "initial.locked-capability-discovery" {
		t.Fatal("stored initial result was mutable")
	}
	stored.Scenarios[0].Interactions[0].InteractionID = "changed"
	again, ok := prepared.InitialResult()
	if !ok || again.Scenarios[0].Interactions[0].InteractionID != "controller-a-capabilities" {
		t.Fatal("InitialResult returned mutable interaction state")
	}
}

func TestRunInitialAcceptsCompleteStoppedProgressWithoutClaimingStatus(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	plan, _ := prepared.initialOrchestrationPlan()
	session := &scriptedInitialSession{progress: stoppedInitialProgress(plan)}
	result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return session, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion != InitialCompletionStopped || !result.TerminalObserved || len(result.Scenarios) != 15 || result.Usage != (ProvisionalUsage{}) {
		t.Fatalf("unexpected stopped result: %+v", result)
	}
	resultType := reflect.TypeOf(result)
	if _, exists := resultType.FieldByName("Status"); exists {
		t.Fatal("d3 result must not assign a qualification status")
	}
	for index := 1; index < len(result.Scenarios); index++ {
		if result.Scenarios[index].ReasonCode == nil || *result.Scenarios[index].ReasonCode != "prerequisite_not_satisfied" {
			t.Fatalf("scenario %d did not preserve dependency stop", index)
		}
	}
}

func TestRunInitialDefersCompletedPredecessorStopReasonToIndependentObservation(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	plan, _ := prepared.initialOrchestrationPlan()
	progress := completedInitialProgress(plan, nil)
	for index := 1; index < len(progress); index++ {
		reason := "prerequisite_not_satisfied"
		progress[index] = ScenarioProgress{CaseID: plan.Cases[index].CaseID, Disposition: ScenarioNotExecuted, ReasonCode: &reason, Interactions: []InteractionProgress{}}
	}
	result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return &scriptedInitialSession{progress: progress}, nil
	}))
	if err != nil || result.Completion != InitialCompletionStopped || !result.TerminalObserved || result.Scenarios[0].Disposition != ScenarioCompleted || result.Scenarios[1].Disposition != ScenarioNotExecuted {
		t.Fatalf("provisional stop result = %+v, %v", result, err)
	}
}

func TestInitialDirectiveHasNoRequestConstructionSurface(t *testing.T) {
	typeOf := reflect.TypeOf(InitialPhaseDirective{})
	if typeOf.NumField() != 6 {
		t.Fatalf("directive field count = %d, want 6", typeOf.NumField())
	}
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		identity := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"path", "route", "method", "request", "payload", "body", "credential", "secret", "key", "signature", "endpoint", "origin", "correlation"} {
			if strings.Contains(identity, forbidden) {
				t.Fatalf("directive exposes forbidden %q field: %s", forbidden, field.Name)
			}
		}
	}
}

func TestRunInitialRejectsInvalidProgressAndClosesSession(t *testing.T) {
	for name, mutate := range map[string]func([]ScenarioProgress, qualificationprofile.PhaseOrchestration){
		"wrong_order": func(progress []ScenarioProgress, plan qualificationprofile.PhaseOrchestration) {
			progress[0].CaseID = plan.Cases[1].CaseID
		},
		"missing_interaction": func(progress []ScenarioProgress, _ qualificationprofile.PhaseOrchestration) {
			progress[0].Interactions = progress[0].Interactions[:2]
		},
		"wire_attempt_limit": func(progress []ScenarioProgress, plan qualificationprofile.PhaseOrchestration) {
			progress[0].Interactions[0].WireAttempts = plan.Cases[0].Interactions[0].MaxWireAttempts + 1
		},
		"not_executed_with_interaction": func(progress []ScenarioProgress, _ qualificationprofile.PhaseOrchestration) {
			reason := "adapter_unavailable"
			progress[0].Disposition, progress[0].ReasonCode = ScenarioNotExecuted, &reason
		},
		"unknown_reason": func(progress []ScenarioProgress, _ qualificationprofile.PhaseOrchestration) {
			reason := "private-secret-reason"
			progress[0] = ScenarioProgress{CaseID: progress[0].CaseID, Disposition: ScenarioNotExecuted, ReasonCode: &reason}
		},
		"completed_after_stopped_dependency": func(progress []ScenarioProgress, _ qualificationprofile.PhaseOrchestration) {
			reason := "adapter_unavailable"
			progress[0] = ScenarioProgress{CaseID: progress[0].CaseID, Disposition: ScenarioNotExecuted, ReasonCode: &reason}
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			plan, _ := prepared.initialOrchestrationPlan()
			progress := completedInitialProgress(plan, nil)
			mutate(progress, plan)
			session := &scriptedInitialSession{progress: progress}
			result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
				return session, nil
			}))
			if !errors.Is(err, ErrInitialPhase) || strings.Contains(err.Error(), "secret") || result.TerminalObserved || session.finishCalls != 0 || session.closeCalls != 1 || !result.CleanupRequired {
				t.Fatalf("RunInitial = %+v, %v; session=%+v", result, err, session)
			}
		})
	}
}

func TestRunInitialRejectsProvisionalLimitExcessBeforeTerminal(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	plan, _ := prepared.initialOrchestrationPlan()
	progress := completedInitialProgress(plan, func(requirement qualificationprofile.InteractionAccountingRequirement) int {
		return requirement.MaxWireAttempts
	})
	session := &scriptedInitialSession{progress: progress}
	result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return session, nil
	}))
	if !errors.Is(err, ErrInitialPhase) || result.TerminalObserved || session.nextIndex >= 15 || session.finishCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("RunInitial = %+v, %v; session=%+v", result, err, session)
	}
	if !usageWithinLimits(result.Usage, prepared.RuntimeLimits()) {
		t.Fatalf("partial result published over-limit usage: %+v", result.Usage)
	}
}

type blockingInitialSession struct {
	entered    chan struct{}
	closeCalls int
}

func (s *blockingInitialSession) NextScenario(ctx context.Context) (ScenarioProgress, error) {
	close(s.entered)
	<-ctx.Done()
	return ScenarioProgress{}, ctx.Err()
}

func (s *blockingInitialSession) Finish(context.Context) error { return nil }
func (s *blockingInitialSession) Close() error {
	s.closeCalls++
	return nil
}

func TestRunInitialIsOneShotCancelableAndCannotCloseWhileActive(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	session := &blockingInitialSession{entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan error, 1)
	go func() {
		_, err := RunInitial(ctx, prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
			return session, nil
		}))
		resultChannel <- err
	}()
	<-session.entered
	if _, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return &scriptedInitialSession{}, nil
	})); !errors.Is(err, ErrInitialPhase) {
		t.Fatalf("second initial attempt = %v", err)
	}
	if err := prepared.Close(); !errors.Is(err, ErrRuntimePreflight) {
		t.Fatalf("active Close = %v", err)
	}
	cancel()
	if err := <-resultChannel; !errors.Is(err, ErrInitialPhase) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled initial run = %v", err)
	}
	if session.closeCalls != 1 || !prepared.CleanupRequired() {
		t.Fatalf("canceled session cleanup=%d required=%t", session.closeCalls, prepared.CleanupRequired())
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("post-run Close = %v", err)
	}
}

func TestRunInitialSanitizesStartFailureAndRejectsNilPorts(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunInitial(canceled, prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return nil, nil
	})); !errors.Is(err, context.Canceled) || prepared.CleanupRequired() {
		t.Fatalf("pre-canceled initial run = %v cleanup=%t", err, prepared.CleanupRequired())
	}
	var typedNil initialExecutorFunc
	if _, err := RunInitial(context.Background(), prepared, typedNil); !errors.Is(err, ErrInitialPhase) || prepared.CleanupRequired() {
		t.Fatalf("typed-nil executor = %v cleanup=%t", err, prepared.CleanupRequired())
	}
	result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return nil, errors.New("credential /private/start-error")
	}))
	if !errors.Is(err, ErrInitialPhase) || strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "/private") ||
		result.OrchestrationStartedAt.IsZero() || !result.CleanupRequired || result.TerminalObserved {
		t.Fatalf("start failure = %+v, %v", result, err)
	}
	stored, ok := prepared.InitialResult()
	if !ok || !stored.CleanupRequired {
		t.Fatal("start failure did not preserve its cleanup obligation")
	}
}

func TestRunInitialSanitizesSessionFailures(t *testing.T) {
	for name, configure := range map[string]func(*scriptedInitialSession){
		"next": func(session *scriptedInitialSession) {
			session.nextHook = func(context.Context, int) {
				session.progress = nil
			}
		},
		"finish": func(session *scriptedInitialSession) {
			session.finishErr = errors.New("credential /private/finish-error")
		},
		"close": func(session *scriptedInitialSession) {
			session.closeErr = errors.New("credential /private/close-error")
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			plan, _ := prepared.initialOrchestrationPlan()
			session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
			configure(session)
			result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
				return session, nil
			}))
			if !errors.Is(err, ErrInitialPhase) || strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "/private") ||
				result.TerminalObserved || result.Completion != "" || session.closeCalls != 1 {
				t.Fatalf("session failure = %+v, %v; session=%+v", result, err, session)
			}
		})
	}
}

func TestRunInitialClipsEveryOperationToCallerDeadline(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	plan, _ := prepared.initialOrchestrationPlan()
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	parentDeadline := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), parentDeadline)
	defer cancel()
	seen := 0
	session.nextHook = func(caseContext context.Context, _ int) {
		deadline, ok := caseContext.Deadline()
		if !ok || !deadline.Equal(parentDeadline) {
			t.Fatalf("case context deadline = %v, %t; want %v", deadline, ok, parentDeadline)
		}
		seen++
	}
	result, err := RunInitial(ctx, prepared, initialExecutorFunc(func(startContext context.Context, _ InitialPhaseDirective) (InitialPhaseSession, error) {
		deadline, ok := startContext.Deadline()
		if !ok || !deadline.Equal(parentDeadline) {
			t.Fatalf("start context deadline = %v, %t; want %v", deadline, ok, parentDeadline)
		}
		return session, nil
	}))
	if err != nil || !result.TerminalObserved || seen != 15 {
		t.Fatalf("clipped run = %+v, %v; seen=%d", result, err, seen)
	}
}

func TestRunInitialPostExecutionStateReplacementFailsClosed(t *testing.T) {
	_, input, _, prepared := prepareRuntimeFixture(t)
	plan, _ := prepared.initialOrchestrationPlan()
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	session.finishHook = func(context.Context) {
		original := input.PersistentStateRoot + "-original"
		if err := os.Rename(input.PersistentStateRoot, original); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(input.PersistentStateRoot, 0700); err != nil {
			t.Fatal(err)
		}
	}
	result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return session, nil
	}))
	if !errors.Is(err, ErrInitialPhase) || result.TerminalObserved || result.Completion != "" || len(result.Scenarios) != 15 || session.closeCalls != 1 {
		t.Fatalf("replacement result = %+v, %v; session=%+v", result, err, session)
	}
	if _, statErr := os.Stat(filepath.Join(input.PersistentStateRoot+"-original", ProviderLocalState)); statErr != nil {
		t.Fatalf("original retained state missing: %v", statErr)
	}
}
