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
)

type reconstructionExecutorFunc func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error)

func (f reconstructionExecutorFunc) StartReconstruction(ctx context.Context, directive ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
	return f(ctx, directive)
}

func runInitialForReconstruction(t *testing.T, prepared *PreparedRuntime, stopped bool) InitialPhaseResult {
	t.Helper()
	plan, ok := prepared.initialOrchestrationPlan()
	if !ok {
		t.Fatal("missing initial plan")
	}
	progress := completedInitialProgress(plan, nil)
	if stopped {
		progress = stoppedInitialProgress(plan)
	}
	result, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return &scriptedInitialSession{progress: progress}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func reconstructionStartFixture() ReconstructionStartProgress {
	components := []struct {
		component string
		prefix    string
	}{
		{component: "provider", prefix: "provider"},
		{component: "external_caller", prefix: "caller"},
		{component: "qualification_adapter", prefix: "adapter"},
		{component: "caller_gateway", prefix: "gateway"},
	}
	replacements := make([]ProcessReplacementProgress, len(components))
	for index, component := range components {
		replacements[index] = ProcessReplacementProgress{
			Component:                     component.component,
			InitialProcessIdentity:        component.prefix + "-process-" + strings.Repeat(string(rune('1'+index)), 32),
			ReconstructionProcessIdentity: component.prefix + "-process-" + strings.Repeat(string(rune('5'+index)), 32),
		}
	}
	return ReconstructionStartProgress{
		InitialInvocationID:        "initial-invocation",
		ReconstructionInvocationID: "reconstruction-invocation",
		ProcessReplacements:        replacements,
	}
}

func stoppedReconstructionProgress(planLength int, caseIDs []string) []ScenarioProgress {
	result := make([]ScenarioProgress, planLength)
	for index := range result {
		reason := "prerequisite_not_satisfied"
		result[index] = ScenarioProgress{CaseID: caseIDs[index], Disposition: ScenarioNotExecuted, ReasonCode: &reason, Interactions: []InteractionProgress{}}
	}
	return result
}

func TestRunReconstructionUsesFreshProcessBoundaryAndNoCallerStateInput(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	initial := runInitialForReconstruction(t, prepared, false)
	plan, policy, ok := prepared.reconstructionOrchestrationPlan()
	if !ok {
		t.Fatal("missing reconstruction plan")
	}
	callerStatePath, ok := prepared.PersistentStatePath(CallerOwnedCorrelationState)
	if !ok {
		t.Fatal("missing caller-owned state path")
	}
	sentinelPath := filepath.Join(callerStatePath, "private-caller-state")
	if err := os.WriteFile(sentinelPath, []byte("caller-owned-correlation"), 0600); err != nil {
		t.Fatal(err)
	}

	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	startProgress := reconstructionStartFixture()
	var directive ReconstructionPhaseDirective
	var startDeadline, firstCaseDeadline time.Time
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(ctx context.Context, supplied ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		directive = cloneReconstructionDirective(supplied)
		startDeadline, _ = ctx.Deadline()
		supplied.CaseIDs[0] = "executor-mutation"
		supplied.RestartComponents[0] = "executor-mutation"
		supplied.PreservedStoreIDs[0] = "executor-mutation"
		session.nextHook = func(caseContext context.Context, index int) {
			if index == 0 {
				firstCaseDeadline, _ = caseContext.Deadline()
			}
		}
		return session, startProgress, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	profileID, profileVersion, profileDigest := prepared.profileIdentity()
	if directive.RuntimeCommitmentDigest != prepared.Digest() || directive.ProfileID != profileID || directive.ProfileVersion != profileVersion ||
		directive.ProfileDigest != profileDigest || directive.PhaseID != ReconstructionPhaseID || len(directive.CaseIDs) != 5 ||
		directive.CaseIDs[0] != "reconstruction.locked-capability-discovery" || directive.CaseIDs[4] != "reconstruction.same-shell-reconnect" ||
		!reflect.DeepEqual(directive.RestartComponents, policy.RestartComponents) || !reflect.DeepEqual(directive.PreservedStoreIDs, policy.PreserveStores) {
		t.Fatalf("unexpected directive: %+v", directive)
	}
	_, executionDeadline, _ := prepared.Deadlines()
	if !startDeadline.Equal(executionDeadline) || time.Until(firstCaseDeadline) < 119*time.Second || time.Until(firstCaseDeadline) > 121*time.Second {
		t.Fatalf("unexpected deadlines: start=%v execution=%v case=%v", startDeadline, executionDeadline, firstCaseDeadline)
	}
	wantPhaseUsage := ProvisionalUsage{ProviderHTTPRequests: 7, GatewayConnectionAttempts: 1}
	wantCumulativeUsage := initial.Usage
	wantCumulativeUsage.ProviderHTTPRequests += 7
	wantCumulativeUsage.GatewayConnectionAttempts++
	if result.PhaseID != ReconstructionPhaseID || len(result.Scenarios) != 5 || result.PhaseUsage != wantPhaseUsage || result.CumulativeUsage != wantCumulativeUsage ||
		result.Completion != ReconstructionCompletionCompleted || !result.TerminalObserved || !result.CleanupRequired ||
		result.OrchestrationStartedAt.Before(initial.OrchestrationFinishedAt) || result.OrchestrationFinishedAt.Before(result.OrchestrationStartedAt) ||
		result.InitialInvocationID != startProgress.InitialInvocationID || result.ReconstructionInvocationID != startProgress.ReconstructionInvocationID ||
		!reflect.DeepEqual(result.ProcessReplacements, startProgress.ProcessReplacements) || session.nextIndex != 5 || session.finishCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("unexpected reconstruction result=%+v session=%+v", result, session)
	}
	if content, readErr := os.ReadFile(sentinelPath); readErr != nil || string(content) != "caller-owned-correlation" {
		t.Fatalf("caller-owned state changed: %q, %v", content, readErr)
	}
	result.ProcessReplacements[0].Component = "changed"
	result.Scenarios[0].Interactions[0].InteractionID = "changed"
	stored, ok := prepared.ReconstructionResult()
	if !ok || stored.ProcessReplacements[0].Component != "provider" || stored.Scenarios[0].Interactions[0].InteractionID == "changed" {
		t.Fatal("stored reconstruction result was mutable")
	}
}

func TestReconstructionDirectiveHasNoReinjectionOrRequestSurface(t *testing.T) {
	typeOf := reflect.TypeOf(ReconstructionPhaseDirective{})
	if typeOf.NumField() != 8 {
		t.Fatalf("directive field count = %d, want 8", typeOf.NumField())
	}
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		identity := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{
			"path", "route", "method", "request", "payload", "body", "credential", "secret", "key", "signature", "endpoint", "origin", "correlation",
			"sandbox_id", "operation_id", "attempt_id", "idempotency_key", "fencing_token", "runtime_session_id", "handoff_reference",
		} {
			if strings.Contains(identity, forbidden) {
				t.Fatalf("directive exposes forbidden %q field: %s", forbidden, field.Name)
			}
		}
	}
	resultType := reflect.TypeOf(ReconstructionPhaseResult{})
	if _, exists := resultType.FieldByName("Status"); exists {
		t.Fatal("d4 result must not assign a qualification status")
	}
	if _, exists := resultType.FieldByName("HarnessReinjected"); exists {
		t.Fatal("d4 must not convert its closed input shape into a self-attested non-reinjection result")
	}
}

func TestRunReconstructionRequiresTerminalInitialButDoesNotConsumeEarlyAttempt(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	called := 0
	executor := reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		called++
		return nil, ReconstructionStartProgress{}, nil
	})
	if _, err := RunReconstruction(context.Background(), prepared, executor); !errors.Is(err, ErrReconstructionPhase) || called != 0 {
		t.Fatalf("early reconstruction = %v, called=%d", err, called)
	}
	runInitialForReconstruction(t, prepared, false)
	plan, _, _ := prepared.reconstructionOrchestrationPlan()
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		called++
		return session, reconstructionStartFixture(), nil
	}))
	if err != nil || !result.TerminalObserved || called != 1 {
		t.Fatalf("post-initial reconstruction = %+v, %v, called=%d", result, err, called)
	}
}

func TestRunReconstructionAcceptsDependencyStoppedProgress(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runInitialForReconstruction(t, prepared, true)
	plan, _, _ := prepared.reconstructionOrchestrationPlan()
	caseIDs := make([]string, len(plan.Cases))
	for index := range plan.Cases {
		caseIDs[index] = plan.Cases[index].CaseID
	}
	session := &scriptedInitialSession{progress: stoppedReconstructionProgress(len(plan.Cases), caseIDs)}
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return session, reconstructionStartFixture(), nil
	}))
	if err != nil || result.Completion != ReconstructionCompletionStopped || !result.TerminalObserved || len(result.Scenarios) != 5 ||
		result.PhaseUsage != (ProvisionalUsage{}) || result.CumulativeUsage != (ProvisionalUsage{}) {
		t.Fatalf("stopped reconstruction = %+v, %v", result, err)
	}
}

func TestRunReconstructionRejectsInvalidProcessReplacementProgress(t *testing.T) {
	for name, mutate := range map[string]func(*ReconstructionStartProgress){
		"missing_component": func(progress *ReconstructionStartProgress) {
			progress.ProcessReplacements = progress.ProcessReplacements[:3]
		},
		"wrong_order": func(progress *ReconstructionStartProgress) {
			progress.ProcessReplacements[0], progress.ProcessReplacements[1] = progress.ProcessReplacements[1], progress.ProcessReplacements[0]
		},
		"same_phase_identity": func(progress *ReconstructionStartProgress) {
			progress.ProcessReplacements[0].ReconstructionProcessIdentity = progress.ProcessReplacements[0].InitialProcessIdentity
		},
		"cross_component_reuse": func(progress *ReconstructionStartProgress) {
			progress.ProcessReplacements[1].InitialProcessIdentity = progress.ProcessReplacements[0].InitialProcessIdentity
		},
		"raw_pid": func(progress *ReconstructionStartProgress) {
			progress.ProcessReplacements[0].InitialProcessIdentity = "12345"
		},
		"same_invocation": func(progress *ReconstructionStartProgress) {
			progress.ReconstructionInvocationID = progress.InitialInvocationID
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			runInitialForReconstruction(t, prepared, false)
			plan, _, _ := prepared.reconstructionOrchestrationPlan()
			session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
			start := reconstructionStartFixture()
			mutate(&start)
			result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
				return session, start, nil
			}))
			if !errors.Is(err, ErrReconstructionPhase) || result.TerminalObserved || len(result.ProcessReplacements) != 0 || session.nextIndex != 0 || session.finishCalls != 0 || session.closeCalls != 1 {
				t.Fatalf("invalid start = %+v, %v; session=%+v", result, err, session)
			}
		})
	}
}

func TestRunReconstructionRejectsInvalidProgressAndPreservesCumulativeLimit(t *testing.T) {
	for name, mutate := range map[string]func([]ScenarioProgress){
		"wrong_order": func(progress []ScenarioProgress) {
			progress[0].CaseID = progress[1].CaseID
		},
		"wire_attempt_limit": func(progress []ScenarioProgress) {
			progress[0].Interactions[0].WireAttempts = 65
		},
		"completed_after_missing_initial_dependency": func(progress []ScenarioProgress) {},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			initialStopped := name == "completed_after_missing_initial_dependency"
			runInitialForReconstruction(t, prepared, initialStopped)
			plan, _, _ := prepared.reconstructionOrchestrationPlan()
			progress := completedInitialProgress(plan, nil)
			mutate(progress)
			session := &scriptedInitialSession{progress: progress}
			result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
				return session, reconstructionStartFixture(), nil
			}))
			if !errors.Is(err, ErrReconstructionPhase) || result.TerminalObserved || session.finishCalls != 0 || session.closeCalls != 1 ||
				!usageWithinLimits(result.CumulativeUsage, prepared.RuntimeLimits()) {
				t.Fatalf("invalid progress = %+v, %v; session=%+v", result, err, session)
			}
		})
	}
}

func TestRunReconstructionCumulativeLimitPreemptsPhaseLimit(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	initial := runInitialForReconstruction(t, prepared, false)
	prepared.limits.MaxProviderHTTPRequests = initial.Usage.ProviderHTTPRequests
	plan, _, _ := prepared.reconstructionOrchestrationPlan()
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return session, reconstructionStartFixture(), nil
	}))
	if !errors.Is(err, ErrReconstructionPhase) || result.TerminalObserved || len(result.Scenarios) != 0 || result.PhaseUsage != (ProvisionalUsage{}) ||
		result.CumulativeUsage != initial.Usage || session.nextIndex != 1 || session.finishCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("cumulative limit result = %+v, %v; session=%+v", result, err, session)
	}
}

func TestRunReconstructionIsOneShotCancelableAndCannotCloseWhileActive(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runInitialForReconstruction(t, prepared, false)
	session := &blockingInitialSession{entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	resultChannel := make(chan error, 1)
	go func() {
		_, err := RunReconstruction(ctx, prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
			return session, reconstructionStartFixture(), nil
		}))
		resultChannel <- err
	}()
	<-session.entered
	if _, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return &scriptedInitialSession{}, ReconstructionStartProgress{}, nil
	})); !errors.Is(err, ErrReconstructionPhase) {
		t.Fatalf("second reconstruction attempt = %v", err)
	}
	if err := prepared.Close(); !errors.Is(err, ErrRuntimePreflight) {
		t.Fatalf("active Close = %v", err)
	}
	cancel()
	if err := <-resultChannel; !errors.Is(err, ErrReconstructionPhase) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reconstruction = %v", err)
	}
	if session.closeCalls != 1 || !prepared.CleanupRequired() {
		t.Fatalf("canceled session cleanup=%d required=%t", session.closeCalls, prepared.CleanupRequired())
	}
}

func TestRunReconstructionSanitizesPortFailuresAndRejectsNil(t *testing.T) {
	for name, configure := range map[string]func(*scriptedInitialSession) error{
		"start": func(*scriptedInitialSession) error { return errors.New("secret /private/start") },
		"next": func(session *scriptedInitialSession) error {
			session.progress = nil
			return nil
		},
		"finish": func(session *scriptedInitialSession) error {
			session.finishErr = errors.New("secret /private/finish")
			return nil
		},
		"close": func(session *scriptedInitialSession) error {
			session.closeErr = errors.New("secret /private/close")
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			runInitialForReconstruction(t, prepared, false)
			plan, _, _ := prepared.reconstructionOrchestrationPlan()
			session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
			startErr := configure(session)
			result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
				return session, reconstructionStartFixture(), startErr
			}))
			if !errors.Is(err, ErrReconstructionPhase) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "/private") ||
				result.TerminalObserved || result.Completion != "" || session.closeCalls != 1 {
				t.Fatalf("port failure = %+v, %v; session=%+v", result, err, session)
			}
		})
	}

	_, _, _, prepared := prepareRuntimeFixture(t)
	runInitialForReconstruction(t, prepared, false)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunReconstruction(canceled, prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return nil, ReconstructionStartProgress{}, nil
	})); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled reconstruction = %v", err)
	}
	var typedNil reconstructionExecutorFunc
	if _, err := RunReconstruction(context.Background(), prepared, typedNil); !errors.Is(err, ErrReconstructionPhase) {
		t.Fatalf("typed-nil reconstruction executor = %v", err)
	}
}

func TestRunReconstructionPostExecutionStateReplacementFailsClosed(t *testing.T) {
	_, input, _, prepared := prepareRuntimeFixture(t)
	runInitialForReconstruction(t, prepared, false)
	plan, _, _ := prepared.reconstructionOrchestrationPlan()
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	session.finishHook = func(context.Context) {
		original := input.PersistentStateRoot + "-reconstruction-original"
		if err := os.Rename(input.PersistentStateRoot, original); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(input.PersistentStateRoot, 0700); err != nil {
			t.Fatal(err)
		}
	}
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		return session, reconstructionStartFixture(), nil
	}))
	if !errors.Is(err, ErrReconstructionPhase) || result.TerminalObserved || result.Completion != "" || len(result.Scenarios) != 5 || session.closeCalls != 1 {
		t.Fatalf("replacement result = %+v, %v; session=%+v", result, err, session)
	}
	if _, statErr := os.Stat(filepath.Join(input.PersistentStateRoot+"-reconstruction-original", CallerOwnedCorrelationState)); statErr != nil {
		t.Fatalf("original caller-owned state missing: %v", statErr)
	}
}

func TestRunReconstructionPostRestartStateReplacementFailsBeforeScenario(t *testing.T) {
	_, input, _, prepared := prepareRuntimeFixture(t)
	runInitialForReconstruction(t, prepared, false)
	plan, _, _ := prepared.reconstructionOrchestrationPlan()
	session := &scriptedInitialSession{progress: completedInitialProgress(plan, nil)}
	result, err := RunReconstruction(context.Background(), prepared, reconstructionExecutorFunc(func(context.Context, ReconstructionPhaseDirective) (ReconstructionPhaseSession, ReconstructionStartProgress, error) {
		original := input.PersistentStateRoot + "-post-restart-original"
		if renameErr := os.Rename(input.PersistentStateRoot, original); renameErr != nil {
			t.Fatal(renameErr)
		}
		if mkdirErr := os.Mkdir(input.PersistentStateRoot, 0700); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		return session, reconstructionStartFixture(), nil
	}))
	if !errors.Is(err, ErrReconstructionPhase) || result.TerminalObserved || len(result.Scenarios) != 0 || len(result.ProcessReplacements) != 0 ||
		session.nextIndex != 0 || session.finishCalls != 0 || session.closeCalls != 1 {
		t.Fatalf("post-restart replacement = %+v, %v; session=%+v", result, err, session)
	}
}
