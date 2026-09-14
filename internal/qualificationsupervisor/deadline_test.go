package qualificationsupervisor

import (
	"context"
	"errors"
	"testing"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

func TestDeadlineFailurePrecedenceAndClipping(t *testing.T) {
	now := time.Now()
	runContext, cancel := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer cancel()
	caseDeadline := now.Add(30 * time.Second)
	if got := effectiveDeadline(runContext, caseDeadline); !got.Equal(caseDeadline) {
		t.Fatal("case did not clip run deadline", got)
	}
	if err := deadlineFailure(runContext, caseDeadline, caseDeadline.Add(-time.Nanosecond)); err != nil {
		t.Fatal("event before deadline rejected", err)
	}
	if err := deadlineFailure(runContext, caseDeadline, caseDeadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline did not preempt simultaneous event", err)
	}

	canceled, stop := context.WithCancel(runContext)
	stop()
	if err := deadlineFailure(canceled, caseDeadline, now); !errors.Is(err, context.Canceled) {
		t.Fatal("early parent cancellation misclassified", err)
	}
}

func TestCaseDeadlineStartsOnlyAtValidatedBoundaries(t *testing.T) {
	firstBoundary := time.Now()
	deadline := advanceCaseDeadline("invocation_accepted", protocol.PhaseStateAwaitingNextScenario, time.Time{}, firstBoundary)
	if !deadline.Equal(firstBoundary.Add(caseExecutionLimit)) {
		t.Fatal("first case did not start at invocation acceptance")
	}
	startedAt := firstBoundary.Add(time.Minute)
	if got := advanceCaseDeadline("scenario_started", protocol.PhaseStateAwaitingStartedResult, deadline, startedAt); !got.Equal(deadline) {
		t.Fatal("scenario start reset case deadline")
	}
	nextBoundary := firstBoundary.Add(90 * time.Second)
	deadline = advanceCaseDeadline("scenario_result", protocol.PhaseStateAwaitingNextScenario, deadline, nextBoundary)
	if !deadline.Equal(nextBoundary.Add(caseExecutionLimit)) {
		t.Fatal("later case did not start at prior result")
	}
	if got := advanceCaseDeadline("scenario_result", protocol.PhaseStateAwaitingTerminal, deadline, nextBoundary); !got.IsZero() {
		t.Fatal("final case retained a case deadline")
	}
}

func TestClippedContextCannotExtendRunAndPreservesCause(t *testing.T) {
	now := time.Now()
	base, baseCancel := context.WithDeadline(context.Background(), now.Add(time.Minute))
	defer baseCancel()
	operation, operationCancel := context.WithDeadline(context.Background(), now.Add(30*time.Second))
	defer operationCancel()
	clipped, release, err := clippedContext(base, operation)
	if err != nil {
		t.Fatal(err)
	}
	deadline, ok := clipped.Deadline()
	if !ok || !deadline.Equal(now.Add(30*time.Second)) {
		release()
		t.Fatal("operation did not clip shared run", deadline, ok)
	}
	release()

	manual, cancel := context.WithCancel(context.Background())
	clipped, release, err = clippedContext(base, manual)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-clipped.Done()
	if !errors.Is(contextFailure(clipped), context.Canceled) {
		release()
		t.Fatal("manual cancellation cause lost", contextFailure(clipped))
	}
	release()
}
