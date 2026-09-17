//go:build darwin || linux

package qualificationsupervisor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
)

func deliveredCompletionProbe(t *testing.T, mode string) (*FrozenPreflight, *StartedProcess) {
	t.Helper()
	frozen, process, codec := startedStartupProbe(t, mode)
	startupContext, startupCancel := context.WithTimeout(context.Background(), realProcessTestLimit)
	defer startupCancel()
	if _, err := process.ObserveStartup(startupContext, codec); err != nil {
		t.Fatal(err)
	}
	document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, 4096))
	if _, err := process.DeliverInvocation(context.Background(), document, []CredentialPayload{{
		ChannelID: "controller-a-provider", Data: []byte("provider-secret"),
	}}); err != nil {
		t.Fatal(err)
	}
	return frozen, process
}

func TestObserveCompletionConsumesTerminalEOFAndCleanExit(t *testing.T) {
	frozen, process := deliveredCompletionProbe(t, "completion")
	_, before, started := frozen.core.budget.snapshot()
	if !started {
		t.Fatal("run budget did not start before preflight")
	}
	ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
	defer cancel()
	if err := process.ObserveCompletion(ctx); err != nil {
		t.Fatal(err)
	}
	_, after, _ := frozen.core.budget.snapshot()
	if !after.Equal(before) || !process.core.cleanlyReaped() ||
		process.core.admission.Machine().State() != protocol.PhaseStateComplete {
		t.Fatal("completion reset budget or missed protocol exit")
	}
	if process.Close() != nil {
		t.Fatal("close after natural completion failed")
	}
	for _, file := range process.core.parent {
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("completed process retained endpoint", err)
		}
	}
	if _, err := frozen.AdmitPhase(context.Background(), "reconstruction"); err != nil {
		t.Fatal("real completed initial phase did not gate reconstruction", err)
	}
	_, reconstructionDeadline, _ := frozen.core.budget.snapshot()
	if !reconstructionDeadline.Equal(before) {
		t.Fatal("reconstruction reset shared deadline")
	}
}

func TestObserveCompletionStreamsSanitizedScenarioProgress(t *testing.T) {
	_, process := deliveredCompletionProbe(t, "completion")
	ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
	defer cancel()
	var observed []ScenarioProgress
	if err := process.ObserveCompletionWithProgress(ctx, func(progress ScenarioProgress) error {
		observed = append(observed, progress)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 15 || observed[0].CaseID != "initial.locked-capability-discovery" ||
		observed[14].CaseID != "initial.provider-mtls-caller-binding-rejection" {
		t.Fatalf("progress = %#v", observed)
	}
	for _, progress := range observed {
		if progress.Disposition != "not_executed" || progress.ReasonCode == nil ||
			*progress.ReasonCode != "prerequisite_not_satisfied" || len(progress.Interactions) != 0 {
			t.Fatalf("unexpected progress = %#v", progress)
		}
	}
}

func TestObserveCompletionProgressCallbackFailsClosed(t *testing.T) {
	frozen, process := deliveredCompletionProbe(t, "completion")
	ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
	defer cancel()
	err := process.ObserveCompletionWithProgress(ctx, func(ScenarioProgress) error { return errors.New("private callback diagnostic") })
	if !errors.Is(err, ErrSupervision) || strings.Contains(err.Error(), "private callback diagnostic") ||
		process.core.cleanlyReaped() || frozen.core.failure == nil {
		t.Fatalf("callback failure was not sanitized: %v", err)
	}
}

func TestObserveCompletionFailsClosedOnExitOutputAndStderr(t *testing.T) {
	assertFailedClosed := func(t *testing.T, frozen *FrozenPreflight, process *StartedProcess, boundary, err error) {
		t.Helper()
		if err == nil || !errors.Is(err, boundary) || strings.Contains(err.Error(), "provider-secret") ||
			process.core.cleanlyReaped() || frozen.core.failure == nil {
			t.Fatal("invalid completion accepted or leaked diagnostics", err)
		}
		select {
		case <-process.core.done:
		case <-time.After(7 * time.Second):
			t.Fatal("failed completion did not reclaim process")
		}
	}

	for _, mode := range []string{"nonclean-completion", "extra-after-terminal"} {
		t.Run(mode, func(t *testing.T) {
			frozen, process := deliveredCompletionProbe(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
			defer cancel()
			assertFailedClosed(t, frozen, process, ErrSupervision, process.ObserveCompletion(ctx))
		})
	}

	t.Run("stderr-overflow", func(t *testing.T) {
		frozen, process, codec := startedStartupProbe(t, "stderr-overflow")
		startupContext, startupCancel := context.WithTimeout(context.Background(), realProcessTestLimit)
		defer startupCancel()
		if _, err := process.ObserveStartup(startupContext, codec); err != nil {
			t.Fatal(err)
		}
		document := marshalDeliveryInvocation(t, deliveryInvocationValue(process.core.admission, 4096))
		_, err := process.DeliverInvocation(context.Background(), document, []CredentialPayload{{
			ChannelID: "controller-a-provider", Data: []byte("provider-secret"),
		}})
		boundary := ErrDelivery
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), realProcessTestLimit)
			defer cancel()
			err = process.ObserveCompletion(ctx)
			boundary = ErrSupervision
		}
		// The stderr drain is concurrent with delivery. Exceeding its budget may
		// therefore close the process either just before delivery commits or
		// while completion is observed; both boundaries must fail closed.
		if !errors.Is(err, ErrProcessIO) {
			t.Fatal("stderr overflow did not retain its bounded-I/O cause", err)
		}
		assertFailedClosed(t, frozen, process, boundary, err)
	})
}

func TestObserveCompletionClipsWaitToCallerDeadline(t *testing.T) {
	_, process := deliveredCompletionProbe(t, "case-stall")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := process.ObserveCompletion(ctx)
	if !errors.Is(err, ErrSupervision) || !errors.Is(err, context.DeadlineExceeded) || process.core.cleanlyReaped() {
		t.Fatal("case wait did not honor clipped deadline", err)
	}
	select {
	case <-process.core.done:
	case <-time.After(7 * time.Second):
		t.Fatal("deadline failure did not reclaim process")
	}
}
