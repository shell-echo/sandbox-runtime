package instance_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/driver/fake"
	"github.com/shell-echo/sandbox-runtime/instance"
	"github.com/shell-echo/sandbox-runtime/instance/memory"
)

func TestNewServiceRequiresDependencies(t *testing.T) {
	if _, err := instance.NewService(nil, fake.NewDriver()); err == nil {
		t.Fatal("NewService should require repository")
	}
	if _, err := instance.NewService(memory.NewRepository(), nil); err == nil {
		t.Fatal("NewService should require driver")
	}
}

func TestServiceLifecycle(t *testing.T) {
	now := time.Date(2026, time.July, 12, 12, 0, 0, 0, time.UTC)
	service, err := instance.NewService(
		memory.NewRepository(),
		fake.NewDriver(),
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
		instance.WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()

	created, err := service.Create(ctx, instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID != "instance-test" || created.State != instance.StateStopped || !created.CreatedAt.Equal(now) {
		t.Fatalf("created = %+v", created)
	}

	running, err := service.Start(ctx, created.ID)
	if err != nil || running.State != instance.StateRunning {
		t.Fatalf("Start = %+v, %v", running, err)
	}
	stopped, err := service.Stop(ctx, created.ID)
	if err != nil || stopped.State != instance.StateStopped {
		t.Fatalf("Stop = %+v, %v", stopped, err)
	}
	if err := service.Remove(ctx, created.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := service.Inspect(ctx, created.ID); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Inspect after remove = %v, want ErrNotFound", err)
	}
}

func TestServiceReconcilesStableRuntimeDrift(t *testing.T) {
	runtime := fake.NewDriver()
	service, err := instance.NewService(
		memory.NewRepository(), runtime,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Start(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	listed, err := service.List(context.Background())
	if err != nil || len(listed) != 1 || listed[0].State != instance.StateRunning {
		t.Fatalf("List after external start = %+v, %v", listed, err)
	}
	if err := runtime.Stop(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	failed, err := service.Inspect(context.Background(), created.ID)
	if err != nil || failed.State != instance.StateFailed || failed.Failure == "" {
		t.Fatalf("Inspect after unexpected stop = %+v, %v", failed, err)
	}
	restarted, err := service.Start(context.Background(), created.ID)
	if err != nil || restarted.State != instance.StateRunning || restarted.Failure != "" {
		t.Fatalf("Start failed instance = %+v, %v", restarted, err)
	}
}

func TestServiceRejectsSuccessfulStartThatImmediatelyExits(t *testing.T) {
	runtime := &exitAfterStartDriver{Driver: fake.NewDriver()}
	repository := memory.NewRepository()
	service, err := instance.NewService(
		repository, runtime,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(context.Background(), created.ID); err == nil {
		t.Fatal("expected post-start confirmation error")
	}
	stored, err := repository.Get(context.Background(), created.ID)
	if err != nil || stored.State != instance.StateFailed {
		t.Fatalf("stored immediately-exited runtime = %+v, %v", stored, err)
	}
}

func TestServiceMarksMissingStableRuntimeFailed(t *testing.T) {
	runtime := fake.NewDriver()
	service, err := instance.NewService(
		memory.NewRepository(), runtime,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Remove(context.Background(), created.ID); err != nil {
		t.Fatal(err)
	}
	failed, err := service.Inspect(context.Background(), created.ID)
	if err != nil || failed.State != instance.StateFailed {
		t.Fatalf("Inspect missing runtime = %+v, %v", failed, err)
	}
}

func TestServicePersistsOnlyBackendIndependentRuntimeFailures(t *testing.T) {
	tests := []struct {
		name        string
		observation instance.RuntimeObservation
		wantFailure string
	}{
		{
			name: "out of memory",
			observation: instance.RuntimeObservation{
				State: instance.RuntimeStopped, ExitCode: 137, StopReason: instance.RuntimeStopReasonOOMKilled,
			},
			wantFailure: "runtime stopped unexpectedly: out of memory (exit code 137)",
		},
		{
			name: "runtime error",
			observation: instance.RuntimeObservation{
				State: instance.RuntimeStopped, ExitCode: 125, StopReason: instance.RuntimeStopReasonRuntimeError,
			},
			wantFailure: "runtime stopped unexpectedly: runtime failure (exit code 125)",
		},
		{
			name:        "non-zero exit",
			observation: instance.RuntimeObservation{State: instance.RuntimeStopped, ExitCode: 1},
			wantFailure: "runtime stopped unexpectedly: exit code 1",
		},
		{
			name:        "clean exit",
			observation: instance.RuntimeObservation{State: instance.RuntimeStopped},
			wantFailure: "runtime stopped unexpectedly",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtime := &observationDriver{Driver: fake.NewDriver()}
			service, err := instance.NewService(
				memory.NewRepository(), runtime,
				instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
			)
			if err != nil {
				t.Fatal(err)
			}
			created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Start(context.Background(), created.ID); err != nil {
				t.Fatal(err)
			}
			runtime.observation = &tc.observation

			failed, err := service.Inspect(context.Background(), created.ID)
			if err != nil || failed.State != instance.StateFailed || failed.Failure != tc.wantFailure {
				t.Fatalf("Inspect unexpected stop = %+v, %v; want failure %q", failed, err, tc.wantFailure)
			}
		})
	}
}

func TestServiceRejectsInvalidRuntimeStopReasons(t *testing.T) {
	tests := []instance.RuntimeObservation{
		{State: instance.RuntimeStopped, StopReason: "backend-secret"},
		{State: instance.RuntimeRunning, StopReason: instance.RuntimeStopReasonRuntimeError},
	}
	for _, observation := range tests {
		runtime := &observationDriver{Driver: fake.NewDriver()}
		service, err := instance.NewService(
			memory.NewRepository(), runtime,
			instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
		)
		if err != nil {
			t.Fatal(err)
		}
		created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
		if err != nil {
			t.Fatal(err)
		}
		runtime.observation = &observation
		if _, err := service.Inspect(context.Background(), created.ID); !errors.Is(err, instance.ErrInvalidRuntime) {
			t.Fatalf("Inspect observation %+v = %v, want ErrInvalidRuntime", observation, err)
		}
	}
}

func TestServiceRecoversInterruptedRemoval(t *testing.T) {
	repository := memory.NewRepository()
	runtime := fake.NewDriver()
	service, err := instance.NewService(
		repository, runtime,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatal(err)
	}
	created.State = instance.StateRemoving
	if err := repository.Update(context.Background(), created); err != nil {
		t.Fatal(err)
	}
	restarted, err := instance.NewService(repository, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if count, err := repository.Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("Count after recovery = %d, %v", count, err)
	}
}

func TestServiceAdoptsManagedRuntimeWithoutMetadata(t *testing.T) {
	runtime := fake.NewDriver()
	spec := instance.Spec{Name: "orphaned-shell", Workload: instance.WorkloadShell}
	if err := runtime.Create(context.Background(), "instance-orphan", spec); err != nil {
		t.Fatal(err)
	}
	repository := memory.NewRepository()
	service, err := instance.NewService(repository, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	adopted, err := repository.Get(context.Background(), "instance-orphan")
	if err != nil || adopted.Name != spec.Name || adopted.State != instance.StateStopped {
		t.Fatalf("adopted instance = %+v, %v", adopted, err)
	}
}

func TestServiceRecoverEnforcesAdoptionLimit(t *testing.T) {
	runtime := fake.NewDriver()
	spec := instance.Spec{Name: "orphaned-shell", Workload: instance.WorkloadShell}
	for _, id := range []string{"instance-one", "instance-two"} {
		if err := runtime.Create(context.Background(), id, spec); err != nil {
			t.Fatal(err)
		}
	}
	repository := memory.NewRepository()
	service, err := instance.NewService(repository, runtime, instance.WithMaxInstances(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); !errors.Is(err, instance.ErrLimitExceeded) {
		t.Fatalf("Recover = %v, want ErrLimitExceeded", err)
	}
	if count, err := repository.Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("adopted count = %d, %v", count, err)
	}
}

func TestServiceRecoverRejectsInvalidRuntimeID(t *testing.T) {
	driver := &resourceListDriver{Driver: fake.NewDriver(), resources: []instance.RuntimeResource{{
		ID: "invalid/id", Spec: instance.Spec{Name: "shell", Workload: instance.WorkloadShell},
	}}}
	repository := memory.NewRepository()
	service, err := instance.NewService(repository, driver)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); !errors.Is(err, instance.ErrInvalidSpec) {
		t.Fatalf("Recover = %v, want ErrInvalidSpec", err)
	}
	if count, _ := repository.Count(context.Background()); count != 0 {
		t.Fatalf("invalid resource was adopted, count=%d", count)
	}
}

func TestServiceListToleratesConcurrentRemovalAndInspectFailure(t *testing.T) {
	now := time.Now()
	stored := &instance.Instance{ID: "instance-one", Name: "shell", Workload: instance.WorkloadShell, State: instance.StateStopped, CreatedAt: now, UpdatedAt: now}
	base := memory.NewRepository()
	if err := base.Create(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	repository := &disappearingRepository{Repository: base}
	service, err := instance.NewService(repository, fake.NewDriver())
	if err != nil {
		t.Fatal(err)
	}
	listed, err := service.List(context.Background())
	if err != nil || len(listed) != 0 {
		t.Fatalf("List during concurrent removal = %+v, %v", listed, err)
	}

	base = memory.NewRepository()
	if err := base.Create(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	driver := &inspectErrorDriver{Driver: fake.NewDriver(), err: errors.New("runtime temporarily unavailable")}
	service, err = instance.NewService(base, driver)
	if err != nil {
		t.Fatal(err)
	}
	listed, err = service.List(context.Background())
	if err != nil || len(listed) != 1 || listed[0].State != instance.StateStopped {
		t.Fatalf("List with transient inspect failure = %+v, %v", listed, err)
	}
}

func TestServiceClampsLifecycleTimestampAfterClockRollback(t *testing.T) {
	current := time.Now().UTC()
	repository := memory.NewRepository()
	service, err := instance.NewService(repository, fake.NewDriver(),
		instance.WithIDGenerator(func() (string, error) { return "instance-one", nil }),
		instance.WithClock(func() time.Time { return current }),
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), instance.Spec{Name: "shell", Workload: instance.WorkloadShell})
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(-time.Hour)
	running, err := service.Start(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Start after clock rollback: %v", err)
	}
	if running.UpdatedAt.Before(created.UpdatedAt) || running.UpdatedAt.Before(running.CreatedAt) {
		t.Fatalf("timestamps moved backward: created=%s running=%s", created.UpdatedAt, running.UpdatedAt)
	}
}

func TestServiceRejectsRuntimeMetadataConflict(t *testing.T) {
	runtime := fake.NewDriver()
	if err := runtime.Create(context.Background(), "instance-one", instance.Spec{Name: "runtime-name", Workload: instance.WorkloadShell}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	repository := memory.NewRepository()
	if err := repository.Create(context.Background(), &instance.Instance{
		ID: "instance-one", Name: "repository-name", Workload: instance.WorkloadShell,
		State: instance.StateStopped, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	service, err := instance.NewService(repository, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Recover(context.Background()); err == nil {
		t.Fatal("expected runtime metadata conflict")
	}
}

func TestServiceSerializesLifecycleOperations(t *testing.T) {
	service, err := instance.NewService(
		memory.NewRepository(),
		fake.NewDriver(),
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.Start(context.Background(), "instance-test")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	var successes, invalid int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, instance.ErrInvalidTransition):
			invalid++
		default:
			t.Errorf("unexpected Start error: %v", err)
		}
	}
	if successes != 1 || invalid != 1 {
		t.Fatalf("successes=%d invalid=%d, want 1 each", successes, invalid)
	}
}

func TestServiceEnforcesInstanceLimitConcurrently(t *testing.T) {
	service, err := instance.NewService(
		memory.NewRepository(),
		fake.NewDriver(),
		instance.WithMaxInstances(2),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	const attempts = 20
	var wg sync.WaitGroup
	errs := make(chan error, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	var successes, limited int
	for err := range errs {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, instance.ErrLimitExceeded):
			limited++
		default:
			t.Errorf("unexpected Create error: %v", err)
		}
	}
	if successes != 2 || limited != attempts-2 {
		t.Fatalf("successes=%d limited=%d", successes, limited)
	}
}

func TestServiceLifecycleLockHonorsContext(t *testing.T) {
	driver := &blockingDriver{started: make(chan struct{}), release: make(chan struct{})}
	service, err := instance.NewService(
		memory.NewRepository(),
		driver,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, err := service.Start(context.Background(), "instance-test")
		first <- err
	}()
	<-driver.started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Stop(ctx, "instance-test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Stop while waiting = %v, want context.Canceled", err)
	}
	close(driver.release)
	if err := <-first; err != nil {
		t.Fatalf("first Start: %v", err)
	}
}

func TestServiceLocksInstanceWhileCreatingRuntime(t *testing.T) {
	driver := &blockingCreateDriver{
		Driver:  fake.NewDriver(),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	service, err := instance.NewService(
		memory.NewRepository(),
		driver,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	created := make(chan error, 1)
	go func() {
		_, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
		created <- err
	}()
	<-driver.started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := service.Inspect(ctx, "instance-test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Inspect during Create = %v, want context deadline", err)
	}

	close(driver.release)
	if err := <-created; err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func TestServiceRecordsBackendFailure(t *testing.T) {
	repository := memory.NewRepository()
	boom := errors.New("boom")
	service, err := instance.NewService(
		repository,
		&errorDriver{createErr: boom},
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}); !errors.Is(err, boom) {
		t.Fatalf("Create = %v, want backend error", err)
	}
	stored, err := repository.Get(context.Background(), "instance-test")
	if err != nil {
		t.Fatalf("Get failed instance: %v", err)
	}
	if stored.State != instance.StateFailed {
		t.Fatalf("failed instance state = %s", stored.State)
	}
}

func TestServiceReconcilesTransientTerminalWriteFailures(t *testing.T) {
	repository := newFlakyRepository()
	service, err := instance.NewService(
		repository,
		fake.NewDriver(),
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	repository.failUpdates(instance.StateStopped, 1)
	created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil || created.State != instance.StateStopped {
		t.Fatalf("Create after transient write failure = %+v, %v", created, err)
	}

	repository.failUpdates(instance.StateRunning, 1)
	running, err := service.Start(context.Background(), created.ID)
	if err != nil || running.State != instance.StateRunning {
		t.Fatalf("Start after transient write failure = %+v, %v", running, err)
	}

	repository.failUpdates(instance.StateStopped, 1)
	stopped, err := service.Stop(context.Background(), created.ID)
	if err != nil || stopped.State != instance.StateStopped {
		t.Fatalf("Stop after transient write failure = %+v, %v", stopped, err)
	}
}

func TestServiceLazilyReconcilesInterruptedTransition(t *testing.T) {
	repository := newFlakyRepository()
	repository.failUpdates(instance.StateStopped, 2)
	service, err := instance.NewService(
		repository,
		fake.NewDriver(),
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if _, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}); !errors.Is(err, errInjected) {
		t.Fatalf("Create = %v, want injected persistence error", err)
	}
	stored, err := repository.Get(context.Background(), "instance-test")
	if err != nil || stored.State != instance.StateCreating {
		t.Fatalf("stored interrupted instance = %+v, %v", stored, err)
	}

	reconciled, err := service.Inspect(context.Background(), "instance-test")
	if err != nil || reconciled.State != instance.StateStopped {
		t.Fatalf("Inspect reconciled instance = %+v, %v", reconciled, err)
	}
}

func TestServiceTreatsConfirmedRuntimeStateAsSuccess(t *testing.T) {
	driver := &lostReplyDriver{Driver: fake.NewDriver()}
	repository := memory.NewRepository()
	service, err := instance.NewService(
		repository,
		driver,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	created, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell})
	if err != nil || created.State != instance.StateStopped {
		t.Fatalf("Create after lost reply = %+v, %v", created, err)
	}
	running, err := service.Start(context.Background(), "instance-test")
	if err != nil || running.State != instance.StateRunning {
		t.Fatalf("Start after lost reply = %+v, %v", running, err)
	}
	stopped, err := service.Stop(context.Background(), "instance-test")
	if err != nil || stopped.State != instance.StateStopped {
		t.Fatalf("Stop after lost reply = %+v, %v", stopped, err)
	}
}

func TestServiceDoesNotMutateAfterTransientPreflightInspectFailure(t *testing.T) {
	driver := &transientInspectDriver{Driver: fake.NewDriver()}
	repository := memory.NewRepository()
	service, err := instance.NewService(
		repository,
		driver,
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	driver.inspectFailures = 1

	if _, err := service.Start(context.Background(), "instance-test"); !errors.Is(err, errInspect) {
		t.Fatalf("Start = %v, want transient inspect error", err)
	}
	stored, err := repository.Get(context.Background(), "instance-test")
	if err != nil || stored.State != instance.StateStopped {
		t.Fatalf("stored state after inspect failure = %+v, %v", stored, err)
	}

	running, err := service.Start(context.Background(), "instance-test")
	if err != nil || running.State != instance.StateRunning {
		t.Fatalf("Start after transient failure = %+v, %v", running, err)
	}
}

func TestServiceRetriesInterruptedRemoval(t *testing.T) {
	repository := newFlakyRepository()
	service, err := instance.NewService(
		repository,
		fake.NewDriver(),
		instance.WithIDGenerator(func() (string, error) { return "instance-test", nil }),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := service.Create(context.Background(), instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	repository.failDeletes(1)
	if err := service.Remove(context.Background(), "instance-test"); !errors.Is(err, errInjected) {
		t.Fatalf("first Remove = %v, want injected persistence error", err)
	}
	stored, err := repository.Get(context.Background(), "instance-test")
	if err != nil || stored.State != instance.StateRemoving {
		t.Fatalf("stored removing instance = %+v, %v", stored, err)
	}
	if err := service.Remove(context.Background(), "instance-test"); err != nil {
		t.Fatalf("retry Remove: %v", err)
	}
	if _, err := repository.Get(context.Background(), "instance-test"); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Get after retried removal = %v", err)
	}
}

type blockingDriver struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	running bool
}

type observationDriver struct {
	instance.Driver
	observation *instance.RuntimeObservation
}

type resourceListDriver struct {
	instance.Driver
	resources []instance.RuntimeResource
}

func (d *resourceListDriver) List(context.Context) ([]instance.RuntimeResource, error) {
	return d.resources, nil
}

type inspectErrorDriver struct {
	instance.Driver
	err error
}

type disappearingRepository struct {
	instance.Repository
}

func (r *disappearingRepository) List(ctx context.Context) ([]*instance.Instance, error) {
	instances, err := r.Repository.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, inst := range instances {
		if err := r.Repository.Delete(ctx, inst.ID); err != nil {
			return nil, err
		}
	}
	return instances, nil
}

func (d *inspectErrorDriver) Inspect(context.Context, string) (instance.RuntimeObservation, error) {
	return instance.RuntimeObservation{}, d.err
}

func (d *observationDriver) Inspect(ctx context.Context, id string) (instance.RuntimeObservation, error) {
	if d.observation != nil {
		return *d.observation, nil
	}
	return d.Driver.Inspect(ctx, id)
}

var _ instance.Driver = (*observationDriver)(nil)

func (d *blockingDriver) Create(context.Context, string, instance.Spec) error { return nil }
func (d *blockingDriver) List(context.Context) ([]instance.RuntimeResource, error) {
	return nil, nil
}
func (d *blockingDriver) Inspect(context.Context, string) (instance.RuntimeObservation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := instance.RuntimeStopped
	if d.running {
		state = instance.RuntimeRunning
	}
	return instance.RuntimeObservation{State: state}, nil
}
func (d *blockingDriver) Start(context.Context, string) error {
	close(d.started)
	<-d.release
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()
	return nil
}
func (d *blockingDriver) Stop(context.Context, string) error {
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
	return nil
}
func (d *blockingDriver) Remove(context.Context, string) error { return nil }

var _ instance.Driver = (*blockingDriver)(nil)

type errorDriver struct {
	createErr error
}

func (d *errorDriver) Create(context.Context, string, instance.Spec) error { return d.createErr }
func (d *errorDriver) List(context.Context) ([]instance.RuntimeResource, error) {
	return nil, nil
}
func (d *errorDriver) Inspect(context.Context, string) (instance.RuntimeObservation, error) {
	return instance.RuntimeObservation{}, instance.ErrNotFound
}
func (d *errorDriver) Start(context.Context, string) error  { return nil }
func (d *errorDriver) Stop(context.Context, string) error   { return nil }
func (d *errorDriver) Remove(context.Context, string) error { return nil }

var _ instance.Driver = (*errorDriver)(nil)

var errInjected = errors.New("injected failure")
var errInspect = errors.New("injected inspect failure")

type flakyRepository struct {
	instance.Repository
	mu             sync.Mutex
	updateFailures map[instance.State]int
	deleteFailures int
}

func newFlakyRepository() *flakyRepository {
	return &flakyRepository{
		Repository:     memory.NewRepository(),
		updateFailures: make(map[instance.State]int),
	}
}

func (r *flakyRepository) failUpdates(state instance.State, count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateFailures[state] += count
}

func (r *flakyRepository) failDeletes(count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteFailures += count
}

func (r *flakyRepository) Update(ctx context.Context, inst *instance.Instance) error {
	r.mu.Lock()
	if r.updateFailures[inst.State] > 0 {
		r.updateFailures[inst.State]--
		r.mu.Unlock()
		return errInjected
	}
	r.mu.Unlock()
	return r.Repository.Update(ctx, inst)
}

func (r *flakyRepository) Delete(ctx context.Context, id string) error {
	r.mu.Lock()
	if r.deleteFailures > 0 {
		r.deleteFailures--
		r.mu.Unlock()
		return errInjected
	}
	r.mu.Unlock()
	return r.Repository.Delete(ctx, id)
}

type lostReplyDriver struct {
	instance.Driver
}

type exitAfterStartDriver struct {
	instance.Driver
}

func (d *exitAfterStartDriver) Start(ctx context.Context, id string) error {
	if err := d.Driver.Start(ctx, id); err != nil {
		return err
	}
	return d.Driver.Stop(ctx, id)
}

var _ instance.Driver = (*exitAfterStartDriver)(nil)

func (d *lostReplyDriver) Create(ctx context.Context, id string, spec instance.Spec) error {
	if err := d.Driver.Create(ctx, id, spec); err != nil {
		return err
	}
	return errInjected
}

func (d *lostReplyDriver) Start(ctx context.Context, id string) error {
	if err := d.Driver.Start(ctx, id); err != nil {
		return err
	}
	return errInjected
}

func (d *lostReplyDriver) Stop(ctx context.Context, id string) error {
	if err := d.Driver.Stop(ctx, id); err != nil {
		return err
	}
	return errInjected
}

var _ instance.Repository = (*flakyRepository)(nil)
var _ instance.Driver = (*lostReplyDriver)(nil)

type transientInspectDriver struct {
	instance.Driver
	mu              sync.Mutex
	inspectFailures int
}

func (d *transientInspectDriver) Start(ctx context.Context, id string) error {
	if err := d.Driver.Start(ctx, id); err != nil {
		return err
	}
	return errInjected
}

func (d *transientInspectDriver) Inspect(ctx context.Context, id string) (instance.RuntimeObservation, error) {
	d.mu.Lock()
	if d.inspectFailures > 0 {
		d.inspectFailures--
		d.mu.Unlock()
		return instance.RuntimeObservation{}, errInspect
	}
	d.mu.Unlock()
	return d.Driver.Inspect(ctx, id)
}

var _ instance.Driver = (*transientInspectDriver)(nil)

type blockingCreateDriver struct {
	instance.Driver
	started chan struct{}
	release chan struct{}
}

func (d *blockingCreateDriver) Create(ctx context.Context, id string, spec instance.Spec) error {
	close(d.started)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.release:
		return d.Driver.Create(ctx, id, spec)
	}
}

var _ instance.Driver = (*blockingCreateDriver)(nil)
