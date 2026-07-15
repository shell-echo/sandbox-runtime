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

func TestServiceKeepsTransitionAfterTransientInspectFailure(t *testing.T) {
	driver := &transientInspectDriver{Driver: fake.NewDriver(), inspectFailures: 1}
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

	if _, err := service.Start(context.Background(), "instance-test"); !errors.Is(err, errInspect) {
		t.Fatalf("Start = %v, want transient inspect error", err)
	}
	stored, err := repository.Get(context.Background(), "instance-test")
	if err != nil || stored.State != instance.StateStarting {
		t.Fatalf("stored state after inspect failure = %+v, %v", stored, err)
	}

	reconciled, err := service.Inspect(context.Background(), "instance-test")
	if err != nil || reconciled.State != instance.StateRunning {
		t.Fatalf("Inspect after transient failure = %+v, %v", reconciled, err)
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
}

func (d *blockingDriver) Create(context.Context, string, instance.Spec) error { return nil }
func (d *blockingDriver) Inspect(context.Context, string) (instance.RuntimeState, error) {
	return instance.RuntimeStopped, nil
}
func (d *blockingDriver) Start(context.Context, string) error {
	close(d.started)
	<-d.release
	return nil
}
func (d *blockingDriver) Stop(context.Context, string) error   { return nil }
func (d *blockingDriver) Remove(context.Context, string) error { return nil }

var _ instance.Driver = (*blockingDriver)(nil)

type errorDriver struct {
	createErr error
}

func (d *errorDriver) Create(context.Context, string, instance.Spec) error { return d.createErr }
func (d *errorDriver) Inspect(context.Context, string) (instance.RuntimeState, error) {
	return "", instance.ErrNotFound
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

func (d *transientInspectDriver) Inspect(ctx context.Context, id string) (instance.RuntimeState, error) {
	d.mu.Lock()
	if d.inspectFailures > 0 {
		d.inspectFailures--
		d.mu.Unlock()
		return "", errInspect
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
