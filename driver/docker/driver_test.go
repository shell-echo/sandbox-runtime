package docker

import (
	"context"
	"errors"
	"fmt"
	"testing"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/shell-echo/sandbox-runtime/instance"
)

func testOptions() Options {
	return Options{
		Image:                   "example/shell:v1",
		PullPolicy:              PullIfNotPresent,
		MemoryBytes:             256 << 20,
		NanoCPUs:                500_000_000,
		PidsLimit:               128,
		OperationTimeoutSeconds: 2,
		PullTimeoutSeconds:      2,
		StopTimeoutSeconds:      5,
		User:                    "65532:65532",
		Command:                 []string{"/bin/sh", "-c", "sleep 3600"},
		Namespace:               "test",
		ControllerID:            "controller-test",
	}
}

func TestDriverLifecycle(t *testing.T) {
	engine := newFakeEngine()
	driver, err := newDriver(engine, testOptions())
	if err != nil {
		t.Fatalf("newDriver: %v", err)
	}
	ctx := context.Background()
	spec := instance.Spec{Name: "terminal", Workload: instance.WorkloadShell}

	if err := driver.Create(ctx, "instance-one", spec); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if engine.ensuredImage != testOptions().Image || engine.ensurePolicy != PullIfNotPresent {
		t.Fatalf("ensure image = %q, %q", engine.ensuredImage, engine.ensurePolicy)
	}
	created := engine.lastCreate
	if created.name != containerName("instance-one") || created.image != testOptions().Image {
		t.Fatalf("create request = %+v", created)
	}
	if created.labels[instanceLabel] != "instance-one" || created.labels[workloadLabel] != "shell" {
		t.Fatalf("labels = %+v", created.labels)
	}
	if created.labels[nameLabel] != spec.Name || created.labels[namespaceLabel] != "test" || created.labels[controllerLabel] != "controller-test" {
		t.Fatalf("ownership labels = %+v", created.labels)
	}
	if created.memoryBytes != testOptions().MemoryBytes || created.pidsLimit != testOptions().PidsLimit {
		t.Fatalf("resource limits = %+v", created)
	}
	if created.user != testOptions().User || !created.readonly || created.tmpfs["/tmp"] == "" {
		t.Fatalf("sandbox filesystem/user = %+v", created)
	}
	engine.containers["foreign-controller"] = containerInfo{labels: map[string]string{
		managedLabel: "true", namespaceLabel: "test", controllerLabel: "controller-other",
	}}
	resources, err := driver.List(ctx)
	if err != nil || len(resources) != 1 || resources[0].ID != "instance-one" || resources[0].Spec != spec {
		t.Fatalf("List = %+v, %v", resources, err)
	}

	if state, err := driver.Inspect(ctx, "instance-one"); err != nil || state.State != instance.RuntimeStopped {
		t.Fatalf("Inspect after Create = %+v, %v", state, err)
	}
	if err := driver.Start(ctx, "instance-one"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state, err := driver.Inspect(ctx, "instance-one"); err != nil || state.State != instance.RuntimeRunning {
		t.Fatalf("Inspect after Start = %+v, %v", state, err)
	}
	if err := driver.Stop(ctx, "instance-one"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := driver.Remove(ctx, "instance-one"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := driver.Remove(ctx, "instance-one"); err != nil {
		t.Fatalf("idempotent Remove: %v", err)
	}
}

func TestDriverCreatePropagatesImagePreparationError(t *testing.T) {
	engine := newFakeEngine()
	engine.ensureErr = errors.New("registry unavailable")
	driver, err := newDriver(engine, testOptions())
	if err != nil {
		t.Fatalf("newDriver: %v", err)
	}
	if err := driver.Create(context.Background(), "instance-one", instance.Spec{Workload: instance.WorkloadShell}); !errors.Is(err, engine.ensureErr) {
		t.Fatalf("Create = %v, want image error", err)
	}
	if engine.lastCreate.name != "" {
		t.Fatal("container creation attempted after image preparation failed")
	}
}

func TestDriverNeverMutatesForeignContainer(t *testing.T) {
	engine := newFakeEngine()
	name := containerName("instance-one")
	engine.containers[name] = containerInfo{
		id: "foreign-id",
		labels: map[string]string{
			managedLabel: "true", instanceLabel: "instance-one", namespaceLabel: "test", controllerLabel: "controller-other",
		},
		status: "running", running: true,
	}
	driver, err := newDriver(engine, testOptions())
	if err != nil {
		t.Fatalf("newDriver: %v", err)
	}

	if _, err := driver.Inspect(context.Background(), "instance-one"); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Inspect foreign = %v, want ErrNotFound", err)
	}
	if err := driver.Start(context.Background(), "instance-one"); !errors.Is(err, instance.ErrNotFound) {
		t.Fatalf("Start foreign = %v, want ErrNotFound", err)
	}
	if err := driver.Remove(context.Background(), "instance-one"); err != nil {
		t.Fatalf("Remove foreign metadata: %v", err)
	}
	if _, exists := engine.containers[name]; !exists || engine.removeCalls != 0 {
		t.Fatal("foreign container was removed")
	}
}

func TestDriverRejectsUnsupportedRuntimeStates(t *testing.T) {
	for _, state := range []containerInfo{
		{status: "paused", running: true, paused: true},
		{status: "restarting", running: true, restarting: true},
		{status: "dead", dead: true},
		{status: "removing"},
	} {
		t.Run(state.status, func(t *testing.T) {
			engine := newFakeEngine()
			state.id = "docker-id"
			state.labels = map[string]string{
				managedLabel: "true", instanceLabel: "instance-one", namespaceLabel: "test", controllerLabel: "controller-test",
			}
			engine.containers[containerName("instance-one")] = state
			driver, err := newDriver(engine, testOptions())
			if err != nil {
				t.Fatalf("newDriver: %v", err)
			}
			if _, err := driver.Inspect(context.Background(), "instance-one"); !errors.Is(err, instance.ErrInvalidRuntime) {
				t.Fatalf("Inspect = %v, want ErrInvalidRuntime", err)
			}
		})
	}
}

func TestDriverClassifiesRuntimeExitWithoutLeakingDiagnostics(t *testing.T) {
	tests := []struct {
		name       string
		info       containerInfo
		wantReason instance.RuntimeStopReason
	}{
		{
			name:       "oom takes precedence",
			info:       containerInfo{status: "exited", exitCode: 137, oomKilled: true, error: "failed to create shim task: /host/private/path"},
			wantReason: instance.RuntimeStopReasonOOMKilled,
		},
		{
			name:       "runtime error",
			info:       containerInfo{status: "exited", exitCode: 125, error: "runc failed at /host/private/path"},
			wantReason: instance.RuntimeStopReasonRuntimeError,
		},
		{
			name:       "ordinary exit",
			info:       containerInfo{status: "exited", exitCode: 1},
			wantReason: instance.RuntimeStopReasonNone,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := newFakeEngine()
			tc.info.id = "docker-id"
			tc.info.labels = map[string]string{
				managedLabel: "true", instanceLabel: "instance-one", namespaceLabel: "test", controllerLabel: "controller-test",
			}
			engine.containers[containerName("instance-one")] = tc.info
			driver, err := newDriver(engine, testOptions())
			if err != nil {
				t.Fatal(err)
			}
			observation, err := driver.Inspect(context.Background(), "instance-one")
			if err != nil || observation.State != instance.RuntimeStopped || observation.ExitCode != tc.info.exitCode || observation.StopReason != tc.wantReason {
				t.Fatalf("Inspect exited = %+v, %v", observation, err)
			}
		})
	}
}

func TestDriverOptionsValidation(t *testing.T) {
	valid := testOptions()
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"image", func(o *Options) { o.Image = "" }},
		{"pull policy", func(o *Options) { o.PullPolicy = "sometimes" }},
		{"memory", func(o *Options) { o.MemoryBytes = 0 }},
		{"cpu", func(o *Options) { o.NanoCPUs = 0 }},
		{"pids", func(o *Options) { o.PidsLimit = 0 }},
		{"operation timeout", func(o *Options) { o.OperationTimeoutSeconds = 0 }},
		{"pull timeout", func(o *Options) { o.PullTimeoutSeconds = 0 }},
		{"timeout", func(o *Options) { o.StopTimeoutSeconds = -1 }},
		{"user", func(o *Options) { o.User = "" }},
		{"command", func(o *Options) { o.Command = nil }},
		{"namespace", func(o *Options) { o.Namespace = "invalid namespace" }},
		{"controller ID", func(o *Options) { o.ControllerID = "invalid controller" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			options := valid
			tc.mutate(&options)
			if _, err := newDriver(newFakeEngine(), options); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if _, err := newDriver(nil, valid); err == nil {
		t.Fatal("expected nil engine error")
	}
}

type fakeEngine struct {
	containers        map[string]containerInfo
	lastCreate        createRequest
	removeCalls       int
	ensuredImage      string
	ensurePolicy      PullPolicy
	ensureErr         error
	ensureHasDeadline bool
	listHasDeadline   bool
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{containers: make(map[string]containerInfo)}
}

func (e *fakeEngine) ping(context.Context) error { return nil }
func (e *fakeEngine) ensureImage(ctx context.Context, image string, policy PullPolicy) error {
	e.ensuredImage = image
	e.ensurePolicy = policy
	_, e.ensureHasDeadline = ctx.Deadline()
	return e.ensureErr
}

func (e *fakeEngine) create(_ context.Context, request createRequest) (string, error) {
	if _, exists := e.containers[request.name]; exists {
		return "", errors.New("container already exists")
	}
	e.lastCreate = request
	id := "docker-" + request.name
	e.containers[request.name] = containerInfo{id: id, labels: request.labels, status: "created"}
	return id, nil
}

func (e *fakeEngine) inspect(_ context.Context, name string) (containerInfo, error) {
	info, exists := e.containers[name]
	if !exists {
		return containerInfo{}, cerrdefs.ErrNotFound
	}
	return info, nil
}

func (e *fakeEngine) listManaged(ctx context.Context, namespace, controllerID string) ([]managedContainer, error) {
	_, e.listHasDeadline = ctx.Deadline()
	containers := make([]managedContainer, 0, len(e.containers))
	for _, info := range e.containers {
		if info.labels[managedLabel] == "true" && info.labels[namespaceLabel] == namespace && info.labels[controllerLabel] == controllerID {
			containers = append(containers, managedContainer{labels: info.labels})
		}
	}
	return containers, nil
}

func (e *fakeEngine) start(_ context.Context, id string) error {
	name, info, err := e.byID(id)
	if err != nil {
		return err
	}
	info.status, info.running = "running", true
	e.containers[name] = info
	return nil
}

func (e *fakeEngine) stop(_ context.Context, id string, _ int) error {
	name, info, err := e.byID(id)
	if err != nil {
		return err
	}
	info.status, info.running = "exited", false
	e.containers[name] = info
	return nil
}

func (e *fakeEngine) remove(_ context.Context, id string) error {
	name, _, err := e.byID(id)
	if err != nil {
		return err
	}
	e.removeCalls++
	delete(e.containers, name)
	return nil
}

func (e *fakeEngine) close() error { return nil }

func (e *fakeEngine) byID(id string) (string, containerInfo, error) {
	for name, info := range e.containers {
		if info.id == id {
			return name, info, nil
		}
	}
	return "", containerInfo{}, fmt.Errorf("%w: %s", cerrdefs.ErrNotFound, id)
}

var _ engine = (*fakeEngine)(nil)

func TestDriverAppliesOperationDeadlines(t *testing.T) {
	engine := newFakeEngine()
	driver, err := newDriver(engine, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Create(context.Background(), "instance-one", instance.Spec{Name: "shell", Workload: instance.WorkloadShell}); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !engine.ensureHasDeadline || !engine.listHasDeadline {
		t.Fatalf("deadline propagation: pull=%v operation=%v", engine.ensureHasDeadline, engine.listHasDeadline)
	}
}
