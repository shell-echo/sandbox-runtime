package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
	lifecyclefile "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/file"
)

func testOptions(t *testing.T) Options {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid = 65532
	}
	if gid == 0 {
		gid = 65532
	}
	return Options{
		Image: "example/shell@sha256:" + strings.Repeat("a", 64), PullPolicy: PullIfNotPresent,
		MemoryBytes: 256 << 20, NanoCPUs: 500_000_000, PidsLimit: 128, TmpfsBytes: 64 << 20,
		OperationTimeoutSeconds: 2, PullTimeoutSeconds: 2, StopTimeoutSeconds: 5,
		User: fmt.Sprintf("%d:%d", uid, gid), Command: []string{"/bin/sh", "-c", "sleep 3600"},
		DataRoot: t.TempDir(), Namespace: "provider-test", ControllerID: "controller-test",
	}
}

func testSandbox(now time.Time) lifecycle.Sandbox {
	return lifecycle.Sandbox{
		ID: "sandbox-one", TenantID: "tenant-one", WorkOrderID: "work-order-one",
		WorkspaceID: "workspace-one", ProviderRevisionID: "provider-revision-one",
		RuntimeProfile: CodingShellRuntimeProfile, SandboxSlotKey: "slots/sandbox-one",
		DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedProvisioning,
		Generation: 1, LeaseExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
}

func testCreateRequest(now time.Time) lifecycle.CreateRequest {
	return lifecycle.CreateRequest{
		OperationID: "operation-one", AttemptID: "attempt-one", FencingToken: 1,
		IdempotencyKey: "idempotency-one", RequestDigest: "sha256:" + strings.Repeat("b", 64),
		Deadline: now.Add(30 * time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-one", TenantID: "tenant-one", WorkOrderID: "work-order-one",
			WorkspaceID: "workspace-one", ProviderRevisionID: "provider-revision-one",
			RuntimeProfile: CodingShellRuntimeProfile, SandboxSlotKey: "slots/sandbox-one",
			LeaseExpiresAt: now.Add(time.Hour),
		},
	}
}

func TestDriverLifecycleUsesStableProviderMounts(t *testing.T) {
	backend := newFakeEngine()
	options := testOptions(t)
	driver, err := newDriver(backend, options)
	if err != nil {
		t.Fatal(err)
	}
	sandbox := testSandbox(time.Now().UTC())
	if err := driver.Create(context.Background(), sandbox); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if backend.createCalls != 1 || backend.startCalls != 1 {
		t.Fatalf("create/start calls = %d/%d", backend.createCalls, backend.startCalls)
	}
	created := backend.lastCreate
	if created.name != containerName(sandbox.ID) || created.workingDirectory != "/workspace" {
		t.Fatalf("container identity = %q, %q", created.name, created.workingDirectory)
	}
	if created.labels[ownerLabel] != providerOwner || created.labels[sandboxLabel] != sandbox.ID ||
		created.labels[runtimeProfileLabel] != CodingShellRuntimeProfile || created.labels[generationLabel] != "1" || created.labels[specDigestLabel] == "" {
		t.Fatalf("ownership labels = %#v", created.labels)
	}
	if created.user != options.User || !created.readonly || created.tmpfs["/tmp"] == "" {
		t.Fatalf("runtime filesystem/user = %#v", created)
	}
	if created.memoryBytes != options.MemoryBytes || created.nanoCPUs != options.NanoCPUs || created.pidsLimit != options.PidsLimit {
		t.Fatalf("resource bounds = %#v", created)
	}
	wantTargets := map[string]bool{"/inputs": true, "/workspace": false, "/outputs": false}
	for _, item := range created.mounts {
		wantReadonly, ok := wantTargets[item.target]
		if !ok || item.readonly != wantReadonly || !filepath.IsAbs(item.source) || !strings.HasPrefix(item.source, driver.dataRoot+string(filepath.Separator)) {
			t.Fatalf("mount = %#v", item)
		}
		delete(wantTargets, item.target)
	}
	if len(wantTargets) != 0 {
		t.Fatalf("missing mounts = %#v", wantTargets)
	}
	paths, err := driver.mountPaths(sandbox.ID)
	if err != nil {
		t.Fatal(err)
	}
	for path, wantMode := range map[string]os.FileMode{paths.inputs: 0o555, paths.workspace: 0o777, paths.outputs: 0o777} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat mount %q: %v", path, err)
		}
		if info.Mode().Perm() != wantMode {
			t.Fatalf("mount mode %q = %v", path, info.Mode().Perm())
		}
	}
	observation, err := driver.Inspect(context.Background(), sandbox.ID)
	if err != nil || observation != (coordinator.RuntimeObservation{State: coordinator.RuntimeReady}) {
		t.Fatalf("Inspect = %#v, %v", observation, err)
	}

	readySandbox := sandbox
	readySandbox.ObservedState = lifecycle.ObservedReady
	readySandbox.ObservedGeneration = readySandbox.Generation
	readySandbox.UpdatedAt = readySandbox.UpdatedAt.Add(time.Second)
	if err := driver.Create(context.Background(), readySandbox); err != nil {
		t.Fatalf("idempotent Create: %v", err)
	}
	if backend.ensureCalls != 1 || backend.createCalls != 1 || backend.startCalls != 1 {
		t.Fatalf("idempotent ensure/create/start calls = %d/%d/%d", backend.ensureCalls, backend.createCalls, backend.startCalls)
	}
	if err := driver.Remove(context.Background(), sandbox.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(paths.root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mount root remains: %v", err)
	}
	if err := driver.Remove(context.Background(), sandbox.ID); err != nil {
		t.Fatalf("idempotent Remove: %v", err)
	}
	if backend.removeCalls != 1 {
		t.Fatalf("remove calls = %d", backend.removeCalls)
	}
}

func TestDriverLostStartResponseReconcilesAfterRestart(t *testing.T) {
	now := time.Now().UTC()
	options := testOptions(t)
	backend := newFakeEngine()
	backend.startErrAfterEffect = context.DeadlineExceeded
	driver, err := newDriver(backend, options)
	if err != nil {
		t.Fatal(err)
	}
	repositoryPath := filepath.Join(t.TempDir(), "provider-lifecycle.json")
	repo, err := lifecyclefile.NewRepository(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	clock := coordinator.ClockFunc(func() time.Time { return now })
	service, err := coordinator.New(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := testCreateRequest(now)
	if _, err := service.AcceptCreate(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	result, err := service.ReconcileOperation(context.Background(), request.OperationID)
	if !errors.Is(err, coordinator.ErrUnknownRuntime) || result.Operation.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("lost response = %#v, %v", result, err)
	}
	if backend.createCalls != 1 || backend.startCalls != 1 {
		t.Fatalf("dispatch calls = %d/%d", backend.createCalls, backend.startCalls)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}

	backend.startErrAfterEffect = nil
	reopened, err := lifecyclefile.NewRepository(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restartedDriver, err := newDriver(backend, options)
	if err != nil {
		t.Fatal(err)
	}
	app, err := application.New(reopened, restartedDriver, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	recovered, err := app.GetSandbox(context.Background(), request.Spec.SandboxID)
	if err != nil || recovered.ObservedState != lifecycle.ObservedReady {
		t.Fatalf("recovered sandbox = %#v, %v", recovered, err)
	}
	operation, err := app.GetOperation(context.Background(), request.OperationID)
	if err != nil || operation.State != lifecycle.OperationOutcomeUnknown {
		t.Fatalf("retained operation evidence = %#v, %v", operation, err)
	}
	if backend.createCalls != 1 || backend.startCalls != 1 {
		t.Fatal("restart recovery repeated runtime mutation")
	}
}

func TestDriverNeverMutatesForeignRuntime(t *testing.T) {
	backend := newFakeEngine()
	driver, err := newDriver(backend, testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	sandbox := testSandbox(time.Now().UTC())
	backend.containers[containerName(sandbox.ID)] = containerInfo{
		id: "backend-secret", status: "running", running: true,
		labels: map[string]string{managedLabel: "true", ownerLabel: providerOwner, sandboxLabel: sandbox.ID,
			namespaceLabel: "foreign", controllerLabel: "foreign"},
	}
	if err := driver.Create(context.Background(), sandbox); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("Create foreign = %v", err)
	}
	if err := driver.Remove(context.Background(), sandbox.ID); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("Remove foreign = %v", err)
	}
	if backend.startCalls != 0 || backend.removeCalls != 0 {
		t.Fatal("foreign runtime was mutated")
	}
}

func TestDriverCancellationAndUnknownOutcome(t *testing.T) {
	backend := newFakeEngine()
	driver, err := newDriver(backend, testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	sandbox := testSandbox(time.Now().UTC())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := driver.Create(cancelled, sandbox); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Create = %v", err)
	}
	if backend.ensureCalls != 0 || backend.createCalls != 0 {
		t.Fatal("cancelled Create dispatched external work")
	}

	backend.createErrAfterEffect = errors.New("connection lost: backend-id=/private/daemon.sock")
	if err := driver.Create(context.Background(), sandbox); !errors.Is(err, coordinator.ErrUnknownRuntime) || strings.Contains(err.Error(), "backend-id") {
		t.Fatalf("unknown Create = %v", err)
	}
	observation, err := driver.Inspect(context.Background(), sandbox.ID)
	if err != nil || observation.State != coordinator.RuntimeProvisioning {
		t.Fatalf("Inspect uncertain Create = %#v, %v", observation, err)
	}
}

func TestDriverOptionsFailClosed(t *testing.T) {
	valid := testOptions(t)
	tests := map[string]func(*Options){
		"unpinned image": func(o *Options) { o.Image = "alpine:3.23" },
		"root user":      func(o *Options) { o.User = "0:0" },
		"named user":     func(o *Options) { o.User = "sandbox" },
		"tmpfs":          func(o *Options) { o.TmpfsBytes = 0 },
		"memory":         func(o *Options) { o.MemoryBytes = 0 },
		"cpu":            func(o *Options) { o.NanoCPUs = 0 },
		"pids":           func(o *Options) { o.PidsLimit = 0 },
		"data root":      func(o *Options) { o.DataRoot = "" },
		"namespace":      func(o *Options) { o.Namespace = "bad namespace" },
		"controller":     func(o *Options) { o.ControllerID = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if _, err := newDriver(newFakeEngine(), options); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("newDriver = %v", err)
			}
		})
	}
}

type fakeEngine struct {
	containers           map[string]containerInfo
	lastCreate           createRequest
	ensureCalls          int
	createCalls          int
	startCalls           int
	removeCalls          int
	createErrAfterEffect error
	startErrAfterEffect  error
}

func newFakeEngine() *fakeEngine { return &fakeEngine{containers: make(map[string]containerInfo)} }

func (e *fakeEngine) ping(context.Context) error { return nil }

func (e *fakeEngine) ensureImage(ctx context.Context, _ string, _ PullPolicy) error {
	e.ensureCalls++
	return ctx.Err()
}

func (e *fakeEngine) create(_ context.Context, request createRequest) (string, error) {
	e.createCalls++
	if _, exists := e.containers[request.name]; exists {
		return "", cerrdefs.ErrAlreadyExists
	}
	e.lastCreate = request
	id := "docker-" + request.name
	e.containers[request.name] = containerInfo{id: id, labels: request.labels, status: "created"}
	return id, e.createErrAfterEffect
}

func (e *fakeEngine) inspect(_ context.Context, name string) (containerInfo, error) {
	info, exists := e.containers[name]
	if !exists {
		return containerInfo{}, cerrdefs.ErrNotFound
	}
	return info, nil
}

func (e *fakeEngine) start(_ context.Context, id string) error {
	e.startCalls++
	name, info, err := e.byID(id)
	if err != nil {
		return err
	}
	info.status, info.running = "running", true
	e.containers[name] = info
	return e.startErrAfterEffect
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
	return "", containerInfo{}, cerrdefs.ErrNotFound
}

var _ engine = (*fakeEngine)(nil)
