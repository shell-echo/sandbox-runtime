// Package docker implements instance.Driver using the Docker Engine API.
package docker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"

	"github.com/shell-echo/sandbox-runtime/instance"
)

const (
	managedLabel    = "io.github.shell-echo.sandbox-runtime.managed"
	instanceLabel   = "io.github.shell-echo.sandbox-runtime.instance-id"
	workloadLabel   = "io.github.shell-echo.sandbox-runtime.workload"
	nameLabel       = "io.github.shell-echo.sandbox-runtime.name"
	namespaceLabel  = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel = "io.github.shell-echo.sandbox-runtime.controller-id"
	containerPrefix = "sandbox-runtime-"
	connectTimeout  = 10 * time.Second
)

// PullPolicy controls when the configured runtime image is pulled.
type PullPolicy string

const (
	PullNever        PullPolicy = "never"
	PullIfNotPresent PullPolicy = "if_not_present"
	PullAlways       PullPolicy = "always"
)

// Options configures Docker-backed runtime resources.
type Options struct {
	Host                    string
	Image                   string
	PullPolicy              PullPolicy
	MemoryBytes             int64
	NanoCPUs                int64
	PidsLimit               int64
	OperationTimeoutSeconds int
	PullTimeoutSeconds      int
	StopTimeoutSeconds      int
	User                    string
	Command                 []string
	Namespace               string
	ControllerID            string
}

func (o Options) validate() error {
	if o.Image == "" {
		return errors.New("docker image is required")
	}
	switch o.PullPolicy {
	case PullNever, PullIfNotPresent, PullAlways:
	default:
		return fmt.Errorf("invalid docker pull policy %q", o.PullPolicy)
	}
	if o.MemoryBytes <= 0 {
		return errors.New("docker memory limit must be greater than zero")
	}
	if o.NanoCPUs <= 0 {
		return errors.New("docker CPU limit must be greater than zero")
	}
	if o.PidsLimit <= 0 {
		return errors.New("docker PID limit must be greater than zero")
	}
	if o.OperationTimeoutSeconds <= 0 {
		return errors.New("docker operation timeout must be greater than zero")
	}
	if o.PullTimeoutSeconds <= 0 {
		return errors.New("docker pull timeout must be greater than zero")
	}
	if o.StopTimeoutSeconds < 0 {
		return errors.New("docker stop timeout must not be negative")
	}
	if o.User == "" {
		return errors.New("docker user is required")
	}
	if len(o.Command) == 0 {
		return errors.New("docker command is required")
	}
	if !validOwnershipValue(o.Namespace) {
		return errors.New("docker namespace must contain 1-63 letters, digits, dots, underscores, or hyphens")
	}
	if !validOwnershipValue(o.ControllerID) {
		return errors.New("docker controller ID must contain 1-63 letters, digits, dots, underscores, or hyphens")
	}
	return nil
}

// Driver manages Docker containers without owning instance metadata or
// lifecycle policy. It verifies ownership labels before every mutation.
type Driver struct {
	engine  engine
	options Options
}

// New connects to Docker Engine, negotiates a compatible API version, and
// fails fast when the selected daemon is unavailable or is not a Linux engine.
func New(ctx context.Context, options Options) (*Driver, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	engine, err := newMobyEngine(options.Host)
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	err = engine.ping(pingCtx)
	cancel()
	if err != nil {
		_ = engine.close()
		return nil, fmt.Errorf("connect to docker engine: %w", err)
	}
	return &Driver{engine: engine, options: options}, nil
}

func newDriver(engine engine, options Options) (*Driver, error) {
	if engine == nil {
		return nil, errors.New("docker engine is required")
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &Driver{engine: engine, options: options}, nil
}

func (d *Driver) Create(ctx context.Context, id string, spec instance.Spec) error {
	if err := instance.ValidateID(id); err != nil {
		return err
	}
	pullCtx, pullCancel := context.WithTimeout(ctx, time.Duration(d.options.PullTimeoutSeconds)*time.Second)
	err := d.engine.ensureImage(pullCtx, d.options.Image, d.options.PullPolicy)
	pullCancel()
	if err != nil {
		return fmt.Errorf("prepare docker image %q: %w", d.options.Image, err)
	}
	init := true
	request := createRequest{
		name:        containerName(id),
		image:       d.options.Image,
		command:     append([]string(nil), d.options.Command...),
		memoryBytes: d.options.MemoryBytes,
		nanoCPUs:    d.options.NanoCPUs,
		pidsLimit:   d.options.PidsLimit,
		stopTimeout: d.options.StopTimeoutSeconds,
		init:        &init,
		user:        d.options.User,
		readonly:    true,
		tmpfs:       map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"},
		labels: map[string]string{
			managedLabel:    "true",
			instanceLabel:   id,
			workloadLabel:   string(spec.Workload),
			nameLabel:       spec.Name,
			namespaceLabel:  d.options.Namespace,
			controllerLabel: d.options.ControllerID,
		},
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	if _, err := d.engine.create(operationCtx, request); err != nil {
		return fmt.Errorf("create docker container: %w", err)
	}
	return nil
}

func (d *Driver) List(ctx context.Context) ([]instance.RuntimeResource, error) {
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	containers, err := d.engine.listManaged(operationCtx, d.options.Namespace, d.options.ControllerID)
	if err != nil {
		return nil, fmt.Errorf("list managed docker containers: %w", err)
	}
	resources := make([]instance.RuntimeResource, 0, len(containers))
	seen := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		id := container.labels[instanceLabel]
		spec := instance.Spec{
			Name: container.labels[nameLabel], Workload: instance.WorkloadType(container.labels[workloadLabel]),
		}
		if err := instance.ValidateID(id); err != nil {
			return nil, fmt.Errorf("managed docker container has invalid instance ID: %w", err)
		}
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("duplicate managed docker instance ID %q", id)
		}
		if err := spec.Validate(); err != nil {
			return nil, fmt.Errorf("managed docker container %q has invalid metadata: %w", id, err)
		}
		seen[id] = struct{}{}
		resources = append(resources, instance.RuntimeResource{ID: id, Spec: spec, CreatedAt: container.createdAt})
	}
	slices.SortFunc(resources, func(a, b instance.RuntimeResource) int { return strings.Compare(a.ID, b.ID) })
	return resources, nil
}

func (d *Driver) Inspect(ctx context.Context, id string) (instance.RuntimeObservation, error) {
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, err := d.inspectOwned(operationCtx, id)
	if err != nil {
		return instance.RuntimeObservation{}, err
	}
	if info.dead || info.paused || info.restarting {
		return instance.RuntimeObservation{}, fmt.Errorf("%w: docker container state %q", instance.ErrInvalidRuntime, info.status)
	}
	if info.running && info.status == "running" {
		return instance.RuntimeObservation{State: instance.RuntimeRunning}, nil
	}
	if !info.running && (info.status == "created" || info.status == "exited") {
		stopReason := instance.RuntimeStopReasonNone
		switch {
		case info.oomKilled:
			stopReason = instance.RuntimeStopReasonOOMKilled
		case info.error != "":
			stopReason = instance.RuntimeStopReasonRuntimeError
		}
		return instance.RuntimeObservation{
			State: instance.RuntimeStopped, ExitCode: info.exitCode, StopReason: stopReason,
		}, nil
	}
	return instance.RuntimeObservation{}, fmt.Errorf("%w: docker container state %q", instance.ErrInvalidRuntime, info.status)
}

func (d *Driver) Start(ctx context.Context, id string) error {
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, err := d.inspectOwned(operationCtx, id)
	if err != nil {
		return err
	}
	if err := d.engine.start(operationCtx, info.id); err != nil {
		return translateNotFound("start docker container", err)
	}
	return nil
}

func (d *Driver) Stop(ctx context.Context, id string) error {
	stopDuration := time.Duration(d.options.StopTimeoutSeconds+d.options.OperationTimeoutSeconds) * time.Second
	operationCtx, cancel := context.WithTimeout(ctx, stopDuration)
	defer cancel()
	info, err := d.inspectOwned(operationCtx, id)
	if err != nil {
		return err
	}
	if err := d.engine.stop(operationCtx, info.id, d.options.StopTimeoutSeconds); err != nil {
		return translateNotFound("stop docker container", err)
	}
	return nil
}

func (d *Driver) Remove(ctx context.Context, id string) error {
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, err := d.inspectOwned(operationCtx, id)
	if errors.Is(err, instance.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := d.engine.remove(operationCtx, info.id); err != nil && !cerrdefs.IsNotFound(err) {
		return fmt.Errorf("remove docker container: %w", err)
	}
	return nil
}

func (d *Driver) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(d.options.OperationTimeoutSeconds)*time.Second)
}

// Close releases idle Docker client connections after the server stops.
func (d *Driver) Close() error {
	return d.engine.close()
}

func (d *Driver) inspectOwned(ctx context.Context, id string) (containerInfo, error) {
	if err := instance.ValidateID(id); err != nil {
		return containerInfo{}, err
	}
	info, err := d.engine.inspect(ctx, containerName(id))
	if err != nil {
		return containerInfo{}, translateNotFound("inspect docker container", err)
	}
	if info.labels[managedLabel] != "true" || info.labels[instanceLabel] != id ||
		info.labels[namespaceLabel] != d.options.Namespace || info.labels[controllerLabel] != d.options.ControllerID {
		return containerInfo{}, fmt.Errorf("%w: docker container %q is not owned by this instance", instance.ErrNotFound, containerName(id))
	}
	return info, nil
}

func validOwnershipValue(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func translateNotFound(operation string, err error) error {
	if cerrdefs.IsNotFound(err) {
		return fmt.Errorf("%s: %w", operation, errors.Join(instance.ErrNotFound, err))
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func containerName(id string) string {
	return containerPrefix + id
}

var _ instance.Driver = (*Driver)(nil)
