// Package docker provides a Docker-backed Provider lifecycle adapter. It is
// independent from the local /instances Docker driver and its models.
package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

const (
	CodingShellRuntimeProfile = "sandbox-runtime-coding-shell-v1"

	managedLabel        = "io.github.shell-echo.sandbox-runtime.managed"
	ownerLabel          = "io.github.shell-echo.sandbox-runtime.owner"
	sandboxLabel        = "io.github.shell-echo.sandbox-runtime.provider-sandbox-id"
	namespaceLabel      = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel     = "io.github.shell-echo.sandbox-runtime.controller-id"
	runtimeProfileLabel = "io.github.shell-echo.sandbox-runtime.runtime-profile"
	specDigestLabel     = "io.github.shell-echo.sandbox-runtime.provider-spec-digest"
	providerOwner       = "provider-lifecycle"
	containerPrefix     = "sandbox-runtime-provider-"
	connectTimeout      = 10 * time.Second
)

var (
	ErrInvalidDriver     = errors.New("invalid Provider Docker lifecycle driver")
	ErrInvalidOptions    = errors.New("invalid Provider Docker lifecycle options")
	ErrOwnershipConflict = errors.New("Provider runtime ownership conflict")
	ErrInvalidRuntime    = errors.New("invalid Provider runtime observation")
)

type PullPolicy string

const (
	PullNever        PullPolicy = "never"
	PullIfNotPresent PullPolicy = "if_not_present"
	PullAlways       PullPolicy = "always"
)

// Options are process-owned development settings for the Provider adapter.
// The image must be pinned by sha256 and User must be a numeric non-root uid:gid.
type Options struct {
	Host                    string
	Image                   string
	PullPolicy              PullPolicy
	MemoryBytes             int64
	NanoCPUs                int64
	PidsLimit               int64
	TmpfsBytes              int64
	OperationTimeoutSeconds int
	PullTimeoutSeconds      int
	StopTimeoutSeconds      int
	User                    string
	Command                 []string
	DataRoot                string
	Namespace               string
	ControllerID            string
}

func (o Options) validate() (int, int, error) {
	if !isSHA256PinnedImage(o.Image) {
		return 0, 0, fmt.Errorf("%w: image must be pinned by sha256 digest", ErrInvalidOptions)
	}
	switch o.PullPolicy {
	case PullNever, PullIfNotPresent, PullAlways:
	default:
		return 0, 0, fmt.Errorf("%w: unsupported pull policy", ErrInvalidOptions)
	}
	if o.MemoryBytes <= 0 || o.NanoCPUs <= 0 || o.PidsLimit <= 0 || o.TmpfsBytes <= 0 {
		return 0, 0, fmt.Errorf("%w: resource limits must be positive", ErrInvalidOptions)
	}
	if o.OperationTimeoutSeconds <= 0 || o.PullTimeoutSeconds <= 0 || o.StopTimeoutSeconds < 0 {
		return 0, 0, fmt.Errorf("%w: invalid operation timeout", ErrInvalidOptions)
	}
	if len(o.Command) == 0 {
		return 0, 0, fmt.Errorf("%w: command is required", ErrInvalidOptions)
	}
	if strings.TrimSpace(o.DataRoot) == "" {
		return 0, 0, fmt.Errorf("%w: data root is required", ErrInvalidOptions)
	}
	if !validOwnershipValue(o.Namespace) || !validOwnershipValue(o.ControllerID) {
		return 0, 0, fmt.Errorf("%w: invalid namespace or controller ID", ErrInvalidOptions)
	}
	uid, gid, err := parseNumericUser(o.User)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// Driver creates only Provider-owned resources and returns backend-neutral
// lifecycle observations. It provides single-controller development evidence.
type Driver struct {
	engine   engine
	options  Options
	dataRoot string
	uid      int
	gid      int
}

func New(ctx context.Context, options Options) (*Driver, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	backend, err := newMobyEngine(options.Host)
	if err != nil {
		return nil, fmt.Errorf("create Provider Docker client: %w", ErrInvalidDriver)
	}
	driver, err := newDriver(backend, options)
	if err != nil {
		_ = backend.close()
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	err = backend.ping(pingCtx)
	cancel()
	if err != nil {
		_ = backend.close()
		return nil, fmt.Errorf("connect to Provider Docker engine: %w", ErrInvalidDriver)
	}
	return driver, nil
}

func newDriver(backend engine, options Options) (*Driver, error) {
	if backend == nil {
		return nil, fmt.Errorf("%w: engine is required", ErrInvalidDriver)
	}
	uid, gid, err := options.validate()
	if err != nil {
		return nil, err
	}
	root, err := prepareDataRoot(options.DataRoot)
	if err != nil {
		return nil, err
	}
	options.Command = append([]string(nil), options.Command...)
	return &Driver{engine: backend, options: options, dataRoot: root, uid: uid, gid: gid}, nil
}

func (d *Driver) Create(ctx context.Context, sandbox lifecycle.Sandbox) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil {
		return ErrInvalidDriver
	}
	if err := sandbox.Validate(); err != nil {
		return err
	}
	if sandbox.RuntimeProfile != CodingShellRuntimeProfile {
		return fmt.Errorf("%w: unsupported runtime profile", ErrInvalidDriver)
	}
	inspectCtx, inspectCancel := d.operationContext(ctx)
	info, found, err := d.inspectOwned(inspectCtx, sandbox)
	if err != nil {
		inspectCancel()
		return err
	}
	if found {
		err := d.startAndConfirm(inspectCtx, sandbox, info)
		inspectCancel()
		return err
	}
	inspectCancel()

	pullCtx, pullCancel := context.WithTimeout(ctx, time.Duration(d.options.PullTimeoutSeconds)*time.Second)
	err = d.engine.ensureImage(pullCtx, d.options.Image, d.options.PullPolicy)
	pullCancel()
	if err != nil {
		return fmt.Errorf("prepare Provider runtime image: %w", err)
	}
	paths, err := d.prepareMounts(sandbox.ID)
	if err != nil {
		return err
	}

	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	if err := contextError(operationCtx); err != nil {
		return err
	}
	info, found, err = d.inspectOwned(operationCtx, sandbox)
	if err != nil {
		return err
	}
	if !found {
		request, requestErr := d.createRequest(sandbox, paths)
		if requestErr != nil {
			return requestErr
		}
		if err := contextError(operationCtx); err != nil {
			return err
		}
		if _, createErr := d.engine.create(operationCtx, request); createErr != nil {
			if cerrdefs.IsInvalidArgument(createErr) || cerrdefs.IsPermissionDenied(createErr) || cerrdefs.IsNotFound(createErr) {
				return ErrInvalidRuntime
			}
			if !cerrdefs.IsConflict(createErr) {
				return unknownRuntime(operationCtx)
			}
		}
		info, found, err = d.inspectOwned(operationCtx, sandbox)
		if err != nil {
			return err
		}
		if !found {
			return unknownRuntime(operationCtx)
		}
	}
	return d.startAndConfirm(operationCtx, sandbox, info)
}

func (d *Driver) startAndConfirm(ctx context.Context, sandbox lifecycle.Sandbox, info containerInfo) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if info.running && info.status == "running" {
		return nil
	}
	if info.dead || info.paused || info.restarting {
		return ErrInvalidRuntime
	}
	if err := d.engine.start(ctx, info.id); err != nil {
		return unknownRuntime(ctx)
	}
	confirmed, found, err := d.inspectOwned(ctx, sandbox)
	if err != nil {
		return err
	}
	if !found || !confirmed.running || confirmed.status != "running" {
		return unknownRuntime(ctx)
	}
	return nil
}

func (d *Driver) Inspect(ctx context.Context, sandboxID string) (coordinator.RuntimeObservation, error) {
	if err := contextError(ctx); err != nil {
		return coordinator.RuntimeObservation{}, err
	}
	if d == nil || d.engine == nil {
		return coordinator.RuntimeObservation{}, ErrInvalidDriver
	}
	if err := lifecycle.ValidateIdentifier(sandboxID); err != nil {
		return coordinator.RuntimeObservation{}, err
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwnedID(operationCtx, sandboxID)
	if err != nil {
		return coordinator.RuntimeObservation{}, err
	}
	if !found {
		return coordinator.RuntimeObservation{State: coordinator.RuntimeAbsent}, nil
	}
	switch {
	case info.running && info.status == "running" && !info.paused && !info.restarting && !info.dead:
		return coordinator.RuntimeObservation{State: coordinator.RuntimeReady}, nil
	case !info.running && info.status == "created":
		return coordinator.RuntimeObservation{State: coordinator.RuntimeProvisioning}, nil
	case info.restarting:
		return coordinator.RuntimeObservation{State: coordinator.RuntimeProvisioning}, nil
	default:
		return coordinator.RuntimeObservation{}, ErrInvalidRuntime
	}
}

// Remove is idempotent and deletes only a resource with the exact Provider
// ownership labels, followed by its deterministic mount root.
func (d *Driver) Remove(ctx context.Context, sandboxID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || d.engine == nil {
		return ErrInvalidDriver
	}
	if err := lifecycle.ValidateIdentifier(sandboxID); err != nil {
		return err
	}
	operationCtx, cancel := d.operationContext(ctx)
	defer cancel()
	info, found, err := d.inspectOwnedID(operationCtx, sandboxID)
	if err != nil {
		return err
	}
	if found {
		if err := d.engine.remove(operationCtx, info.id); err != nil && !cerrdefs.IsNotFound(err) {
			return unknownRuntime(operationCtx)
		}
	}
	return d.removeMounts(sandboxID)
}

func (d *Driver) Close() error {
	if d == nil || d.engine == nil {
		return nil
	}
	return d.engine.close()
}

type mountPaths struct {
	root      string
	inputs    string
	workspace string
	outputs   string
}

func (d *Driver) prepareMounts(sandboxID string) (mountPaths, error) {
	paths, err := d.mountPaths(sandboxID)
	if err != nil {
		return mountPaths{}, err
	}
	if err := ensureDirectory(paths.root, 0o700, -1, -1); err != nil {
		return mountPaths{}, fmt.Errorf("prepare Provider mount root: %w", err)
	}
	// Docker Desktop does not consistently preserve host uid/gid ownership for
	// bind mounts. The hashed parent remains 0700; only its guest-mounted leaves
	// are world-readable or writable so the configured numeric user works across
	// native Linux and development VMs.
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{{paths.inputs, 0o555}, {paths.workspace, 0o777}, {paths.outputs, 0o777}} {
		if err := ensureDirectory(directory.path, directory.mode, d.uid, d.gid); err != nil {
			return mountPaths{}, fmt.Errorf("prepare Provider mount: %w", err)
		}
	}
	return paths, nil
}

func (d *Driver) removeMounts(sandboxID string) error {
	paths, err := d.mountPaths(sandboxID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(paths.root); err != nil {
		return fmt.Errorf("remove Provider mounts: %w", err)
	}
	return nil
}

func (d *Driver) mountPaths(sandboxID string) (mountPaths, error) {
	if err := lifecycle.ValidateIdentifier(sandboxID); err != nil {
		return mountPaths{}, err
	}
	sum := sha256.Sum256([]byte(sandboxID))
	root := filepath.Join(d.dataRoot, hex.EncodeToString(sum[:]))
	return mountPaths{
		root: root, inputs: filepath.Join(root, "inputs"),
		workspace: filepath.Join(root, "workspace"), outputs: filepath.Join(root, "outputs"),
	}, nil
}

func (d *Driver) createRequest(sandbox lifecycle.Sandbox, paths mountPaths) (createRequest, error) {
	digest, err := d.specDigest(sandbox)
	if err != nil {
		return createRequest{}, err
	}
	init := true
	return createRequest{
		name: containerName(sandbox.ID), image: d.options.Image,
		command: append([]string(nil), d.options.Command...), user: d.options.User,
		workingDirectory: "/workspace", readonly: true, init: &init,
		memoryBytes: d.options.MemoryBytes, nanoCPUs: d.options.NanoCPUs,
		pidsLimit: d.options.PidsLimit, stopTimeout: d.options.StopTimeoutSeconds,
		tmpfs: map[string]string{
			"/tmp": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=1777", d.options.TmpfsBytes),
		},
		mounts: []bindMount{
			{source: paths.inputs, target: "/inputs", readonly: true},
			{source: paths.workspace, target: "/workspace"},
			{source: paths.outputs, target: "/outputs"},
		},
		labels: map[string]string{
			managedLabel: "true", ownerLabel: providerOwner, sandboxLabel: sandbox.ID,
			namespaceLabel: d.options.Namespace, controllerLabel: d.options.ControllerID,
			runtimeProfileLabel: sandbox.RuntimeProfile, specDigestLabel: digest,
		},
	}, nil
}

func (d *Driver) inspectOwned(ctx context.Context, sandbox lifecycle.Sandbox) (containerInfo, bool, error) {
	digest, err := d.specDigest(sandbox)
	if err != nil {
		return containerInfo{}, false, err
	}
	return d.inspectOwnedWithDigest(ctx, sandbox.ID, digest)
}

func (d *Driver) inspectOwnedID(ctx context.Context, sandboxID string) (containerInfo, bool, error) {
	return d.inspectOwnedWithDigest(ctx, sandboxID, "")
}

func (d *Driver) inspectOwnedWithDigest(ctx context.Context, sandboxID, expectedDigest string) (containerInfo, bool, error) {
	info, err := d.engine.inspect(ctx, containerName(sandboxID))
	if cerrdefs.IsNotFound(err) {
		return containerInfo{}, false, nil
	}
	if err != nil {
		return containerInfo{}, false, unknownRuntime(ctx)
	}
	labels := info.labels
	if labels[managedLabel] != "true" || labels[ownerLabel] != providerOwner ||
		labels[sandboxLabel] != sandboxID || labels[namespaceLabel] != d.options.Namespace ||
		labels[controllerLabel] != d.options.ControllerID || labels[runtimeProfileLabel] != CodingShellRuntimeProfile ||
		lifecycle.ValidateDigest(labels[specDigestLabel]) != nil ||
		(expectedDigest != "" && labels[specDigestLabel] != expectedDigest) {
		return containerInfo{}, false, ErrOwnershipConflict
	}
	return info, true, nil
}

func (d *Driver) specDigest(sandbox lifecycle.Sandbox) (string, error) {
	value := struct {
		SandboxID          string
		TenantID           string
		WorkOrderID        string
		WorkspaceID        string
		ProviderRevisionID string
		RuntimeProfile     string
		SandboxSlotKey     string
		Image              string
		User               string
		Command            []string
		Memory             int64
		CPU                int64
		PIDs               int64
		Tmpfs              int64
	}{
		SandboxID: sandbox.ID, TenantID: sandbox.TenantID, WorkOrderID: sandbox.WorkOrderID,
		WorkspaceID: sandbox.WorkspaceID, ProviderRevisionID: sandbox.ProviderRevisionID,
		RuntimeProfile: sandbox.RuntimeProfile, SandboxSlotKey: sandbox.SandboxSlotKey,
		Image: d.options.Image, User: d.options.User, Command: d.options.Command,
		Memory: d.options.MemoryBytes, CPU: d.options.NanoCPUs,
		PIDs: d.options.PidsLimit, Tmpfs: d.options.TmpfsBytes,
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode Provider runtime identity: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (d *Driver) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(d.options.OperationTimeoutSeconds)*time.Second)
}

func prepareDataRoot(configured string) (string, error) {
	absolute, err := filepath.Abs(configured)
	if err != nil {
		return "", fmt.Errorf("%w: resolve data root", ErrInvalidOptions)
	}
	clean := filepath.Clean(absolute)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("%w: data root must not be filesystem root", ErrInvalidOptions)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", fmt.Errorf("prepare Provider data root: %w", err)
	}
	if err := ensureDirectory(clean, 0o700, -1, -1); err != nil {
		return "", fmt.Errorf("prepare Provider data root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("resolve Provider data root: %w", err)
	}
	return resolved, nil
}

func ensureDirectory(path string, mode os.FileMode, uid, gid int) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, mode); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a real directory")
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if uid >= 0 && gid >= 0 {
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func parseNumericUser(value string) (int, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%w: user must be numeric uid:gid", ErrInvalidOptions)
	}
	uid64, uidErr := strconv.ParseUint(parts[0], 10, 31)
	gid64, gidErr := strconv.ParseUint(parts[1], 10, 31)
	if uidErr != nil || gidErr != nil || uid64 == 0 || gid64 == 0 {
		return 0, 0, fmt.Errorf("%w: user must be numeric non-root uid:gid", ErrInvalidOptions)
	}
	return int(uid64), int(gid64), nil
}

func validOwnershipValue(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func isSHA256PinnedImage(image string) bool {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false
	}
	digested, ok := named.(reference.Digested)
	return ok && digested.Digest().Algorithm() == digest.SHA256 && digested.Digest().Validate() == nil
}

func containerName(sandboxID string) string {
	sum := sha256.Sum256([]byte(sandboxID))
	return containerPrefix + hex.EncodeToString(sum[:12])
}

func unknownRuntime(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return errors.Join(coordinator.ErrUnknownRuntime, err)
	}
	return coordinator.ErrUnknownRuntime
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var (
	_ coordinator.Driver        = (*Driver)(nil)
	_ coordinator.OrphanCleaner = (*Driver)(nil)
)
