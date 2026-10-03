//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	slice6RunLabel  = "io.github.shell-echo.sandbox-runtime.phase6-slice6-run"
	slice6LedgerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_RESOURCE_LEDGER"
)

// slice6DockerRun owns only resources bearing one unpredictable run label.
// A failed Docker create may have taken effect before returning its ID, so
// cleanup re-discovers the exact label instead of trusting an in-memory list.
// The final gate still needs durable raw receipts and all non-Docker classes.
type slice6DockerRun struct {
	id string
}

func newSlice6DockerRun() (slice6DockerRun, error) {
	id, err := phase6security.NewSlice6RunID()
	if err != nil {
		return slice6DockerRun{}, err
	}
	return slice6DockerRun{id: id}, nil
}

func (run slice6DockerRun) label() string { return slice6RunLabel + "=" + run.id }

func (run slice6DockerRun) docker(ctx context.Context, arguments ...string) ([]byte, error) {
	if run.id == "" || len(run.id) != 32 || !lowerHexSlice6(run.id) {
		return nil, errors.New("invalid Slice 6 Docker run identity")
	}
	return exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
}

func (run slice6DockerRun) labeledIDs(ctx context.Context, resource string) ([]string, error) {
	var arguments []string
	switch resource {
	case "container":
		arguments = []string{"ps", "-aq", "--no-trunc", "--filter", "label=" + run.label()}
	case "network":
		arguments = []string{"network", "ls", "-q", "--no-trunc", "--filter", "label=" + run.label()}
	case "volume":
		arguments = []string{"volume", "ls", "-q", "--filter", "label=" + run.label()}
	default:
		return nil, errors.New("unsupported Slice 6 Docker resource class")
	}
	output, err := run.docker(ctx, arguments...)
	if err != nil {
		return nil, fmt.Errorf("inspect Slice 6 %s ownership: %w", resource, err)
	}
	values := strings.Fields(string(output))
	for _, value := range values {
		if resource != "volume" && (len(value) != 64 || !lowerHexSlice6(value)) {
			return nil, errors.New("invalid Slice 6 Docker resource identity")
		}
		if resource == "volume" && (value == "" || strings.ContainsAny(value, "/\\\x00\n\r")) {
			return nil, errors.New("invalid Slice 6 Docker volume identity")
		}
	}
	return values, nil
}

func (run slice6DockerRun) cleanup(ctx context.Context) error {
	var failures []error
	for _, resource := range []string{"container", "network", "volume"} {
		ids, err := run.labeledIDs(ctx, resource)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, id := range ids {
			var arguments []string
			switch resource {
			case "container":
				// Pinned external images may declare implicit anonymous
				// VOLUME paths. Remove only volumes attached to this exact
				// run-labeled container; named volumes remain independently
				// tracked and are removed in the volume phase below.
				arguments = []string{"rm", "-f", "-v", id}
			case "network":
				arguments = []string{"network", "rm", id}
			case "volume":
				arguments = []string{"volume", "rm", id}
			}
			if _, err := run.docker(ctx, arguments...); err != nil {
				failures = append(failures, fmt.Errorf("remove exact Slice 6 %s %s: %w", resource, id, err))
			}
		}
	}
	for _, resource := range []string{"container", "network", "volume"} {
		ids, err := run.labeledIDs(ctx, resource)
		if err != nil {
			failures = append(failures, err)
		} else if len(ids) != 0 {
			failures = append(failures, fmt.Errorf("Slice 6 %s resources remain: %d", resource, len(ids)))
		}
	}
	return errors.Join(failures...)
}

// Docker create can succeed even when its response is lost. Only an exact
// name plus the unpredictable run label may recover that container; absence
// after an ambiguous create is not proof that no anonymous volume was made.
func slice6RecoverVaultContainer(ctx context.Context, run slice6DockerRun, name string) (string, error) {
	return slice6RecoverVaultContainerWithDocker(ctx, run, name, run.docker)
}

func slice6CanonicalCreatedID(output []byte, createErr error) string {
	if createErr != nil {
		return ""
	}
	id := strings.TrimSpace(string(output))
	if len(id) != 64 || !lowerHexSlice6(id) {
		return ""
	}
	return id
}

func slice6VaultCreateAdmitted(output []byte, createErr error, recoveredID string) bool {
	id := slice6CanonicalCreatedID(output, createErr)
	return id != "" && id == recoveredID
}

func slice6StartVaultFromCreateReceipt(ctx context.Context, output []byte, createErr error,
	recoveredID string, volumes []string, docker func(context.Context, ...string) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || !slice6VaultCreateAdmitted(output, createErr, recoveredID) ||
		len(volumes) != 2 || docker == nil {
		return errors.New("Vault create response was not admitted for start")
	}
	started, err := docker(ctx, "start", recoveredID)
	if err != nil || strings.TrimSpace(string(started)) != recoveredID {
		return errors.New("Vault start failed after exact create receipt")
	}
	return nil
}

func slice6RecoverVaultContainerWithDocker(ctx context.Context, run slice6DockerRun, name string,
	docker func(context.Context, ...string) ([]byte, error)) (string, error) {
	if len(run.id) != 32 || !lowerHexSlice6(run.id) || name != "sr-p6-vault-switch-"+run.id {
		return "", errors.New("invalid exact Vault recovery identity")
	}
	output, err := docker(ctx, "ps", "-aq", "--no-trunc", "--filter", "name=^/"+name+"$",
		"--filter", "label="+run.label())
	if err != nil {
		return "", errors.New("exact Vault create outcome cannot be queried")
	}
	ids := strings.Fields(string(output))
	if len(ids) > 1 {
		return "", errors.New("ambiguous exact Vault create outcome")
	}
	if len(ids) == 0 {
		return "", nil
	}
	id := ids[0]
	if len(id) != 64 || !lowerHexSlice6(id) {
		return "", errors.New("invalid recovered Vault container ID")
	}
	inspect, err := docker(ctx, "inspect", id)
	var containers []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err != nil || json.Unmarshal(inspect, &containers) != nil || len(containers) != 1 ||
		containers[0].ID != id || containers[0].Name != "/"+name ||
		containers[0].Config.Labels[slice6RunLabel] != run.id {
		return "", errors.New("recovered Vault container identity mismatch")
	}
	return id, nil
}

func slice6VaultImplicitVolumes(ctx context.Context, run slice6DockerRun, containerID string) ([]string, error) {
	if len(containerID) != 64 || !lowerHexSlice6(containerID) {
		return nil, errors.New("invalid exact Vault container identity")
	}
	inspect, err := run.docker(ctx, "inspect", containerID)
	var containers []struct {
		Mounts []struct {
			Type        string `json:"Type"`
			Name        string `json:"Name"`
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	if err != nil || json.Unmarshal(inspect, &containers) != nil || len(containers) != 1 {
		return nil, errors.New("exact Vault container mounts unavailable")
	}
	volumes := make([]string, 0, 2)
	destinations := map[string]bool{}
	for _, mount := range containers[0].Mounts {
		if mount.Type != "volume" {
			continue
		}
		if len(mount.Name) != 64 || !lowerHexSlice6(mount.Name) ||
			(mount.Destination != "/vault/file" && mount.Destination != "/vault/logs") ||
			destinations[mount.Destination] {
			return nil, errors.New("unknown implicit volume on exact Vault container")
		}
		destinations[mount.Destination] = true
		volumeInspect, inspectErr := run.docker(ctx, "volume", "inspect", mount.Name)
		var observed []struct {
			Labels map[string]string `json:"Labels"`
		}
		if inspectErr != nil || json.Unmarshal(volumeInspect, &observed) != nil || len(observed) != 1 {
			return nil, errors.New("exact anonymous volume metadata unavailable")
		}
		if _, anonymous := observed[0].Labels["com.docker.volume.anonymous"]; !anonymous {
			return nil, errors.New("implicit Vault image volume is not marked anonymous")
		}
		volumes = append(volumes, mount.Name)
	}
	if len(volumes) != 2 || !destinations["/vault/file"] || !destinations["/vault/logs"] {
		return nil, errors.New("Vault image did not produce its two reviewed implicit volumes")
	}
	return volumes, nil
}

func slice6CheckImplicitVolumesRemoved(ctx context.Context, run slice6DockerRun, volumes []string) error {
	if len(volumes) != 2 {
		return errors.New("exact implicit volume ownership proof is incomplete")
	}
	for _, volume := range volumes {
		output, err := run.docker(ctx, "volume", "inspect", volume)
		if err == nil || !strings.Contains(string(output), ": no such volume") {
			return errors.New("exact anonymous volume removal is unproved")
		}
	}
	return nil
}

// A pinned external image may declare VOLUME even though the gate supplies no
// --mount argument. This opt-in real-Docker check proves that exact labeled
// container cleanup also removes those daemon-created anonymous volumes.
func TestPhase6Slice6AnonymousVolumeCleanup(t *testing.T) {
	if os.Getenv(slice6LedgerEnv) != "1" {
		t.Skip("set " + slice6LedgerEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if cleanupErr := run.cleanup(cleanupContext); cleanupErr != nil {
			t.Errorf("exact anonymous-volume probe cleanup: %v", cleanupErr)
		}
	})
	created, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-anon-volume-"+run.id,
		"--label", run.label(), "--network=none", "--user=20090:30090", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--read-only", "--log-driver=none",
		"--memory=64m", "--cpus=0.25", "--pids-limit=16", slice6VaultTestImage)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create exact no-secret Vault-image anonymous-volume probe")
	}
	volumes, err := slice6VaultImplicitVolumes(ctx, run, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := slice6CheckImplicitVolumesRemoved(ctx, run, volumes); err != nil {
		t.Fatal(err)
	}
}

// This is a no-secret failure drill: Docker creates the pinned Vault image's
// two anonymous volumes, then fails to start a deliberately absent executable.
// It must never start a Vault process or allocate an issuer.
func TestPhase6Slice6VaultStartFailureCleanup(t *testing.T) {
	if os.Getenv(slice6LedgerEnv) != "1" {
		t.Skip("set " + slice6LedgerEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	name := "sr-p6-vault-switch-" + run.id
	var volumes []string
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("failed-start Vault exact cleanup: %v", err)
		}
		if len(volumes) == 2 {
			if err := slice6CheckImplicitVolumesRemoved(cleanup, run, volumes); err != nil {
				t.Errorf("failed-start Vault anonymous volumes: %v", err)
			}
		}
	})
	created, createErr := run.docker(ctx, "create", "--pull=never", "--name", name, "--label", run.label(),
		"--network=none", "--user=20090:30090", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
		"--read-only", "--log-driver=none", "--memory=64m", "--cpus=0.25", "--pids-limit=16",
		"--entrypoint=/phase6-intentionally-absent-executable", slice6VaultTestImage)
	id := slice6CanonicalCreatedID(created, createErr)
	recovered, recoverErr := slice6RecoverVaultContainer(ctx, run, name)
	if id == "" || recoverErr != nil || recovered != id {
		t.Fatal("failed-start drill could not prove exact created Vault container")
	}
	volumes, err = slice6VaultImplicitVolumes(ctx, run, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.docker(ctx, "start", id); err == nil {
		t.Fatal("deliberately absent executable unexpectedly started")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := slice6CheckImplicitVolumesRemoved(ctx, run, volumes); err != nil {
		t.Fatal(err)
	}
}

func TestPhase6Slice6VaultUncertainCreateCleanup(t *testing.T) {
	if os.Getenv(slice6LedgerEnv) != "1" {
		t.Skip("set " + slice6LedgerEnv + "=1")
	}
	for _, mode := range []string{"lost-response", "noncanonical-response"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			run, err := newSlice6DockerRun()
			if err != nil {
				t.Fatal(err)
			}
			name := "sr-p6-vault-switch-" + run.id
			var volumes []string
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
				defer stop()
				if err := run.cleanup(cleanup); err != nil {
					t.Errorf("uncertain-create exact cleanup: %v", err)
				}
				if len(volumes) == 2 {
					if err := slice6CheckImplicitVolumesRemoved(cleanup, run, volumes); err != nil {
						t.Errorf("uncertain-create anonymous volumes: %v", err)
					}
				}
			})
			created, createErr := run.docker(ctx, "create", "--pull=never", "--name", name,
				"--label", run.label(), "--network=none", "--user=20090:30090", "--cap-drop=ALL",
				"--security-opt=no-new-privileges:true", "--read-only", "--log-driver=none",
				"--memory=64m", "--cpus=0.25", "--pids-limit=16",
				"--entrypoint=/phase6-intentionally-absent-executable", slice6VaultTestImage)
			id := slice6CanonicalCreatedID(created, createErr)
			recovered, recoverErr := slice6RecoverVaultContainer(ctx, run, name)
			if id == "" || recoverErr != nil || recovered != id {
				t.Fatal("uncertain-create drill could not prove exact container")
			}
			volumes, err = slice6VaultImplicitVolumes(ctx, run, recovered)
			if err != nil {
				t.Fatal(err)
			}
			response := created
			responseErr := errors.New("simulated lost Docker create response")
			if mode == "noncanonical-response" {
				response = []byte("noncanonical Docker create response")
				responseErr = nil
			}
			if err := slice6StartVaultFromCreateReceipt(ctx, response, responseErr, recovered, volumes,
				func(_ context.Context, _ ...string) ([]byte, error) {
					t.Fatal("uncertain create response invoked Vault start")
					return nil, nil
				}); err == nil {
				t.Fatal("uncertain create response was admitted for Vault start")
			}
			if err := run.cleanup(ctx); err != nil {
				t.Fatal(err)
			}
			if err := slice6CheckImplicitVolumesRemoved(ctx, run, volumes); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// This opt-in test exercises exact ownership and cleanup against the actual
// Docker daemon. It does not exercise the authenticated multi-role service
// chain and must never be projected as a Slice 6 release scenario.
func TestPhase6Slice6DockerResourceLedger(t *testing.T) {
	if os.Getenv(slice6LedgerEnv) != "1" {
		t.Skip("set " + slice6LedgerEnv + "=1 for the real Docker ownership component")
	}
	image := os.Getenv("SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_IMAGE")
	manifestPath := os.Getenv("SANDBOX_RUNTIME_PHASE6_LOCAL_ROLE_MANIFEST")
	if len(image) != 71 || !strings.HasPrefix(image, "sha256:") || !lowerHexSlice6(strings.TrimPrefix(image, "sha256:")) {
		t.Fatal("exact local role image digest is required")
	}
	if !absoluteCleanSlice6Path(manifestPath) {
		t.Fatal("absolute private local role candidate manifest is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	sourceRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	headDocument, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal("exact source revision is unavailable")
	}
	sourceRevision := strings.TrimSpace(string(headDocument))
	if err := verifyCleanSlice6Source(ctx, sourceRoot, sourceRevision); err != nil {
		t.Fatal(err)
	}
	manifest, err := phase6rolecandidate.LoadCurrent(ctx, sourceRoot, manifestPath)
	if err != nil || manifest.RuntimeStoreImageID != image || manifest.Source.Deployment != "provider-runtime" ||
		manifest.Source.BuildTarget != "core" || manifest.Source.SourceRevision != sourceRevision {
		t.Fatal("Provider resource-ledger image is not bound to the current core-role candidate")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := run.cleanup(cleanupContext); err != nil {
			t.Errorf("exact Slice 6 Docker resource cleanup: %v", err)
		}
	})
	inspect, err := run.docker(ctx, "image", "inspect", image)
	var images []struct {
		ID     string `json:"Id"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err != nil || json.Unmarshal(inspect, &images) != nil || len(images) != 1 || images[0].ID != image ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.phase6-candidate"] != "local-only-non-release" ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.source-revision"] != sourceRevision ||
		images[0].Config.Labels["io.github.shell-echo.sandbox-runtime.role-target"] != "core" {
		t.Fatal("local-only role image is not loaded by exact digest")
	}
	var network phase6security.Network
	for _, candidate := range phase6security.Slice6DesiredNetworks() {
		if candidate.Name == "network-provider-runtime" {
			network = candidate
		}
	}
	if network.Name == "" {
		t.Fatal("reviewed Provider role network is absent")
	}
	observedNetwork, err := createSlice6ProfileNetwork(ctx, run, network)
	if err != nil {
		t.Fatal(err)
	}
	networkID := observedNetwork.NetworkID
	address, err := phase6security.Slice6DesiredEndpointAddress(network.Name, "provider-runtime")
	if err != nil {
		t.Fatal(err)
	}
	account := phase6security.Slice6DesiredUIDGID()["provider-runtime"]
	containerName := "sr-p6-s6-role-" + run.id
	output, err := run.docker(ctx, "create", "--pull=never", "--network", networkID, "--ip", address,
		"--label", run.label(), "--name", containerName, "--read-only",
		"--user", fmt.Sprintf("%d:%d", account[0], account[1]),
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "128m",
		image, "--help")
	if err != nil || len(strings.TrimSpace(string(output))) != 64 || !lowerHexSlice6(strings.TrimSpace(string(output))) {
		t.Fatalf("create exact run-owned high-UID role: %v: %.256s", err, output)
	}
	containerID := strings.TrimSpace(string(output))
	output, err = run.docker(ctx, "start", "-a", containerID)
	if err != nil || !bytes.Contains(output, []byte("sandbox-runtime")) {
		t.Fatalf("real role command did not run: %v: %.256s", err, output)
	}
	for resource, wanted := range map[string]string{"container": containerID, "network": networkID} {
		ids, err := run.labeledIDs(ctx, resource)
		if err != nil || len(ids) != 1 || ids[0] != wanted {
			t.Fatalf("exact %s ownership was not observable: %v, %v", resource, ids, err)
		}
	}
	// Drop both returned IDs as if the create reply were lost after Docker had
	// committed the side effect. Cleanup must use the run label, not only the
	// IDs that the caller happened to retain in memory.
	if _, err := run.docker(ctx, "network", "create", "--driver", "bridge", "--internal", "--label", run.label(), "sr-p6-s6-unack-"+run.id); err != nil {
		t.Fatalf("create unacknowledged run-owned network: %v", err)
	}
	if _, err := run.docker(ctx, "create", "--pull=never", "--network", networkID,
		"--label", run.label(), "--name", containerName+"-unack", image, "--help"); err != nil {
		t.Fatalf("create unacknowledged run-owned container: %v", err)
	}
	for _, resource := range []string{"container", "network"} {
		ids, err := run.labeledIDs(ctx, resource)
		if err != nil || len(ids) != 2 {
			t.Fatalf("unacknowledged %s was not discoverable: %v, %v", resource, ids, err)
		}
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact run-owned Docker resources remain: %v", err)
	}
	t.Log("real local role process and isolated network: run-scoped ownership and exact Docker cleanup; no service-chain claim")
}
