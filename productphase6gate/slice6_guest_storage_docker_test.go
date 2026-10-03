//go:build phase6slice6gate

package productphase6gate

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"golang.org/x/sys/unix"
)

const slice6GuestStorageDockerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_STORAGE_DOCKER"

func slice6GuestStorageVolumeName(run slice6DockerRun, mount phase6security.Mount) string {
	return "sr-p6-" + mount.StorageID + "-" + run.id
}

func slice6GuestStorageArchive(run slice6DockerRun, mount phase6security.Mount) ([]byte, error) {
	receipt := phase6security.Slice6GuestStorageReceipt{
		Protocol: "sandbox-runtime.guest-storage.v1", Identity: run.id, StorageID: mount.StorageID,
	}
	if receipt.Validate(run.id, mount.StorageID) != nil {
		return nil, fmt.Errorf("invalid Guest storage receipt")
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{guestdevelopment.StorageIdentityFileName: encoded}
	if mount.StorageID == "guest-inputs" {
		files[phase6security.Slice6GuestInputsManifestFileName] = []byte(phase6security.Slice6GuestInputsManifest)
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range []string{guestdevelopment.StorageIdentityFileName, phase6security.Slice6GuestInputsManifestFileName} {
		contents, present := files[name]
		if !present {
			continue
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents))}); err != nil {
			return nil, err
		}
		if _, err := writer.Write(contents); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil || buffer.Len() > 1<<20 {
		return nil, fmt.Errorf("Guest storage preparation archive unavailable")
	}
	return buffer.Bytes(), nil
}

// The only bootstrap writer is a networkless one-shot root prep container.
// It exits and is removed before Guest receives the three named volumes.
func slice6PrepareGuestStorageVolumes(t *testing.T, ctx context.Context, run slice6DockerRun,
	uid, gid uint32) map[string]string {
	t.Helper()
	if uid < 10000 || gid < 10000 || len(run.id) != 32 || !lowerHexSlice6(run.id) {
		t.Fatal("Guest storage owner or run identity unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal("Guest storage prep source unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	volumes := make(map[string]string, 3)
	for _, mount := range phase6security.Slice6GuestStorageMounts() {
		if mount.Kind != "guest_storage" {
			continue
		}
		name := slice6GuestStorageVolumeName(run, mount)
		created, createErr := run.docker(ctx, "volume", "create", "--name", name, "--label", run.label())
		if createErr != nil || strings.TrimSpace(string(created)) != name {
			t.Fatal("create exact Guest-owned storage volume")
		}
		archive, err := slice6GuestStorageArchive(run, mount)
		if err != nil {
			t.Fatal(err)
		}
		mode := "0700"
		if mount.ReadOnly {
			mode = "0500"
		}
		script := "set -eu; test -z \"$(ls -A /volume)\"; tar -xf - -C /volume; " +
			"chmod " + mode + " /volume; chown -R " +
			strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10) + " /volume; " +
			"test \"$(stat -c '%u:%g:%a' /volume)\" = '" +
			strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10) + ":" + mode[1:] + "'"
		prepName := "sr-p6-prep-" + mount.StorageID + "-" + run.id
		output, createErr := run.docker(ctx, "create", "-i", "--pull=never", "--name", prepName,
			"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no", "--user=0:0",
			"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt=no-new-privileges:true",
			"--security-opt=seccomp="+seccomp, "--read-only", "--memory=67108864", "--cpus=0.500",
			"--pids-limit=16", "--mount", "type=volume,src="+name+",dst=/volume",
			slice6PinnedAlpineImage, "/bin/sh", "-ec", script)
		prepID := slice6CanonicalCreatedID(output, createErr)
		if prepID == "" {
			t.Fatalf("create Guest storage prep: %s", slice6DockerCreateFailure(ctx, output, createErr))
		}
		start := exec.CommandContext(ctx, "docker", "start", "-a", "-i", prepID)
		start.Stdin = bytes.NewReader(archive)
		if _, err := start.CombinedOutput(); err != nil {
			state, _ := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", prepID)
			t.Fatalf("one-shot Guest storage prep failed: state=%q", strings.TrimSpace(string(state)))
		}
		state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", prepID)
		if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
			t.Fatal("Guest storage prep did not exit cleanly")
		}
		if _, err := run.docker(ctx, "rm", prepID); err != nil {
			t.Fatal("remove exact Guest storage prep container")
		}
		volumes[mount.StorageID] = name
	}
	if len(volumes) != 3 {
		t.Fatal("Guest storage volume inventory incomplete")
	}
	return volumes
}

func slice6VerifyGuestStorageVolume(ctx context.Context, run slice6DockerRun, name string) error {
	document, err := run.docker(ctx, "volume", "inspect", name)
	var volumes []struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	}
	if err != nil || len(document) == 0 || len(document) > 8192 ||
		json.Unmarshal(document, &volumes) != nil || len(volumes) != 1 ||
		volumes[0].Name != name || volumes[0].Labels[slice6RunLabel] != run.id {
		return fmt.Errorf("Guest storage volume ownership or identity unavailable")
	}
	return nil
}

// Docker would silently create a missing named volume on container create.
// Resolve every fixed storage ID before that point and reject a same-run swap.
func slice6ValidateGuestStorageVolumes(ctx context.Context, run slice6DockerRun, volumes map[string]string) error {
	if len(volumes) != 3 {
		return fmt.Errorf("Guest storage volume inventory incomplete")
	}
	for _, mount := range phase6security.Slice6GuestStorageMounts() {
		if mount.Kind != "guest_storage" {
			continue
		}
		name := volumes[mount.StorageID]
		if name != slice6GuestStorageVolumeName(run, mount) {
			return fmt.Errorf("Guest storage volume identity mismatch")
		}
		if err := slice6VerifyGuestStorageVolume(ctx, run, name); err != nil {
			return err
		}
	}
	return nil
}

func slice6PreflightGuestStorageCapacity(ctx context.Context, run slice6DockerRun) error {
	root, err := filepath.Abs("..")
	if err != nil {
		return errSlice6Capacity
	}
	var host unix.Statfs_t
	if err := unix.Statfs(root, &host); err != nil || host.Bsize <= 0 || host.Bavail == 0 ||
		uint64(host.Bavail) > math.MaxInt64/uint64(host.Bsize) {
		return errSlice6Capacity
	}
	name := "sr-p6-guest-capacity-" + run.id
	document, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", name,
		"--label", run.label(), "--network=none", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
		slice6CapacityImage, "df", "-B1", "/")
	if err != nil {
		return errSlice6Capacity
	}
	dockerAvailable, err := parseSlice6DockerAvailable(document)
	if err != nil {
		return err
	}
	return slice6GuestStorageCapacityBudget(0).admit(slice6CapacityObservation{
		hostPhysicalAvailableBytes:  int64(host.Bavail) * int64(host.Bsize),
		dockerBackingAvailableBytes: dockerAvailable,
	})
}

func slice6RunGuestStorageProbe(t *testing.T, ctx context.Context, run slice6DockerRun,
	image string, uid, gid uint32, volumes map[string]string, ordinal int) {
	t.Helper()
	if err := slice6ValidateGuestStorageVolumes(ctx, run, volumes); err != nil {
		t.Fatal(err)
	}
	owner := strconv.FormatUint(uint64(uid), 10) + ":" + strconv.FormatUint(uint64(gid), 10)
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal("Guest storage probe source unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	script := "set -eu; " +
		"test \"$(stat -c '%u:%g:%a' /workspace)\" = '" + owner + ":700'; " +
		"test \"$(stat -c '%u:%g:%a' /var/lib/sandbox-runtime/guest-state)\" = '" + owner + ":700'; " +
		"test \"$(stat -c '%u:%g:%a' /inputs)\" = '" + owner + ":500'; " +
		"test \"$(stat -c '%u:%g:%a' /outputs)\" = '" + owner + ":700'; " +
		"test \"$(stat -c '%u:%g:%a' /tmp)\" = '" + owner + ":700'; " +
		"test \"$(stat -f -c %T /outputs)\" = tmpfs; " +
		"test \"$(stat -f -c %T /tmp)\" = tmpfs; " +
		"test \"$(df -B1 /outputs | awk 'NR==2 {print $2}')\" = 8388608; " +
		"test \"$(df -B1 /tmp | awk 'NR==2 {print $2}')\" = 8388608; " +
		"test \"$(cat /inputs/input-manifest.json)\" = '" + phase6security.Slice6GuestInputsManifest + "'; " +
		"test -f /workspace/" + guestdevelopment.StorageIdentityFileName + "; " +
		"test -f /var/lib/sandbox-runtime/guest-state/" + guestdevelopment.StorageIdentityFileName + "; " +
		"if touch /inputs/denied 2>/dev/null; then exit 1; fi; " +
		"touch /workspace/probe; rm /workspace/probe; touch /var/lib/sandbox-runtime/guest-state/probe; " +
		"rm /var/lib/sandbox-runtime/guest-state/probe"
	name := "sr-p6-guest-storage-probe-" + strconv.Itoa(ordinal) + "-" + run.id
	tmpfs := func(target string) string {
		return target + ":rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=" +
			strconv.FormatUint(uint64(uid), 10) + ",gid=" + strconv.FormatUint(uint64(gid), 10)
	}
	output, createErr := run.docker(ctx, "create", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network=none", "--restart=no", "--user="+owner,
		"--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--security-opt=seccomp="+seccomp,
		"--read-only", "--memory=134217728", "--cpus=0.200", "--pids-limit=32",
		"--mount", "type=volume,src="+volumes["guest-workspace"]+",dst="+phase6security.Slice6GuestWorkspaceRoot,
		"--mount", "type=volume,src="+volumes["guest-state"]+",dst="+phase6security.Slice6GuestStateRoot,
		"--mount", "type=volume,src="+volumes["guest-inputs"]+",dst="+phase6security.Slice6GuestInputsRoot+",readonly",
		"--tmpfs", tmpfs(phase6security.Slice6GuestOutputsRoot),
		"--tmpfs", tmpfs(phase6security.Slice6GuestTempRoot),
		"--entrypoint=/bin/sh", image, "-ec", script)
	id := slice6CanonicalCreatedID(output, createErr)
	if id == "" {
		t.Fatalf("create no-secret Guest storage probe: %s", slice6DockerCreateFailure(ctx, output, createErr))
	}
	document, err := run.docker(ctx, "inspect", id)
	var containers []struct {
		ID     string `json:"Id"`
		Config struct {
			Image, User string
			Labels      map[string]string
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string
			ReadonlyRootfs bool
			Privileged     bool
			Tmpfs          map[string]string
		} `json:"HostConfig"`
		Mounts []struct {
			Type, Name, Destination string
			RW                      bool
		} `json:"Mounts"`
	}
	if err != nil || json.Unmarshal(document, &containers) != nil || len(containers) != 1 ||
		containers[0].ID != id || containers[0].Config.Image != image ||
		containers[0].Config.User != owner || containers[0].Config.Labels[slice6RunLabel] != run.id ||
		containers[0].HostConfig.NetworkMode != "none" || !containers[0].HostConfig.ReadonlyRootfs ||
		containers[0].HostConfig.Privileged || len(containers[0].HostConfig.Tmpfs) != 2 || len(containers[0].Mounts) != 3 {
		t.Fatal("Guest storage probe container confinement or mount inventory drift")
	}
	for _, mount := range containers[0].Mounts {
		if mount.Type != "volume" ||
			!(mount.Name == volumes["guest-workspace"] && mount.Destination == phase6security.Slice6GuestWorkspaceRoot && mount.RW ||
				mount.Name == volumes["guest-state"] && mount.Destination == phase6security.Slice6GuestStateRoot && mount.RW ||
				mount.Name == volumes["guest-inputs"] && mount.Destination == phase6security.Slice6GuestInputsRoot && !mount.RW) {
			t.Fatal("Guest storage probe gained wrong volume or write direction")
		}
	}
	for _, target := range []string{phase6security.Slice6GuestOutputsRoot, phase6security.Slice6GuestTempRoot} {
		options := containers[0].HostConfig.Tmpfs[target]
		if !strings.Contains(options, "size=8388608") || !strings.Contains(options, "noexec") ||
			!strings.Contains(options, "nosuid") || !strings.Contains(options, "nodev") {
			t.Fatal("Guest tmpfs effective size or hardening options drift")
		}
	}
	if _, err := run.docker(ctx, "start", "-a", id); err != nil {
		t.Fatal("no-secret Guest storage or actual tmpfs mount probe failed")
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", id)
	if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
		t.Fatal("Guest storage probe did not exit cleanly")
	}
	if _, err := run.docker(ctx, "rm", "-v", id); err != nil {
		t.Fatal("remove exact Guest storage probe container")
	}
}

// This is an explicitly no-secret Docker mechanism gate. It neither starts a
// Guest production process nor consumes an issuer; the source-bound image is
// used only to inspect the Guest mount shape and existing BusyBox executable.
func TestSlice6GuestStorageDockerMounts(t *testing.T) {
	if os.Getenv(slice6GuestStorageDockerEnv) != "1" {
		t.Skip("set " + slice6GuestStorageDockerEnv + "=1 for no-secret Guest storage mounts")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	_, images, err := slice6VaultLoadStaticInputs(ctx, slice6VaultStaticInputsFromEnvironment())
	if err != nil || images.LocalRoleTargets["core"].Reference == "" {
		t.Fatal("source-bound core candidate unavailable before Guest storage allocation")
	}
	image := images.LocalRoleTargets["core"]
	if image.Location != "local" || image.Kind != phase6security.ImageIdentityOCIManifest ||
		image.Reference != image.Digest {
		t.Fatal("Guest core candidate image identity drift")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("Guest storage drill exact cleanup: %v", err)
		}
	})
	if err := slice6PreflightGuestStorageCapacity(ctx, run); err != nil {
		t.Fatal("host and Docker capacity do not admit incremental Guest storage candidate budget")
	}
	owner := phase6security.Slice6DesiredUIDGID()["guest-runtime"]
	volumes := slice6PrepareGuestStorageVolumes(t, ctx, run, owner[0], owner[1])
	if err := slice6ValidateGuestStorageVolumes(ctx, run, map[string]string{
		"guest-workspace": volumes["guest-state"],
		"guest-state":     volumes["guest-workspace"],
		"guest-inputs":    volumes["guest-inputs"],
	}); err == nil {
		t.Fatal("same-run Guest workspace/state volume swap accepted")
	}
	if err := slice6VerifyGuestStorageVolume(ctx, run, "sr-p6-guest-absent-"+run.id); err == nil {
		t.Fatal("absent Guest volume would be silently created")
	}
	slice6RunGuestStorageProbe(t, ctx, run, image.Reference, owner[0], owner[1], volumes, 1)
	slice6RunGuestStorageProbe(t, ctx, run, image.Reference, owner[0], owner[1], volumes, 2)
	if err := run.cleanup(ctx); err != nil {
		t.Fatal("exact no-secret Guest storage cleanup failed")
	}
	t.Log("source-bound no-secret Guest volumes retained across two containers; real owner/mode/read-only and 8MiB tmpfs mounts verified, exact cleanup zero; no Guest PID1 or issuer")
}
