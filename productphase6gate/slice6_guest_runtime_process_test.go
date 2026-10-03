//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6GuestRuntimeProcessEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_RUNTIME_PROCESS"

// The shell digest is measured from the exact selected Guest image before it
// is used as a v3 toolchain. This is a finite, networkless operator probe.
func slice6MeasureGuestShell(ctx context.Context, run slice6DockerRun, principal phase6security.Principal) (string, error) {
	if principal.Name != "guest-runtime" || principal.ImageReference != principal.ImageDigest ||
		principal.UID == 0 || principal.GID == 0 {
		return "", errors.New("Guest shell image identity unavailable")
	}
	output, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-guest-shell-"+run.id,
		"--label", run.label(), "--network=none", "--restart=no", "--read-only",
		"--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID), "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--memory=67108864", "--cpus=0.2",
		"--pids-limit=16", "--entrypoint=/bin/busybox", principal.ImageReference,
		"sha256sum", "/bin/sh")
	fields := strings.Fields(string(output))
	if err != nil || len(output) > 256 || len(fields) != 2 || len(fields[0]) != 64 ||
		!lowerHexSlice6(fields[0]) || fields[1] != "/bin/sh" {
		return "", errors.New("selected Guest image shell digest unavailable")
	}
	return "sha256:" + fields[0], nil
}

// This component runner is called only while Product PID1, its real SQL edge,
// both Guest signers and the Vault-backed Guest material agent remain alive.
// It cannot fabricate a Product binding: the finite fixture receipt supplies
// that exact ID and generation.
func slice6RunGuestRuntimePID1(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, binding slice6GuestBindingFixtureReceipt,
	socketVolumes, anchorFiles map[string]string, productID string,
	onConnected func(string) error) (resultErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	profile := composed.Profile
	plan, err := slice6BuildGuestRuntimeLaunchPlan(profile)
	if err != nil || binding.Protocol != slice6GuestBindingFixtureProtocol || binding.RunID != run.id ||
		binding.ProfileDigest != profile.ProfileDigest || binding.GuestID == "" ||
		binding.BindingGeneration != 1 || !binding.IdempotentReplay ||
		len(socketVolumes) != 67 || len(productID) != 64 || !lowerHexSlice6(productID) {
		return errors.New("Guest PID1 has no same-run Product binding or source-bound placement")
	}
	product, err := slice6InspectProductRuntimeMember(ctx, run, productID)
	if err != nil || product.ID != productID || product.Name != "/sr-p6-product-runtime-"+run.id {
		return errors.New("Guest PID1 requires the running same-run Product process")
	}
	productEdge, ok := product.NetworkSettings.Networks[plan.ProductNetwork.Name]
	if !ok || productEdge.NetworkID == "" {
		return errors.New("Guest Product edge is not live")
	}
	productOnly := plan.ProductNetwork
	productOnly.Principals = []string{"product-runtime"}
	if _, err := observeSlice6ProfileNetwork(ctx, run, productEdge.NetworkID, productOnly,
		map[string]string{"product-runtime": productID}); err != nil {
		return errors.New("Guest Product bridge has unreviewed member before Guest admission")
	}
	if err := slice6PreflightGuestStorageCapacity(ctx, run); err != nil {
		return err
	}
	shellDigest, err := slice6MeasureGuestShell(ctx, run, plan.Principal)
	if err != nil {
		return err
	}
	files, err := slice6BuildGuestRuntimeInputs(composed, run.id, binding.GuestID,
		binding.BindingGeneration, shellDigest)
	if err != nil {
		return err
	}
	archive, err := phase6security.BuildSlice6PrivateConfigArchive(profile, "guest-runtime", files)
	for _, value := range files {
		clear(value)
	}
	if err != nil {
		return err
	}
	slice6PrepareOneControllerPrivateConfig(t, ctx, run, profile, "guest-runtime", archive)
	storage := slice6PrepareGuestStorageVolumes(t, ctx, run, plan.Principal.UID, plan.Principal.GID)
	if err := slice6ValidateGuestStorageVolumes(ctx, run, storage); err != nil {
		return err
	}
	internal, err := createSlice6ProfileNetwork(ctx, run, plan.InternalNetwork)
	if err != nil {
		return err
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return err
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompDocument, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompDocument)
	clear(seccompDocument)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		return errors.New("Guest PID1 seccomp source drift")
	}
	private, _ := phase6security.Slice6PrivateConfigMount("guest-runtime")
	configVolume := "sr-p6-config-guest-runtime-" + run.id
	if err := slice6VerifyGuestFixtureVolume(ctx, run, configVolume); err != nil {
		return err
	}
	anchors, err := slice6AnchorMountArguments(profile, "guest-runtime", anchorFiles)
	if err != nil {
		return err
	}
	owner := fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID)
	tmpfs := func(target string) string {
		return target + ":rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=" +
			strconv.FormatUint(uint64(plan.Principal.UID), 10) + ",gid=" +
			strconv.FormatUint(uint64(plan.Principal.GID), 10)
	}
	args := []string{"create", "--pull=never", "--name", "sr-p6-guest-runtime-" + run.id,
		"--label", run.label(), "--log-driver=none", "--network", productEdge.NetworkID,
		"--ip", plan.ProductIP, "--restart=no", "--user", owner, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(plan.Principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(plan.Principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(plan.Principal.Resources.PIDs, 10),
		"--mount", "type=volume,src=" + configVolume + ",dst=" + private.Target + ",readonly",
		"--tmpfs", tmpfs(phase6security.Slice6GuestOutputsRoot),
		"--tmpfs", tmpfs(phase6security.Slice6GuestTempRoot)}
	for _, mount := range plan.Principal.Mounts {
		switch mount.Kind {
		case "private_socket":
			volume := socketVolumes[mount.StorageID]
			if volume == "" || slice6VerifyGuestFixtureVolume(ctx, run, volume) != nil {
				return errors.New("Guest private signer socket volume missing")
			}
			args = append(args, "--mount", "type=volume,src="+volume+",dst="+mount.Target+",readonly")
		case "guest_storage":
			volume := storage[mount.StorageID]
			if volume == "" {
				return errors.New("Guest storage volume missing")
			}
			option := "type=volume,src=" + volume + ",dst=" + mount.Target
			if mount.ReadOnly {
				option += ",readonly"
			}
			args = append(args, "--mount", option)
		}
	}
	args = append(args, anchors...)
	args = append(args, plan.Principal.ImageReference, "--config",
		private.Target+"/"+phase6security.Slice6StartupConfigFile, "guest", "serve")
	created, err := run.docker(ctx, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return errors.New("create independent Guest PID1")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := run.docker(cleanup, "rm", "-f", "-v", id); err != nil {
			resultErr = errors.Join(resultErr, errors.New("Guest PID1 exact cleanup unconfirmed"))
		}
	}()
	if _, err := run.docker(ctx, "network", "connect", "--ip", plan.InternalIP, internal.NetworkID, id); err != nil {
		return errors.New("Guest internal isolated network connect failed")
	}
	if err := slice6VerifyGuestRuntimeContainer(ctx, run, id, plan, productEdge.NetworkID,
		internal.NetworkID, configVolume, storage, socketVolumes, anchorFiles, seccomp); err != nil {
		return err
	}
	if _, err := run.docker(ctx, "start", id); err != nil {
		return errors.New("start independent Guest PID1")
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		guest, inspectErr := slice6InspectProductRuntimeMember(ctx, run, id)
		if inspectErr != nil || guest.ID != id || guest.Name != "/sr-p6-guest-runtime-"+run.id {
			return errors.New("Guest PID1 stopped or restarted before connected readiness")
		}
		probe, probeErr := run.docker(ctx, "exec", "--user", owner, id,
			"/bin/busybox", "wget", "-qO-", "http://127.0.0.1:8086/readyz")
		if probeErr == nil && len(probe) <= 1024 {
			if _, err := observeSlice6ProfileNetwork(ctx, run, productEdge.NetworkID, plan.ProductNetwork,
				map[string]string{"product-runtime": productID, "guest-runtime": id}); err != nil {
				return errors.New("Guest Product bridge actual membership drift")
			}
			if _, err := observeSlice6ProfileNetwork(ctx, run, internal.NetworkID, plan.InternalNetwork,
				map[string]string{"guest-runtime": id}); err != nil {
				return errors.New("Guest isolated internal bridge actual membership drift")
			}
			t.Log("real independent Guest PID1 reached connected /readyz while Product PID1 and both Guest agents remained live; same-run two-edge network membership observed")
			if onConnected != nil {
				if err := onConnected(id); err != nil {
					return errors.Join(errors.New("Guest live dependent gate failed"), err)
				}
				guest, err := slice6InspectProductRuntimeMember(ctx, run, id)
				if err != nil || guest.ID != id || guest.Name != "/sr-p6-guest-runtime-"+run.id {
					return errors.New("Guest PID1 changed during live dependent gate")
				}
			}
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("Guest PID1 did not reach connected readiness within fixed deadline")
}

func slice6VerifyGuestRuntimeContainer(ctx context.Context, run slice6DockerRun, id string,
	plan slice6GuestRuntimeLaunchPlan, productNetworkID, internalNetworkID, configVolume string,
	storage, sockets, anchors map[string]string, seccomp string) error {
	raw, err := run.docker(ctx, "inspect", id)
	var found []struct {
		Image  string
		Config struct {
			Image, User     string
			Entrypoint, Cmd []string
			Labels          map[string]string
		}
		HostConfig struct {
			ReadonlyRootfs, Privileged  bool
			CapDrop, SecurityOpt        []string
			Memory, NanoCpus, PidsLimit int64
			NetworkMode                 string
			Tmpfs                       map[string]string
			PortBindings                map[string]any
			RestartPolicy               struct{ Name string }
			LogConfig                   struct{ Type string }
		}
		Mounts []struct {
			Type, Name, Source, Destination string
			RW                              bool
		}
		NetworkSettings struct {
			Networks map[string]slice6MigrationNetworkEndpoint
		}
	}
	seccompDocument, seccompErr := os.ReadFile(seccomp)
	var canonical bytes.Buffer
	if seccompErr == nil {
		seccompErr = json.Compact(&canonical, seccompDocument)
	}
	clear(seccompDocument)
	private, _ := phase6security.Slice6PrivateConfigMount("guest-runtime")
	if err != nil || seccompErr != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 ||
		found[0].Image != plan.Principal.ImageDigest || found[0].Config.Image != plan.Principal.ImageReference ||
		found[0].Config.User != fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID) ||
		found[0].Config.Labels[slice6RunLabel] != run.id ||
		!slices.Equal(found[0].Config.Entrypoint, []string{"/usr/local/bin/phase6-role"}) ||
		!slices.Equal(found[0].Config.Cmd, []string{"--config", private.Target + "/" + phase6security.Slice6StartupConfigFile, "guest", "serve"}) ||
		!found[0].HostConfig.ReadonlyRootfs || found[0].HostConfig.Privileged ||
		!slices.Equal(found[0].HostConfig.CapDrop, []string{"ALL"}) ||
		!slices.Contains(found[0].HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(found[0].HostConfig.SecurityOpt, "seccomp="+canonical.String()) ||
		found[0].HostConfig.Memory != plan.Principal.Resources.MemoryBytes ||
		found[0].HostConfig.NanoCpus != plan.Principal.Resources.CPUMillis*1_000_000 ||
		found[0].HostConfig.PidsLimit != plan.Principal.Resources.PIDs ||
		found[0].HostConfig.NetworkMode != productNetworkID ||
		found[0].HostConfig.RestartPolicy.Name != "no" || found[0].HostConfig.LogConfig.Type != "none" ||
		len(found[0].HostConfig.PortBindings) != 0 || len(found[0].HostConfig.Tmpfs) != 2 ||
		len(found[0].NetworkSettings.Networks) != 2 {
		return errors.New("Guest created-container identity or least-privilege drift")
	}
	for name, want := range map[string]struct{ id, ip string }{
		plan.ProductNetwork.Name:  {productNetworkID, plan.ProductIP},
		plan.InternalNetwork.Name: {internalNetworkID, plan.InternalIP},
	} {
		observed, ok := found[0].NetworkSettings.Networks[name]
		if !ok || observed.NetworkID != want.id || observed.IPAMConfig.IPv4Address != want.ip {
			return errors.New("Guest fixed network or IP drift")
		}
	}
	for _, target := range []string{phase6security.Slice6GuestOutputsRoot, phase6security.Slice6GuestTempRoot} {
		options := found[0].HostConfig.Tmpfs[target]
		if !strings.Contains(options, "size=8388608") || !strings.Contains(options, "noexec") ||
			!strings.Contains(options, "nosuid") || !strings.Contains(options, "nodev") {
			return errors.New("Guest bounded tmpfs drift")
		}
	}
	want := map[string]struct {
		kind, source string
		writable     bool
	}{
		private.Target: {"volume", configVolume, false},
	}
	for _, mount := range plan.Principal.Mounts {
		switch mount.Kind {
		case "private_socket":
			want[mount.Target] = struct {
				kind, source string
				writable     bool
			}{"volume", sockets[mount.StorageID], false}
		case "guest_storage":
			want[mount.Target] = struct {
				kind, source string
				writable     bool
			}{"volume", storage[mount.StorageID], !mount.ReadOnly}
		case "trust_anchor":
			want[mount.Target] = struct {
				kind, source string
				writable     bool
			}{"bind", anchors[mount.StorageID], false}
		}
	}
	if len(found[0].Mounts) != len(want) {
		return errors.New("Guest mount count drift")
	}
	for _, mount := range found[0].Mounts {
		expected, ok := want[mount.Destination]
		if !ok || expected.source == "" || expected.kind != mount.Type || expected.writable != mount.RW ||
			(mount.Type == "volume" && mount.Name != expected.source) ||
			(mount.Type == "bind" && mount.Source != expected.source) {
			return errors.New("Guest unreviewed mount, owner or write direction")
		}
		delete(want, mount.Destination)
	}
	if len(want) != 0 {
		return errors.New("Guest mount inventory incomplete")
	}
	return nil
}
