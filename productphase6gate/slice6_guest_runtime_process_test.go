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
const slice6GuestImageUtilityPreflightEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_IMAGE_UTILITY_PREFLIGHT"

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

func slice6ProbeGuestUtilities(ctx context.Context, run slice6DockerRun, principal phase6security.Principal) error {
	if principal.Name != "guest-runtime" || principal.ImageReference == "" ||
		principal.ImageReference != principal.ImageDigest || principal.UID == 0 || principal.GID == 0 {
		return errors.New("selected Guest utility image identity unavailable")
	}
	output, runErr, overflow := slice6DockerBounded(ctx, 256, nil,
		"run", "--rm", "--pull=never", "--network=none", "--restart=no",
		"--name", "sr-p6-guest-utilities-"+run.id, "--label", run.label(),
		"--read-only", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
		"--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=67108864",
		"--cpus=0.2", "--pids-limit=16", "--entrypoint=/bin/sh", principal.ImageReference,
		"-ec", "test -x /bin/busybox; /bin/busybox wget --help >/dev/null 2>&1; /bin/busybox df --help >/dev/null 2>&1")
	defer clear(output)
	if runErr != nil || overflow || len(output) != 0 {
		return errors.New("selected Guest HTTP or filesystem utility unavailable")
	}
	return nil
}

func TestSlice6SelectedGuestImageUtilitiesNoIssuer(t *testing.T) {
	if os.Getenv(slice6GuestImageUtilityPreflightEnv) != "1" {
		t.Skip("set " + slice6GuestImageUtilityPreflightEnv + "=1 with R4 source-bound image inputs")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()
	external, images, err := slice6VaultLoadStaticInputs(ctx, slice6VaultStaticInputsFromEnvironment())
	if err != nil || slice6VaultPreflightAllStoredImages(ctx, external, images) != nil {
		t.Fatal("selected Guest image static source or Docker store unavailable")
	}
	binding, ok := images.LocalRoleTargets["core"]
	identity := phase6security.Slice6DesiredUIDGID()["guest-runtime"]
	if !ok || binding.Reference == "" || binding.Reference != binding.Digest || identity[0] == 0 || identity[1] == 0 {
		t.Fatal("selected Guest image or non-root identity unavailable")
	}
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("selected Guest utility preflight exact cleanup: %v", err)
		}
	})
	principal := phase6security.Principal{Name: "guest-runtime", ImageReference: binding.Reference,
		ImageDigest: binding.Digest, UID: identity[0], GID: identity[1]}
	shell, err := slice6MeasureGuestShell(ctx, run, principal)
	if err != nil || shell == "" || slice6ProbeGuestUtilities(ctx, run, principal) != nil {
		t.Fatal("selected Guest shell/HTTP/df utilities unavailable before issuer")
	}
	t.Logf("pre-issuer selected Guest shell=%s and bounded HTTP/df utilities verified", shell)
}

// This component runner is called only while Product PID1, its real SQL edge,
// both Guest signers and the Vault-backed Guest material agent remain alive.
// It cannot fabricate a Product binding: the finite fixture receipt supplies
// that exact ID and generation.
func slice6RunGuestRuntimePID1(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, binding slice6GuestBindingFixtureReceipt,
	socketVolumes, anchorFiles map[string]string, productID, preIssuerShellDigest string,
	onConnected func(string) error) (resultErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	profile := composed.Profile
	plan, err := slice6BuildGuestRuntimeLaunchPlan(profile)
	if err != nil || binding.Protocol != slice6GuestBindingFixtureProtocol || binding.RunID != run.id ||
		binding.ProfileDigest != profile.ProfileDigest || binding.GuestID == "" ||
		binding.BindingGeneration != 1 || !binding.IdempotentReplay ||
		len(socketVolumes) != 68 || len(productID) != 64 || !lowerHexSlice6(productID) {
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
	if err != nil || shellDigest != preIssuerShellDigest || preIssuerShellDigest == "" {
		return errors.New("selected Guest shell changed after pre-issuer measurement")
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
	configVolume := "sr-p6-config-guest-runtime-" + run.id
	args, err := slice6GuestRuntimeCreateArguments(ctx, run, profile, plan, productEdge.NetworkID,
		configVolume, storage, socketVolumes, anchorFiles, seccomp)
	if err != nil {
		return err
	}
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
	if err := slice6VerifyGuestRuntimeRunningNetworks(ctx, run, id, plan,
		productEdge.NetworkID, internal.NetworkID); err != nil {
		return err
	}
	owner := fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID)
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
				before, beforeErr := slice6InspectProductRuntimeMember(ctx, run, id)
				if beforeErr != nil {
					return errors.New("Guest PID1 identity unavailable before dependent gate")
				}
				if err := onConnected(id); err != nil {
					return errors.Join(errors.New("Guest live dependent gate failed"), err)
				}
				guest, err := slice6InspectProductRuntimeMember(ctx, run, id)
				if err == nil {
					if slice6RuntimeMemberFingerprint(guest, true) != slice6RuntimeMemberFingerprint(before, true) {
						return errors.New("Guest PID1 changed during live dependent gate")
					}
				} else if os.Getenv(slice6GuestLiveRevokeEnv) == "1" {
					stopped, stateErr := slice6GuestStoppedAfterRevoke(ctx, run, id, before)
					if stateErr != nil || !stopped {
						return errors.New("Guest PID1 post-revoke exit was not verified")
					}
				} else {
					return errors.New("Guest PID1 changed during live dependent gate")
				}
			}
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("Guest PID1 did not reach connected readiness within fixed deadline")
}

// Both the real PID1 gate and the no-issuer created-container diagnostic use
// this one closed Docker request. The latter never starts Guest or its peers.
func slice6GuestRuntimeCreateArguments(ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, plan slice6GuestRuntimeLaunchPlan, productNetworkID,
	configVolume string, storage, sockets, anchorFiles map[string]string, seccomp string) ([]string, error) {
	if len(productNetworkID) != 64 || !lowerHexSlice6(productNetworkID) ||
		configVolume != "sr-p6-config-guest-runtime-"+run.id ||
		slice6VerifyGuestFixtureVolume(ctx, run, configVolume) != nil {
		return nil, errors.New("Guest PID1 private config or network unavailable")
	}
	seccompDocument, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompDocument)
	clear(seccompDocument)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		return nil, errors.New("Guest PID1 seccomp source drift")
	}
	private, ok := phase6security.Slice6PrivateConfigMount("guest-runtime")
	if !ok {
		return nil, errors.New("Guest PID1 private mount unavailable")
	}
	anchors, err := slice6AnchorMountArguments(profile, "guest-runtime", anchorFiles)
	if err != nil {
		return nil, err
	}
	owner := fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID)
	tmpfs := func(target string) string {
		return target + ":rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=" +
			strconv.FormatUint(uint64(plan.Principal.UID), 10) + ",gid=" +
			strconv.FormatUint(uint64(plan.Principal.GID), 10)
	}
	args := []string{"create", "--pull=never", "--name", "sr-p6-guest-runtime-" + run.id,
		"--label", run.label(), "--log-driver=none", "--network", productNetworkID,
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
			volume := sockets[mount.StorageID]
			if volume == "" || slice6VerifyGuestFixtureVolume(ctx, run, volume) != nil {
				return nil, errors.New("Guest private signer socket volume missing")
			}
			args = append(args, "--mount", "type=volume,src="+volume+",dst="+mount.Target+",readonly")
		case "guest_storage":
			volume := storage[mount.StorageID]
			if volume == "" {
				return nil, errors.New("Guest storage volume missing")
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
	return args, nil
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
	if err := slice6ValidateGuestRuntimeCreatedNetworks(found[0].NetworkSettings.Networks,
		plan, productNetworkID, internalNetworkID); err != nil {
		return err
	}
	for _, target := range []string{phase6security.Slice6GuestOutputsRoot, phase6security.Slice6GuestTempRoot} {
		if !slice6GuestRuntimeTmpfsMatches(found[0].HostConfig.Tmpfs[target],
			plan.Principal.UID, plan.Principal.GID) {
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

func slice6GuestRuntimeTmpfsMatches(options string, uid, gid uint32) bool {
	actual := strings.Split(options, ",")
	want := []string{"rw", "noexec", "nosuid", "nodev", "size=8388608", "mode=0700",
		"uid=" + strconv.FormatUint(uint64(uid), 10),
		"gid=" + strconv.FormatUint(uint64(gid), 10)}
	slices.Sort(actual)
	slices.Sort(want)
	return slices.Equal(actual, want)
}

type slice6GuestNetworkExpectation struct {
	id, name, ip string
}

func slice6GuestRuntimeNetworkExpectations(plan slice6GuestRuntimeLaunchPlan,
	productNetworkID, internalNetworkID string) ([2]slice6GuestNetworkExpectation, error) {
	want := [2]slice6GuestNetworkExpectation{
		{productNetworkID, plan.ProductNetwork.Name, plan.ProductIP},
		{internalNetworkID, plan.InternalNetwork.Name, plan.InternalIP},
	}
	if len(want[0].id) != 64 || len(want[1].id) != 64 ||
		!lowerHexSlice6(want[0].id) || !lowerHexSlice6(want[1].id) ||
		want[0].id == want[1].id || want[0].name == "" || want[1].name == "" ||
		want[0].name == want[1].name || want[0].ip == "" || want[1].ip == "" {
		return [2]slice6GuestNetworkExpectation{}, errors.New("Guest two-network target invalid")
	}
	return want, nil
}

// Docker can leave the effective NetworkID unset on a created container. The
// requested endpoint must still be present once, under exactly its name or ID.
func slice6ValidateGuestRuntimeCreatedNetworks(networks map[string]slice6MigrationNetworkEndpoint,
	plan slice6GuestRuntimeLaunchPlan, productNetworkID, internalNetworkID string) error {
	want, err := slice6GuestRuntimeNetworkExpectations(plan, productNetworkID, internalNetworkID)
	if err != nil || len(networks) != 2 {
		return errors.New("Guest created two-network inventory drift")
	}
	for _, target := range want {
		byID, hasID := networks[target.id]
		byName, hasName := networks[target.name]
		if hasID == hasName {
			return errors.New("Guest created network key missing or duplicated")
		}
		key, endpoint := target.id, byID
		if hasName {
			key, endpoint = target.name, byName
		}
		if err := slice6ValidateGuestFixtureCreatedNetwork(
			map[string]slice6MigrationNetworkEndpoint{key: endpoint},
			target.id, target.name, target.ip); err != nil {
			return errors.New("Guest created requested network or IP drift")
		}
	}
	return nil
}

func slice6ValidateGuestRuntimeRunningNetworks(networks map[string]slice6GuestFixtureRunningEndpoint,
	plan slice6GuestRuntimeLaunchPlan, productNetworkID, internalNetworkID string) error {
	want, err := slice6GuestRuntimeNetworkExpectations(plan, productNetworkID, internalNetworkID)
	if err != nil || len(networks) != 2 {
		return errors.New("Guest running two-network inventory drift")
	}
	for _, target := range want {
		byID, hasID := networks[target.id]
		byName, hasName := networks[target.name]
		if hasID == hasName {
			return errors.New("Guest running network key missing or duplicated")
		}
		key, endpoint := target.id, byID
		if hasName {
			key, endpoint = target.name, byName
		}
		if err := slice6ValidateGuestFixtureRunningNetwork(
			map[string]slice6GuestFixtureRunningEndpoint{key: endpoint},
			target.id, target.name, target.ip); err != nil {
			return errors.New("Guest running effective network or IP drift")
		}
	}
	return nil
}

func slice6VerifyGuestRuntimeRunningNetworks(ctx context.Context, run slice6DockerRun, id string,
	plan slice6GuestRuntimeLaunchPlan, productNetworkID, internalNetworkID string) error {
	member, err := slice6InspectProductRuntimeMember(ctx, run, id)
	if err != nil || member.ID != id || member.Name != "/sr-p6-guest-runtime-"+run.id {
		return errors.New("Guest running network witness PID1 unavailable")
	}
	raw, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		ID     string `json:"Id"`
		Name   string
		Config struct{ Labels map[string]string }
		State  struct {
			Running bool
			Pid     int
		}
		NetworkSettings struct {
			Networks map[string]slice6GuestFixtureRunningEndpoint
		}
	}
	if err != nil || json.Unmarshal(raw, &observed) != nil || len(observed) != 1 ||
		observed[0].ID != id || observed[0].Name != member.Name ||
		observed[0].Config.Labels[slice6RunLabel] != run.id ||
		!observed[0].State.Running || observed[0].State.Pid != member.State.Pid {
		return errors.New("Guest running network witness inspect unavailable")
	}
	return slice6ValidateGuestRuntimeRunningNetworks(observed[0].NetworkSettings.Networks,
		plan, productNetworkID, internalNetworkID)
}
