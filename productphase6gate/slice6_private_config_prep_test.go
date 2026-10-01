//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6PrivateConfigPrepEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_PRIVATE_CONFIG_PREP"
const slice6PinnedAlpineImage = "docker.io/library/alpine@sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"

// This tests the exact one-shot root preparation mechanism with non-secret
// fixture bytes. It is not a substitute for preparing 75 real principal file
// sets or observing their final read-only mounts in the Slice 6 release gate.
func TestPhase6Slice6PrivateConfigPrepRestrictedDocker(t *testing.T) {
	if os.Getenv(slice6PrivateConfigPrepEnv) != "1" {
		t.Skip("set " + slice6PrivateConfigPrepEnv + "=1 for restricted Docker private-config preparation")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact private-config prep cleanup: %v", err)
		}
	})
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	volume := "sr-p6-private-config-" + run.id
	if _, err := run.docker(ctx, "volume", "create", "--label", run.label(), volume); err != nil {
		t.Fatal("create exact run-owned private-config volume")
	}
	const uid, gid = "62001", "62002"
	// Exercise the same exact archive builder that the final per-principal
	// runner must use. This synthetic Profile is only a mechanism fixture.
	profile := phase6security.Profile{}
	for _, name := range phase6security.Slice6DesiredDeploymentNames() {
		principal := phase6security.Principal{Name: name}
		if mount, needed := phase6security.Slice6PrivateConfigMount(name); needed {
			principal.Mounts = []phase6security.Mount{mount}
		}
		profile.Principals = append(profile.Principals, principal)
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := phase6security.BuildSlice6PrivateConfigArchive(profile, "workload-credential-controller",
		map[string][]byte{phase6security.Slice6ProfileConfigFile: profileBytes})
	if err != nil {
		t.Fatal("build exact private-config preparation archive")
	}
	defer clear(prepared.Archive)
	prepName := "sr-p6-private-prep-" + run.id
	prepScript := "set -eu; test -z \"$(ls -A /config)\"; tar -xf - -C /config; " +
		"test \"$(find /config -mindepth 1 -maxdepth 1 | wc -l)\" -eq 1; " +
		"chmod 0700 /config; chmod 0600 /config/profile.json; chown " + uid + ":" + gid + " /config/profile.json /config"
	prepArguments := []string{"create", "-i", "--pull=never", "--name", prepName,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no", "--user=0:0",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp=" + seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src=" + volume + ",dst=/config", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", prepScript}
	created, err := run.docker(ctx, prepArguments...)
	prepID := strings.TrimSpace(string(created))
	if err != nil || len(prepID) != 64 || !lowerHexSlice6(prepID) {
		t.Fatal("create restricted one-shot prep container")
	}
	inspected, err := run.docker(ctx, "inspect", prepID)
	var inspectedContainers []struct {
		Config struct {
			User string `json:"User"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string   `json:"NetworkMode"`
			ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
			Privileged     bool     `json:"Privileged"`
			CapDrop        []string `json:"CapDrop"`
			CapAdd         []string `json:"CapAdd"`
			SecurityOpt    []string `json:"SecurityOpt"`
			Memory         int64    `json:"Memory"`
			NanoCpus       int64    `json:"NanoCpus"`
			PidsLimit      int64    `json:"PidsLimit"`
			Binds          []string `json:"Binds"`
			Mounts         []struct {
				Type, Source, Target string
				ReadOnly             bool
			} `json:"Mounts"`
			LogConfig struct {
				Type string `json:"Type"`
			} `json:"LogConfig"`
		} `json:"HostConfig"`
	}
	if err != nil || json.Unmarshal(inspected, &inspectedContainers) != nil || len(inspectedContainers) != 1 {
		t.Fatal("inspect prep hardening unavailable")
	}
	host := inspectedContainers[0].HostConfig
	seccompSource, err := os.ReadFile(seccomp)
	if err != nil {
		t.Fatal("read locked prep seccomp source")
	}
	var compactSeccomp bytes.Buffer
	if json.Compact(&compactSeccomp, seccompSource) != nil {
		t.Fatal("compact locked prep seccomp source")
	}
	seccompMatches := slices.Contains(host.SecurityOpt, "seccomp="+compactSeccomp.String())
	if inspectedContainers[0].Config.User != "0:0" || host.NetworkMode != "none" || !host.ReadonlyRootfs ||
		host.Privileged || !slices.Equal(host.CapDrop, []string{"ALL"}) || !slices.Equal(host.CapAdd, []string{"CAP_CHOWN"}) ||
		!slices.Contains(host.SecurityOpt, "no-new-privileges:true") || !seccompMatches ||
		host.Memory != 64<<20 || host.NanoCpus != 500_000_000 || host.PidsLimit != 16 || len(host.Binds) != 0 ||
		len(host.Mounts) != 1 || host.Mounts[0].Type != "volume" || host.Mounts[0].Source != volume ||
		host.Mounts[0].Target != "/config" || host.Mounts[0].ReadOnly || host.LogConfig.Type != "none" {
		t.Fatalf("prep container effective hardening differs: user=%q network=%q ro=%v privileged=%v drop=%v add=%v securityOptCount=%d seccompMatch=%v memory=%d cpu=%d pids=%d binds=%v mounts=%+v log=%q",
			inspectedContainers[0].Config.User, host.NetworkMode, host.ReadonlyRootfs, host.Privileged,
			host.CapDrop, host.CapAdd, len(host.SecurityOpt), seccompMatches, host.Memory, host.NanoCpus, host.PidsLimit,
			host.Binds, host.Mounts, host.LogConfig.Type)
	}
	start := exec.CommandContext(ctx, "docker", "start", "-a", "-i", prepID)
	start.Stdin = bytes.NewReader(prepared.Archive)
	if output, err := start.CombinedOutput(); err != nil {
		state, _ := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}:{{.State.Error}}", prepID)
		t.Fatalf("restricted one-shot private-config prep failed: %v, state=%q, output=%.256q", err, state, output)
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", prepID)
	if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
		t.Fatal("prep did not exit successfully before runtime")
	}
	if _, err := run.docker(ctx, "rm", prepID); err != nil {
		t.Fatal("remove exact prep container before runtime")
	}
	retryArguments := slices.Clone(prepArguments)
	for index := range retryArguments {
		if retryArguments[index] == "--name" {
			retryArguments[index+1] = "sr-p6-private-prep-retry-" + run.id
		}
	}
	retryCreated, err := run.docker(ctx, retryArguments...)
	retryID := strings.TrimSpace(string(retryCreated))
	if err != nil || len(retryID) != 64 || !lowerHexSlice6(retryID) {
		t.Fatal("create nonempty-volume rejection probe")
	}
	retry := exec.CommandContext(ctx, "docker", "start", "-a", "-i", retryID)
	retry.Stdin = bytes.NewReader(prepared.Archive)
	if _, err := retry.CombinedOutput(); err == nil {
		t.Fatal("one-shot prep accepted a preexisting nonempty volume")
	}
	if _, err := run.docker(ctx, "rm", retryID); err != nil {
		t.Fatal("remove exact nonempty-volume rejection probe")
	}
	expected := strings.TrimPrefix(prepared.Digests[phase6security.Slice6ProfileConfigFile], "sha256:") +
		"  /config/profile.json"
	readerScript := "set -eu; test \"$(stat -c '%u:%g:%a' /config)\" = '" + uid + ":" + gid + ":700'; " +
		"test \"$(stat -c '%u:%g:%a' /config/profile.json)\" = '" + uid + ":" + gid + ":600'; " +
		"test \"$(find /config -mindepth 1 -maxdepth 1 | wc -l)\" -eq 1; " +
		"test \"$(sha256sum /config/profile.json)\" = '" + expected + "'; " +
		"if touch /config/denied 2>/dev/null; then exit 1; fi"
	if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-private-reader-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--user="+uid+":"+gid,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp="+seccomp,
		"--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/config,readonly", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", readerScript); err != nil {
		t.Fatal("non-root read-only private-config ownership, digest or write denial failed")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatal("exact private-config prep resource cleanup failed")
	}
	t.Log("restricted one-shot root prep, distinct non-root owner, file digest, read-only write denial and exact cleanup passed; fixture component only")
}
