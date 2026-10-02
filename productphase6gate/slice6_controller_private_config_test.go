//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6ControllerPrivateConfigEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CONTROLLER_PRIVATE_CONFIG"

// These are same-run, source-bound inputs for the three controller UIDs.
// This does not launch a controller or claim a release scenario.
func slice6PrepareControllerPrivateConfigs(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs) {
	t.Helper()
	profileBytes, err := json.Marshal(composed.Profile)
	if err != nil {
		t.Fatal("encode same-run Profile")
	}
	peerBytes, err := json.Marshal(composed.PeerSources)
	if err != nil {
		t.Fatal("encode same-run peer-CRL sources")
	}
	defer clear(profileBytes)
	defer clear(peerBytes)
	for _, target := range []struct {
		deployment string
		files      map[string][]byte
	}{
		{"certificate-controller", map[string][]byte{
			phase6security.Slice6ProfileConfigFile:  profileBytes,
			phase6security.Slice6PeerCRLSourcesFile: peerBytes,
		}},
		{"workload-credential-controller", map[string][]byte{
			phase6security.Slice6ProfileConfigFile: profileBytes,
		}},
		{"break-glass-controller", map[string][]byte{
			phase6security.Slice6ProfileConfigFile: profileBytes,
		}},
	} {
		prepared, err := phase6security.BuildSlice6PrivateConfigArchive(composed.Profile, target.deployment, target.files)
		if err != nil {
			t.Fatalf("prepare real %s private files: %v", target.deployment, err)
		}
		slice6PrepareOneControllerPrivateConfig(t, ctx, run, composed.Profile, target.deployment, prepared)
	}
}

func slice6PrepareOneControllerPrivateConfig(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, deployment string, prepared phase6security.Slice6PrivateConfigArchive) {
	t.Helper()
	defer clear(prepared.Archive)
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == deployment {
			principal = candidate
			break
		}
	}
	mount, needed := phase6security.Slice6PrivateConfigMount(deployment)
	if !needed || principal.Name == "" || principal.UID == 0 || principal.GID == 0 || len(prepared.Digests) == 0 {
		t.Fatal("controller private-config owner or purpose unavailable")
	}
	names := strings.Split(mount.PrivateFiles, ",")
	if len(names) != len(prepared.Digests) || prepared.TotalBytes < 1 || prepared.TotalBytes > mount.MaxBytes {
		t.Fatal("controller private-config logical file budget unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	volume := "sr-p6-config-" + deployment + "-" + run.id
	created, err := run.docker(ctx, "volume", "create", "--label", run.label(), volume)
	if err != nil || strings.TrimSpace(string(created)) != volume {
		t.Fatal("create exact run-owned controller private-config volume")
	}
	owner := fmt.Sprintf("%d:%d", principal.UID, principal.GID)
	prepName := "sr-p6-config-prep-" + deployment + "-" + run.id
	prepScript := fmt.Sprintf("set -eu; test -z \"$(ls -A /config)\"; tar -xf - -C /config; "+
		"test \"$(find /config -mindepth 1 -maxdepth 1 | wc -l)\" -eq %d; "+
		"chmod 0700 /config; chmod 0600 /config/*; chown %s /config/* /config", len(names), owner)
	created, err = run.docker(ctx, "create", "-i", "--pull=never", "--name", prepName,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no", "--user=0:0",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp="+seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/config", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", prepScript)
	prepID := strings.TrimSpace(string(created))
	if err != nil || len(prepID) != 64 || !lowerHexSlice6(prepID) {
		t.Fatal("create restricted controller private-config prep container")
	}
	inspection, err := run.docker(ctx, "inspect", prepID)
	var containers []struct {
		Config     struct{ User string } `json:"Config"`
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
			LogConfig struct{ Type string } `json:"LogConfig"`
		} `json:"HostConfig"`
	}
	if err != nil || json.Unmarshal(inspection, &containers) != nil || len(containers) != 1 {
		t.Fatal("inspect restricted controller private-config prep")
	}
	host := containers[0].HostConfig
	seccompSource, err := os.ReadFile(seccomp)
	if err != nil {
		t.Fatal("read locked controller prep seccomp")
	}
	var compactSeccomp bytes.Buffer
	if json.Compact(&compactSeccomp, seccompSource) != nil {
		t.Fatal("canonicalize locked controller prep seccomp")
	}
	if containers[0].Config.User != "0:0" || host.NetworkMode != "none" || !host.ReadonlyRootfs ||
		host.Privileged || len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" ||
		len(host.CapAdd) != 1 || host.CapAdd[0] != "CAP_CHOWN" ||
		!slices.Contains(host.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(host.SecurityOpt, "seccomp="+compactSeccomp.String()) || host.LogConfig.Type != "none" ||
		host.Memory != 64<<20 ||
		host.NanoCpus != 500_000_000 || host.PidsLimit != 16 || len(host.Binds) != 0 ||
		len(host.Mounts) != 1 || host.Mounts[0].Type != "volume" || host.Mounts[0].Source != volume ||
		host.Mounts[0].Target != "/config" || host.Mounts[0].ReadOnly {
		t.Fatal("controller private-config prep hardening drifted")
	}
	start := exec.CommandContext(ctx, "docker", "start", "-a", "-i", prepID)
	start.Stdin = bytes.NewReader(prepared.Archive)
	if output, err := start.CombinedOutput(); err != nil {
		t.Fatalf("restricted controller private-config prep failed: %v: %.128q", err, output)
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", prepID)
	if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
		t.Fatal("controller private-config prep did not exit successfully")
	}
	if _, err := run.docker(ctx, "rm", prepID); err != nil {
		t.Fatal("remove controller prep before any runtime reader")
	}
	var reader strings.Builder
	fmt.Fprintf(&reader, "set -eu; test \"$(stat -c '%%u:%%g:%%a' /config)\" = '%s:700'; ", owner)
	fmt.Fprintf(&reader, "test \"$(find /config -mindepth 1 -maxdepth 1 | wc -l)\" -eq %d; ", len(names))
	for _, name := range names {
		digest := strings.TrimPrefix(prepared.Digests[name], "sha256:")
		if len(digest) != 64 || !lowerHexSlice6(digest) {
			t.Fatal("invalid controller private file digest")
		}
		fmt.Fprintf(&reader, "test \"$(stat -c '%%u:%%g:%%a' /config/%s)\" = '%s:600'; ", name, owner)
		fmt.Fprintf(&reader, "test \"$(sha256sum /config/%s)\" = '%s  /config/%s'; ", name, digest, name)
	}
	reader.WriteString("if touch /config/denied 2>/dev/null; then exit 1; fi")
	if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-config-reader-"+deployment+"-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--user="+owner,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp="+seccomp,
		"--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/config,readonly", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", reader.String()); err != nil {
		t.Fatal("controller UID could not reopen exact read-only private file set")
	}
	t.Logf("same-run %s private_config: owner=%s files=%d logical_bytes=%d exact digests/modes and read-only denial; no controller process",
		deployment, owner, len(names), prepared.TotalBytes)
}
