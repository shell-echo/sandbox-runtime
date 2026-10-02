//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The operator owns only empty, per-controller named-volume creation. A
// controller must create ledger.json itself; this diagnostic never seeds it.
func slice6PrepareControllerLedgerVolumes(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile) {
	t.Helper()
	if phase6security.VerifySlice6ControllerLedgerMounts(profile) != nil {
		t.Fatal("controller ledger allocations are not closed")
	}
	storage := make(map[string]bool)
	for _, deployment := range []string{"certificate-controller", "workload-credential-controller", "break-glass-controller"} {
		mount, ledgerPath, err := phase6security.Slice6ControllerLedgerMount(deployment)
		maxBytes := phase6security.Slice6ControllerLedgerMaxBytes
		if deployment == "break-glass-controller" {
			maxBytes = 128 << 20
		}
		if err != nil || mount.ReadOnly || mount.MaxBytes != maxBytes ||
			storage[mount.StorageID] || ledgerPath != mount.Target+"/ledger.json" {
			t.Fatal("controller persistent ledger identity is unavailable or shared")
		}
		storage[mount.StorageID] = true
		slice6PrepareOneControllerLedgerVolume(t, ctx, run, profile, deployment, mount)
	}
}

func slice6PrepareOneControllerLedgerVolume(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, deployment string, mount phase6security.Mount) {
	t.Helper()
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == deployment {
			principal = candidate
			break
		}
	}
	if principal.Name == "" || principal.UID == 0 || principal.GID == 0 {
		t.Fatal("controller ledger owner unavailable")
	}
	owner := fmt.Sprintf("%d:%d", principal.UID, principal.GID)
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	volume := "sr-p6-ledger-" + deployment + "-" + run.id
	created, err := run.docker(ctx, "volume", "create", "--label", run.label(), volume)
	if err != nil || strings.TrimSpace(string(created)) != volume {
		t.Fatal("create exact run-owned empty controller ledger volume")
	}
	volumeInspect, err := run.docker(ctx, "volume", "inspect", volume)
	var volumes []struct {
		Name   string            `json:"Name"`
		Driver string            `json:"Driver"`
		Labels map[string]string `json:"Labels"`
	}
	if err != nil || json.Unmarshal(volumeInspect, &volumes) != nil || len(volumes) != 1 ||
		volumes[0].Name != volume || volumes[0].Driver != "local" ||
		volumes[0].Labels[slice6RunLabel] != run.id {
		t.Fatal("controller ledger volume identity, driver or run ownership mismatch")
	}
	prepName := "sr-p6-ledger-prep-" + deployment + "-" + run.id
	prepScript := "set -eu; test -z \"$(ls -A /ledger)\"; chmod 0700 /ledger; chown " + owner + " /ledger"
	created, err = run.docker(ctx, "create", "--pull=never", "--name", prepName,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no", "--user=0:0",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp="+seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/ledger", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", prepScript)
	prepID := strings.TrimSpace(string(created))
	if err != nil || len(prepID) != 64 || !lowerHexSlice6(prepID) {
		t.Fatal("create restricted empty controller ledger prep")
	}
	inspect, err := run.docker(ctx, "inspect", prepID)
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
	if err != nil || json.Unmarshal(inspect, &containers) != nil || len(containers) != 1 {
		t.Fatal("inspect empty controller ledger prep")
	}
	host := containers[0].HostConfig
	seccompSource, err := os.ReadFile(seccomp)
	if err != nil {
		t.Fatal("read locked controller ledger prep seccomp")
	}
	var compactSeccomp bytes.Buffer
	if json.Compact(&compactSeccomp, seccompSource) != nil {
		t.Fatal("canonicalize locked controller ledger prep seccomp")
	}
	if containers[0].Config.User != "0:0" || host.NetworkMode != "none" || !host.ReadonlyRootfs ||
		host.Privileged || len(host.CapDrop) != 1 || host.CapDrop[0] != "ALL" ||
		len(host.CapAdd) != 1 || host.CapAdd[0] != "CAP_CHOWN" ||
		!slices.Contains(host.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(host.SecurityOpt, "seccomp="+compactSeccomp.String()) || host.LogConfig.Type != "none" ||
		host.Memory != 64<<20 ||
		host.NanoCpus != 500_000_000 || host.PidsLimit != 16 || len(host.Binds) != 0 ||
		len(host.Mounts) != 1 || host.Mounts[0].Type != "volume" || host.Mounts[0].Source != volume ||
		host.Mounts[0].Target != "/ledger" || host.Mounts[0].ReadOnly {
		t.Fatal("empty controller ledger prep hardening drifted")
	}
	if _, err := run.docker(ctx, "start", "-a", prepID); err != nil {
		t.Fatal("restricted empty controller ledger prep failed")
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", prepID)
	if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
		t.Fatal("controller ledger prep did not exit successfully")
	}
	if _, err := run.docker(ctx, "rm", prepID); err != nil {
		t.Fatal("remove controller ledger prep before runtime")
	}
	probe := "set -eu; test \"$(stat -c '%u:%g:%a' /ledger)\" = '" + owner +
		":700'; test -z \"$(ls -A /ledger)\"; if touch /ledger/denied 2>/dev/null; then exit 1; fi"
	if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-ledger-reader-"+deployment+"-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--user="+owner,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp="+seccomp,
		"--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/ledger,readonly", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", probe); err != nil {
		t.Fatal("controller UID could not verify its distinct empty ledger directory")
	}
	t.Logf("same-run %s persistent_ledger: storage=%s owner=%s empty 0700 directory and read-only observer; no controller file or restart",
		deployment, mount.StorageID, owner)
}
