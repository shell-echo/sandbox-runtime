//go:build phase6slice6gate

package productphase6gate

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Docker Desktop keeps named-volume contents in the daemon's Linux VM. A
// verified, root-owned file in each exact run-owned volume can be mounted as
// one read-only file at the Profile target. No CA key, host source path or
// daemon mountpoint is added to the stable Profile or process configuration.
func slice6PrepareTrustAnchorVolumes(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs) map[string]string {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalTrustAnchors(composed.Profile) != nil ||
		len(composed.AnchorPaths) != len(composed.Profile.TrustAnchors) {
		t.Fatal("same-run trust-anchor inventory drift")
	}
	result := make(map[string]string, len(composed.Profile.TrustAnchors))
	for _, anchor := range composed.Profile.TrustAnchors {
		if result[anchor.StorageID] != "" {
			t.Fatal("trust-anchor storage alias")
		}
		result[anchor.StorageID] = slice6PrepareOneTrustAnchorVolume(t, ctx, run, anchor,
			composed.AnchorPaths[anchor.ID])
	}
	return result
}

func slice6PrepareOneTrustAnchorVolume(t *testing.T, ctx context.Context, run slice6DockerRun,
	anchor phase6security.TrustAnchor, sourcePath string) string {
	t.Helper()
	if anchor.OwnerUID != 0 || anchor.OwnerGID != 0 || anchor.WriterAuthority != "operator" ||
		!filepath.IsAbs(sourcePath) || strings.ContainsAny(anchor.StorageID, "/\\\x00\n\r ") ||
		anchor.StorageID == "" || !strings.HasPrefix(anchor.TargetPath, "/run/trust/") {
		t.Fatal("unsafe trust-anchor staging input")
	}
	info, err := os.Lstat(sourcePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Size() < 1 || info.Size() > 256<<10 {
		t.Fatal("unsafe same-run source CA bundle")
	}
	bundle, err := os.ReadFile(sourcePath)
	digest := sha256.Sum256(bundle)
	if err != nil || "sha256:"+hex.EncodeToString(digest[:]) != anchor.BundleDigest {
		t.Fatal("same-run source CA bundle digest drift")
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: "bundle.pem", Mode: 0o444, Size: int64(len(bundle))}); err != nil {
		t.Fatal("encode trust-anchor archive header")
	}
	if _, err := writer.Write(bundle); err != nil {
		t.Fatal("encode trust-anchor archive payload")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("encode exact public trust-anchor archive")
	}
	volume := "sr-p6-anchor-" + anchor.StorageID + "-" + run.id
	created, err := run.docker(ctx, "volume", "create", "--label", run.label(), volume)
	if err != nil || strings.TrimSpace(string(created)) != volume {
		t.Fatal("create exact run-owned trust-anchor volume")
	}
	volumeDocument, err := run.docker(ctx, "volume", "inspect", volume)
	var volumes []struct {
		Name       string            `json:"Name"`
		Driver     string            `json:"Driver"`
		Mountpoint string            `json:"Mountpoint"`
		Labels     map[string]string `json:"Labels"`
	}
	if err != nil || json.Unmarshal(volumeDocument, &volumes) != nil || len(volumes) != 1 ||
		volumes[0].Name != volume || volumes[0].Driver != "local" || volumes[0].Labels[slice6RunLabel] != run.id ||
		!filepath.IsAbs(volumes[0].Mountpoint) || filepath.Clean(volumes[0].Mountpoint) != volumes[0].Mountpoint ||
		filepath.Base(volumes[0].Mountpoint) != "_data" ||
		filepath.Base(filepath.Dir(volumes[0].Mountpoint)) != volume {
		t.Fatal("trust-anchor volume driver, mountpoint or run ownership drift")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	name := "sr-p6-anchor-prep-" + anchor.ID + "-" + run.id
	created, err = run.docker(ctx, "create", "-i", "--pull=never", "--name", name,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no", "--user=0:0",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp="+seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/anchor", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", "set -eu; test -z \"$(ls -A /anchor)\"; tar -xf - -C /anchor; "+
			"test \"$(find /anchor -mindepth 1 -maxdepth 1 | wc -l)\" -eq 1; "+
			"chmod 0444 /anchor/bundle.pem; chown 0:0 /anchor/bundle.pem")
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create restricted trust-anchor prep")
	}
	inspectDocument, err := run.docker(ctx, "inspect", id)
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
	if err != nil || json.Unmarshal(inspectDocument, &containers) != nil || len(containers) != 1 {
		t.Fatal("inspect restricted trust-anchor prep")
	}
	seccompDocument, err := os.ReadFile(seccomp)
	if err != nil {
		t.Fatal(err)
	}
	var compactSeccomp bytes.Buffer
	if json.Compact(&compactSeccomp, seccompDocument) != nil {
		t.Fatal("canonicalize locked trust-anchor prep seccomp")
	}
	host := containers[0].HostConfig
	if containers[0].Config.User != "0:0" || host.NetworkMode != "none" || !host.ReadonlyRootfs ||
		host.Privileged || !slices.Equal(host.CapDrop, []string{"ALL"}) ||
		!slices.Equal(host.CapAdd, []string{"CAP_CHOWN"}) ||
		!slices.Contains(host.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(host.SecurityOpt, "seccomp="+compactSeccomp.String()) ||
		host.Memory != 64<<20 || host.NanoCpus != 500_000_000 || host.PidsLimit != 16 ||
		host.LogConfig.Type != "none" || len(host.Binds) != 0 || len(host.Mounts) != 1 ||
		host.Mounts[0].Type != "volume" || host.Mounts[0].Source != volume ||
		host.Mounts[0].Target != "/anchor" || host.Mounts[0].ReadOnly {
		t.Fatal("restricted trust-anchor prep hardening drift")
	}
	command := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
	command.Stdin = bytes.NewReader(archive.Bytes())
	if output, startErr := command.CombinedOutput(); startErr != nil {
		t.Fatalf("restricted trust-anchor prep failed: %v: %.128q", startErr, output)
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", id)
	if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
		t.Fatal("restricted trust-anchor prep did not exit successfully")
	}
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove exact trust-anchor prep before runtime")
	}
	fileSource := volumes[0].Mountpoint + "/bundle.pem"
	probe := "test \"$(stat -c '%u:%g:%a' " + anchor.TargetPath + ")\" = '0:0:444' && " +
		"test \"$(sha256sum " + anchor.TargetPath + ")\" = '" + hex.EncodeToString(digest[:]) + "  " + anchor.TargetPath + "'"
	if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--network=none", "--read-only",
		"--user", "65532:65532", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--mount", "type=bind,src="+fileSource+",dst="+anchor.TargetPath+",readonly",
		slice6PinnedAlpineImage, "/bin/sh", "-ec", probe); err != nil {
		t.Fatal("non-root trust-anchor file bind, owner, mode or digest observation failed")
	}
	return fileSource
}

func slice6AnchorMountArguments(profile phase6security.Profile, deployment string,
	files map[string]string) ([]string, error) {
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == deployment {
			principal = candidate
			break
		}
	}
	if principal.Name == "" || len(files) != len(profile.TrustAnchors) {
		return nil, fmt.Errorf("unavailable trust-anchor mount inventory")
	}
	byStorage := make(map[string]phase6security.TrustAnchor, len(profile.TrustAnchors))
	for _, anchor := range profile.TrustAnchors {
		byStorage[anchor.StorageID] = anchor
	}
	var arguments []string
	for _, mount := range principal.Mounts {
		if mount.Kind != "trust_anchor" {
			continue
		}
		anchor, ok := byStorage[mount.StorageID]
		source := files[mount.StorageID]
		if !ok || !mount.ReadOnly || mount.Target != anchor.TargetPath || source == "" {
			return nil, fmt.Errorf("trust-anchor consumer mount drift")
		}
		arguments = append(arguments, "--mount", "type=bind,src="+source+",dst="+mount.Target+",readonly")
	}
	if len(arguments) == 0 {
		return nil, fmt.Errorf("trust-anchor consumer missing")
	}
	return arguments, nil
}
