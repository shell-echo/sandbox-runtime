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

// These volumes are fresh socket-directory allocations, not a socket server.
// Each issuance client has an independent storage ID, GID and volume. The
// reverse managed-CSR edge is a different volume owned by the certificate
// controller and mounted read-only by the credential controller.
func slice6PrepareCredentialControllerSocketVolumes(t *testing.T, ctx context.Context,
	run slice6DockerRun, profile phase6security.Profile) map[string]string {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(profile.CredentialIssuerSockets) != 12 {
		t.Fatal("incomplete same-run credential socket inventory")
	}
	result := make(map[string]string, 13)
	var credential, certificate phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "workload-credential-controller":
			credential = principal
		case "certificate-controller":
			certificate = principal
		}
	}
	if credential.UID == 0 || credential.GID == 0 || certificate.UID == 0 || certificate.GID == 0 {
		t.Fatal("controller socket owners unavailable")
	}
	for _, binding := range profile.CredentialIssuerSockets {
		_, server, client, err := profile.CredentialIssuerSocketForClient(binding.ClientDeployment)
		if err != nil || server.Name != credential.Name || client.Name != binding.ClientDeployment ||
			client.GID == credential.GID || result[binding.SocketStorageID] != "" {
			t.Fatal("credential issuer socket owner or storage alias")
		}
		result[binding.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
			binding.SocketStorageID, binding.SocketDirectory, credential.UID, client.GID, 0o710)
	}
	reverse := profile.CertificateController.CredentialController
	if reverse.SocketStorageID == "" || reverse.SocketDirectory == "" ||
		result[reverse.SocketStorageID] != "" || reverse.DirectoryMode != 0o710 {
		t.Fatal("reverse credential CSR socket drift")
	}
	result[reverse.SocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		reverse.SocketStorageID, reverse.SocketDirectory, certificate.UID, credential.GID, reverse.DirectoryMode)
	if len(result) != 13 {
		t.Fatal("credential socket volume count drift")
	}
	return result
}

// Certificate-controller sockets are additional independent allocations. The
// reverse credential-managed CSR directory was allocated above because the
// credential process needs to mount it before the certificate process starts.
func slice6PrepareCertificateControllerSocketVolumes(t *testing.T, ctx context.Context,
	run slice6DockerRun, profile phase6security.Profile, credentialVolumes map[string]string) map[string]string {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(credentialVolumes) != 13 || len(profile.TLSAgentBindings)+len(profile.PostgresClientAgents) != 36 {
		t.Fatal("incomplete same-run certificate socket inventory")
	}
	result := make(map[string]string, len(credentialVolumes)+37)
	for storageID, volume := range credentialVolumes {
		if storageID == "" || volume == "" {
			t.Fatal("credential socket allocation missing")
		}
		result[storageID] = volume
	}
	authority := profile.CertificateController
	if authority.SelfSocketStorageID == "" || result[authority.SelfSocketStorageID] != "" ||
		authority.SelfDirectoryMode != 0o700 {
		t.Fatal("certificate self socket inventory drift")
	}
	result[authority.SelfSocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
		authority.SelfSocketStorageID, authority.SelfSocketDirectory, authority.UID, authority.GID,
		authority.SelfDirectoryMode)
	addAgent := func(binding phase6security.TLSAgentBinding) {
		t.Helper()
		if binding.ControllerSocketStorageID == "" || result[binding.ControllerSocketStorageID] != "" ||
			binding.ControllerUID != authority.UID || binding.ControllerGID != authority.GID ||
			binding.ControllerDirectoryMode != 0o710 || binding.AgentGID == authority.GID {
			t.Fatal("certificate agent socket inventory drift")
		}
		result[binding.ControllerSocketStorageID] = slice6PrepareOneControllerSocketVolume(t, ctx, run,
			binding.ControllerSocketStorageID, binding.ControllerSocketDirectory,
			authority.UID, binding.AgentGID, binding.ControllerDirectoryMode)
	}
	for _, binding := range profile.TLSAgentBindings {
		addAgent(binding)
	}
	for _, binding := range profile.PostgresClientAgents {
		addAgent(binding.TLSAgentBinding)
	}
	if len(result) != 50 || result[authority.CredentialController.SocketStorageID] == "" {
		t.Fatal("certificate socket allocation count or reverse CSR socket drift")
	}
	return result
}

func slice6PrepareOneControllerSocketVolume(t *testing.T, ctx context.Context, run slice6DockerRun,
	storageID, directory string, uid, gid, directoryMode uint32) string {
	t.Helper()
	if storageID == "" || strings.ContainsAny(storageID, "/\\\x00\n\r ") ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		uid == 0 || gid == 0 || directoryMode != 0o700 && directoryMode != 0o710 {
		t.Fatal("invalid controller socket volume input")
	}
	volume := "sr-p6-socket-" + storageID + "-" + run.id
	created, err := run.docker(ctx, "volume", "create", "--label", run.label(), volume)
	if err != nil || strings.TrimSpace(string(created)) != volume {
		t.Fatal("create exact run-owned socket volume")
	}
	volumeDocument, err := run.docker(ctx, "volume", "inspect", volume)
	var observed []struct {
		Name   string            `json:"Name"`
		Driver string            `json:"Driver"`
		Labels map[string]string `json:"Labels"`
	}
	if err != nil || json.Unmarshal(volumeDocument, &observed) != nil || len(observed) != 1 ||
		observed[0].Name != volume || observed[0].Driver != "local" ||
		observed[0].Labels[slice6RunLabel] != run.id {
		t.Fatal("socket volume identity, driver or ownership drift")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	owner := fmt.Sprintf("%d:%d", uid, gid)
	name := "sr-p6-socket-prep-" + storageID + "-" + run.id
	prepScript := "set -eu; test -z \"$(ls -A /socket)\"; chmod " +
		fmt.Sprintf("%04o", directoryMode) + " /socket; chown " + owner + " /socket"
	created, err = run.docker(ctx, "create", "--pull=never", "--name", name,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no", "--user=0:0",
		"--cap-drop=ALL", "--cap-add=CHOWN", "--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp="+seccomp, "--read-only", "--memory=64m", "--cpus=0.5", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/socket", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", prepScript)
	prepID := strings.TrimSpace(string(created))
	if err != nil || len(prepID) != 64 || !lowerHexSlice6(prepID) {
		t.Fatal("create restricted socket volume prep")
	}
	inspectDocument, err := run.docker(ctx, "inspect", prepID)
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
		t.Fatal("inspect restricted socket prep")
	}
	seccompDocument, err := os.ReadFile(seccomp)
	if err != nil {
		t.Fatal("read locked socket prep seccomp")
	}
	var compactSeccomp bytes.Buffer
	if json.Compact(&compactSeccomp, seccompDocument) != nil {
		t.Fatal("canonicalize locked socket prep seccomp")
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
		host.Mounts[0].Target != "/socket" || host.Mounts[0].ReadOnly {
		t.Fatal("restricted socket prep hardening drift")
	}
	if _, err := run.docker(ctx, "start", "-a", prepID); err != nil {
		t.Fatal("restricted socket prep failed")
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", prepID)
	if err != nil || strings.TrimSpace(string(state)) != "exited:0" {
		t.Fatal("restricted socket prep did not exit successfully")
	}
	if _, err := run.docker(ctx, "rm", prepID); err != nil {
		t.Fatal("remove exact socket prep before runtime")
	}
	probe := "set -eu; test \"$(stat -c '%u:%g:%a' /socket)\" = '" + owner + ":" +
		fmt.Sprintf("%o", directoryMode) + "'; " +
		"test -z \"$(ls -A /socket)\"; if touch /socket/denied 2>/dev/null; then exit 1; fi"
	if _, err := run.docker(ctx, "run", "--rm", "--pull=never",
		"--name", "sr-p6-socket-reader-"+storageID+"-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--user", owner,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--mount", "type=volume,src="+volume+",dst=/socket,readonly", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", probe); err != nil {
		t.Fatal("socket volume owner/mode/emptiness/read-only observation failed")
	}
	return volume
}
