//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const slice6CertificateProcessEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CERTIFICATE_PROCESS"
const slice6QuiesceProcessEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_QUIESCE_PROCESS"

// This opt-in diagnostic starts the second real controller while the first is
// live. Even two issued managed leaves do not constitute the 16-scenario gate
// or a proof that final shutdown's cyclic revocations are ordered safely.
func slice6RunCertificateControllerStartup(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, networkID, ip string, socketVolumes, anchorFiles map[string]string,
	config, bootstrapKey []byte, stopCredential func(), onTerminated func()) {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(socketVolumes) != 50 || len(config) == 0 || len(bootstrapKey) == 0 ||
		networkID == "" || ip == "" {
		t.Fatal("incomplete real certificate controller startup input")
	}
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "certificate-controller" {
			principal = candidate
			break
		}
	}
	if principal.Name == "" || principal.ImageLocation != "local" ||
		principal.ImageReference != principal.ImageDigest || principal.UID == 0 || principal.GID == 0 ||
		!principal.ReadOnlyRootFilesystem || !principal.NoNewPrivileges ||
		!slices.Equal(principal.DroppedCapabilities, []string{"ALL"}) ||
		principal.Resources.MemoryBytes < 64<<20 || principal.Resources.CPUMillis < 100 || principal.Resources.PIDs < 16 {
		t.Fatal("certificate controller immutable runtime constraints drifted")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccompPath := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompBytes, err := os.ReadFile(seccompPath)
	seccompDigest := sha256.Sum256(seccompBytes)
	if err != nil || principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		t.Fatal("certificate controller seccomp source drifted")
	}
	privateMount, privateNeeded := phase6security.Slice6PrivateConfigMount(principal.Name)
	_, ledgerPath, ledgerErr := phase6security.Slice6ControllerLedgerMount(principal.Name)
	if !privateNeeded || privateMount.Target != "/run/phase6/config" || ledgerErr != nil ||
		ledgerPath != "/var/lib/phase6-certificate-controller/ledger.json" {
		t.Fatal("certificate controller private or ledger mount drift")
	}
	nonce, err := phase6security.NewSlice6RunID()
	if err != nil {
		t.Fatal(err)
	}
	configVolume := "sr-p6-config-" + principal.Name + "-" + run.id
	ledgerVolume := "sr-p6-ledger-" + principal.Name + "-" + run.id
	arguments := []string{"create", "-i", "--pull=never", "--name", "sr-p6-certificate-live-" + run.id,
		"--label", run.label(), "--log-driver=none", "--network", networkID, "--ip", ip,
		"--restart=no", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccompPath,
		"--read-only", "--memory", strconv.FormatInt(principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(principal.Resources.PIDs, 10),
		"--mount", "type=volume,src=" + configVolume + ",dst=" + privateMount.Target + ",readonly",
		"--mount", "type=volume,src=" + ledgerVolume + ",dst=" + filepath.Dir(ledgerPath),
	}
	anchorArguments, err := slice6AnchorMountArguments(profile, principal.Name, anchorFiles)
	if err != nil {
		t.Fatal("certificate controller trust-anchor mounts unavailable")
	}
	arguments = append(arguments, anchorArguments...)
	socketMounts := 0
	credentialSocket, _, _, err := profile.CredentialIssuerSocketForClient(principal.Name)
	if err != nil {
		t.Fatal("certificate controller credential socket unavailable")
	}
	for _, mount := range principal.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		volume := socketVolumes[mount.StorageID]
		if volume == "" || (mount.StorageID == credentialSocket.SocketStorageID) != mount.ReadOnly {
			t.Fatal("certificate controller private socket mount drift")
		}
		value := "type=volume,src=" + volume + ",dst=" + mount.Target
		if mount.ReadOnly {
			value += ",readonly"
		}
		arguments = append(arguments, "--mount", value)
		socketMounts++
	}
	if socketMounts != 39 {
		t.Fatalf("certificate controller socket mount count drifted: %d", socketMounts)
	}
	arguments = append(arguments, "-e", "SR_PHASE6_FD_RUN_ID="+run.id,
		"-e", "SR_PHASE6_FD_TARGET=certificate-controller",
		"-e", "SR_PHASE6_FD_NONCE="+nonce, principal.ImageReference)
	created, err := run.docker(ctx, arguments...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create real certificate controller failed")
	}
	inspectDocument, err := run.docker(ctx, "inspect", id)
	var containers []struct {
		Image  string `json:"Image"`
		Config struct {
			Image      string   `json:"Image"`
			User       string   `json:"User"`
			Entrypoint []string `json:"Entrypoint"`
			Hostname   string   `json:"Hostname"`
		} `json:"Config"`
		HostConfig struct {
			ReadonlyRootfs bool   `json:"ReadonlyRootfs"`
			Privileged     bool   `json:"Privileged"`
			NetworkMode    string `json:"NetworkMode"`
		} `json:"HostConfig"`
	}
	if err != nil || json.Unmarshal(inspectDocument, &containers) != nil || len(containers) != 1 ||
		containers[0].Image != principal.ImageDigest || containers[0].Config.Image != principal.ImageReference ||
		containers[0].Config.User != fmt.Sprintf("%d:%d", principal.UID, principal.GID) ||
		containers[0].Config.Hostname != id[:12] || !containers[0].HostConfig.ReadonlyRootfs ||
		containers[0].HostConfig.Privileged || containers[0].HostConfig.NetworkMode != networkID ||
		!slices.Equal(containers[0].Config.Entrypoint, []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}) {
		t.Fatal("real certificate controller image, identity, entrypoint or isolation drifted")
	}
	credentialKey, err := slice6ReadPrivateSigningKey(composed.CredentialKeys["credential-"+principal.Name])
	if err != nil {
		t.Fatal("certificate controller credential signing key unavailable")
	}
	responseKey, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[profile.CertificateController.ResponseKeyID])
	if err != nil || phase6security.CertificateControllerPublicKeyDigest(responseKey.Public().(ed25519.PublicKey)) !=
		profile.CertificateController.ResponsePublicKeyDigest {
		clear(credentialKey)
		clear(responseKey)
		t.Fatal("certificate controller response signing key drifted")
	}
	requestKey, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[profile.CertificateController.ManagedRequestKeyID])
	if err != nil || phase6security.TLSAgentRequestPublicKeyDigest(requestKey.Public().(ed25519.PublicKey)) !=
		profile.CertificateController.ManagedRequestKeyDigest {
		clear(credentialKey)
		clear(responseKey)
		clear(requestKey)
		t.Fatal("certificate controller managed CSR signing key drifted")
	}
	envelope := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
		Target: "certificate-controller", ContainerID: id, Nonce: nonce,
		Config: bytes.Clone(config), Files: []phase6fdloader.PrivateFile{
			{FD: 3, Data: credentialKey}, {FD: 4, Data: responseKey},
			{FD: 5, Data: bytes.Clone(bootstrapKey)}, {FD: 6, Data: requestKey},
		}}
	defer envelope.Destroy()
	encoded, err := json.Marshal(envelope)
	if err != nil || envelope.Validate(phase6fdloader.Expected{RunID: run.id,
		Target: envelope.Target, Nonce: nonce, ContainerHostname: id[:12]}) != nil {
		clear(encoded)
		t.Fatal("real certificate controller private FD envelope invalid")
	}
	defer clear(encoded)
	type startResult struct {
		output []byte
		err    error
	}
	completed := make(chan startResult, 1)
	startupInput := bytes.Clone(encoded)
	go func() {
		command := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
		command.Stdin = bytes.NewReader(startupInput)
		output, startErr := command.CombinedOutput()
		clear(startupInput)
		completed <- startResult{output: output, err: startErr}
	}()
	var secondaryCredentialSocket string
	credentialPrincipal := phase6security.Principal{}
	for _, candidate := range profile.Principals {
		if candidate.Name == "workload-credential-controller" {
			credentialPrincipal = candidate
		}
	}
	for _, binding := range profile.CredentialIssuerSockets {
		if binding.ClientDeployment != principal.Name {
			secondaryCredentialSocket = binding.SocketPath
			break
		}
	}
	if secondaryCredentialSocket == "" || credentialPrincipal.UID == 0 || credentialPrincipal.GID == 0 {
		t.Fatal("credential managed readiness witness missing")
	}
	deadline := time.Now().Add(75 * time.Second)
	ready := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		ledgerDocument, ledgerErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
			id, "/bin/sh", "-ec", "cat "+ledgerPath)
		var ledger workloadpki.Ledger
		if ledgerErr == nil && len(ledgerDocument) <= 8<<20 && json.Unmarshal(ledgerDocument, &ledger) == nil {
			self, credential := false, false
			for _, record := range ledger.Certificates {
				self = self || record.PolicyID == profile.CertificateController.ManagedPolicyID && record.State == "active"
				credential = credential || record.PolicyID == profile.CertificateController.CredentialController.PolicyID && record.State == "active"
			}
			if self && credential {
				_, witnessErr := run.docker(ctx, "exec", "--user",
					fmt.Sprintf("%d:%d", credentialPrincipal.UID, credentialPrincipal.GID),
					"sr-p6-credential-live-"+run.id, "/bin/sh", "-ec", "test -S "+secondaryCredentialSocket)
				if witnessErr == nil {
					ready = true
					break
				}
			}
		}
		select {
		case result := <-completed:
			stage := slice6ControllerFailureStage(result.output)
			clear(result.output)
			t.Fatalf("real certificate controller exited before managed ledger and credential listener: stage=%s exit=%v", stage, result.err)
		case <-time.After(300 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("two-controller managed issuance and credential listener were not observed in time")
	}
	t.Log("real certificate controller PID1 issued self and credential managed leaves; credential controller opened post-switch listeners; final shutdown ordering not yet proven")
	if os.Getenv(slice6QuiesceProcessEnv) == "1" {
		for _, target := range []string{"sr-p6-credential-live-" + run.id, id} {
			if _, err := run.docker(ctx, "kill", "--signal=USR1", target); err != nil {
				t.Fatal("signal controller quiesce")
			}
		}
		credentialLedgerMount, credentialLedgerPath, ledgerErr := phase6security.Slice6ControllerLedgerMount("workload-credential-controller")
		if ledgerErr != nil || credentialLedgerMount.Target == "" {
			t.Fatal("credential controller ledger mount unavailable")
		}
		for _, witness := range []struct {
			id   string
			uid  uint32
			gid  uint32
			path string
		}{
			{"sr-p6-credential-live-" + run.id, credentialPrincipal.UID, credentialPrincipal.GID, credentialLedgerPath},
			{id, principal.UID, principal.GID, ledgerPath},
		} {
			quiesced := false
			for attempt := 0; attempt < 50 && ctx.Err() == nil; attempt++ {
				document, readErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", witness.uid, witness.gid),
					witness.id, "/bin/sh", "-ec", "cat "+witness.path)
				var ledger struct {
					QuiescedAt *time.Time `json:"quiesced_at"`
				}
				if readErr == nil && len(document) <= 8<<20 && json.Unmarshal(document, &ledger) == nil && ledger.QuiescedAt != nil {
					quiesced = true
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if !quiesced {
				t.Fatal("controller did not persist quiesce receipt")
			}
		}
		t.Log("both real controller PID1 processes persisted quiesce receipts before terminal shutdown")
	}
	stopCredential()
	if _, err := run.docker(ctx, "stop", "-t", "5", id); err != nil {
		t.Fatal("stop real certificate controller diagnostic")
	}
	select {
	case result := <-completed:
		stage := slice6ControllerFailureStage(result.output)
		clear(result.output)
		if result.err != nil {
			if onTerminated == nil || stage != "credential-revoke" {
				t.Fatalf("certificate controller did not shut down cleanly after credential controller: stage=%s exit=%v", stage, result.err)
			}
			t.Log("quiesced certificate controller retained a sticky terminal credential-revoke failure; independent operator cleanup required")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("certificate controller attached start did not drain")
	}
	if onTerminated != nil {
		onTerminated()
	}
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove stopped certificate controller diagnostic")
	}
}
