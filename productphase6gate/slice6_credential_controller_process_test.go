//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6CredentialProcessEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CREDENTIAL_PROCESS"

// This diagnostic starts the real R19 credential-controller image, not an
// Alpine stand-in. It can only prove the bounded bootstrap phase until the
// separate certificate controller is also running and able to sign its CSR.
func slice6RunCredentialControllerBootstrap(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, networkID, ip string, socketVolumes, anchorFiles map[string]string,
	config, managementToken, bootstrapKey []byte, onBootstrapReady func(stopCredential func())) {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(socketVolumes) != 13 || len(config) == 0 || len(managementToken) == 0 || len(bootstrapKey) == 0 {
		t.Fatal("incomplete real credential controller startup input")
	}
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "workload-credential-controller" {
			principal = candidate
			break
		}
	}
	if principal.Name == "" || principal.ImageLocation != "local" ||
		principal.ImageReference != principal.ImageDigest || principal.UID == 0 || principal.GID == 0 ||
		!principal.ReadOnlyRootFilesystem || !principal.NoNewPrivileges ||
		!slices.Equal(principal.DroppedCapabilities, []string{"ALL"}) ||
		principal.Resources.MemoryBytes < 64<<20 || principal.Resources.CPUMillis < 100 || principal.Resources.PIDs < 16 ||
		ip == "" || networkID == "" {
		t.Fatal("credential controller immutable runtime constraints drifted")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccompPath := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompBytes, err := os.ReadFile(seccompPath)
	seccompDigest := sha256.Sum256(seccompBytes)
	if err != nil || principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		t.Fatal("credential controller seccomp source drifted")
	}
	nonce, err := phase6security.NewSlice6RunID()
	if err != nil {
		t.Fatal(err)
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount(principal.Name)
	privateMount, privateNeeded := phase6security.Slice6PrivateConfigMount(principal.Name)
	if err != nil || !privateNeeded || privateMount.Target != "/run/phase6/config" ||
		ledgerPath != "/var/lib/phase6-credential-controller/ledger.json" {
		t.Fatal("credential controller private mount drift")
	}
	configVolume := "sr-p6-config-" + principal.Name + "-" + run.id
	ledgerVolume := "sr-p6-ledger-" + principal.Name + "-" + run.id
	arguments := []string{"create", "-i", "--pull=never", "--name", "sr-p6-credential-live-" + run.id,
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
		t.Fatal("credential controller trust-anchor mounts unavailable")
	}
	arguments = append(arguments, anchorArguments...)
	for _, binding := range profile.CredentialIssuerSockets {
		volume := socketVolumes[binding.SocketStorageID]
		if volume == "" {
			t.Fatal("credential issuer volume omitted")
		}
		arguments = append(arguments, "--mount", "type=volume,src="+volume+",dst="+binding.SocketDirectory)
	}
	reverse := profile.CertificateController.CredentialController
	if socketVolumes[reverse.SocketStorageID] == "" {
		t.Fatal("reverse managed CSR volume omitted")
	}
	arguments = append(arguments,
		"--mount", "type=volume,src="+socketVolumes[reverse.SocketStorageID]+",dst="+reverse.SocketDirectory+",readonly",
		"-e", "SR_PHASE6_FD_RUN_ID="+run.id,
		"-e", "SR_PHASE6_FD_TARGET=workload-credential-controller-v2",
		"-e", "SR_PHASE6_FD_NONCE="+nonce, principal.ImageReference)
	created, err := run.docker(ctx, arguments...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create real credential controller failed")
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
		t.Fatal("real credential controller image, identity, entrypoint or isolation drifted")
	}
	requestKey, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[reverse.RequestKeyID])
	if err != nil || phase6security.TLSAgentRequestPublicKeyDigest(requestKey.Public().(ed25519.PublicKey)) != reverse.RequestKeyDigest {
		clear(requestKey)
		t.Fatal("credential managed CSR private key drifted")
	}
	envelope := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
		Target: "workload-credential-controller-v2", ContainerID: id, Nonce: nonce,
		Config: bytes.Clone(config), Files: []phase6fdloader.PrivateFile{
			{FD: 3, Data: bytes.Clone(managementToken)},
			{FD: 4, Data: bytes.Clone(bootstrapKey)},
			{FD: 5, Data: requestKey},
		}}
	defer envelope.Destroy()
	encoded, err := json.Marshal(envelope)
	if err != nil || envelope.Validate(phase6fdloader.Expected{RunID: run.id,
		Target: envelope.Target, Nonce: nonce, ContainerHostname: id[:12]}) != nil {
		clear(encoded)
		t.Fatal("real controller private FD envelope invalid")
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
	bootstrapSocket, bootstrapStorageID := "", ""
	for _, binding := range profile.CredentialIssuerSockets {
		if binding.ClientDeployment == "certificate-controller" {
			bootstrapSocket, bootstrapStorageID = binding.SocketPath, binding.SocketStorageID
		}
	}
	if bootstrapSocket == "" || socketVolumes[bootstrapStorageID] == "" {
		t.Fatal("certificate controller bootstrap socket missing")
	}
	deadline := time.Now().Add(30 * time.Second)
	ready := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		probe := "test -S " + bootstrapSocket + " && test -f " + ledgerPath +
			" && test \"$(stat -c '%u:%g:%a' " + ledgerPath + ")\" = '" +
			fmt.Sprintf("%d:%d:600", principal.UID, principal.GID) + "'"
		if _, probeErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
			id, "/bin/sh", "-ec", probe); probeErr == nil {
			ready = true
			break
		}
		select {
		case result := <-completed:
			stage := slice6ControllerFailureStage(result.output)
			clear(result.output)
			t.Fatalf("real credential controller exited before bootstrap listener and ledger: stage=%s, exit=%v", stage, result.err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("real credential controller bootstrap listener and ledger not observed in time")
	}
	t.Log("real R19 credential controller PID1 reached private certificate-client listener and created its own ledger; managed PKI switch not yet proven")
	stopped := false
	stopCredential := func() {
		t.Helper()
		if stopped {
			t.Fatal("credential controller diagnostic stopped twice")
		}
		if _, err := run.docker(ctx, "stop", "-t", "5", id); err != nil {
			t.Fatal("stop real credential controller diagnostic")
		}
		select {
		case result := <-completed:
			// Before the peer exists, a deliberate TERM can report managed-client
			// unavailable. After the peer exists, shutdown must be clean.
			if result.err != nil && (onBootstrapReady != nil ||
				!bytes.Contains(result.output, []byte("stage managed-client"))) {
				clear(result.output)
				t.Fatal("real credential controller failed outside expected pre-switch cancellation")
			}
			clear(result.output)
		case <-time.After(15 * time.Second):
			t.Fatal("real credential controller attached start did not drain")
		}
		if _, err := run.docker(ctx, "rm", id); err != nil {
			t.Fatal("remove stopped credential controller diagnostic")
		}
		if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--network=none",
			"--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID), "--cap-drop=ALL", "--read-only",
			"--mount", "type=volume,src="+ledgerVolume+",dst=/ledger,readonly", slice6PinnedAlpineImage,
			"/bin/sh", "-ec", "test -f /ledger/ledger.json && test -z \"$(find /ledger -mindepth 1 -maxdepth 1 ! -name ledger.json)\""); err != nil {
			t.Fatal("credential controller ledger ownership or exact file cleanup failed")
		}
		if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--network=none",
			"--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID), "--cap-drop=ALL", "--read-only",
			"--mount", "type=volume,src="+socketVolumes[bootstrapStorageID]+",dst=/socket,readonly",
			slice6PinnedAlpineImage, "/bin/sh", "-ec", "test -z \"$(ls -A /socket)\""); err != nil {
			t.Fatal("credential controller socket inode cleanup failed")
		}
		stopped = true
	}
	if onBootstrapReady != nil {
		onBootstrapReady(stopCredential)
	}
	if !stopped {
		stopCredential()
	}
	if ctx.Err() != nil {
		t.Fatal(errors.New("credential controller diagnostic context expired"))
	}
}

var slice6ControllerStagePattern = regexp.MustCompile(`stage [a-z][a-z-]{0,63}:`)

func slice6ControllerFailureStage(output []byte) string {
	if match := slice6ControllerStagePattern.Find(output); match != nil {
		return strings.TrimSuffix(strings.TrimPrefix(string(match), "stage "), ":")
	}
	for _, stage := range []string{"phase6-fd-loader: input", "phase6-fd-loader: fd", "phase6-fd-loader: exec"} {
		if bytes.Contains(output, []byte(stage)) {
			return strings.ReplaceAll(stage, ": ", "-")
		}
	}
	return "unknown"
}
