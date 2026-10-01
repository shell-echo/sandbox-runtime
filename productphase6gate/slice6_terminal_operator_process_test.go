//go:build phase6slice6gate

package productphase6gate

import (
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
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
)

const slice6TerminalOperatorEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_TERMINAL_OPERATOR"

type slice6TerminalOperatorInput struct {
	Protocol              string    `json:"protocol"`
	RunID                 string    `json:"run_id"`
	ProfileJSON           []byte    `json:"profile_json"`
	PeerSourcesJSON       []byte    `json:"peer_sources_json"`
	CertificateLedgerJSON []byte    `json:"certificate_ledger_json"`
	CredentialLedgerJSON  []byte    `json:"credential_ledger_json"`
	ManagementAccessor    string    `json:"management_accessor"`
	PlanDigest            string    `json:"plan_digest"`
	VaultEndpoint         string    `json:"vault_endpoint"`
	VaultServerCAPEM      []byte    `json:"vault_server_ca_pem"`
	ClientCertificatePEM  []byte    `json:"client_certificate_pem"`
	ClientPrivateKeyPEM   []byte    `json:"client_private_key_pem"`
	OperatorToken         []byte    `json:"operator_token"`
	TokenExpiresAt        time.Time `json:"token_expires_at"`
}

func slice6RunTerminalOperator(t *testing.T, parent context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, vaultID, privateRoot, managementAccessor string,
	general slice6VaultRoot, credential *slice6TerminalOperatorCredential) {
	t.Helper()
	if os.Getenv(slice6TerminalOperatorEnv) != "1" || credential == nil ||
		!credential.ExpiresAt.After(time.Now().Add(90*time.Second)) ||
		phase6security.VerifySlice6DesiredFinalExternalProfile(composed.Profile) != nil ||
		len(vaultID) != 64 || !lowerHexSlice6(vaultID) {
		t.Fatal("terminal operator requires prefrozen live run authority")
	}
	ctx, cancel := context.WithTimeout(parent, 120*time.Second)
	defer cancel()
	certificateLedger := slice6ReadTerminalLedger(t, ctx, run, composed.Profile, "certificate-controller")
	credentialLedger := slice6ReadTerminalLedger(t, ctx, run, composed.Profile, "workload-credential-controller")
	defer clear(certificateLedger)
	defer clear(credentialLedger)
	plan, err := phase6terminalcleanup.Build(run.id, composed.Profile, composed.PeerSources,
		certificateLedger, credentialLedger, managementAccessor, time.Now().UTC())
	if err != nil || plan.Validate() != nil {
		t.Fatal("independently read quiesced ledgers cannot bind the exact terminal cleanup plan")
	}
	profileJSON, err := json.Marshal(composed.Profile)
	if err != nil {
		t.Fatal("encode exact operator Profile input")
	}
	peerJSON, err := json.Marshal(composed.PeerSources)
	if err != nil {
		t.Fatal("encode exact operator peer source input")
	}
	input := slice6TerminalOperatorInput{Protocol: "sandbox-runtime.phase6-terminal-cleanup-input.v1",
		RunID: run.id, ProfileJSON: profileJSON, PeerSourcesJSON: peerJSON,
		CertificateLedgerJSON: certificateLedger, CredentialLedgerJSON: credentialLedger,
		ManagementAccessor: managementAccessor, PlanDigest: plan.Digest,
		VaultEndpoint: "https://vault.sandbox-runtime.test:8200", VaultServerCAPEM: general.PEM,
		ClientCertificatePEM: credential.LeafPEM, ClientPrivateKeyPEM: credential.KeyPEM,
		OperatorToken: credential.Token, TokenExpiresAt: credential.ExpiresAt}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 18<<20 {
		clear(encoded)
		t.Fatal("bounded terminal operator envelope unavailable")
	}
	defer clear(encoded)
	sourceRoot, err := filepath.EvalSymlinks(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT"))
	if err != nil || !filepath.IsAbs(sourceRoot) {
		t.Fatal("terminal operator requires independent clean source checkout")
	}
	revisionDocument, err := exec.CommandContext(ctx, "git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil || verifyCleanSlice6Source(ctx, sourceRoot, strings.TrimSpace(string(revisionDocument))) != nil {
		t.Fatal("terminal operator source is not an immutable clean revision")
	}
	binaryPath := filepath.Join(privateRoot, "phase6-terminal-cleanup")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binaryPath, "./cmd/phase6-terminal-cleanup")
	build.Dir = sourceRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	if _, err := build.CombinedOutput(); err != nil {
		t.Fatal("build source-bound one-shot terminal operator")
	}
	if err := os.Chmod(binaryPath, 0o500); err != nil {
		t.Fatal("restrict terminal operator binary")
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil || len(binary) < 1 {
		t.Fatal("read source-bound terminal operator command")
	}
	binaryHash := sha256.Sum256(binary)
	clear(binary)
	operatorNetworkName := "sr-p6-terminal-only-" + run.id
	networkDocument, err := run.docker(ctx, "network", "create", "--driver=bridge", "--internal",
		"--opt=com.docker.network.bridge.gateway_mode_ipv4=isolated", "--label", run.label(), operatorNetworkName)
	networkID := strings.TrimSpace(string(networkDocument))
	if err != nil || len(networkID) != 64 || !lowerHexSlice6(networkID) {
		t.Fatal("create isolated Vault-only terminal operator network")
	}
	if _, err := run.docker(ctx, "network", "connect", "--alias", "vault.sandbox-runtime.test",
		networkID, vaultID); err != nil {
		t.Fatal("attach sole Vault endpoint to terminal operator network")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccompPath := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompDocument, err := os.ReadFile(seccompPath)
	if err != nil {
		t.Fatal("read locked terminal operator seccomp")
	}
	seccompHash := sha256.Sum256(seccompDocument)
	var controllerSeccompDigest string
	for _, principal := range composed.Profile.Principals {
		if principal.Name == "certificate-controller" {
			controllerSeccompDigest = principal.SeccompDigest
		}
	}
	if controllerSeccompDigest != "sha256:"+hex.EncodeToString(seccompHash[:]) {
		t.Fatal("terminal operator seccomp differs from reviewed controller profile")
	}
	identity := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	containerName := "sr-p6-terminal-cleanup-" + run.id
	created, err := run.docker(ctx, "create", "-i", "--pull=never", "--name", containerName,
		"--label", run.label(), "--log-driver=none", "--network", networkID,
		"--restart=no", "--user", identity, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--security-opt", "seccomp="+seccompPath,
		"--read-only", "--memory=128m", "--cpus=0.5", "--pids-limit=32",
		"--mount", "type=bind,src="+binaryPath+",dst=/phase6-terminal-cleanup,readonly",
		"--entrypoint=/phase6-terminal-cleanup", slice6VaultTestImage, "--one-shot")
	containerID := strings.TrimSpace(string(created))
	if err != nil || len(containerID) != 64 || !lowerHexSlice6(containerID) {
		t.Fatal("create restricted terminal operator task")
	}
	slice6VerifyTerminalContainer(t, ctx, run, containerID, networkID, identity, binaryPath, seccompPath)
	attached := exec.CommandContext(ctx, "docker", "start", "-a", "-i", containerID)
	attached.Stdin = bytes.NewReader(encoded)
	output, startErr := attached.CombinedOutput()
	defer clear(output)
	slice6VerifyTerminalNetwork(t, ctx, run, networkID, vaultID, containerID)
	var receipt phase6terminalcleanup.Receipt
	if startErr != nil || len(output) > 16<<10 || json.Unmarshal(bytes.TrimSpace(output), &receipt) != nil ||
		!receipt.Complete || !receipt.SelfRevoked || receipt.PlanDigest != plan.Digest ||
		receipt.RunID != run.id || receipt.ProfileDigest != composed.Profile.ProfileDigest ||
		len(receipt.Certificates) != 2 || len(receipt.Tokens) != 2 || receipt.IssuerCRLSHA == "" {
		t.Fatal("terminal operator did not return an exact complete private receipt")
	}
	for _, target := range append(receipt.Certificates, receipt.Tokens...) {
		if !target.Confirmed {
			t.Fatal("terminal operator reported an unconfirmed target")
		}
	}
	if _, err := run.docker(ctx, "rm", containerID); err != nil {
		t.Fatal("remove exact completed terminal operator task")
	}
	if _, err := run.docker(ctx, "network", "disconnect", networkID, vaultID); err != nil {
		t.Fatal("remove Vault from terminal-only network")
	}
	if _, err := run.docker(ctx, "network", "rm", networkID); err != nil {
		t.Fatal("remove exact terminal-only network")
	}
	t.Logf("one-shot terminal operator confirmed two certs, two token accessors, complete CRL and self-revoke; source-bound binary sha256:%s; private receipt plan=%s", hex.EncodeToString(binaryHash[:]), plan.Digest)
}

func slice6ReadTerminalLedger(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, owner string) []byte {
	t.Helper()
	var principal phase6security.Principal
	for _, value := range profile.Principals {
		if value.Name == owner {
			principal = value
		}
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount(owner)
	if err != nil || principal.UID == 0 || principal.GID == 0 {
		t.Fatal("unknown exclusive terminal ledger owner")
	}
	volume := "sr-p6-ledger-" + owner + "-" + run.id
	identity := fmt.Sprintf("%d:%d", principal.UID, principal.GID)
	document, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-terminal-read-"+owner+"-"+run.id,
		"--label", run.label(), "--network=none", "--user", identity, "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--read-only", "--memory=32m", "--cpus=0.25", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst=/ledger,readonly", slice6PinnedAlpineImage,
		"/bin/sh", "-ec", "test \"$(stat -c '%u:%g:%a' /ledger/ledger.json)\" = '"+identity+":600' && test -z \"$(find /ledger -mindepth 1 -maxdepth 1 ! -name ledger.json)\" && cat /ledger/ledger.json")
	if err != nil || len(document) < 1 || len(document) > 8<<20 || filepath.Base(ledgerPath) != "ledger.json" {
		clear(document)
		t.Fatal("independent exact quiesced ledger read failed")
	}
	return document
}

func slice6VerifyTerminalContainer(t *testing.T, ctx context.Context, run slice6DockerRun,
	id, networkID, identity, binaryPath, seccompPath string) {
	t.Helper()
	document, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		Image  string `json:"Image"`
		Config struct {
			Image      string   `json:"Image"`
			User       string   `json:"User"`
			Entrypoint []string `json:"Entrypoint"`
			Cmd        []string `json:"Cmd"`
			Env        []string `json:"Env"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string         `json:"NetworkMode"`
			ReadonlyRootfs bool           `json:"ReadonlyRootfs"`
			Privileged     bool           `json:"Privileged"`
			CapDrop        []string       `json:"CapDrop"`
			CapAdd         []string       `json:"CapAdd"`
			SecurityOpt    []string       `json:"SecurityOpt"`
			Memory         int64          `json:"Memory"`
			NanoCPUs       int64          `json:"NanoCpus"`
			PidsLimit      int64          `json:"PidsLimit"`
			PortBindings   map[string]any `json:"PortBindings"`
			LogConfig      struct {
				Type string `json:"Type"`
			} `json:"LogConfig"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if err != nil || json.Unmarshal(document, &observed) != nil || len(observed) != 1 ||
		observed[0].Image != strings.TrimPrefix(slice6VaultTestImage, "docker.io/hashicorp/vault@") {
		// The pinned reference and effective image ID are the same digest in
		// this locked image. An unexpected image fails before stdin delivery.
		t.Fatal("terminal operator image identity drift")
	}
	container := observed[0]
	seccompSource, readErr := os.ReadFile(seccompPath)
	var compactSeccomp bytes.Buffer
	if readErr != nil || json.Compact(&compactSeccomp, seccompSource) != nil {
		t.Fatal("canonicalize terminal operator seccomp")
	}
	if container.Config.Image != slice6VaultTestImage || container.Config.User != identity ||
		!slices.Equal(container.Config.Entrypoint, []string{"/phase6-terminal-cleanup"}) ||
		!slices.Equal(container.Config.Cmd, []string{"--one-shot"}) ||
		container.HostConfig.NetworkMode != networkID || !container.HostConfig.ReadonlyRootfs ||
		container.HostConfig.Privileged || !slices.Equal(container.HostConfig.CapDrop, []string{"ALL"}) ||
		len(container.HostConfig.CapAdd) != 0 ||
		container.HostConfig.Memory != 128<<20 || container.HostConfig.NanoCPUs != 500000000 ||
		container.HostConfig.PidsLimit != 32 || len(container.HostConfig.PortBindings) != 0 ||
		container.HostConfig.LogConfig.Type != "none" || container.HostConfig.RestartPolicy.Name != "no" ||
		len(container.Mounts) != 1 || container.Mounts[0].Type != "bind" ||
		container.Mounts[0].Source != binaryPath || container.Mounts[0].Destination != "/phase6-terminal-cleanup" ||
		container.Mounts[0].RW {
		t.Fatal("terminal operator effective task bounds drift")
	}
	for _, value := range container.Config.Env {
		if value != "NAME=vault" && !strings.HasPrefix(value, "PATH=") {
			t.Fatal("terminal operator inherited an unreviewed environment variable")
		}
	}
	if len(container.Config.Env) != 2 ||
		!slices.Contains(container.HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(container.HostConfig.SecurityOpt, "seccomp="+compactSeccomp.String()) {
		t.Fatal("terminal operator environment or security options drift")
	}
}

func slice6VerifyTerminalNetwork(t *testing.T, ctx context.Context, run slice6DockerRun,
	networkID, vaultID, operatorID string) {
	t.Helper()
	document, err := run.docker(ctx, "network", "inspect", networkID)
	var observed []struct {
		Internal   bool                       `json:"Internal"`
		Options    map[string]string          `json:"Options"`
		Containers map[string]json.RawMessage `json:"Containers"`
	}
	if err != nil || json.Unmarshal(document, &observed) != nil || len(observed) != 1 ||
		!observed[0].Internal ||
		observed[0].Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" ||
		(len(observed[0].Containers) != 1 && len(observed[0].Containers) != 2) ||
		observed[0].Containers[vaultID] == nil {
		t.Fatal("terminal operator bridge has unexpected members or isolation")
	}
	for id := range observed[0].Containers {
		if id != vaultID && id != operatorID {
			t.Fatal("terminal operator bridge contains an unknown endpoint")
		}
	}
}
