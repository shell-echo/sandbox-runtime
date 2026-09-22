//go:build phase6slicegate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	gateVaultImage                 = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
	gateCredentialControllerConfig = "sandbox-runtime.workload-credential-controller-config.v1"
	gateMaterialAgentConfig        = "sandbox-runtime.workload-material-agent-config.v1"
)

type gateCredentialControllerInput struct {
	Protocol                string                   `json:"protocol"`
	SocketPath              string                   `json:"socket_path"`
	LedgerPath              string                   `json:"ledger_path"`
	SocketUID               uint32                   `json:"socket_uid"`
	SocketGID               uint32                   `json:"socket_gid"`
	ExpectedClientUID       uint32                   `json:"expected_client_uid"`
	ExpectedClientGID       uint32                   `json:"expected_client_gid"`
	MaxConnections          int                      `json:"max_connections"`
	ReapIntervalSeconds     int                      `json:"reap_interval_seconds"`
	OverlapSeconds          int                      `json:"overlap_seconds"`
	VaultEndpoint           string                   `json:"vault_endpoint"`
	VaultCABundle           []byte                   `json:"vault_ca_bundle"`
	VaultServerName         string                   `json:"vault_server_name"`
	OperationTimeoutSeconds int                      `json:"operation_timeout_seconds"`
	Identities              []gateCredentialIdentity `json:"identities"`
	Policies                []gateCredentialPolicy   `json:"policies"`
}

type gateCredentialIdentity struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
}

type gateCredentialPolicy struct {
	ID            string            `json:"id"`
	AgentID       string            `json:"agent_id"`
	Role          secretref.Role    `json:"role"`
	Purpose       secretref.Purpose `json:"purpose"`
	BindingDigest string            `json:"binding_digest"`
	BackendID     string            `json:"backend_id"`
	VaultPolicy   string            `json:"vault_policy"`
	MaxTTLSeconds int               `json:"max_ttl_seconds"`
	Renewable     bool              `json:"renewable"`
	Migration     bool              `json:"migration"`
}

type gateMaterialAgentInput struct {
	Protocol                   string              `json:"protocol"`
	SocketPath                 string              `json:"socket_path"`
	SocketUID                  uint32              `json:"socket_uid"`
	SocketGID                  uint32              `json:"socket_gid"`
	ExpectedClientUID          uint32              `json:"expected_client_uid"`
	ExpectedClientGID          uint32              `json:"expected_client_gid"`
	Role                       secretref.Role      `json:"role"`
	MaxConnections             int                 `json:"max_connections"`
	MaxResolutions             int                 `json:"max_resolutions"`
	Migration                  bool                `json:"migration"`
	CredentialControllerSocket string              `json:"credential_controller_socket"`
	CredentialControllerUID    uint32              `json:"credential_controller_uid"`
	CredentialControllerGID    uint32              `json:"credential_controller_gid"`
	CredentialAgentID          string              `json:"credential_agent_id"`
	CredentialPolicyID         string              `json:"credential_policy_id"`
	CredentialBackendID        string              `json:"credential_backend_id"`
	CredentialTTLSeconds       int                 `json:"credential_ttl_seconds"`
	CredentialBinding          secretref.Binding   `json:"credential_binding"`
	VaultEndpoint              string              `json:"vault_endpoint"`
	VaultCABundle              []byte              `json:"vault_ca_bundle"`
	VaultServerName            string              `json:"vault_server_name"`
	VaultMount                 string              `json:"vault_mount"`
	VaultReferenceAuthority    string              `json:"vault_reference_authority"`
	OperationTimeoutSeconds    int                 `json:"operation_timeout_seconds"`
	Bindings                   []secretref.Binding `json:"bindings"`
	BreakGlassSocket           string              `json:"break_glass_socket"`
	BreakGlassControllerSocket string              `json:"break_glass_controller_socket"`
	BreakGlassControllerUID    uint32              `json:"break_glass_controller_uid"`
	BreakGlassControllerGID    uint32              `json:"break_glass_controller_gid"`
	ExpectedOperatorUID        uint32              `json:"expected_operator_uid"`
	ExpectedOperatorGID        uint32              `json:"expected_operator_gid"`
}

type gateVaultMaterial struct {
	Schema        string `json:"schema"`
	BindingDigest string `json:"binding_digest"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
	State         string `json:"state"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Material      []byte `json:"material"`
}

type gateBreakGlassControllerInput struct {
	Protocol          string                `json:"protocol"`
	SocketPath        string                `json:"socket_path"`
	LedgerPath        string                `json:"ledger_path"`
	AuditPath         string                `json:"audit_path"`
	SocketUID         uint32                `json:"socket_uid"`
	SocketGID         uint32                `json:"socket_gid"`
	ExpectedClientUID uint32                `json:"expected_client_uid"`
	ExpectedClientGID uint32                `json:"expected_client_gid"`
	MaxConnections    int                   `json:"max_connections"`
	MaxTTLSeconds     int                   `json:"max_ttl_seconds"`
	Actors            []gateBreakGlassActor `json:"actors"`
}

type gateBreakGlassActor struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
}

func prepareGateVault(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	environment.vaultContainer = "sr-phase6-vault-" + environment.runID
	environment.vaultRootToken = "phase6-vault-" + environment.runID
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", environment.vaultContainer,
		"-p", "127.0.0.1::8200", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+environment.vaultRootToken, gateVaultImage,
		"server", "-dev", "-dev-root-token-id="+environment.vaultRootToken, "-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls").CombinedOutput()
	if err != nil {
		t.Fatalf("start Phase 6 Vault: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", environment.vaultContainer).Run() })
	portDocument, err := exec.CommandContext(ctx, "docker", "port", environment.vaultContainer, "8200/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	portValue := strings.TrimSpace(string(portDocument))
	separator := strings.LastIndex(portValue, ":")
	if separator < 0 {
		t.Fatal("Phase 6 Vault port unavailable")
	}
	environment.vaultEndpoint = "https://127.0.0.1:" + portValue[separator+1:]
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		environment.vaultCA, err = exec.CommandContext(ctx, "docker", "exec", environment.vaultContainer, "cat", "/tmp/vault-tls/vault-ca.pem").Output()
		if err == nil && bytes.Contains(environment.vaultCA, []byte("BEGIN CERTIFICATE")) {
			break
		}
		clear(environment.vaultCA)
		time.Sleep(200 * time.Millisecond)
	}
	if len(environment.vaultCA) == 0 {
		t.Fatal("Phase 6 Vault CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(environment.vaultCA) {
		t.Fatal("Phase 6 Vault CA invalid")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitFor(t, 30*time.Second, "Phase 6 Vault", func() bool {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, environment.vaultEndpoint+"/v1/sys/health", nil)
		request.Header.Set("X-Vault-Token", environment.vaultRootToken)
		response, requestErr := client.Do(request)
		if requestErr != nil {
			return false
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return response.StatusCode == http.StatusOK
	})
	gateVaultWrite(t, ctx, client, environment, "/v1/sys/mounts/kv", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})

	environment.credentialBindings = make(map[string]secretref.Binding, len(environment.materials))
	environment.credentialKeys = make(map[string]ed25519.PrivateKey, len(environment.materials))
	for name, materials := range environment.materials {
		policyRules := make([]string, 0, len(materials))
		for _, material := range materials {
			path := strings.TrimPrefix(material.Binding.Reference.String(), "secret://phase6/kv/")
			if path == material.Binding.Reference.String() || strings.Contains(path, "/") {
				t.Fatal("invalid Phase 6 Vault material reference")
			}
			value := gateVaultMaterial{Schema: "sandbox-runtime.vault-kv-material.v1", BindingDigest: material.Binding.Digest(),
				Version: material.Binding.Version, Revision: material.Revision, Digest: material.Digest, State: string(material.Window.State),
				NotBefore: material.Window.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: material.Window.NotAfter.UTC().Format(time.RFC3339Nano), Material: material.Bytes}
			gateVaultWrite(t, ctx, client, environment, "/v1/kv/data/"+path, map[string]any{"data": value})
			policyRules = append(policyRules, fmt.Sprintf("path %q { capabilities = [\"read\"] }", "kv/data/"+path))
		}
		policyID := gateCredentialPolicyID(name)
		gateVaultWrite(t, ctx, client, environment, "/v1/sys/policies/acl/"+policyID, map[string]any{"policy": strings.Join(policyRules, "\n")})
		role := materials[0].Binding.Role
		binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://phase6/credential/" + strings.ReplaceAll(name, "-", "_")), Version: "v1",
			Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant, Role: role}
		if binding.Validate() != nil {
			t.Fatal("invalid Phase 6 workload credential binding")
		}
		environment.credentialBindings[name] = binding
		_, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		environment.credentialKeys[name] = privateKey
	}
	credentialDirectory, err := os.MkdirTemp("/tmp", "sr-p6-cred-")
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(credentialDirectory, 0o700) != nil || os.Chown(credentialDirectory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare Phase 6 credential controller directory")
	}
	t.Cleanup(func() { _ = os.RemoveAll(credentialDirectory) })
	environment.paths.credentialSocket = filepath.Join(credentialDirectory, "controller.sock")
	environment.paths.credentialLedger = filepath.Join(credentialDirectory, "ledger.json")
}

func prepareGateBreakGlass(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	environment.breakGlassKeys = make(map[string]ed25519.PrivateKey)
	for _, actorID := range []string{"phase6-requester", "phase6-approver-a", "phase6-approver-b", "phase6-operator"} {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		environment.breakGlassKeys[actorID] = privateKey
	}
	_, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	environment.breakGlassControllerKey = controllerKey
	directory, err := os.MkdirTemp("/tmp", "sr-p6-bg-")
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare Phase 6 break-glass directory")
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	environment.paths.breakGlassControllerSocket = filepath.Join(directory, "controller.sock")
	environment.paths.breakGlassLedger = filepath.Join(directory, "authority.json")
	environment.paths.breakGlassAudit = filepath.Join(directory, "audit.ndjson")
	for _, name := range []string{"product-runtime", "provider-runtime", "gateway", "guest", "browser", "desktop"} {
		agentDirectory, err := os.MkdirTemp("/tmp", "sr-p6-bgagent-")
		if err != nil {
			t.Fatal(err)
		}
		if os.Chmod(agentDirectory, 0o700) != nil || os.Chown(agentDirectory, os.Getuid(), os.Getgid()) != nil {
			t.Fatal("prepare Phase 6 break-glass agent directory")
		}
		t.Cleanup(func() { _ = os.RemoveAll(agentDirectory) })
		environment.paths.breakGlassSockets[name] = filepath.Join(agentDirectory, "agent.sock")
	}
}

func gateVaultWrite(t *testing.T, ctx context.Context, client *http.Client, environment *gateEnvironment, path string, value any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, environment.vaultEndpoint+path, bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", environment.vaultRootToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("Phase 6 Vault setup request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		t.Fatalf("Phase 6 Vault setup status=%d", response.StatusCode)
	}
}

func gateCredentialPolicyID(name string) string { return "p6-" + name }
func gateCredentialAgentID(name string) string  { return name + "-agent" }

func startGateCredentialController(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	input := gateCredentialControllerInput{Protocol: gateCredentialControllerConfig, SocketPath: environment.paths.credentialSocket,
		LedgerPath: environment.paths.credentialLedger, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), MaxConnections: 32,
		ReapIntervalSeconds: 1, OverlapSeconds: 3, VaultEndpoint: environment.vaultEndpoint, VaultCABundle: environment.vaultCA,
		VaultServerName: "127.0.0.1", OperationTimeoutSeconds: 3}
	for _, name := range []string{"product-migration", "provider-migration", "product-runtime", "provider-runtime", "gateway", "guest", "browser", "desktop"} {
		privateKey := environment.credentialKeys[name]
		input.Identities = append(input.Identities, gateCredentialIdentity{AgentID: gateCredentialAgentID(name), PublicKey: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))})
		migration := strings.HasSuffix(name, "-migration")
		input.Policies = append(input.Policies, gateCredentialPolicy{ID: gateCredentialPolicyID(name), AgentID: gateCredentialAgentID(name),
			Role: environment.materials[name][0].Binding.Role, Purpose: secretref.PurposeWorkloadCredential,
			BindingDigest: environment.credentialBindings[name].Digest(), BackendID: "vault-primary", VaultPolicy: gateCredentialPolicyID(name),
			MaxTTLSeconds: 30, Renewable: !migration, Migration: migration})
	}
	document, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	process := startGateProcessInputFile(t, ctx, "workload-credential-controller", environment.paths.credentialControllerBin,
		filepath.Join(environment.paths.directory, "workload-credential-controller.log"), document, []byte(environment.vaultRootToken))
	clear(document)
	environment.credentialController = process
	environment.dependencies = append(environment.dependencies, process)
	t.Cleanup(func() { bestEffortStopGateProcess(process) })
	waitFor(t, 15*time.Second, "workload credential controller socket", func() bool {
		select {
		case err := <-process.done:
			t.Fatalf("credential controller stopped before ready: %v; log=%s", err, gateLog(process))
		default:
		}
		info, err := os.Lstat(environment.paths.credentialSocket)
		return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600
	})
}

func startGateBreakGlassController(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	input := gateBreakGlassControllerInput{Protocol: "sandbox-runtime.break-glass-controller-config.v1",
		SocketPath: environment.paths.breakGlassControllerSocket, LedgerPath: environment.paths.breakGlassLedger, AuditPath: environment.paths.breakGlassAudit,
		SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()), ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()),
		MaxConnections: 16, MaxTTLSeconds: 900}
	for _, actor := range []struct{ id, kind string }{
		{"phase6-requester", "requester"}, {"phase6-approver-a", "approver"}, {"phase6-approver-b", "approver"}, {"phase6-operator", "operator"},
	} {
		input.Actors = append(input.Actors, gateBreakGlassActor{ID: actor.id, Kind: actor.kind,
			PublicKey: base64.RawURLEncoding.EncodeToString(environment.breakGlassKeys[actor.id].Public().(ed25519.PublicKey))})
	}
	for _, name := range []string{"product-runtime", "provider-runtime", "gateway", "guest", "browser", "desktop"} {
		input.Actors = append(input.Actors, gateBreakGlassActor{ID: gateCredentialAgentID(name), Kind: "target-agent",
			PublicKey: base64.RawURLEncoding.EncodeToString(environment.credentialKeys[name].Public().(ed25519.PublicKey))})
	}
	document, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	process := startGateProcessInputFile(t, ctx, "break-glass-controller", environment.paths.breakGlassControllerBin,
		filepath.Join(environment.paths.directory, "break-glass-controller.log"), document, environment.breakGlassControllerKey)
	clear(document)
	environment.breakGlassController = process
	environment.dependencies = append(environment.dependencies, process)
	t.Cleanup(func() { bestEffortStopGateProcess(process) })
	waitFor(t, 15*time.Second, "break-glass controller socket", func() bool {
		select {
		case err := <-process.done:
			t.Fatalf("break-glass controller stopped before ready: %v; log=%s", err, gateLog(process))
		default:
		}
		info, err := os.Lstat(environment.paths.breakGlassControllerSocket)
		return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600
	})
}

func startGateMaterialAgent(t *testing.T, ctx context.Context, environment *gateEnvironment, name string, maxResolutions int) *gateProcess {
	t.Helper()
	materials := environment.materials[name]
	if len(materials) == 0 {
		t.Fatalf("missing %s material set", name)
	}
	bindings := make([]secretref.Binding, 0, len(materials))
	for _, material := range materials {
		bindings = append(bindings, material.Binding)
	}
	migration := strings.HasSuffix(name, "-migration")
	input := gateMaterialAgentInput{Protocol: gateMaterialAgentConfig, SocketPath: environment.paths.materialSockets[name],
		SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()), ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()),
		Role: materials[0].Binding.Role, MaxConnections: 16, MaxResolutions: maxResolutions, Migration: migration,
		CredentialControllerSocket: environment.paths.credentialSocket, CredentialControllerUID: uint32(os.Getuid()), CredentialControllerGID: uint32(os.Getgid()),
		CredentialAgentID: gateCredentialAgentID(name), CredentialPolicyID: gateCredentialPolicyID(name), CredentialBackendID: "vault-primary",
		CredentialTTLSeconds: 30, CredentialBinding: environment.credentialBindings[name], VaultEndpoint: environment.vaultEndpoint,
		VaultCABundle: environment.vaultCA, VaultServerName: "127.0.0.1", VaultMount: "kv", VaultReferenceAuthority: "phase6",
		OperationTimeoutSeconds: 3, Bindings: bindings}
	if !migration {
		input.BreakGlassSocket = environment.paths.breakGlassSockets[name]
		input.BreakGlassControllerSocket = environment.paths.breakGlassControllerSocket
		input.BreakGlassControllerUID = uint32(os.Getuid())
		input.BreakGlassControllerGID = uint32(os.Getgid())
		input.ExpectedOperatorUID = uint32(os.Getuid())
		input.ExpectedOperatorGID = uint32(os.Getgid())
	}
	document, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	process := startGateProcessInputFile(t, ctx, name+"-material-agent", environment.paths.materialAgentBin,
		filepath.Join(environment.paths.directory, name+"-material-agent.log"), document, environment.credentialKeys[name])
	clear(document)
	environment.materialAgents[name] = process
	environment.materialAgentHistory = append(environment.materialAgentHistory, process)
	waitFor(t, 15*time.Second, name+" material agent socket", func() bool {
		select {
		case err := <-process.done:
			t.Fatalf("%s stopped before socket became ready: %v; log=%s", process.name, err, gateLog(process))
		default:
		}
		info, err := os.Lstat(environment.paths.materialSockets[name])
		return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600
	})
	if !migration {
		waitFor(t, 15*time.Second, name+" break-glass agent socket", func() bool {
			info, err := os.Lstat(environment.paths.breakGlassSockets[name])
			return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600
		})
	}
	return process
}

func startGateProcessInputFile(t *testing.T, ctx context.Context, name, command, logPath string, input, inherited []byte, arguments ...string) *gateProcess {
	t.Helper()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		_ = stdinRead.Close()
		_ = stdinWrite.Close()
		_ = logFile.Close()
		t.Fatal(err)
	}
	process := &gateProcess{name: name, command: command, logPath: logPath, log: logFile, done: make(chan error, 1), startedAt: time.Now().UTC()}
	process.cmd = exec.CommandContext(ctx, command, arguments...)
	process.cmd.Stdin = stdinRead
	process.cmd.Stdout, process.cmd.Stderr = logFile, logFile
	process.cmd.ExtraFiles = []*os.File{readFile}
	if err := process.cmd.Start(); err != nil {
		_ = stdinRead.Close()
		_ = stdinWrite.Close()
		_ = readFile.Close()
		_ = writeFile.Close()
		_ = logFile.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	_ = stdinRead.Close()
	_ = readFile.Close()
	if _, err := stdinWrite.Write(input); err != nil {
		_ = stdinWrite.Close()
		_ = writeFile.Close()
		t.Fatalf("write %s input", name)
	}
	_ = stdinWrite.Close()
	if _, err := writeFile.Write(inherited); err != nil {
		_ = writeFile.Close()
		t.Fatalf("write %s inherited authority", name)
	}
	_ = writeFile.Close()
	go func() {
		err := process.cmd.Wait()
		process.mu.Lock()
		process.finished = time.Now().UTC()
		if process.cmd.ProcessState != nil {
			process.exitCode = process.cmd.ProcessState.ExitCode()
		}
		process.mu.Unlock()
		process.done <- err
		close(process.done)
	}()
	return process
}

func runGateMigration(t *testing.T, ctx context.Context, environment *gateEnvironment, role, configPath string, agent *gateProcess) {
	t.Helper()
	command := exec.CommandContext(ctx, environment.paths.binary, "--config", configPath, role, "migrate")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s migration: %v: %s", role, err, output)
	}
	select {
	case agentErr := <-agent.done:
		if agentErr != nil {
			t.Fatalf("%s migration agent exit: %v; log=%s", role, agentErr, gateLog(agent))
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s one-shot migration agent did not exit", role)
	}
	_ = agent.log.Close()
	if _, err := os.Lstat(agentSocketForRole(environment, role+"-migration")); !os.IsNotExist(err) {
		t.Fatalf("%s migration agent socket retained after one-shot resolution", role)
	}
}

func agentSocketForRole(environment *gateEnvironment, name string) string {
	return environment.paths.materialSockets[name]
}

func startRuntimeMaterialAgents(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	for _, name := range []string{"product-runtime", "provider-runtime", "gateway", "guest", "browser", "desktop"} {
		agent := startGateMaterialAgent(t, ctx, environment, name, 0)
		environment.dependencies = append(environment.dependencies, agent)
		t.Cleanup(func() { bestEffortStopGateProcess(agent) })
	}
}

func runGateMigrations(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	for _, item := range []struct {
		name, role, config string
	}{
		{"product-migration", "product", environment.paths.productMigrationConfig},
		{"provider-migration", "provider", environment.paths.providerMigrationConfig},
	} {
		agent := startGateMaterialAgent(t, ctx, environment, item.name, 1)
		runGateMigration(t, ctx, environment, item.role, item.config, agent)
	}
	applyRuntimeGrants(t, ctx, environment.productDB)
	applyRuntimeGrants(t, ctx, environment.providerDB)
	fmt.Fprint(os.Stderr, "phase6_slice5_migrations=complete distinct_os_uid_established=false\n")
}
