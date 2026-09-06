package caller

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/provisioning"
)

type downstreamCallerProcess struct {
	command  *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	stderr   *bytes.Buffer
	done     chan error
	once     sync.Once
	endpoint io.ReadCloser
	final    io.WriteCloser
	template map[string]any
}

type downstreamCallerResponse struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
	OK       bool   `json:"ok"`
	Outcome  string `json:"outcome"`
}

// This is process-boundary component evidence. The separately locked ADR 0033
// topology and real-Chromium scenarios remain outside this test.
func TestTwoDownstreamCallerProcessesBootstrapIndependentlyAndRemainControllable(t *testing.T) {
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "downstream-fencing-caller")
	build := exec.Command("go", "build", "-race", "-o", binary, "./cmd/downstream-fencing-caller")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build downstream caller: %v: %s", err, bytes.TrimSpace(output))
	}

	providerA, callerConfigA, providerConfigA, templateA, requestA := newDownstreamProcessBootstrapFixture(t, "a", 11)
	providerB, callerConfigB, providerConfigB, templateB, requestB := newDownstreamProcessBootstrapFixture(t, "b", 21)
	processA := startDownstreamCallerProcess(t, binary, moduleRoot, callerConfigA, providerConfigA, templateA, requestA)
	processB := startDownstreamCallerProcess(t, binary, moduleRoot, callerConfigB, providerConfigB, templateB, requestB)

	waitForDownstreamProcessBootstrap(t, providerA, processA)
	waitForDownstreamProcessBootstrap(t, providerB, processB)
	if processA.command.Process.Pid == processB.command.Process.Pid {
		t.Fatal("downstream callers did not receive distinct process identities")
	}

	shutdownDownstreamCallerProcess(t, processA, 1)
	assertDownstreamCallerProcessAlive(t, processB)
	shutdownDownstreamCallerProcess(t, processB, 2)
}

func TestDownstreamCallerRejectsMissingProvisioningFDsCleanly(t *testing.T) {
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "downstream-fencing-caller")
	build := exec.Command("go", "build", "-race", "-o", binary, "./cmd/downstream-fencing-caller")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build downstream caller: %v: %s", err, bytes.TrimSpace(output))
	}
	command := exec.Command(binary, "-config", "/private/caller.json", "-provider-bootstrap-config", "/private/provider.json")
	command.Dir = moduleRoot
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 || string(output) != "downstream-fencing caller provisioning required\n" {
		t.Fatalf("missing provisioning exit = %v, output = %q", err, output)
	}
}

func newDownstreamProcessBootstrapFixture(t *testing.T, suffix string, createFence int64) (*browserBootstrapProvider, string, string, map[string]any, provisioning.Request) {
	t.Helper()
	material := newBrowserBootstrapTestMaterial(t, "spiffe://downstream-caller/controller-"+suffix)
	config := &material.config
	config.Controller.JWSKeyID = "downstream-controller-" + suffix + "-key"
	config.TenantID = "tenant-downstream-" + suffix
	config.WorkOrderID = "work-order-downstream-" + suffix
	config.SandboxID = "sandbox-downstream-" + suffix
	config.WorkspaceID = "workspace-downstream-" + suffix
	config.WorkspaceRevisionID = "workspace-revision-downstream-" + suffix
	config.BranchID = "branch-downstream-" + suffix
	config.ProviderResolutionID = "provider-resolution-downstream-" + suffix
	config.CreateOperationID = "operation-create-downstream-" + suffix
	config.CreateAttemptID = "attempt-create-downstream-" + suffix
	config.CreateFencingToken = createFence
	config.CreateIdempotencyKey = "idempotency-create-downstream-" + suffix
	config.OpenOperationID = "operation-open-downstream-" + suffix
	config.OpenAttemptID = "attempt-open-downstream-" + suffix
	config.OpenFencingToken = createFence + 1
	config.OpenIdempotencyKey = "idempotency-open-downstream-" + suffix
	config.BrowserSessionID = "browser-session-downstream-" + suffix

	provider := &browserBootstrapProvider{
		t: t, jwsPublic: material.jwsPublic, jti: map[string]bool{}, readAttempts: map[string]int{},
	}
	server := newBrowserBootstrapTestServer(t, material, provider.serveHTTP)
	t.Cleanup(server.Close)
	config.ProviderBaseURL = server.URL
	provider.config = *config

	root := t.TempDir()
	providerConfig := writeDownstreamProcessJSON(t, root, "provider-bootstrap-"+suffix+".json", config)
	callerConfig := map[string]any{
		"ca_file": config.CAFile,
		"gateways": map[string]string{
			"gateway-a": "https://127.0.0.1:" + strconv.Itoa(19000+int(createFence)),
			"gateway-b": "https://127.0.0.1:" + strconv.Itoa(20000+int(createFence)),
		},
		"principal": map[string]any{
			"id": "principal-" + suffix, "token": "caller-process-private-token-0000000" + suffix,
			"caller_id": "caller-" + suffix, "tenant_id": config.TenantID,
		},
		"endpoint": map[string]any{
			"id": "endpoint-" + suffix, "tenant_id": config.TenantID, "sandbox_id": config.SandboxID,
			"browser_session_id": config.BrowserSessionID, "capability_profile_id": "browser-v1",
		},
		"grant_binding": map[string]any{
			"id": "binding-" + suffix, "grant_id": "grant-downstream-" + suffix,
			"principal_id": "principal-" + suffix, "endpoint_id": "endpoint-" + suffix, "lifetime_millis": 120000,
		},
	}
	callerConfigPath := writeDownstreamProcessJSON(t, root, "caller-"+suffix+".json", callerConfig)
	request := provisioning.Request{
		Version: provisioning.ProtocolVersion, RequestID: "provisioning-" + suffix,
		ControllerSubject: config.Controller.ControllerSubject,
		TenantID:          config.TenantID, SandboxID: config.SandboxID, BrowserSessionID: config.BrowserSessionID,
		CapabilityProfileID: "browser-v1",
	}
	return provider, callerConfigPath, providerConfig, callerConfig, request
}

func writeDownstreamProcessJSON(t *testing.T, root, name string, value any) string {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeBrowserBootstrapTestFile(t, root, name, document, 0o600)
}

func startDownstreamCallerProcess(
	t *testing.T,
	binary, moduleRoot, callerConfig, providerConfig string,
	template map[string]any,
	request provisioning.Request,
) *downstreamCallerProcess {
	t.Helper()
	command := exec.Command(binary, "-config", callerConfig, "-provider-bootstrap-config", providerConfig)
	command.Dir = moduleRoot
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	endpointRead, endpointWrite, err := os.Pipe()
	if err != nil {
		_ = requestRead.Close()
		_ = requestWrite.Close()
		t.Fatal(err)
	}
	finalRead, finalWrite, err := os.Pipe()
	if err != nil {
		_ = requestRead.Close()
		_ = requestWrite.Close()
		_ = endpointRead.Close()
		_ = endpointWrite.Close()
		t.Fatal(err)
	}
	command.ExtraFiles = []*os.File{requestRead, endpointWrite, finalRead}
	stdin, err := command.StdinPipe()
	if err != nil {
		closeDownstreamProvisioningPipes(requestRead, requestWrite, endpointRead, endpointWrite, finalRead, finalWrite)
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		closeDownstreamProvisioningPipes(requestRead, requestWrite, endpointRead, endpointWrite, finalRead, finalWrite)
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		closeDownstreamProvisioningPipes(requestRead, requestWrite, endpointRead, endpointWrite, finalRead, finalWrite)
		t.Fatal(err)
	}
	_ = requestRead.Close()
	_ = endpointWrite.Close()
	_ = finalRead.Close()
	process := &downstreamCallerProcess{
		command: command, stdin: stdin, stdout: stdout, stderr: stderr, done: make(chan error, 1),
		endpoint: endpointRead, final: finalWrite, template: template,
	}
	go func() {
		process.done <- command.Wait()
		close(process.done)
	}()
	t.Cleanup(func() { process.stop() })
	if err := provisioning.WriteRequest(requestWrite, request); err != nil {
		process.stop()
		t.Fatal(err)
	}
	if err := requestWrite.Close(); err != nil {
		process.stop()
		t.Fatal(err)
	}
	return process
}

func closeDownstreamProvisioningPipes(files ...*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

func (p *downstreamCallerProcess) stop() {
	p.once.Do(func() {
		_ = p.endpoint.Close()
		_ = p.final.Close()
		_ = p.stdin.Close()
		_ = p.command.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
		}
	})
}

func waitForDownstreamProcessBootstrap(t *testing.T, provider *browserBootstrapProvider, process *downstreamCallerProcess) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		provider.mu.Lock()
		createRequests, openRequests, protectedRequests := provider.createRequests, provider.openRequests, provider.protectedRequests
		provider.mu.Unlock()
		if createRequests == 1 && openRequests == 1 && protectedRequests == 6 {
			envelope, err := provisioning.ReadEndpoint(process.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			finalConfig := map[string]any{
				"ca_file": process.template["ca_file"], "gateways": process.template["gateways"],
				"principals": []any{process.template["principal"]},
				"endpoints":  []any{envelope.Endpoint}, "grant_bindings": []any{envelope.GrantBinding},
			}
			encoded, err := json.Marshal(finalConfig)
			if err != nil {
				t.Fatal(err)
			}
			if err := provisioning.WriteFinalConfiguration(process.final, provisioning.FinalConfiguration{
				Version: provisioning.ProtocolVersion, RequestID: envelope.RequestID, Config: encoded,
			}); err != nil {
				t.Fatal(err)
			}
			if err := process.final.Close(); err != nil {
				t.Fatal(err)
			}
			assertDownstreamCallerProcessAlive(t, process)
			return
		}
		select {
		case err := <-process.done:
			t.Fatalf("downstream caller exited before bootstrap completed: %v: %s", err, bytes.TrimSpace(process.stderr.Bytes()))
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("downstream caller did not complete Provider bootstrap")
}

func assertDownstreamCallerProcessAlive(t *testing.T, process *downstreamCallerProcess) {
	t.Helper()
	select {
	case err := <-process.done:
		t.Fatalf("downstream caller exited unexpectedly: %v: %s", err, bytes.TrimSpace(process.stderr.Bytes()))
	default:
	}
	if err := process.command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("downstream caller process is not alive: %v", err)
	}
}

func shutdownDownstreamCallerProcess(t *testing.T, process *downstreamCallerProcess, sequence uint64) {
	t.Helper()
	if _, err := io.WriteString(process.stdin, `{"version":1,"sequence":`+strconv.FormatUint(sequence, 10)+`,"action":"shutdown"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	responseResult := make(chan struct {
		response downstreamCallerResponse
		err      error
	}, 1)
	go func() {
		var response downstreamCallerResponse
		err := json.NewDecoder(process.stdout).Decode(&response)
		responseResult <- struct {
			response downstreamCallerResponse
			err      error
		}{response: response, err: err}
	}()
	select {
	case result := <-responseResult:
		if result.err != nil || result.response.Version != 1 || result.response.Sequence != sequence || !result.response.OK || result.response.Outcome != "terminated" {
			t.Fatalf("shutdown response = %#v, error = %v", result.response, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("downstream caller did not answer shutdown")
	}
	select {
	case err := <-process.done:
		if err != nil || process.stderr.Len() != 0 {
			t.Fatalf("downstream caller exit = %v, stderr = %s", err, bytes.TrimSpace(process.stderr.Bytes()))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("downstream caller did not exit after shutdown")
	}
}
