//go:build darwin || linux

package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/provisioning"
	"golang.org/x/sys/unix"
)

func TestDownstreamCallerProcessProvisionsOnceAndShutsDown(t *testing.T) {
	request := downstreamProvisioningRequest("request-success")
	process, endpoint, err := startDownstreamHelper(t, context.Background(), "normal", request)
	if err != nil {
		t.Fatal(err)
	}
	if !downstreamEndpointMatchesRequest(endpoint, request, time.Now().UTC()) {
		t.Fatal("endpoint did not correlate with request")
	}
	if err := process.commit(context.Background(), downstreamCallerConfig(endpoint)); err != nil {
		t.Fatal(err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := process.shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.done:
	default:
		t.Fatal("successful shutdown did not reap child")
	}
	if !downstreamParentIOClosed(process) {
		t.Fatal("successful shutdown retained parent pipe ends")
	}
}

func TestDownstreamEndpointMatchesRequestRejectsDriftAndExpiry(t *testing.T) {
	request := downstreamProvisioningRequest("request-correlation")
	now := time.Now().UTC()
	baseline := downstreamHelperEndpoint(request)
	if !downstreamEndpointMatchesRequest(baseline, request, now) {
		t.Fatal("valid endpoint did not correlate with request")
	}

	tests := map[string]func(*provisioning.EndpointEnvelope){
		"version": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.Version = provisioning.ProtocolVersion + 1
		},
		"request ID": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.RequestID = "different-request"
		},
		"tenant": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.Endpoint.TenantID = "different-tenant"
		},
		"sandbox": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.Endpoint.SandboxID = "different-sandbox"
		},
		"browser session": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.Endpoint.BrowserSessionID = "different-session"
		},
		"capability profile": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.Endpoint.CapabilityProfileID = "different-profile"
		},
		"expired grant": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.GrantBinding.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
		},
		"expired handoff": func(endpoint *provisioning.EndpointEnvelope) {
			endpoint.GrantBinding.ExpiresAt = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
			endpoint.HandoffExpiresAt = now.Add(-time.Second).Format(time.RFC3339Nano)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := baseline
			mutate(&candidate)
			if downstreamEndpointMatchesRequest(candidate, request, now) {
				t.Fatal("drifted or expired endpoint matched request")
			}
		})
	}
}

func TestDownstreamCallerProcessRejectsUncorrelatedEndpointAndReaps(t *testing.T) {
	request := downstreamProvisioningRequest("private-request-correlation-canary")
	marker := filepath.Join(t.TempDir(), "pid")
	_, _, err := startDownstreamCallerCommand(
		context.Background(), os.Args[0], downstreamHelperArguments("mismatched-endpoint", marker),
		filepath.Join(t.TempDir(), "child.log"), request,
	)
	if !errors.Is(err, errDownstreamCallerProcess) {
		t.Fatalf("start error = %v", err)
	}
	assertFixedDownstreamError(t, err, request.RequestID, "private-handoff-correlation-canary")
	assertHelperReaped(t, marker)
}

func TestDownstreamCallerProcessCancelDuringEndpointReadReaps(t *testing.T) {
	request := downstreamProvisioningRequest("private-request-cancel-canary")
	marker := filepath.Join(t.TempDir(), "pid")
	logPath := filepath.Join(t.TempDir(), "child.log")
	ctx, cancel := context.WithCancel(context.Background())
	type startResult struct {
		err error
	}
	result := make(chan startResult, 1)
	go func() {
		_, _, err := startDownstreamCallerCommand(
			ctx, os.Args[0], downstreamHelperArguments("hang-before-endpoint", marker),
			logPath, request,
		)
		result <- startResult{err: err}
	}()
	waitForHelperPID(t, marker)
	cancel()
	var err error
	select {
	case started := <-result:
		err = started.err
	case <-time.After(5 * time.Second):
		t.Fatal("canceled caller start did not return")
	}
	if !errors.Is(err, errDownstreamCallerProcess) {
		t.Fatalf("start error = %v", err)
	}
	assertFixedDownstreamError(t, err, request.RequestID)
	assertHelperReaped(t, marker)
}

func TestDownstreamCallerProcessEarlyExitIsReaped(t *testing.T) {
	request := downstreamProvisioningRequest("private-request-exit-canary")
	marker := filepath.Join(t.TempDir(), "pid")
	_, _, err := startDownstreamCallerCommand(
		context.Background(), os.Args[0], downstreamHelperArguments("exit-after-request", marker),
		filepath.Join(t.TempDir(), "child.log"), request,
	)
	if !errors.Is(err, errDownstreamCallerProcess) {
		t.Fatalf("start error = %v", err)
	}
	assertFixedDownstreamError(t, err, request.RequestID)
	assertHelperReaped(t, marker)
}

func TestDownstreamCallerProcessCommitTimeoutReaps(t *testing.T) {
	request := downstreamProvisioningRequest("private-request-commit-timeout-canary")
	marker := filepath.Join(t.TempDir(), "pid")
	process, endpoint, err := startDownstreamCallerCommand(
		context.Background(), os.Args[0], downstreamHelperArguments("hang-before-final", marker),
		filepath.Join(t.TempDir(), "child.log"), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	config := downstreamCallerConfig(endpoint)
	config.CAFile = "/" + strings.Repeat("private-commit-canary", 24_000)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = process.commit(ctx, config)
	if !errors.Is(err, errDownstreamCallerProcess) {
		t.Fatalf("commit error = %v", err)
	}
	assertFixedDownstreamError(t, err, request.RequestID, endpoint.Endpoint.HandoffReference, config.CAFile)
	assertHelperReaped(t, marker)
}

func TestDownstreamCallerProcessSecondCommitFailsClosed(t *testing.T) {
	request := downstreamProvisioningRequest("private-request-once-canary")
	marker := filepath.Join(t.TempDir(), "pid")
	process, endpoint, err := startDownstreamCallerCommand(
		context.Background(), os.Args[0], downstreamHelperArguments("normal", marker),
		filepath.Join(t.TempDir(), "child.log"), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	config := downstreamCallerConfig(endpoint)
	if err := process.commit(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	err = process.commit(context.Background(), config)
	if !errors.Is(err, errDownstreamCallerProcess) {
		t.Fatalf("second commit error = %v", err)
	}
	assertFixedDownstreamError(t, err, request.RequestID, endpoint.Endpoint.HandoffReference)
	assertHelperReaped(t, marker)
	if !downstreamParentIOClosed(process) {
		t.Fatal("failed second commit retained parent pipe ends")
	}
}

func TestDownstreamCallerProcessNaturalExitCleansParentIOAndReaps(t *testing.T) {
	request := downstreamProvisioningRequest("request-natural-exit")
	marker := filepath.Join(t.TempDir(), "pid")
	process, endpoint, err := startDownstreamCallerCommand(
		context.Background(), os.Args[0], downstreamHelperArguments("exit-after-final", marker),
		filepath.Join(t.TempDir(), "child.log"), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.commit(context.Background(), downstreamCallerConfig(endpoint)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.done:
	case <-time.After(5 * time.Second):
		t.Fatal("caller did not exit")
	}
	if !downstreamParentIOClosed(process) {
		t.Fatal("natural exit retained parent pipe ends")
	}
	assertHelperReaped(t, marker)
}

func TestDownstreamCallerProcessHelper(t *testing.T) {
	mode, marker, ok := downstreamHelperMode()
	if !ok {
		return
	}
	if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(90)
	}
	requestInput := os.NewFile(3, "helper-request")
	endpointOutput := os.NewFile(4, "helper-endpoint")
	finalInput := os.NewFile(5, "helper-final")
	if !helperPipeDirection(requestInput, unix.O_RDONLY) || !helperPipeDirection(endpointOutput, unix.O_WRONLY) ||
		!helperPipeDirection(finalInput, unix.O_RDONLY) {
		os.Exit(91)
	}
	unix.CloseOnExec(3)
	unix.CloseOnExec(4)
	unix.CloseOnExec(5)

	request, err := provisioning.ReadRequest(requestInput)
	_ = requestInput.Close()
	if err != nil {
		os.Exit(92)
	}
	if mode == "exit-after-request" {
		os.Exit(0)
	}
	if mode == "hang-before-endpoint" {
		for {
			time.Sleep(time.Second)
		}
	}
	envelope := downstreamHelperEndpoint(request)
	if mode == "mismatched-endpoint" {
		envelope.Endpoint.TenantID = "another-tenant"
		envelope.Endpoint.HandoffReference = "ref:browser-session:private-handoff-correlation-canary"
	}
	if err := provisioning.WriteEndpoint(endpointOutput, envelope); err != nil {
		os.Exit(93)
	}
	if err := endpointOutput.Close(); err != nil {
		os.Exit(94)
	}
	if mode == "hang-before-final" {
		for {
			time.Sleep(time.Second)
		}
	}
	final, err := provisioning.ReadFinalConfiguration(finalInput)
	_ = finalInput.Close()
	if err != nil || final.RequestID != request.RequestID {
		os.Exit(95)
	}
	if mode == "exit-after-final" {
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}

	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var command downstreamcaller.Command
		if json.Unmarshal(scanner.Bytes(), &command) != nil {
			os.Exit(96)
		}
		response := downstreamcaller.Response{Version: downstreamcaller.ProtocolVersion, Sequence: command.Sequence}
		if command.Action == downstreamcaller.ActionShutdown {
			response.OK = true
			response.Outcome = downstreamcaller.OutcomeTerminated
			if encoder.Encode(response) != nil {
				os.Exit(97)
			}
			os.Exit(0)
		}
		response.ErrorCode = downstreamcaller.ErrorInvalidCommand
		if encoder.Encode(response) != nil {
			os.Exit(98)
		}
	}
	if scanner.Err() != nil {
		os.Exit(99)
	}
	os.Exit(0)
}

func startDownstreamHelper(
	t *testing.T,
	ctx context.Context,
	mode string,
	request provisioning.Request,
) (*downstreamCallerProcess, provisioning.EndpointEnvelope, error) {
	t.Helper()
	root := t.TempDir()
	return startDownstreamCallerCommand(
		ctx, os.Args[0], downstreamHelperArguments(mode, filepath.Join(root, "pid")),
		filepath.Join(root, "child.log"), request,
	)
}

func downstreamHelperArguments(mode, marker string) []string {
	return []string{"-test.run=^TestDownstreamCallerProcessHelper$", "--", mode, marker}
}

func downstreamHelperMode() (string, string, bool) {
	for index, argument := range os.Args {
		if argument == "--" && index+2 < len(os.Args) {
			return os.Args[index+1], os.Args[index+2], true
		}
	}
	return "", "", false
}

func helperPipeDirection(file *os.File, direction int) bool {
	if file == nil {
		return false
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	return err == nil && flags&unix.O_ACCMODE == direction
}

func downstreamProvisioningRequest(id string) provisioning.Request {
	return provisioning.Request{
		Version: provisioning.ProtocolVersion, RequestID: id,
		ControllerSubject: "spiffe://downstream/controller-a", TenantID: "tenant-a", SandboxID: "sandbox-a",
		BrowserSessionID: "browser-session-a", CapabilityProfileID: "browser-v1",
	}
}

func downstreamHelperEndpoint(request provisioning.Request) provisioning.EndpointEnvelope {
	now := time.Now().UTC()
	return provisioning.EndpointEnvelope{
		Version: provisioning.ProtocolVersion, RequestID: request.RequestID,
		Endpoint: provisioning.Endpoint{
			ID: "endpoint-a", TenantID: request.TenantID, SandboxID: request.SandboxID,
			BrowserSessionID: request.BrowserSessionID, CapabilityProfileID: request.CapabilityProfileID,
			HandoffReference: "ref:browser-session:opaque-a", ConnectionGeneration: 7,
		},
		GrantBinding: provisioning.GrantBinding{
			ID: "binding-a", GrantID: "grant-a", PrincipalID: "principal-a", EndpointID: "endpoint-a",
			ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		},
		HandoffExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339Nano),
	}
}

func downstreamCallerConfig(endpoint provisioning.EndpointEnvelope) downstreamcaller.Config {
	return downstreamcaller.Config{
		CAFile: "/private/ca.pem",
		Gateways: map[string]string{
			"gateway-a": "https://127.0.0.1:19001", "gateway-b": "https://127.0.0.1:19002",
		},
		Principals: []downstreamcaller.Principal{{
			ID: endpoint.GrantBinding.PrincipalID, Token: strings.Repeat("t", 32), CallerID: "caller-a",
			TenantID: endpoint.Endpoint.TenantID,
		}},
		Endpoints: []downstreamcaller.Endpoint{{
			ID: endpoint.Endpoint.ID, TenantID: endpoint.Endpoint.TenantID, SandboxID: endpoint.Endpoint.SandboxID,
			BrowserSessionID: endpoint.Endpoint.BrowserSessionID, CapabilityProfileID: endpoint.Endpoint.CapabilityProfileID,
			HandoffReference: endpoint.Endpoint.HandoffReference, ConnectionGeneration: endpoint.Endpoint.ConnectionGeneration,
		}},
		GrantBindings: []downstreamcaller.GrantBinding{{
			ID: endpoint.GrantBinding.ID, GrantID: endpoint.GrantBinding.GrantID,
			PrincipalID: endpoint.GrantBinding.PrincipalID, EndpointID: endpoint.GrantBinding.EndpointID,
			ExpiresAt: endpoint.GrantBinding.ExpiresAt,
		}},
	}
}

func assertHelperReaped(t *testing.T, marker string) {
	t.Helper()
	pid := waitForHelperPID(t, marker)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := unix.Kill(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper process %d was not reaped", pid)
}

func waitForHelperPID(t *testing.T, marker string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(marker)
		if err == nil {
			pid, parseErr := strconv.Atoi(string(content))
			if parseErr != nil || pid < 1 {
				t.Fatalf("invalid helper PID marker: %q", content)
			}
			return pid
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("helper PID marker was not created")
	return 0
}

func assertFixedDownstreamError(t *testing.T, err error, private ...string) {
	t.Helper()
	if err == nil || err.Error() != errDownstreamCallerProcess.Error() {
		t.Fatalf("error = %v", err)
	}
	for _, value := range private {
		if value != "" && strings.Contains(fmt.Sprint(err), value) {
			t.Fatalf("error exposed private value %q", value)
		}
	}
}

func downstreamParentIOClosed(process *downstreamCallerProcess) bool {
	if process == nil {
		return true
	}
	process.ioMu.Lock()
	defer process.ioMu.Unlock()
	return process.input == nil && process.outputFile == nil && process.final == nil
}
