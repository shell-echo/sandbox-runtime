package providerapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	execrepository "github.com/shell-echo/sandbox-runtime/provider/exec/repository"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func TestProtectedExecVerticalProjectsAcceptCancelResultAndOperation(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &transportExecApp{result: validTransportExecResult()}
	handler := newExecTransportHandler(t, identity, publicKey, &releaseGateGuard{decision: admission.MutationGuardAccepted}, app, app)

	execRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec", operation: admission.OperationExec, allowUnavailable: true}, privateKey, material.client, "jti-exec-vertical-0001")
	execResponse := httptest.NewRecorder()
	handler.ServeHTTP(execResponse, execRequest)
	if execResponse.Code != http.StatusAccepted || app.execCalls != 1 || app.lastExec.Command[0] != "true" {
		t.Fatalf("exec response=%d calls=%d request=%#v body=%s", execResponse.Code, app.execCalls, app.lastExec, execResponse.Body.String())
	}
	var execOperation providerv1.Operation
	if err := json.Unmarshal(execResponse.Body.Bytes(), &execOperation); err != nil || execOperation.Type != providerv1.OperationExec || execOperation.ResultReference != "ref:exec/operation-1/result" {
		t.Fatalf("exec operation=%#v decode=%v", execOperation, err)
	}

	cancelRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodPost, path: "/v1/sandboxes/sandbox-1/exec:cancel", operation: admission.OperationCancelExec}, privateKey, material.client, "jti-exec-cancel-0001")
	cancelResponse := httptest.NewRecorder()
	handler.ServeHTTP(cancelResponse, cancelRequest)
	if cancelResponse.Code != http.StatusAccepted || app.cancelCalls != 1 || app.lastCancellation.TargetOperationID != "exec-operation-1" {
		t.Fatalf("cancel response=%d calls=%d intent=%#v body=%s", cancelResponse.Code, app.cancelCalls, app.lastCancellation, cancelResponse.Body.String())
	}

	resultRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1/exec-result", operation: admission.OperationReadResult}, privateKey, material.client, "jti-exec-result-0001")
	resultResponse := httptest.NewRecorder()
	handler.ServeHTTP(resultResponse, resultRequest)
	if resultResponse.Code != http.StatusOK || app.resultCalls != 1 {
		t.Fatalf("result response=%d calls=%d body=%s", resultResponse.Code, app.resultCalls, resultResponse.Body.String())
	}
	var result providerv1.ExecResult
	if err := json.Unmarshal(resultResponse.Body.Bytes(), &result); err != nil || result.Status != providerv1.ExecCompleted || result.ExitCode == nil || *result.ExitCode != 7 || result.StdoutReference != "ref:exec/output/stdout" {
		t.Fatalf("exec result=%#v decode=%v", result, err)
	}

	operationRequest := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true}, privateKey, material.client, "jti-exec-operation-0001")
	operationResponse := httptest.NewRecorder()
	handler.ServeHTTP(operationResponse, operationRequest)
	if operationResponse.Code != http.StatusOK {
		t.Fatalf("operation response=%d body=%s", operationResponse.Code, operationResponse.Body.String())
	}
}

func TestProtectedExecResultStateAndCorrelationMatrix(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		err    error
		mutate func(*providerexec.Result)
		want   int
		code   string
	}{
		{name: "pending", err: execrepository.ErrPending, want: http.StatusServiceUnavailable, code: "SANDBOX_EXEC_RESULT_PENDING"},
		{name: "missing", err: execrepository.ErrNotFound, want: http.StatusNotFound, code: "SANDBOX_EXEC_RESULT_NOT_FOUND"},
		{name: "expired", err: execrepository.ErrExpired, want: http.StatusGone, code: "SANDBOX_EXEC_RESULT_EXPIRED"},
		{name: "correlation", mutate: func(r *providerexec.Result) { r.SandboxID = "sandbox-other" }, want: http.StatusServiceUnavailable, code: "SANDBOX_PROVIDER_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := validTransportExecResult()
			if test.mutate != nil {
				test.mutate(&result)
			}
			app := &transportExecApp{result: result, resultErr: test.err}
			handler := newExecTransportHandler(t, identity, publicKey, &releaseGateGuard{decision: admission.MutationGuardAccepted}, app, nil)
			request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1/exec-result", operation: admission.OperationReadResult}, privateKey, material.client, "jti-exec-result-"+test.name+"-1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("response=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			var standard providerv1.StandardError
			if err := json.Unmarshal(response.Body.Bytes(), &standard); err != nil || standard.Code != test.code {
				t.Fatalf("error=%#v decode=%v", standard, err)
			}
		})
	}
}

func TestProtectedExecOperationRejectsAdmissionCorrelationMismatch(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	identity, err := newClientIdentityAdmission([]string{testAllowedIdentity})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	app := &transportExecApp{operationSandboxID: "sandbox-other"}
	handler := newExecTransportHandler(t, identity, publicKey, &releaseGateGuard{decision: admission.MutationGuardAccepted}, app, app)
	request := newProtectedReleaseRequest(t, protectedReleaseRoute{method: http.MethodGet, path: "/v1/operations/operation-1", operation: admission.OperationReadOperation, allowUnavailable: true}, privateKey, material.client, "jti-exec-operation-correlation1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
}

type transportExecApp struct {
	mu                 sync.Mutex
	execCalls          int
	cancelCalls        int
	resultCalls        int
	lastExec           providerexec.Request
	lastCancellation   providerexec.CancellationIntent
	result             providerexec.Result
	resultErr          error
	operationSandboxID string
}

func (a *transportExecApp) AcceptExec(_ context.Context, request providerexec.Request) (provideroperation.View, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.execCalls++
	a.lastExec = request.Clone()
	return provideroperation.View{
		OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.FencingToken,
		SandboxID: request.SandboxID, Type: provideroperation.TypeExec, Status: provideroperation.StatusRunning,
		ProviderOperationID: request.OperationID, ResultReference: "ref:exec/" + request.OperationID + "/result", ObservedAt: releaseGateTestTime(),
	}, nil
}

func (a *transportExecApp) AcceptCancellation(_ context.Context, intent providerexec.CancellationIntent) (provideroperation.View, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cancelCalls++
	a.lastCancellation = intent
	return provideroperation.View{
		OperationID: intent.OperationID, AttemptID: intent.AttemptID, FencingToken: intent.FencingToken,
		SandboxID: intent.SandboxID, Type: provideroperation.TypeCancelExec, Status: provideroperation.StatusAccepted,
		ProviderOperationID: intent.OperationID, ObservedAt: releaseGateTestTime(),
	}, nil
}

func (a *transportExecApp) GetResult(context.Context, string) (providerexec.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resultCalls++
	return *a.result.Clone(), a.resultErr
}

func (a *transportExecApp) ReadOperation(_ context.Context, operationID string) (provideroperation.View, error) {
	if operationID != "operation-1" {
		return provideroperation.View{}, provideroperation.ErrNotFound
	}
	sandboxID := a.operationSandboxID
	if sandboxID == "" {
		sandboxID = "sandbox-1"
	}
	return provideroperation.View{
		OperationID: operationID, AttemptID: "attempt-1", FencingToken: 1, SandboxID: sandboxID,
		Type: provideroperation.TypeExec, Status: provideroperation.StatusSucceeded,
		ProviderOperationID: operationID, ResultReference: "ref:exec/operation-1/result", ObservedAt: releaseGateTestTime(),
	}, nil
}

func newExecTransportHandler(t *testing.T, identity *clientIdentityAdmission, publicKey ed25519.PublicKey, guard *releaseGateGuard, app ExecApplication, reader provideroperation.Reader) http.Handler {
	t.Helper()
	gate, err := admission.NewProtectedOperationGate(mustTestTrustedKeySource(t, publicKey), testAdmissionClock{now: releaseGateTestTime()}, guard)
	if err != nil {
		t.Fatal(err)
	}
	var operationReader provideroperation.Reader
	if reader != nil {
		operationReader, err = provideroperation.NewAggregator(reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	handler, err := newProtectedHandler(identity, ProtectedTransportOptions{
		Gate: gate, ExecApplication: app, OperationReader: operationReader, Now: func() time.Time { return releaseGateTestTime() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func validTransportExecResult() providerexec.Result {
	now := releaseGateTestTime()
	exitCode := 7
	result, _ := providerexec.NewResult(providerexec.Request{
		SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
		ResultRetention: time.Hour,
	}, now, now.Add(time.Second), providerexec.ResultOutcome{
		Status: providerexec.ResultCompleted, ExitCode: &exitCode,
		StdoutReference: "ref:exec/output/stdout", StderrReference: "ref:exec/output/stderr",
	})
	return result
}

var (
	_ ExecApplication          = (*transportExecApp)(nil)
	_ provideroperation.Reader = (*transportExecApp)(nil)
)
