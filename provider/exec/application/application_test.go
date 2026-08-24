package application

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

var applicationTestNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

type recordingExecutor struct {
	calls      int
	reference  providerexec.ExecutionReference
	err        error
	invocation providerexec.Invocation
	deadline   time.Time
}

func (e *recordingExecutor) Start(ctx context.Context, invocation providerexec.Invocation) (providerexec.ExecutionReference, error) {
	e.calls++
	e.invocation = invocation
	e.deadline, _ = ctx.Deadline()
	return e.reference, e.err
}

func applicationRequest() providerexec.Request {
	return providerexec.Request{
		SandboxID:          "sandbox-1",
		OperationID:        "operation-1",
		AttemptID:          "attempt-1",
		FencingToken:       1,
		ExpectedGeneration: 1,
		IdempotencyKey:     "exec-request-1",
		RequestDigest:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:           time.Now().UTC().Add(time.Hour),
		Command:            []string{"printf", "hello"},
		WorkingDirectory:   "/workspace/src",
		ResultRetention:    time.Hour,
		Environment:        map[string]string{"HOME": "envref:grant/exec-home"},
		SecretReferenceIDs: []string{"secret-ref-1"},
		SecretGrantID:      "grant:exec-1",
		SecretGrantDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		StdinReference:     "ref:stdin-1",
		CaptureMaxBytes:    65536,
	}
}

func newApplication(t *testing.T, executor providerexec.Executor) *Application {
	t.Helper()
	application, err := New(executor, ClockFunc(func() time.Time { return applicationTestNow }))
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func TestNewRejectsNilDependencies(t *testing.T) {
	executor := &recordingExecutor{}
	clock := ClockFunc(func() time.Time { return applicationTestNow })
	if _, err := New(nil, clock); !errors.Is(err, providerexec.ErrInvalidApplication) {
		t.Fatalf("New(nil, clock) error = %v", err)
	}
	if _, err := New(executor, nil); !errors.Is(err, providerexec.ErrInvalidApplication) {
		t.Fatalf("New(executor, nil) error = %v", err)
	}
}

func TestStartRejectsBeforeExecutorDispatch(t *testing.T) {
	tests := []struct {
		name    string
		context context.Context
		mutate  func(*providerexec.Request)
		want    error
	}{
		{name: "cancelled context", context: cancelledContext(), want: context.Canceled},
		{name: "invalid request", context: context.Background(), mutate: func(r *providerexec.Request) { r.Command = nil }, want: providerexec.ErrInvalidRequest},
		{name: "expired deadline", context: context.Background(), mutate: func(r *providerexec.Request) { r.Deadline = applicationTestNow }, want: providerexec.ErrDeadlineExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &recordingExecutor{reference: "ref:exec/receipt-1"}
			request := applicationRequest()
			if test.mutate != nil {
				test.mutate(&request)
			}
			_, err := newApplication(t, executor).Start(test.context, request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Start() error = %v, want %v", err, test.want)
			}
			if executor.calls != 0 {
				t.Fatalf("executor calls = %d, want 0", executor.calls)
			}
		})
	}
}

func TestStartForwardsDeadlineAndImmutableInvocation(t *testing.T) {
	executor := &recordingExecutor{reference: "ref:exec/receipt-1"}
	request := applicationRequest()
	dispatch, err := newApplication(t, executor).Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if dispatch.ExecutionReference != "ref:exec/receipt-1" || !dispatch.AcceptedAt.Equal(applicationTestNow) {
		t.Fatalf("dispatch = %#v", dispatch)
	}
	if !executor.deadline.Equal(request.Deadline) || !executor.invocation.StartedAt.Equal(applicationTestNow) {
		t.Fatalf("executor timing = deadline %s, started %s", executor.deadline, executor.invocation.StartedAt)
	}
	request.Command[0] = "changed-command"
	request.SecretReferenceIDs[0] = "changed-reference"
	request.Environment["HOME"] = "envref:changed"
	if executor.invocation.Request.Command[0] != "printf" || executor.invocation.Request.SecretReferenceIDs[0] != "secret-ref-1" || executor.invocation.Request.Environment["HOME"] != "envref:grant/exec-home" {
		t.Fatalf("executor received mutable request: %#v", executor.invocation.Request)
	}
}

func TestStartPreservesKnownExecutorErrorAndMakesCancellationUnknown(t *testing.T) {
	known := errors.New("capacity exhausted")
	for name, executorErr := range map[string]error{
		"known error":       known,
		"cancelled":         context.Canceled,
		"deadline exceeded": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			executor := &recordingExecutor{reference: "ref:exec/receipt-1", err: executorErr}
			_, err := newApplication(t, executor).Start(context.Background(), applicationRequest())
			if executorErr == known {
				if !errors.Is(err, known) {
					t.Fatalf("Start() error = %v, want known executor error", err)
				}
				return
			}
			if !errors.Is(err, providerexec.ErrDispatchUnknown) {
				t.Fatalf("Start() error = %v, want ErrDispatchUnknown", err)
			}
		})
	}
}

func TestStartRejectsInvalidExecutorReferenceWithoutLeakage(t *testing.T) {
	backendReference := providerexec.ExecutionReference("/var/lib/docker/containers/abc")
	executor := &recordingExecutor{reference: backendReference}
	_, err := newApplication(t, executor).Start(context.Background(), applicationRequest())
	if !errors.Is(err, providerexec.ErrInvalidDispatch) {
		t.Fatalf("Start() error = %v, want ErrInvalidDispatch", err)
	}
	if strings.Contains(err.Error(), string(backendReference)) {
		t.Fatalf("Start() leaked backend reference in %q", err)
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
