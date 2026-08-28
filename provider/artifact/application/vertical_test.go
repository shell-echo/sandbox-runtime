package application

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	artifactmemory "github.com/shell-echo/sandbox-runtime/provider/artifact/repository/memory"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type verticalSandboxReader struct {
	sandbox lifecycle.Sandbox
	err     error
}

func (r verticalSandboxReader) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	return r.sandbox, r.err
}

type verticalSupport struct{ err error }

func (s verticalSupport) CheckSupport(context.Context, artifact.Request) error { return s.err }

type verticalStager struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *verticalStager) Stage(ctx context.Context, request artifact.Request, acceptedAt time.Time) (artifact.Evidence, error) {
	s.once.Do(func() { close(s.started) })
	select {
	case <-s.release:
		return applicationEvidence(request, artifact.StatusStaged), nil
	case <-ctx.Done():
		return artifact.Evidence{}, ctx.Err()
	}
}

func TestVerticalAcceptUsesProcessWorkerAndSynchronizesTenantAuthority(t *testing.T) {
	repository := artifactmemory.NewRepository()
	stager := &verticalStager{started: make(chan struct{}), release: make(chan struct{})}
	vertical, err := NewVertical(repository, stager, verticalReadySandbox(), verticalSupport{}, ClockFunc(func() time.Time { return applicationTestTime }))
	if err != nil {
		t.Fatal(err)
	}
	defer vertical.Close()
	request := applicationRequest("operation-vertical", "key-vertical")
	requestContext, cancel := context.WithCancel(context.Background())
	reservation, err := vertical.Accept(requestContext, request)
	if err != nil || reservation.Operation.Status != artifact.OperationAccepted {
		t.Fatalf("Accept() = %#v, %v", reservation, err)
	}
	cancel()
	<-stager.started
	close(stager.release)
	waitArtifactStatus(t, repository, request.OperationID, artifact.OperationSucceeded)
	authority, err := repository.GetSandboxAuthority(context.Background(), request.SandboxID)
	if err != nil || authority.Generation != request.ExpectedGeneration || authority.FencingToken != request.FencingToken {
		t.Fatalf("synchronized authority = %#v, %v", authority, err)
	}
}

func TestVerticalRejectsTenantAndUnsupportedChecksBeforeAcceptance(t *testing.T) {
	for _, test := range []struct {
		name      string
		sandboxes SandboxReader
		support   artifact.SupportChecker
		want      error
	}{
		{name: "tenant", sandboxes: verticalSandboxWithTenant("tenant-other"), support: verticalSupport{}, want: artifact.ErrTenantBinding},
		{name: "support", sandboxes: verticalReadySandbox(), support: verticalSupport{err: errors.New("scanner missing")}, want: artifact.ErrUnsupportedChecks},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := artifactmemory.NewRepository()
			stager := &verticalStager{started: make(chan struct{}), release: make(chan struct{})}
			vertical, err := NewVertical(repository, stager, test.sandboxes, test.support, ClockFunc(func() time.Time { return applicationTestTime }))
			if err != nil {
				t.Fatal(err)
			}
			defer vertical.Close()
			request := applicationRequest("operation-"+test.name, "key-"+test.name)
			if _, err := vertical.Accept(context.Background(), request); !errors.Is(err, test.want) {
				t.Fatalf("Accept() error = %v, want %v", err, test.want)
			}
			if _, err := repository.GetStage(context.Background(), request.OperationID); !errors.Is(err, artifact.ErrNotFound) {
				t.Fatalf("pre-accept failure persisted operation: %v", err)
			}
		})
	}
}

func TestVerticalCloseWaitsAndPersistsUnknownOutcome(t *testing.T) {
	repository := artifactmemory.NewRepository()
	stager := &verticalStager{started: make(chan struct{}), release: make(chan struct{})}
	vertical, err := NewVertical(repository, stager, verticalReadySandbox(), verticalSupport{}, ClockFunc(func() time.Time { return applicationTestTime }))
	if err != nil {
		t.Fatal(err)
	}
	request := applicationRequest("operation-close", "key-close")
	if _, err := vertical.Accept(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	<-stager.started
	if err := vertical.Close(); err != nil {
		t.Fatal(err)
	}
	operation, err := repository.GetStage(context.Background(), request.OperationID)
	if err != nil || operation.Status != artifact.OperationOutcomeUnknown {
		t.Fatalf("closed worker operation = %#v, %v", operation, err)
	}
}

func verticalReadySandbox() SandboxReader { return verticalSandboxWithTenant("tenant-1") }

func verticalSandboxWithTenant(tenantID string) SandboxReader {
	return verticalSandboxReader{sandbox: lifecycle.Sandbox{
		ID: "sandbox-1", TenantID: tenantID, WorkOrderID: "work-1", WorkspaceID: "workspace-1",
		ProviderRevisionID: "revision-1", RuntimeProfile: "runtime-1", SandboxSlotKey: "slots/one",
		DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady,
		Generation: 4, ObservedGeneration: 4, LeaseExpiresAt: applicationTestTime.Add(time.Hour),
		CreatedAt: applicationTestTime.Add(-time.Hour), UpdatedAt: applicationTestTime,
	}}
}

func waitArtifactStatus(t *testing.T, repository *artifactmemory.Repository, operationID string, want artifact.OperationStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := repository.GetStage(context.Background(), operationID)
		if err == nil && operation.Status == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	operation, err := repository.GetStage(context.Background(), operationID)
	t.Fatalf("operation status = %#v, %v; want %s", operation, err, want)
}
