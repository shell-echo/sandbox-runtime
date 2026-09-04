//go:build integration

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	artifactapplication "github.com/shell-echo/sandbox-runtime/provider/artifact/application"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	execapplication "github.com/shell-echo/sandbox-runtime/provider/exec/application"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

// TestProviderArtifactUsageVerticalIntegration is same-repository,
// single-controller development evidence. It does not exercise an independent
// caller, public Gateway, multi-controller storage, or tenant isolation.
func TestProviderArtifactUsageVerticalIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DOCKER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 to run against Docker Engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	dataRoot, err := os.MkdirTemp(".", ".provider-artifact-usage-vertical-")
	if err != nil {
		t.Fatal(err)
	}
	dataRoot, err = filepath.Abs(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataRoot) })

	image := f7IntegrationPinnedImage(ctx, t)
	controllerID := "p25g-controller-" + time.Now().UTC().Format("150405.000000000")
	sandboxID := "p25g-sandbox-" + time.Now().UTC().Format("150405.000000000")
	lifecycleConfig := f7LifecycleConfig(dataRoot, image, controllerID)
	t.Cleanup(func() { f7RemoveSandbox(t, lifecycleConfig, sandboxID) })
	execConfig := config.ProviderExecConfig{Enabled: true, RepositoryFile: filepath.Join(dataRoot, "exec.json")}
	usageConfig := config.ProviderUsageConfig{Enabled: true, RepositoryFile: filepath.Join(dataRoot, "usage.json")}
	artifactConfig := config.ProviderArtifactConfig{
		Enabled: true, RepositoryFile: filepath.Join(dataRoot, "artifacts.json"), StagingRoot: filepath.Join(dataRoot, "staging"),
		ActiveContentCommand: []string{"true"}, MalwareCommand: []string{"true"},
	}

	composition, err := openP25GComposition(ctx, lifecycleConfig, execConfig, usageConfig, artifactConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if composition != nil {
			_ = composition.Close()
		}
	}()

	now := time.Now().UTC()
	create := f7CreateRequest(now, sandboxID)
	create.Spec.LeaseExpiresAt = now.Add(5 * time.Minute)
	if _, err := composition.lifecycle.AcceptCreate(ctx, create); err != nil {
		t.Fatalf("accept lifecycle create: %v", err)
	}
	if err := composition.lifecycle.Recover(ctx); err != nil {
		t.Fatalf("recover lifecycle create: %v", err)
	}
	ready, err := composition.lifecycle.GetSandbox(ctx, sandboxID)
	if err != nil || ready.ObservedState != lifecycle.ObservedReady || ready.ObservedGeneration != ready.Generation {
		t.Fatalf("ready sandbox = %#v, %v", ready, err)
	}

	content := []byte("hello-artifact\n")
	execRequest := p25gExecRequest(now, sandboxID)
	if view, err := composition.exec.AcceptExec(ctx, execRequest); err != nil || view.Type != provideroperation.TypeExec {
		t.Fatalf("accept output-producing exec = %#v, %v", view, err)
	}
	result := waitP25GExecResult(t, composition.exec, execRequest.OperationID)
	if result.Status != providerexec.ResultCompleted || result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("output-producing exec result = %#v", result)
	}
	usageEvidence, err := composition.usage.GetEvidence(ctx, execRequest.OperationID, time.Now().UTC())
	if err != nil {
		t.Fatalf("read usage evidence: %v", err)
	}
	assertP25GUsageEvidence(t, usageEvidence)

	stagedRequest := p25gArtifactRequest(time.Now().UTC(), sandboxID, "p25g-artifact-staged", 2, "/outputs/report.txt", p25gDigest(content))
	stagedReservation, err := composition.artifact.Accept(ctx, stagedRequest)
	if err != nil || stagedReservation.Operation.Status != artifact.OperationAccepted {
		t.Fatalf("accept staged artifact = %#v, %v", stagedReservation, err)
	}
	stagedOperation := waitP25GArtifact(t, composition.artifact, stagedRequest.OperationID)
	if stagedOperation.Status != artifact.OperationSucceeded {
		t.Fatalf("staged operation = %#v", stagedOperation)
	}
	stagedEvidence, err := composition.artifact.GetEvidence(ctx, stagedRequest.OperationID)
	if err != nil || stagedEvidence.Status != artifact.StatusStaged || !strings.HasPrefix(stagedEvidence.StagingReference, "ref:staging/") || strings.Contains(stagedEvidence.StagingReference, dataRoot) {
		t.Fatalf("staged evidence = %#v, %v", stagedEvidence, err)
	}

	rejectedRequest := p25gArtifactRequest(time.Now().UTC(), sandboxID, "p25g-artifact-rejected", 3, "/outputs/report.txt", "sha256:"+strings.Repeat("f", 64))
	if _, err := composition.artifact.Accept(ctx, rejectedRequest); err != nil {
		t.Fatalf("accept rejected artifact: %v", err)
	}
	rejectedOperation := waitP25GArtifact(t, composition.artifact, rejectedRequest.OperationID)
	rejectedEvidence, rejectedErr := composition.artifact.GetEvidence(ctx, rejectedRequest.OperationID)
	if rejectedOperation.Status != artifact.OperationFailed || rejectedOperation.Failure != artifact.FailureContentRejected || rejectedErr != nil || rejectedEvidence.Status != artifact.StatusRejected || rejectedEvidence.ContentDigest != p25gDigest(content) {
		t.Fatalf("rejected artifact = %#v, evidence %#v, %v", rejectedOperation, rejectedEvidence, rejectedErr)
	}

	missingRequest := p25gArtifactRequest(time.Now().UTC(), sandboxID, "p25g-artifact-missing", 4, "/outputs/missing.txt", p25gDigest([]byte("missing")))
	if _, err := composition.artifact.Accept(ctx, missingRequest); err != nil {
		t.Fatalf("accept missing artifact: %v", err)
	}
	missingOperation := waitP25GArtifact(t, composition.artifact, missingRequest.OperationID)
	if missingOperation.Status != artifact.OperationFailed || missingOperation.Failure != artifact.FailureSourceMissing {
		t.Fatalf("missing artifact operation = %#v", missingOperation)
	}
	if _, err := composition.artifact.GetEvidence(ctx, missingRequest.OperationID); !errors.Is(err, artifact.ErrEvidenceNotFound) {
		t.Fatalf("missing artifact evidence error = %v", err)
	}

	operationReader, err := newProviderOperationReader(composition.lifecycle, composition.exec, nil, composition.artifact, nil)
	if err != nil {
		t.Fatal(err)
	}
	for operationID, wantType := range map[string]provideroperation.Type{
		create.OperationID:          provideroperation.TypeCreate,
		execRequest.OperationID:     provideroperation.TypeExec,
		stagedRequest.OperationID:   provideroperation.TypeArtifactStage,
		rejectedRequest.OperationID: provideroperation.TypeArtifactStage,
	} {
		view, err := operationReader.ReadOperation(ctx, operationID)
		if err != nil || view.Type != wantType {
			t.Fatalf("aggregated operation %q = %#v, %v; want %s", operationID, view, err, wantType)
		}
	}

	stagedReference := stagedEvidence.StagingReference
	usageID := usageEvidence.EvidenceID
	if err := composition.Close(); err != nil {
		t.Fatalf("close first P2.5g composition: %v", err)
	}
	composition = nil

	composition, err = openP25GComposition(ctx, lifecycleConfig, execConfig, usageConfig, artifactConfig)
	if err != nil {
		t.Fatalf("restart P2.5g composition: %v", err)
	}
	recoveredArtifact, err := composition.artifact.GetEvidence(ctx, stagedRequest.OperationID)
	if err != nil || recoveredArtifact.StagingReference != stagedReference {
		t.Fatalf("recovered artifact evidence = %#v, %v", recoveredArtifact, err)
	}
	recoveredUsage, err := composition.usage.GetEvidence(ctx, execRequest.OperationID, time.Now().UTC())
	if err != nil || recoveredUsage.EvidenceID != usageID {
		t.Fatalf("recovered usage evidence = %#v, %v", recoveredUsage, err)
	}
}

type p25gComposition struct {
	lifecycle *lifecycleapplication.Application
	exec      *execapplication.Vertical
	artifact  *artifactapplication.Vertical
	usage     usage.EvidenceReader
	closers   []func() error
}

func openP25GComposition(ctx context.Context, lifecycleConfig config.ProviderLifecycleConfig, execConfig config.ProviderExecConfig, usageConfig config.ProviderUsageConfig, artifactConfig config.ProviderArtifactConfig) (*p25gComposition, error) {
	lifecycleApp, runtime, closeLifecycle, err := newProviderLifecycleRuntime(ctx, lifecycleConfig)
	if err != nil {
		return nil, err
	}
	store, collector, closeUsage, err := newProviderUsageCollector(usageConfig)
	if err != nil {
		return nil, errors.Join(err, closeLifecycle())
	}
	execApp, closeExec, err := newProviderExecApplication(ctx, execConfig, lifecycleApp, runtime, collector)
	if err != nil {
		return nil, errors.Join(err, closeUsage(), closeLifecycle())
	}
	usageReader, err := newProviderUsageReader(usageConfig, store, collector, execApp, nil)
	if err != nil {
		return nil, errors.Join(err, closeExec(), closeUsage(), closeLifecycle())
	}
	artifactApp, closeArtifact, err := newProviderArtifactApplication(ctx, artifactConfig, lifecycleApp, runtime)
	if err != nil {
		return nil, errors.Join(err, closeExec(), closeUsage(), closeLifecycle())
	}
	return &p25gComposition{
		lifecycle: lifecycleApp, exec: execApp, artifact: artifactApp, usage: usageReader,
		closers: []func() error{closeArtifact, closeExec, closeUsage, closeLifecycle},
	}, nil
}

func (c *p25gComposition) Close() error {
	if c == nil {
		return nil
	}
	var result error
	for _, closeComponent := range c.closers {
		result = errors.Join(result, closeComponent())
	}
	c.closers = nil
	return result
}

func p25gExecRequest(now time.Time, sandboxID string) providerexec.Request {
	return providerexec.Request{
		SandboxID: sandboxID, OperationID: "p25g-exec-output", AttemptID: "p25g-exec-output-attempt",
		FencingToken: 2, ExpectedGeneration: 1, IdempotencyKey: "p25g-exec-output-key",
		RequestDigest: "sha256:" + strings.Repeat("d", 64), Deadline: now.Add(2 * time.Minute),
		Command: []string{"sh", "-c", "printf 'hello-artifact\\n' > /outputs/report.txt"}, WorkingDirectory: "/workspace",
		ResultRetention: 3 * time.Minute,
	}
}

func p25gArtifactRequest(now time.Time, sandboxID, operationID string, fencingToken int64, sourcePath, expectedDigest string) artifact.Request {
	return artifact.Request{
		SandboxID: sandboxID, TenantID: "tenant-f7", OperationID: operationID, AttemptID: operationID + "-attempt",
		FencingToken: fencingToken, ExpectedGeneration: 1, IdempotencyKey: operationID + "-key",
		RequestDigest: "sha256:" + strings.Repeat(string('a'+rune(fencingToken)), 64), Deadline: now.Add(2 * time.Minute),
		ArtifactReference: "artifact-ref:platform/" + operationID, SourcePath: sourcePath,
		ExpectedDigest: expectedDigest, ExpectedMediaType: "text/plain", MaxBytes: 4096, Retention: time.Minute,
	}
}

func waitP25GExecResult(t *testing.T, application *execapplication.Vertical, operationID string) providerexec.Result {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		result, err := application.GetResult(context.Background(), operationID)
		if err == nil {
			return result
		}
		time.Sleep(100 * time.Millisecond)
	}
	result, err := application.GetResult(context.Background(), operationID)
	t.Fatalf("exec result did not become available: %#v, %v", result, err)
	return providerexec.Result{}
}

func waitP25GArtifact(t *testing.T, application *artifactapplication.Vertical, operationID string) artifact.Operation {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		operation, err := application.GetOperation(context.Background(), operationID)
		if err == nil && operation.Status != artifact.OperationAccepted && operation.Status != artifact.OperationRunning {
			return operation
		}
		time.Sleep(25 * time.Millisecond)
	}
	operation, err := application.GetOperation(context.Background(), operationID)
	t.Fatalf("artifact operation did not become terminal: %#v, %v", operation, err)
	return artifact.Operation{}
}

func assertP25GUsageEvidence(t *testing.T, evidence usage.Evidence) {
	t.Helper()
	if evidence.ReconciliationStatus != usage.ReconciliationPartial || len(evidence.Entries) != 2 {
		t.Fatalf("usage evidence = %#v", evidence)
	}
	meters := map[usage.Meter]bool{}
	for _, entry := range evidence.Entries {
		meters[entry.Meter] = true
	}
	if !meters[usage.MeterWallTime] || !meters[usage.MeterExecCount] || len(meters) != 2 {
		t.Fatalf("usage meters = %#v", meters)
	}
}

func p25gDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
