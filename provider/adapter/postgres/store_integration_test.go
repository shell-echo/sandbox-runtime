//go:build integration

package providerpostgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/browserbinding"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	browsermux "github.com/shell-echo/sandbox-runtime/provider/browser/mux"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	"github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktoprepository "github.com/shell-echo/sandbox-runtime/provider/desktop/repository"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

const providerPostgresImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func TestProviderTransactionalStateIntegration(t *testing.T) { //nolint:maintidx
	if os.Getenv("SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	container := fmt.Sprintf("sandbox-runtime-provider-state-%d-%d", time.Now().UnixNano(), os.Getpid())
	remove := func() { _ = exec.Command("docker", "rm", "-f", container).Run() }
	t.Cleanup(remove)
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container,
		"-e", "POSTGRES_PASSWORD=provider-admin", "-e", "POSTGRES_DB=provider",
		"-p", "127.0.0.1::5432", providerPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start PostgreSQL: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := "postgres://postgres:provider-admin@127.0.0.1:" + port + "/provider?sslmode=disable"
	waitForProviderPostgres(t, ctx, adminDSN)
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `CREATE ROLE provider_migrator LOGIN PASSWORD 'migration-secret'; CREATE ROLE provider_runtime LOGIN PASSWORD 'runtime-secret'; GRANT CREATE ON DATABASE provider TO provider_migrator`); err != nil {
		t.Fatal(err)
	}
	migrationDSN := "postgres://provider_migrator:migration-secret@127.0.0.1:" + port + "/provider?sslmode=disable"
	runtimeDSN := "postgres://provider_runtime:runtime-secret@127.0.0.1:" + port + "/provider?sslmode=disable"
	migrationPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationPool.Close()
	if err := ApplyMigrations(ctx, migrationPool); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `GRANT USAGE ON SCHEMA sandbox_runtime_provider TO provider_runtime;
GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO provider_runtime;
GRANT SELECT,UPDATE ON sandbox_runtime_provider.control_state TO provider_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON sandbox_runtime_provider.schema_migrations FROM provider_runtime`); err != nil {
		t.Fatal(err)
	}
	runtimePool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	if err := VerifySeparatedRoles(ctx, migrationPool, runtimePool, "provider_migrator", "provider_runtime"); err != nil {
		t.Fatal(err)
	}
	if err := VerifySchemaCompatibility(ctx, runtimePool); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimePool.Exec(ctx, `CREATE TABLE sandbox_runtime_provider.unsafe(id bigint)`); err == nil {
		t.Fatal("runtime role retained DDL authority")
	}
	if _, err := runtimePool.Exec(ctx, `INSERT INTO sandbox_runtime_provider.schema_migrations(version,digest) VALUES(999,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err == nil {
		t.Fatal("runtime role retained migration-ledger write authority")
	}
	if _, err := runtimePool.Exec(ctx, `DELETE FROM sandbox_runtime_provider.control_state`); err == nil {
		t.Fatal("runtime role retained destructive control-state authority")
	}
	storeA, _ := New(runtimePool, time.Second)
	secondPool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer secondPool.Close()
	storeB, _ := New(secondPool, time.Second)
	now := time.Now().UTC()
	exerciseProviderRepositories(t, ctx, storeA, storeB, now)
	request := admission.MutationGuardRequest{ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1, JTIFingerprint: sha256.Sum256([]byte("one-use-jti")), ExpiresAt: now.Add(4 * time.Minute)}
	var accepted, replayed, failed atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			store := storeA
			if index%2 == 1 {
				store = storeB
			}
			guard, _ := NewAdmissionGuard(store, fixedClock{now: now})
			decision, reserveErr := guard.Reserve(ctx, request)
			if reserveErr != nil {
				failed.Add(1)
			} else if decision == admission.MutationGuardAccepted {
				accepted.Add(1)
			} else if decision == admission.MutationGuardReplayed {
				replayed.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if accepted.Load() != 1 || replayed.Load() != 31 || failed.Load() != 0 {
		t.Fatalf("concurrent admission accepted=%d replayed=%d failed=%d", accepted.Load(), replayed.Load(), failed.Load())
	}
	usageRepository, _ := NewUsageRepository(storeA, fixedClock{now: now})
	evidence := usage.Evidence{EvidenceID: "usage-1", SandboxID: "sandbox-1", OperationID: "operation-1", AttemptID: "attempt-1", FencingToken: 1,
		Entries:              []usage.Entry{{EntryID: "entry-1", SandboxID: "sandbox-1", OperationID: "operation-1", Meter: usage.MeterExecCount, Quantity: 1, Unit: "count", MeterSource: usage.SourceRuntime, EvidenceReference: "ref:usage/1", OccurredAt: now}},
		ReconciliationStatus: usage.ReconciliationComplete, ObservedAt: now, RetainedUntil: now.Add(time.Hour), EvidenceDigest: "sha256:" + strings.Repeat("b", 64)}
	if err := usageRepository.Put(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(ctx, "docker", "pause", container).CombinedOutput(); err != nil {
		t.Fatalf("pause PostgreSQL: %v: %s", err, output)
	}
	faultCtx, faultCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	if err := storeA.Ping(faultCtx); err == nil {
		t.Fatal("paused PostgreSQL remained ready")
	}
	faultCancel()
	if output, err := exec.CommandContext(ctx, "docker", "unpause", container).CombinedOutput(); err != nil {
		t.Fatalf("unpause PostgreSQL: %v: %s", err, output)
	}
	waitForProviderPostgres(t, ctx, runtimeDSN)
	if output, err := exec.CommandContext(ctx, "docker", "restart", container).CombinedOutput(); err != nil {
		t.Fatalf("restart PostgreSQL: %v: %s", err, output)
	}
	// Docker Desktop may reallocate an anonymous published host port across a
	// container restart. Re-resolve that infrastructure coordinate; the
	// retained database volume and Provider documents are the state under test.
	portOutput, err = exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err = net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	runtimeDSN = "postgres://provider_runtime:runtime-secret@127.0.0.1:" + port + "/provider?sslmode=disable"
	migrationDSN = "postgres://provider_migrator:migration-secret@127.0.0.1:" + port + "/provider?sslmode=disable"
	waitForProviderPostgres(t, ctx, runtimeDSN)
	restartedPool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedPool.Close()
	restartedStore, _ := New(restartedPool, time.Second)
	restartedGuard, _ := NewAdmissionGuard(restartedStore, fixedClock{now: now})
	if decision, err := restartedGuard.Reserve(ctx, request); err != nil || decision != admission.MutationGuardReplayed {
		t.Fatalf("post-restart admission = %v, %v", decision, err)
	}
	restartedUsage, _ := NewUsageRepository(restartedStore, fixedClock{now: now})
	if retained, err := restartedUsage.GetEvidence(ctx, "operation-1", now.Add(time.Minute)); err != nil || retained.EvidenceID != evidence.EvidenceID {
		t.Fatalf("post-restart usage = %#v, %v", retained, err)
	}
	restartedMigrationPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedMigrationPool.Close()
	if _, err := restartedMigrationPool.Exec(ctx, `INSERT INTO sandbox_runtime_provider.schema_migrations(version,digest) VALUES(999,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err != nil {
		t.Fatal(err)
	}
	if err := VerifySchemaCompatibility(ctx, restartedPool); err == nil {
		t.Fatal("newer Provider schema was accepted")
	}
	if _, err := restartedMigrationPool.Exec(ctx, `DELETE FROM sandbox_runtime_provider.schema_migrations WHERE version=999`); err != nil {
		t.Fatal(err)
	}
	if err := VerifySchemaCompatibility(ctx, restartedPool); err != nil {
		t.Fatal(err)
	}
	restartedBrowser, _ := NewBrowserRepository(restartedStore)
	if retained, err := restartedBrowser.GetOpenAt(ctx, "browser-operation-1", now.Add(2*time.Second)); err != nil || retained.Status != browser.StatusSucceeded {
		t.Fatalf("post-restart Browser session = %#v, %v", retained, err)
	}
	restartedReference, _ := NewBrowserReferenceStore(restartedStore)
	if retained, err := restartedReference.Get(ctx, "ref:browser-session:00000000000000000000000000000001"); err != nil || retained.RevokedAt == nil || retained.TenantBindingDigest == "" {
		t.Fatalf("post-restart Browser revoked reference = %#v, %v", retained, err)
	}
	remove()
	output, err = exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/"+container+"$", "--format", "{{.Names}}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("PostgreSQL container retained: err=%v output=%s", err, output)
	}
}

func exerciseProviderRepositories(t *testing.T, ctx context.Context, writer, reader *Store, now time.Time) { //nolint:maintidx
	t.Helper()
	lifecycleWriter, _ := NewLifecycleRepository(writer)
	lifecycleReader, _ := NewLifecycleRepository(reader)
	create := lifecycle.CreateRequest{
		OperationID: "lifecycle-create-1", AttemptID: "lifecycle-attempt-1", FencingToken: 1,
		IdempotencyKey: "lifecycle-key-1", RequestDigest: "sha256:" + strings.Repeat("1", 64), Deadline: now.Add(time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-lifecycle-1", TenantID: "tenant-1", WorkOrderID: "work-1", WorkspaceID: "workspace-1",
			ProviderRevisionID: "provider-revision-1", RuntimeProfile: "sandbox-runtime-coding-shell-v1", SandboxSlotKey: "primary-code",
			LeaseExpiresAt: now.Add(time.Hour),
		},
	}
	sandbox, operation, err := lifecycle.StartCreate(create, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycleWriter.ReserveCreate(ctx, create.IdempotencyKey, create.RequestDigest, sandbox, operation); err != nil {
		t.Fatalf("lifecycle reserve: %v", err)
	}
	if retained, err := lifecycleReader.GetSandbox(ctx, sandbox.ID); err != nil || retained.ID != sandbox.ID {
		t.Fatalf("transactional lifecycle read = %#v, %v", retained, err)
	}

	execWriter, _ := NewExecRepository(writer)
	execReader, _ := NewExecRepository(reader)
	execRequest := providerexec.Request{
		SandboxID: sandbox.ID, OperationID: "exec-operation-1", AttemptID: "exec-attempt-1", FencingToken: 1, ExpectedGeneration: 1,
		IdempotencyKey: "exec-key-1", RequestDigest: "sha256:" + strings.Repeat("2", 64), Deadline: now.Add(time.Minute),
		Command: []string{"printf", "hello"}, WorkingDirectory: "/workspace", ResultRetention: time.Hour,
	}
	if _, err := execWriter.ReserveExecution(ctx, execRequest, providerexec.Dispatch{ExecutionReference: "ref:exec/transactional-1", AcceptedAt: now}); err != nil {
		t.Fatalf("exec reserve: %v", err)
	}
	if retained, err := execReader.GetExecution(ctx, execRequest.OperationID); err != nil || retained.Request.OperationID != execRequest.OperationID {
		t.Fatalf("transactional exec read = %#v, %v", retained, err)
	}

	sessionWriter, _ := NewSessionRepository(writer)
	sessionReader, _ := NewSessionRepository(reader)
	sessionAuthority := session.SandboxAuthority{
		SandboxID: sandbox.ID, ProviderRevisionID: create.Spec.ProviderRevisionID, Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: "terminal-v1",
	}
	if err := sessionWriter.PutSandboxAuthority(ctx, sessionAuthority); err != nil {
		t.Fatalf("terminal authority: %v", err)
	}
	sessionRequest := session.OpenRequest{
		SandboxID: sandbox.ID, ProviderRevisionID: create.Spec.ProviderRevisionID, OperationID: "terminal-operation-1", AttemptID: "terminal-attempt-1",
		FencingToken: 1, IdempotencyKey: "terminal-key-1", RequestDigest: "sha256:" + strings.Repeat("3", 64), Deadline: now.Add(time.Hour),
		ExpectedGeneration: 1, RuntimeSessionID: "terminal-session-1", RuntimeType: session.RuntimeTerminal, CapabilityProfileID: "terminal-v1", ExpiresAt: now.Add(30 * time.Minute),
	}
	if _, err := sessionWriter.ReserveOpen(ctx, sessionRequest, now); err != nil {
		t.Fatalf("terminal reserve: %v", err)
	}
	if retained, err := sessionReader.GetOpenAt(ctx, sessionRequest.OperationID, now.Add(time.Second)); err != nil || retained.Request.RuntimeSessionID != sessionRequest.RuntimeSessionID {
		t.Fatalf("transactional terminal read = %#v, %v", retained, err)
	}

	artifactWriter, _ := NewArtifactRepository(writer)
	artifactReader, _ := NewArtifactRepository(reader)
	artifactAuthority := artifact.SandboxAuthority{SandboxID: sandbox.ID, Generation: 1, FencingToken: 1}
	if err := artifactWriter.PutSandboxAuthority(ctx, artifactAuthority); err != nil {
		t.Fatalf("artifact authority: %v", err)
	}
	artifactRequest := artifact.Request{
		SandboxID: sandbox.ID, TenantID: "tenant-1", OperationID: "artifact-operation-1", AttemptID: "artifact-attempt-1",
		FencingToken: 1, ExpectedGeneration: 1, IdempotencyKey: "artifact-key-1", RequestDigest: "sha256:" + strings.Repeat("4", 64),
		Deadline: now.Add(time.Hour), ArtifactReference: "artifact-ref:platform/artifact-1", SourcePath: "/outputs/report.json",
		ExpectedDigest: "sha256:" + strings.Repeat("5", 64), ExpectedMediaType: "application/json", MaxBytes: 1024, Retention: time.Hour,
	}
	if _, err := artifactWriter.ReserveStage(ctx, artifactRequest, now); err != nil {
		t.Fatalf("artifact reserve: %v", err)
	}
	if retained, err := artifactReader.GetStage(ctx, artifactRequest.OperationID); err != nil || retained.Request.OperationID != artifactRequest.OperationID {
		t.Fatalf("transactional artifact read = %#v, %v", retained, err)
	}

	browserWriter, _ := NewBrowserRepository(writer)
	browserReader, _ := NewBrowserRepository(reader)
	browserAuthority := browser.SandboxAuthority{
		SandboxID: "sandbox-browser-1", ProviderRevisionID: create.Spec.ProviderRevisionID, Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 1, CapabilityProfileID: browser.CapabilityProfileID, NetworkPolicyReference: "browser-egress-policy-1",
	}
	if err := browserWriter.SynchronizeSandboxAuthority(ctx, browserAuthority); err != nil {
		t.Fatalf("Browser authority: %v", err)
	}
	browserRequest := browser.OpenRequest{
		SandboxID: browserAuthority.SandboxID, ProviderRevisionID: browserAuthority.ProviderRevisionID, OperationID: "browser-operation-1", AttemptID: "browser-attempt-1",
		FencingToken: 1, IdempotencyKey: "browser-key-1", RequestDigest: "sha256:" + strings.Repeat("8", 64), Deadline: now.Add(time.Hour),
		ExpectedGeneration: 1, BrowserSessionID: "browser-session-1", CapabilityProfileID: browser.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute),
	}
	var browserAccepted, browserReplayed, browserFailed atomic.Int64
	var browserWait sync.WaitGroup
	for index := range 8 {
		browserWait.Add(1)
		go func() {
			defer browserWait.Done()
			repository := browserWriter
			if index%2 == 1 {
				repository = browserReader
			}
			reservation, reserveErr := repository.ReserveOpen(ctx, browserRequest, now)
			switch {
			case reserveErr != nil:
				browserFailed.Add(1)
			case reservation.Replayed:
				browserReplayed.Add(1)
			default:
				browserAccepted.Add(1)
			}
		}()
	}
	browserWait.Wait()
	if browserAccepted.Load() != 1 || browserReplayed.Load() != 7 || browserFailed.Load() != 0 {
		t.Fatalf("concurrent Browser reserve accepted=%d replayed=%d failed=%d", browserAccepted.Load(), browserReplayed.Load(), browserFailed.Load())
	}
	if retained, err := browserReader.GetOpenAt(ctx, browserRequest.OperationID, now.Add(time.Second)); err != nil || retained.Request.BrowserSessionID != browserRequest.BrowserSessionID {
		t.Fatalf("transactional Browser read = %#v, %v", retained, err)
	}
	if replay, err := browserReader.ReserveOpen(ctx, browserRequest, now); err != nil || !replay.Replayed {
		t.Fatalf("transactional Browser replay = %#v, %v", replay, err)
	}
	browserReceipt := browser.AllocationReceipt{
		Reference: "ref:browser/00000000000000000000000000000001", SandboxID: browserRequest.SandboxID,
		BrowserSessionID: browserRequest.BrowserSessionID, OperationID: browserRequest.OperationID, AttemptID: browserRequest.AttemptID,
		FencingToken: browserRequest.FencingToken, ExpectedGeneration: browserRequest.ExpectedGeneration, ConnectionGeneration: 1,
		AllocatedAt: now.Add(time.Second), ExpiresAt: browserRequest.ExpiresAt,
	}
	browserAttached, err := browserWriter.AttachAllocation(ctx, browserReceipt)
	if err != nil {
		t.Fatalf("Browser allocation: %v", err)
	}
	browserRunning := browserAttached.Record
	browserReferenceWriter, _ := NewBrowserReferenceStore(writer)
	browserReferenceReader, _ := NewBrowserReferenceStore(reader)
	browserReference, err := reference.NewRecord("ref:browser-session:00000000000000000000000000000001", browserRunning, now.Add(2*time.Second))
	if err != nil {
		t.Fatalf("Browser reference: %v", err)
	}
	if err := browserReferenceWriter.Create(ctx, browserReference); err != nil {
		t.Fatalf("Browser reference persist: %v", err)
	}
	if retained, err := browserReferenceReader.FindRunning(ctx, browserRunning); err != nil || retained.Reference != browserReference.Reference {
		t.Fatalf("transactional Browser reference read = %#v, %v", retained, err)
	}
	browserSucceeded, err := browser.Transition(browserRunning, browser.StatusSucceeded, now.Add(3*time.Second), &browser.EndpointEvidence{InternalEndpointReference: browserReference.Reference, ConnectionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := browserWriter.UpdateOpenAt(ctx, browserSucceeded, browser.StatusRunning, now.Add(3*time.Second)); err != nil {
		t.Fatalf("Browser succeeded transition: %v", err)
	}
	binding := reference.Binding{Version: 2, Reference: browserReference.Reference, TenantBindingDigest: browserbinding.Prefix + strings.Repeat("a", 64),
		SandboxID: browserRequest.SandboxID, BrowserSessionID: browserRequest.BrowserSessionID, CapabilityProfileID: browser.CapabilityProfileID,
		ConnectionGeneration: 1, ExpiresAt: browserRequest.ExpiresAt}
	competing := binding
	competing.TenantBindingDigest = browserbinding.Prefix + strings.Repeat("b", 64)
	startBind := make(chan struct{})
	bindErrors := make(chan error, 2)
	go func() { <-startBind; bindErrors <- browserReferenceWriter.Bind(ctx, binding, now.Add(4*time.Second)) }()
	go func() { <-startBind; bindErrors <- browserReferenceReader.Bind(ctx, competing, now.Add(4*time.Second)) }()
	close(startBind)
	bindWinners, bindConflicts := 0, 0
	for range 2 {
		switch bindErr := <-bindErrors; {
		case bindErr == nil:
			bindWinners++
		case errors.Is(bindErr, reference.ErrConflict):
			bindConflicts++
		default:
			t.Fatalf("concurrent Browser binding: %v", bindErr)
		}
	}
	if bindWinners != 1 || bindConflicts != 1 {
		t.Fatalf("concurrent Browser binding winners=%d conflicts=%d", bindWinners, bindConflicts)
	}
	bound, err := browserReferenceReader.Get(ctx, browserReference.Reference)
	if err != nil || bound.TenantBindingDigest == "" {
		t.Fatalf("Browser binding projection = %#v, %v", bound, err)
	}
	idempotent := binding
	if bound.TenantBindingDigest == competing.TenantBindingDigest {
		idempotent = competing
	}
	if err := browserReferenceWriter.Bind(ctx, idempotent, now.Add(4*time.Second)); err != nil {
		t.Fatalf("idempotent Browser binding: %v", err)
	}
	private := browserhandoffv2.OpenRequest{BindingVersion: browserhandoffv2.BindingVersion,
		BindingIssuer: browserhandoffv2.BindingIssuer, Protocol: browserhandoffv2.ProtocolID,
		RequestID: "browser-private-open-1", Resource: browserhandoffv2.ResourceBrowser,
		TenantBindingDigest: idempotent.TenantBindingDigest, ProviderRevisionID: browserRequest.ProviderRevisionID,
		SandboxID: browserRequest.SandboxID, BrowserSessionID: browserRequest.BrowserSessionID,
		CapabilityProfileID: browser.CapabilityProfileID, MediaProfileID: browserhandoffv2.MediaProfileID,
		ControlProfileID: browserhandoffv2.ControlProfileID, HandoffReference: browserReference.Reference,
		HandoffDigest: browserhandoffv2.ReferenceDigest(browserReference.Reference), ConnectionGeneration: 1,
		ConnectionEpoch: "browser-connection-1", ControlLeaseDigest: "sha256:" + strings.Repeat("c", 64),
		ControlFence: 1, AuthorityExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		HandoffExpiresAt: browserRequest.ExpiresAt.Format(time.RFC3339Nano)}
	private.AuthorityDigest = browserhandoffv2.AuthorityDigest(private)
	private.RequestDigest = browserhandoffv2.RequestDigest(private)
	created, err := browserReferenceWriter.BindConnectionWithOwnership(ctx, private, now.Add(4*time.Second))
	if err != nil || !created {
		t.Fatalf("Browser v2 connection projection ownership=%v err=%v", created, err)
	}
	created, err = browserReferenceReader.BindConnectionWithOwnership(ctx, private, now.Add(4*time.Second))
	if err != nil || created {
		t.Fatalf("Browser v2 duplicate across pools ownership=%v err=%v", created, err)
	}
	muxAuthority, err := browsermux.NewProviderAuthority(browserReader, browserReferenceReader, writer)
	if err != nil {
		t.Fatal(err)
	}
	open := executorprotocol.Open{Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser,
		RequestID: "browser-mux-open-1", TenantBindingDigest: idempotent.TenantBindingDigest,
		ProviderRevisionID: browserRequest.ProviderRevisionID, SandboxID: browserRequest.SandboxID, RuntimeSessionID: browserRequest.BrowserSessionID,
		CapabilityProfileID: browser.CapabilityProfileID, MediaProfileID: "browser-cdp-v1", ControlProfileID: "browser-control-v1",
		HandoffReference: browserReference.Reference, ConnectionGeneration: 1, ConnectionEpoch: private.ConnectionEpoch,
		AuthorityExpiresAt: private.AuthorityExpiresAt, HandoffExpiresAt: browserRequest.ExpiresAt.Format(time.RFC3339Nano), Codec: "application/json"}
	open.Fence, err = browserhandoffv2.ExecutorFence(private.AuthorityDigest)
	if err != nil {
		t.Fatal(err)
	}
	open.HandoffDigest = executorprotocol.ReferenceDigest(open.HandoffReference)
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	if err := browserReferenceWriter.ReserveExecutor(ctx, open, now.Add(4*time.Second)); err != nil {
		t.Fatalf("Browser v2 executor attempt reservation: %v", err)
	}
	if selected, err := muxAuthority.Resolve(ctx, open); err != nil || selected.Reference != browserReceipt.Reference {
		t.Fatalf("Browser mux selected allocation = %#v, %v", selected, err)
	}
	if err := muxAuthority.Claim(ctx, open); err != nil {
		t.Fatalf("Browser executor request claim: %v", err)
	}
	restartedMuxAuthority, err := browsermux.NewProviderAuthority(browserReader, browserReferenceWriter, writer)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedMuxAuthority.Claim(ctx, open); err == nil {
		t.Fatal("Browser executor replay survived a Provider authority restart")
	}
	mutatedOpen := open
	mutatedOpen.Codec = "application/cdp+json"
	mutatedOpen.RequestDigest = mutatedOpen.CalculateRequestDigest()
	if err := restartedMuxAuthority.Claim(ctx, mutatedOpen); err == nil {
		t.Fatal("Browser executor request ID accepted with a different digest")
	}
	wrongTenant := open
	wrongTenant.TenantBindingDigest = browserbinding.Prefix + strings.Repeat("d", 64)
	wrongTenant.AuthorityDigest = wrongTenant.CalculateAuthorityDigest()
	wrongTenant.RequestDigest = wrongTenant.CalculateRequestDigest()
	if _, err := muxAuthority.Resolve(ctx, wrongTenant); err == nil {
		t.Fatal("Browser mux selected a cross-tenant allocation")
	}
	parallel := private
	parallel.ConnectionEpoch = "browser-connection-2"
	parallel.RequestID = "browser-private-open-2"
	parallel.AuthorityDigest = browserhandoffv2.AuthorityDigest(parallel)
	parallel.RequestDigest = browserhandoffv2.RequestDigest(parallel)
	if err := browserReferenceReader.BindConnection(ctx, parallel, now.Add(4*time.Second)); !errors.Is(err, reference.ErrConflict) {
		t.Fatalf("parallel Browser writer admitted across pools: %v", err)
	}
	if err := browserReferenceReader.CloseConnection(ctx, private.HandoffReference, private.ConnectionEpoch, private.AuthorityDigest); err != nil {
		t.Fatalf("Browser old connection close: %v", err)
	}
	if _, err := muxAuthority.Resolve(ctx, open); err == nil {
		t.Fatal("closed Browser connection retained mux authority")
	}
	if err := browserReferenceWriter.BindConnection(ctx, parallel, now.Add(4*time.Second)); err != nil {
		t.Fatalf("Browser exact replacement across pools: %v", err)
	}
	other := open
	other.ConnectionEpoch = parallel.ConnectionEpoch
	other.RequestID = "browser-mux-open-2"
	other.AuthorityExpiresAt = parallel.AuthorityExpiresAt
	other.Fence, err = browserhandoffv2.ExecutorFence(parallel.AuthorityDigest)
	if err != nil {
		t.Fatal(err)
	}
	other.AuthorityDigest = other.CalculateAuthorityDigest()
	other.RequestDigest = other.CalculateRequestDigest()
	if err := browserReferenceReader.ReserveExecutor(ctx, other, now.Add(4*time.Second)); err != nil {
		t.Fatalf("Browser replacement executor reserve: %v", err)
	}
	if err := restartedMuxAuthority.Claim(ctx, other); err != nil {
		t.Fatalf("Browser replacement claim after mux restart: %v", err)
	}
	if err := restartedMuxAuthority.Claim(ctx, open); err == nil {
		t.Fatal("old Browser epoch was revived after replacement")
	}
	browserAuthority.FencingToken = 2
	if err := browserReader.SynchronizeSandboxAuthority(ctx, browserAuthority); err != nil {
		t.Fatalf("Browser authority advance: %v", err)
	}
	if err := browserReferenceWriter.Bind(ctx, idempotent, now.Add(4*time.Second)); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("stale Browser authority rebound: %v", err)
	}
	if _, err := muxAuthority.Resolve(ctx, open); err == nil {
		t.Fatal("Browser mux selected stale fenced allocation")
	}
	if err := browserReferenceReader.Revoke(ctx, browserReference.Reference, now.Add(4*time.Second)); err != nil {
		t.Fatalf("Browser reference revoke: %v", err)
	}
	if err := browserReferenceWriter.Bind(ctx, idempotent, now.Add(5*time.Second)); !errors.Is(err, reference.ErrStale) {
		t.Fatalf("revoked Browser reference rebound: %v", err)
	}
	if retained, err := browserReferenceWriter.Get(ctx, browserReference.Reference); err != nil || retained.RevokedAt == nil {
		t.Fatalf("transactional Browser reference revocation = %#v, %v", retained, err)
	}
	staleRequest := browserRequest
	staleRequest.OperationID = "browser-stale-operation-1"
	staleRequest.IdempotencyKey = "browser-stale-key-1"
	if _, err := browserWriter.ReserveOpen(ctx, staleRequest, now.Add(5*time.Second)); !errors.Is(err, browser.ErrStaleFencingToken) {
		t.Fatalf("stale Browser fencing token accepted: %v", err)
	}

	desktopWriter, _ := NewDesktopRepository(writer)
	desktopReader, _ := NewDesktopRepository(reader)
	desktopAuthority := desktop.SandboxAuthority{
		SandboxID: "sandbox-desktop-1", ProviderRevisionID: create.Spec.ProviderRevisionID, Ready: true, Generation: 1,
		LeaseExpiresAt: now.Add(time.Hour), FencingToken: 3, CapabilityProfileID: desktop.CapabilityProfileID, NetworkPolicyReference: "desktop-egress-policy-1",
	}
	if err := desktopWriter.SynchronizeSandboxAuthority(ctx, desktopAuthority); err != nil {
		t.Fatalf("Desktop authority: %v", err)
	}
	desktopRequest := desktop.OpenRequest{
		SandboxID: desktopAuthority.SandboxID, ProviderRevisionID: desktopAuthority.ProviderRevisionID, OperationID: "desktop-operation-1", AttemptID: "desktop-attempt-1",
		FencingToken: 3, IdempotencyKey: "desktop-key-1", RequestDigest: "sha256:" + strings.Repeat("6", 64), Deadline: now.Add(time.Hour),
		ExpectedGeneration: 1, DesktopSessionID: "desktop-session-1", CapabilityProfileID: desktop.CapabilityProfileID, ExpiresAt: now.Add(30 * time.Minute),
	}
	if _, err := desktopWriter.ReserveOpen(ctx, desktopRequest, now); err != nil {
		t.Fatalf("Desktop reserve: %v", err)
	}
	if retained, err := desktopReader.GetOpenAt(ctx, desktopRequest.OperationID, now.Add(time.Second)); err != nil || retained.Request.DesktopSessionID != desktopRequest.DesktopSessionID {
		t.Fatalf("transactional Desktop read = %#v, %v", retained, err)
	}
	desktopOpen, err := desktopWriter.GetOpenAt(ctx, desktopRequest.OperationID, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	desktopOpening, err := desktop.Transition(desktopOpen, desktop.StatusRunning, now.Add(time.Second), nil)
	if err != nil || desktopWriter.UpdateOpenAt(ctx, desktopOpening, desktop.StatusAccepted, now.Add(time.Second)) != nil {
		t.Fatalf("Desktop opening transition = %#v, %v", desktopOpening, err)
	}
	desktopReceipt := desktop.AllocationReceipt{
		Reference: "ref:desktop/00000000000000000000000000000001", SandboxID: desktopRequest.SandboxID,
		DesktopSessionID: desktopRequest.DesktopSessionID, OperationID: desktopRequest.OperationID, AttemptID: desktopRequest.AttemptID,
		FencingToken: desktopRequest.FencingToken, ExpectedGeneration: desktopRequest.ExpectedGeneration, ConnectionGeneration: 1,
		AllocatedAt: now.Add(time.Second), ExpiresAt: desktopRequest.ExpiresAt,
	}
	desktopAttached, err := desktopWriter.AttachAllocation(ctx, desktopReceipt)
	if err != nil {
		t.Fatal(err)
	}
	desktopActive, err := desktop.Transition(desktopAttached.Record, desktop.StatusSucceeded, now.Add(2*time.Second), &desktop.EndpointEvidence{InternalEndpointReference: "ref:desktop-session:postgres-concurrency", ConnectionGeneration: 1})
	if err != nil || desktopWriter.UpdateOpenAt(ctx, desktopActive, desktop.StatusRunning, now.Add(2*time.Second)) != nil {
		t.Fatalf("Desktop active transition = %#v, %v", desktopActive, err)
	}
	desktopAuthority.FencingToken = 4
	if err := desktopWriter.SynchronizeSandboxAuthority(ctx, desktopAuthority); err != nil {
		t.Fatal(err)
	}
	desktopCloseRequest := desktop.CloseRequest{
		SandboxID: desktopRequest.SandboxID, ProviderRevisionID: desktopRequest.ProviderRevisionID,
		OperationID: "desktop-close-operation-1", AttemptID: "desktop-close-attempt-1", FencingToken: 4,
		IdempotencyKey: "desktop-close-key-1", RequestDigest: "sha256:" + strings.Repeat("7", 64),
		Deadline: now.Add(time.Hour), ExpectedGeneration: 1, DesktopSessionID: desktopRequest.DesktopSessionID,
		ConnectionGeneration: 1, Reason: "caller_complete",
	}
	desktopClose, err := desktopWriter.ReserveClose(ctx, desktopCloseRequest, now.Add(3*time.Second), false)
	if err != nil {
		t.Fatal(err)
	}
	desktopRunningClose, err := desktop.TransitionClose(desktopClose.Record, desktop.StatusRunning, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	desktopSources, err := desktopWriter.ListOpen(ctx)
	if err != nil || len(desktopSources) != 1 {
		t.Fatalf("Desktop close source = %#v, %v", desktopSources, err)
	}
	startDesktopCAS := make(chan struct{})
	desktopCASErrors := make(chan error, 2)
	for _, repository := range []*DesktopRepository{desktopWriter, desktopReader} {
		go func(repository *DesktopRepository) {
			<-startDesktopCAS
			desktopCASErrors <- repository.UpdateClose(ctx, desktopRunningClose, desktop.StatusAccepted, desktopSources[0])
		}(repository)
	}
	close(startDesktopCAS)
	winners, conflicts := 0, 0
	for range 2 {
		switch updateErr := <-desktopCASErrors; {
		case updateErr == nil:
			winners++
		case errors.Is(updateErr, desktoprepository.ErrConflict):
			conflicts++
		default:
			t.Fatalf("Desktop concurrent close CAS = %v", updateErr)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("Desktop concurrent close CAS winners=%d conflicts=%d", winners, conflicts)
	}
	if persisted, err := desktopReader.GetClose(ctx, desktopCloseRequest.OperationID); err != nil || persisted.Status != desktop.StatusRunning || !persisted.ObservedAt.Equal(desktopRunningClose.ObservedAt) {
		t.Fatalf("Desktop concurrent close projection = %#v, %v", persisted, err)
	}
}

func waitForProviderPostgres(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			err = pool.Ping(ctx)
			pool.Close()
		}
		if err == nil {
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("PostgreSQL did not become ready: %v", lastErr)
}
