//go:build integration

package docker_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/moby/moby/client"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	networkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
)

const identityPostgresImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"

type lostCleanupResponse struct {
	*providerpostgres.BrowserBoundIdentityRepository
	lose atomic.Bool
}

type lostCreateCommit struct {
	*providerpostgres.BrowserBoundIdentityRepository
	lose atomic.Bool
}

func (r *lostCreateCommit) CompleteCreate(ctx context.Context,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	if r.lose.Swap(false) {
		return sandboxidentity.Reservation{}, errors.New("PostgreSQL CompleteCreate unavailable before commit")
	}
	return r.BrowserBoundIdentityRepository.CompleteCreate(ctx, ticket)
}

type countedBoundBrowser struct {
	*browserdocker.Driver
	creates atomic.Int64
}

func (r *countedBoundBrowser) AllocateBound(ctx context.Context, allocation providerbrowser.Allocation,
	ticket sandboxidentity.Reservation) (providerbrowser.AllocationReceipt, error) {
	r.creates.Add(1)
	return r.Driver.AllocateBound(ctx, allocation, ticket)
}

func (r *lostCleanupResponse) CompleteCleanupAuthorized(ctx context.Context, ticket sandboxidentity.Reservation,
	confirm func(context.Context, sandboxidentity.Reservation) error) error {
	err := r.BrowserBoundIdentityRepository.CompleteCleanupAuthorized(ctx, ticket, confirm)
	if err == nil && r.lose.Swap(false) {
		return errors.New("PostgreSQL committed CompleteCleanup but response was lost")
	}
	return err
}

// TestBrowserBoundPostgresDockerIntegration composes real Provider-owned
// PostgreSQL CAS transitions with the actual high-UID Browser/gateway Docker
// path. It is not the distinct-process TLS/egress/deployment Slice 6 gate.
func TestBrowserBoundPostgresDockerIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BROWSER_BOUND_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_BROWSER_BOUND_POSTGRES_INTEGRATION=1")
	}
	gatewayImage := os.Getenv(gatewayImageEnvironment)
	if !strings.HasPrefix(gatewayImage, "sha256:") || len(gatewayImage) != len("sha256:")+64 {
		t.Fatal("set " + gatewayImageEnvironment + " to the immutable local gateway image ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	api, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if _, err := api.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatal(err)
	}
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(bytes)
	namespace, controller := "browser-pg-bound-"+token, "controller-"+token
	uplink, policy := "sr-browser-pg-uplink-"+token, "browser-policy-"+token
	pgContainer := "sr-browser-pg-bound-" + token
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := cleanupIntegrationResources(cleanup, api, namespace, controller); err != nil {
			t.Errorf("cleanup exact Browser resources: %v", err)
		}
		if _, err := api.NetworkRemove(cleanup, uplink, client.NetworkRemoveOptions{}); err != nil {
			t.Errorf("remove exact Browser uplink: %v", err)
		}
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", pgContainer).CombinedOutput(); err != nil {
			t.Errorf("remove exact PostgreSQL container: %v: %.512s", err, output)
		}
	})
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", pgContainer,
		"-e", "POSTGRES_PASSWORD=identity-admin", "-e", "POSTGRES_DB=provider_browser",
		"-p", "127.0.0.1::5432", identityPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start identity PostgreSQL: %v: %.512s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", pgContainer, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := "postgres://postgres:identity-admin@127.0.0.1:" + port + "/provider_browser?sslmode=disable"
	runtimeDSN := "postgres://browser_provider_runtime:identity-runtime@127.0.0.1:" + port + "/provider_browser?sslmode=disable"
	var admin *pgxpool.Pool
	for ctx.Err() == nil {
		admin, err = pgxpool.New(ctx, adminDSN)
		if err == nil {
			err = admin.Ping(ctx)
			if err == nil {
				break
			}
			admin.Close()
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("connect identity PostgreSQL: %v", err)
	}
	defer admin.Close()
	if err := providerpostgres.ApplyMigrations(ctx, admin); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE ROLE browser_provider_runtime LOGIN PASSWORD 'identity-runtime'`,
		`REVOKE CONNECT ON DATABASE provider_browser FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE provider_browser TO browser_provider_runtime`,
		`GRANT USAGE ON SCHEMA sandbox_runtime_provider TO browser_provider_runtime`,
		`GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO browser_provider_runtime`,
		`GRANT SELECT,UPDATE ON sandbox_runtime_provider.control_state TO browser_provider_runtime`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	firstPool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer firstPool.Close()
	secondPool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer secondPool.Close()
	for _, pool := range []*pgxpool.Pool{firstPool, secondPool} {
		if err := providerpostgres.VerifySchemaCompatibility(ctx, pool); err != nil {
			t.Fatal(err)
		}
		if err := providerpostgres.VerifyRuntimeRole(ctx, pool, "browser_provider_runtime"); err != nil {
			t.Fatal(err)
		}
	}
	plan := sandboxidentity.Plan{ProfileDigest: testIdentityDigest("a"), OwnerPrincipalDigest: testIdentityDigest("b"),
		TemplateDigest: testIdentityDigest("c"), ServiceName: "postgres", ServiceIdentityDigest: testIdentityDigest("d"),
		OwnerDeployment: "provider-browser-runtime", Template: "browser-sandbox-runtime",
		ControllerID: controller, Namespace: namespace, TrustEdgeID: "provider-browser-postgres",
		MaterialBindingID: "browser-provider-runtime-dsn", EgressPolicyID: "provider-browser-egress",
		BrokerDeployment: "egress-broker-provider-browser", BrokerRoleEdgeID: "egress-role-provider-browser",
		BrokerExternalEdgeID: "egress-provider-browser-postgres", DatabaseName: "provider_browser",
		RuntimeRole: "browser_provider_runtime", Capacity: 1,
		Slots: []sandboxidentity.Slot{{ID: "browser-0000", WorkloadUID: 41000, WorkloadGID: 51000,
			GatewayUID: 43000, GatewayGID: 53000}}}
	firstStore, err := providerpostgres.New(firstPool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := providerpostgres.New(secondPool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, err := providerpostgres.NewBrowserBoundIdentityRepository(ctx, firstStore, plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := providerpostgres.NewBrowserBoundIdentityRepository(ctx, secondStore, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Initialize(ctx, func(check context.Context, checked sandboxidentity.Plan) error {
		if checked.Namespace != namespace || checked.ControllerID != controller {
			return errors.New("identity clean check selected another owner")
		}
		filters := make(client.Filters).Add("label", managedLabel+"=true").
			Add("label", namespaceLabel+"="+namespace).Add("label", controllerLabel+"="+controller)
		containers, err := api.ContainerList(check, client.ContainerListOptions{All: true, Filters: filters})
		if err != nil {
			return err
		}
		networks, err := api.NetworkList(check, client.NetworkListOptions{Filters: filters})
		if err != nil {
			return err
		}
		if len(containers.Items) != 0 || len(networks.Items) != 0 {
			return errors.New("identity bootstrap found owned Docker resources")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := createOwnedUplink(ctx, api, uplink, namespace); err != nil {
		t.Fatal(err)
	}
	verifier, err := realProvenanceVerifier()
	if err != nil {
		t.Fatal(err)
	}
	networkOptions := networkdocker.Options{Host: os.Getenv("DOCKER_HOST"),
		GatewayImage: gatewayImage, UplinkNetwork: uplink, Namespace: namespace, ControllerID: controller,
		Policies:    []gateway.Policy{{Reference: policy, AllowedHosts: []string{"allowed.test"}}},
		MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
		OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10}
	network, err := networkdocker.New(ctx, networkOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := plan.ProjectRuntimeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	driverOptions := browserdocker.Options{Host: os.Getenv("DOCKER_HOST"),
		Image: browserimage.LockedPublication().Image(), PullPolicy: browserdocker.PullIfNotPresent,
		MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
		InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
		OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120,
		StopTimeoutSeconds: 10, DataRoot: t.TempDir(),
		ManifestPath: filepath.Join(root, "profiles/browser/image/manifest.json"),
		SeccompPath:  filepath.Join(root, "profiles/browser/image/chromium-seccomp.json"),
		Namespace:    namespace, ControllerID: controller, NetworkPolicyReference: policy,
		MaxSessionsPerSandbox: 1, MaxSessionsPerController: 1, Clock: browserdocker.ClockFunc(time.Now)}
	driver, err := browserdocker.NewBound(ctx, driverOptions, verifier, network, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	counted := &countedBoundBrowser{Driver: driver}
	firstRuntime, err := browserapplication.NewBrowserIdentityRuntime(first, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	lostResponseLedger := &lostCleanupResponse{BrowserBoundIdentityRepository: second}
	secondRuntime, err := browserapplication.NewBrowserIdentityRuntime(lostResponseLedger, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sessions, err := providerpostgres.NewBrowserRepository(firstStore)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.SynchronizeSandboxAuthority(ctx, providerbrowser.SandboxAuthority{
		SandboxID: "sandbox-" + token, ProviderRevisionID: "revision-" + token,
		Ready: true, Generation: 1, LeaseExpiresAt: now.Add(5 * time.Minute), FencingToken: 1,
		CapabilityProfileID: providerbrowser.CapabilityProfileID, NetworkPolicyReference: policy,
	}); err != nil {
		t.Fatal(err)
	}
	open := providerbrowser.OpenRequest{SandboxID: "sandbox-" + token, ProviderRevisionID: "revision-" + token,
		OperationID: "operation-" + token, AttemptID: "attempt-" + token, FencingToken: 1,
		IdempotencyKey: "idempotency-" + token, RequestDigest: testIdentityDigest("e"),
		Deadline: now.Add(4 * time.Minute), ExpectedGeneration: 1,
		BrowserSessionID: "browser-" + token, CapabilityProfileID: providerbrowser.CapabilityProfileID,
		ExpiresAt: now.Add(4 * time.Minute)}
	// A reservation that never acquired the BeginCreate permit can be retired
	// under the same Provider row lock, without a fabricated Docker receipt.
	abandoned := open
	abandoned.OperationID = "abandoned-" + token
	abandoned.AttemptID = "abandoned-attempt-" + token
	abandoned.BrowserSessionID = "abandoned-browser-" + token
	abandoned.IdempotencyKey = "abandoned-key-" + token
	abandoned.RequestDigest = testIdentityDigest("f")
	abandonedOpen, err := sessions.ReserveOpen(ctx, abandoned, now)
	if err != nil {
		t.Fatal(err)
	}
	abandonedAllocation := providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
		SandboxID: abandoned.SandboxID, BrowserSessionID: abandoned.BrowserSessionID,
		OperationID: abandoned.OperationID, AttemptID: abandoned.AttemptID,
		FencingToken: abandoned.FencingToken, ExpectedGeneration: abandoned.ExpectedGeneration,
		RequestDigest: abandoned.RequestDigest, NetworkPolicyReference: policy,
		ExpiresAt: abandoned.ExpiresAt}, AllocatedAt: abandonedOpen.Record.AcceptedAt}
	abandonedSpecs, err := driver.DesiredSpecDigests(abandonedAllocation)
	if err != nil {
		t.Fatal(err)
	}
	abandonedTicket, err := first.ReserveAuthorized(ctx, abandonedAllocation, abandonedSpecs)
	if err != nil || abandonedTicket.Status != sandboxidentity.Reserved {
		t.Fatalf("undispatched reservation = %+v, %v", abandonedTicket, err)
	}
	failed, err := providerbrowser.Transition(abandonedOpen.Record, providerbrowser.StatusFailed, now.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.UpdateOpenAt(ctx, failed, providerbrowser.StatusAccepted, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := second.RetireUnallocated(ctx, failed); err != nil {
		t.Fatalf("release never-dispatched reservation: %v", err)
	}
	if err := first.RetireUnallocated(ctx, failed); err != nil {
		t.Fatalf("exact retired replay: %v", err)
	}
	if _, err := first.BeginCreateAuthorized(ctx, abandonedAllocation, abandonedTicket); err == nil {
		t.Fatal("stale BeginCreate crossed never-dispatched retirement")
	}
	if _, err := first.ReserveAuthorized(ctx, abandonedAllocation, abandonedSpecs); err == nil {
		t.Fatal("retired Browser claim replayed")
	}
	if reservations, err := second.Reservations(ctx); err != nil || len(reservations) != 0 || counted.creates.Load() != 0 {
		t.Fatalf("never-dispatched retirement left slot or Docker dispatch: %+v, %v, %d", reservations, err, counted.creates.Load())
	}
	openReservation, err := sessions.ReserveOpen(ctx, open, now)
	if err != nil {
		t.Fatal(err)
	}
	allocation := providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
		SandboxID: "sandbox-" + token, BrowserSessionID: "browser-" + token,
		OperationID: "operation-" + token, AttemptID: "attempt-" + token,
		FencingToken: 1, ExpectedGeneration: 1, RequestDigest: testIdentityDigest("e"),
		NetworkPolicyReference: policy, ExpiresAt: open.ExpiresAt}, AllocatedAt: openReservation.Record.AcceptedAt}
	if _, err := second.Reservations(ctx); err != nil {
		t.Fatal(err)
	}
	type allocationResult struct {
		receipt providerbrowser.AllocationReceipt
		err     error
	}
	start := make(chan struct{})
	results := make(chan allocationResult, 2)
	for _, candidate := range []*browserapplication.BrowserIdentityRuntime{firstRuntime, secondRuntime} {
		go func(candidate *browserapplication.BrowserIdentityRuntime) {
			<-start
			receipt, allocateErr := candidate.Allocate(ctx, allocation)
			results <- allocationResult{receipt: receipt, err: allocateErr}
		}(candidate)
	}
	close(start)
	var receipt providerbrowser.AllocationReceipt
	succeeded := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if succeeded > 0 && result.receipt != receipt {
				t.Fatalf("concurrent PG allocation returned different receipts: %+v, %+v", receipt, result.receipt)
			}
			receipt = result.receipt
			succeeded++
		} else if !errors.Is(result.err, providerbrowser.ErrAllocationUnknown) {
			t.Fatalf("concurrent PG allocation returned non-fenced error: %v", result.err)
		}
	}
	if succeeded == 0 || counted.creates.Load() != 1 {
		t.Fatalf("concurrent PG CAS dispatched %d Docker creates, successes %d", counted.creates.Load(), succeeded)
	}
	reservations, err := second.Reservations(ctx)
	if err != nil || len(reservations) != 1 || reservations[0].Status != sandboxidentity.Active ||
		reservations[0].Slot != plan.Slots[0] {
		t.Fatalf("second PostgreSQL connection did not observe exact Active slot: %+v, %v", reservations, err)
	}
	if retry, err := secondRuntime.Allocate(ctx, allocation); err != nil || retry != receipt {
		t.Fatalf("Active retry created or changed receipt: %+v, %v", retry, err)
	}
	topology, err := inspectTopology(ctx, api, allocation.Request, uplink)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		topology.browserContainer: "41000:51000", topology.gatewayContainer: "43000:53000",
	} {
		observed, err := api.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if err != nil || observed.Container.Config == nil || observed.Container.Config.User != want {
			t.Fatalf("container %s user = %#v, %v", name, observed.Container, err)
		}
		processes, err := api.ContainerTop(ctx, name, client.ContainerTopOptions{Arguments: []string{"-o", "uid,gid,pid,args"}})
		if err != nil || slices.Index(processes.Titles, "UID") < 0 || slices.Index(processes.Titles, "GID") < 0 || len(processes.Processes) == 0 {
			t.Fatalf("container %s process identity unavailable: %v", name, err)
		}
		uid, gid := slices.Index(processes.Titles, "UID"), slices.Index(processes.Titles, "GID")
		for _, process := range processes.Processes {
			if len(process) != len(processes.Titles) || process[uid]+":"+process[gid] != want {
				t.Fatalf("container %s process UID/GID drift: %v", name, process)
			}
		}
	}
	if observation, err := secondRuntime.Observe(ctx, receipt); err != nil || observation.State != providerbrowser.AllocationRunning {
		t.Fatalf("PG-bound observation = %#v, %v", observation, err)
	}
	stream, err := secondRuntime.Attach(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	cdp := &cdpClient{stream: stream}
	var version struct {
		Product string `json:"product"`
	}
	if err := cdp.call(ctx, "", "Browser.getVersion", nil, &version); err != nil || !strings.HasPrefix(version.Product, "Chrome/") {
		t.Fatalf("PG-bound high-UID CDP = %#v, %v", version, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	lostResponseLedger.lose.Store(true)
	if err := secondRuntime.Cleanup(ctx, receipt); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("lost CompleteCleanup response was treated as success: %v", err)
	}
	if after, err := first.Reservations(ctx); err != nil || len(after) != 0 {
		t.Fatalf("slot not released after exact Docker absence: %+v, %v", after, err)
	}
	assertResourcesAbsent(t, ctx, api, topology)
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	if err := network.Close(); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(ctx, "docker", "restart", pgContainer).CombinedOutput(); err != nil {
		t.Fatalf("restart identity PostgreSQL: %v: %.512s", err, output)
	}
	restartedPortOutput, err := exec.CommandContext(ctx, "docker", "port", pgContainer, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, restartedPort, err := net.SplitHostPort(strings.TrimSpace(string(restartedPortOutput)))
	if err != nil {
		t.Fatal(err)
	}
	restartedDSN := "postgres://browser_provider_runtime:identity-runtime@127.0.0.1:" + restartedPort + "/provider_browser?sslmode=disable"
	restartedFirstPool, err := pgxpool.New(ctx, restartedDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedFirstPool.Close()
	restartedSecondPool, err := pgxpool.New(ctx, restartedDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer restartedSecondPool.Close()
	for {
		pingCtx, stop := context.WithTimeout(ctx, time.Second)
		firstErr, secondErr := restartedFirstPool.Ping(pingCtx), restartedSecondPool.Ping(pingCtx)
		stop()
		if firstErr == nil && secondErr == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("identity PostgreSQL did not recover after restart: %v, %v", firstErr, secondErr)
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	restartedFirstStore, err := providerpostgres.New(restartedFirstPool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	restartedSecondStore, err := providerpostgres.New(restartedSecondPool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	first, err = providerpostgres.NewBrowserBoundIdentityRepository(ctx, restartedFirstStore, plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err = providerpostgres.NewBrowserBoundIdentityRepository(ctx, restartedSecondStore, plan)
	if err != nil {
		t.Fatal(err)
	}
	network, err = networkdocker.New(ctx, networkOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	driver, err = browserdocker.NewBound(ctx, driverOptions, verifier, network, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	counted = &countedBoundBrowser{Driver: driver}
	firstRuntime, err = browserapplication.NewBrowserIdentityRuntime(first, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	secondRuntime, err = browserapplication.NewBrowserIdentityRuntime(second, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err = providerpostgres.NewBrowserRepository(restartedFirstStore)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstRuntime.Cleanup(ctx, receipt); err != nil {
		t.Fatalf("recover committed cleanup after PostgreSQL/application restart: %v", err)
	}
	if _, err := firstRuntime.Attach(ctx, receipt); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("stale attach after cleanup = %v", err)
	}
	specs, err := driver.DesiredSpecDigests(allocation)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := first.ReserveAuthorized(ctx, allocation, specs); err == nil {
		t.Fatalf("retired allocation replay reserved slot again: %+v", replay)
	}
	assertResourcesAbsent(t, ctx, api, topology)
	if after, err := second.Reservations(ctx); err != nil || len(after) != 0 {
		t.Fatalf("retired replay changed slot state: %+v, %v", after, err)
	}
	// A different admitted operation in the same sandbox/generation may reuse
	// the finite UID after exact cleanup; the old claim remains retired.
	freshNow := time.Now().UTC()
	freshOpen := open
	freshOpen.OperationID = "operation-fresh-" + token
	freshOpen.BrowserSessionID = "browser-fresh-" + token
	freshOpen.AttemptID = "attempt-fresh-" + token
	freshOpen.IdempotencyKey = "idempotency-fresh-" + token
	freshOpen.RequestDigest = testIdentityDigest("f")
	freshOpen.Deadline = freshNow.Add(4 * time.Minute)
	freshOpen.ExpiresAt = freshOpen.Deadline
	freshSession, err := sessions.ReserveOpen(ctx, freshOpen, freshNow)
	if err != nil {
		t.Fatal(err)
	}
	freshAllocation := providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
		SandboxID: freshOpen.SandboxID, BrowserSessionID: freshOpen.BrowserSessionID,
		OperationID: freshOpen.OperationID, AttemptID: freshOpen.AttemptID,
		FencingToken: freshOpen.FencingToken, ExpectedGeneration: freshOpen.ExpectedGeneration,
		RequestDigest: freshOpen.RequestDigest, NetworkPolicyReference: policy,
		ExpiresAt: freshOpen.ExpiresAt}, AllocatedAt: freshSession.Record.AcceptedAt}
	lostCreateLedger := &lostCreateCommit{BrowserBoundIdentityRepository: second}
	lostCreateLedger.lose.Store(true)
	lostCreateRuntime, err := browserapplication.NewBrowserIdentityRuntime(lostCreateLedger, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lostCreateRuntime.Allocate(ctx, freshAllocation); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("pre-commit failure did not retain Creating: %v", err)
	}
	if held, err := first.Reservations(ctx); err != nil || len(held) != 1 || held[0].Status != sandboxidentity.Creating ||
		counted.creates.Load() != 1 {
		t.Fatalf("finished dispatch without PG commit = %+v, %v, %d", held, err, counted.creates.Load())
	}
	freshReceipt, err := secondRuntime.Allocate(ctx, freshAllocation)
	if err != nil {
		t.Fatalf("finished Creating dispatch did not recover without replay: %v", err)
	}
	if counted.creates.Load() != 1 {
		t.Fatalf("finished Creating recovery replayed Docker dispatch %d times", counted.creates.Load())
	}
	freshTopology, err := inspectTopology(ctx, api, freshAllocation.Request, uplink)
	if err != nil {
		t.Fatal(err)
	}
	if err := firstRuntime.Cleanup(ctx, receipt); err != nil {
		t.Fatalf("old released cleanup retry after UID reuse = %v", err)
	}
	if observed, err := secondRuntime.Observe(ctx, freshReceipt); err != nil || observed.State != providerbrowser.AllocationRunning {
		t.Fatalf("old cleanup affected new active Browser: %#v, %v", observed, err)
	}
	if err := firstRuntime.Cleanup(ctx, freshReceipt); err != nil {
		t.Fatal(err)
	}
	assertResourcesAbsent(t, ctx, api, freshTopology)
	if after, err := second.Reservations(ctx); err != nil || len(after) != 0 {
		t.Fatalf("fresh slot not released: %+v, %v", after, err)
	}
	// A terminal Browser record with a completed Docker dispatch but no
	// allocation attachment must be cleaned, not reanimated for user access.
	terminalNow := time.Now().UTC()
	terminalOpen := freshOpen
	terminalOpen.OperationID = "operation-terminal-" + token
	terminalOpen.BrowserSessionID = "browser-terminal-" + token
	terminalOpen.AttemptID = "attempt-terminal-" + token
	terminalOpen.IdempotencyKey = "idempotency-terminal-" + token
	terminalOpen.RequestDigest = testIdentityDigest("1")
	terminalOpen.Deadline = terminalNow.Add(4 * time.Minute)
	terminalOpen.ExpiresAt = terminalOpen.Deadline
	terminalSession, err := sessions.ReserveOpen(ctx, terminalOpen, terminalNow)
	if err != nil {
		t.Fatal(err)
	}
	terminalAllocation := providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
		SandboxID: terminalOpen.SandboxID, BrowserSessionID: terminalOpen.BrowserSessionID,
		OperationID: terminalOpen.OperationID, AttemptID: terminalOpen.AttemptID,
		FencingToken: terminalOpen.FencingToken, ExpectedGeneration: terminalOpen.ExpectedGeneration,
		RequestDigest: terminalOpen.RequestDigest, NetworkPolicyReference: policy,
		ExpiresAt: terminalOpen.ExpiresAt}, AllocatedAt: terminalSession.Record.AcceptedAt}
	lostTerminalLedger := &lostCreateCommit{BrowserBoundIdentityRepository: second}
	lostTerminalLedger.lose.Store(true)
	lostTerminalRuntime, err := browserapplication.NewBrowserIdentityRuntime(lostTerminalLedger, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lostTerminalRuntime.Allocate(ctx, terminalAllocation); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("terminal pre-commit failure = %v", err)
	}
	terminalTopology, err := inspectTopology(ctx, api, terminalAllocation.Request, uplink)
	if err != nil {
		t.Fatal(err)
	}
	terminalFailed, err := providerbrowser.Transition(terminalSession.Record, providerbrowser.StatusFailed,
		terminalNow.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.UpdateOpenAt(ctx, terminalFailed, providerbrowser.StatusAccepted, terminalNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	lostTerminalCleanupLedger := &lostCleanupResponse{BrowserBoundIdentityRepository: second}
	lostTerminalCleanupLedger.lose.Store(true)
	lostTerminalCleanupRuntime, err := browserapplication.NewBrowserIdentityRuntime(lostTerminalCleanupLedger, counted, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	if err := lostTerminalCleanupRuntime.RetireUnallocated(ctx, terminalFailed); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("lost terminal cleanup response was not ambiguous: %v", err)
	}
	if err := secondRuntime.RetireUnallocated(ctx, terminalFailed); err != nil {
		t.Fatalf("released terminal cleanup proof did not finalize: %v", err)
	}
	if err := firstRuntime.RetireUnallocated(ctx, terminalFailed); err != nil {
		t.Fatalf("already-finalized terminal cleanup was not idempotent: %v", err)
	}
	assertResourcesAbsent(t, ctx, api, terminalTopology)
	if after, err := first.Reservations(ctx); err != nil || len(after) != 0 || counted.creates.Load() != 2 {
		t.Fatalf("terminal cleanup left UID held or replayed Docker: %+v, %v, %d", after, err, counted.creates.Load())
	}
	runBrowserBoundProcessCrashComponent(t, ctx, api, first, firstRuntime, sessions,
		plan, driverOptions, networkOptions, restartedDSN, uplink, open, token)
}

func testIdentityDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
