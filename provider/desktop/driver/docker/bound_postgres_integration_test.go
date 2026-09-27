//go:build integration

package docker_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/moby/moby/client"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopapplication "github.com/shell-echo/sandbox-runtime/provider/desktop/application"
	desktopdocker "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/docker"
	networkdocker "github.com/shell-echo/sandbox-runtime/provider/desktop/network/docker"
	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
	restricteddocker "github.com/shell-echo/sandbox-runtime/provider/network/restricted/docker"
)

const desktopBoundPostgresImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"

type denyDesktopMuxAuthority struct{}

func (denyDesktopMuxAuthority) Authorize(context.Context, desktopbroker.SessionOpen) error {
	return errors.New("no media admission in identity gate")
}
func (denyDesktopMuxAuthority) Probe(context.Context) (desktopbroker.SessionOpen, error) {
	return desktopbroker.SessionOpen{}, errors.New("no media admission in identity gate")
}

// TestDesktopBoundPostgresDockerIntegration is a real Provider PG CAS, finite
// UID, restricted-egress and Docker lifecycle gate. The media chain and six
// separate role processes remain distinct, mandatory release gates.
func TestDesktopBoundPostgresDockerIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DESKTOP_BOUND_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DESKTOP_BOUND_POSTGRES_INTEGRATION=1")
	}
	candidatePath := os.Getenv("SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST")
	candidate, err := desktopcandidate.LoadCurrent(candidatePath)
	if err != nil || candidate.VerifySource("../../../..") != nil {
		t.Fatalf("load exact Desktop v3 candidate: %v", err)
	}
	gatewayImage := os.Getenv("SANDBOX_RUNTIME_GATEWAY_SLOT_IMAGE")
	if !strings.HasPrefix(gatewayImage, "sha256:") || len(gatewayImage) != 71 {
		t.Fatal("set SANDBOX_RUNTIME_GATEWAY_SLOT_IMAGE to an immutable local gateway image")
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
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(random)
	namespace, controller := "desktop-pg-bound-"+token, "controller-"+token
	uplink, policy := "sr-desktop-pg-uplink-"+token, "desktop-policy-"+token
	pgContainer := "sr-desktop-pg-bound-" + token
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		filters := make(client.Filters).Add("label", restricted.ManagedLabel+"=true").
			Add("label", restricted.NamespaceLabel+"="+namespace)
		containers, listErr := api.ContainerList(cleanup, client.ContainerListOptions{All: true, Filters: filters})
		if listErr != nil {
			t.Errorf("list exact Desktop cleanup resources: %v", listErr)
		} else {
			for _, item := range containers.Items {
				if _, err := api.ContainerRemove(cleanup, item.ID, client.ContainerRemoveOptions{Force: true}); err != nil {
					t.Errorf("remove exact Desktop test container: %v", err)
				}
			}
		}
		networks, listErr := api.NetworkList(cleanup, client.NetworkListOptions{Filters: filters})
		if listErr != nil {
			t.Errorf("list exact Desktop cleanup networks: %v", listErr)
		} else {
			for _, item := range networks.Items {
				if _, err := api.NetworkRemove(cleanup, item.ID, client.NetworkRemoveOptions{}); err != nil {
					t.Errorf("remove exact Desktop test network: %v", err)
				}
			}
		}
		if output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", pgContainer).CombinedOutput(); err != nil {
			t.Errorf("remove exact Desktop PostgreSQL container: %v: %.512s", err, output)
		}
	})
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", pgContainer,
		"-e", "POSTGRES_PASSWORD=identity-admin", "-e", "POSTGRES_DB=provider_desktop",
		"-p", "127.0.0.1::5432", desktopBoundPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start Desktop identity PostgreSQL: %v: %.512s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", pgContainer, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := "postgres://postgres:identity-admin@127.0.0.1:" + port + "/provider_desktop?sslmode=disable"
	runtimeDSN := "postgres://desktop_provider_runtime:identity-runtime@127.0.0.1:" + port + "/provider_desktop?sslmode=disable"
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
		t.Fatalf("connect Desktop identity PostgreSQL: %v", err)
	}
	defer admin.Close()
	if err := providerpostgres.ApplyMigrations(ctx, admin); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE ROLE desktop_provider_runtime LOGIN PASSWORD 'identity-runtime'`,
		`REVOKE CONNECT ON DATABASE provider_desktop FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE provider_desktop TO desktop_provider_runtime`,
		`GRANT USAGE ON SCHEMA sandbox_runtime_provider TO desktop_provider_runtime`,
		`GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO desktop_provider_runtime`,
		`GRANT SELECT,UPDATE ON sandbox_runtime_provider.control_state TO desktop_provider_runtime`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	pool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := providerpostgres.VerifySchemaCompatibility(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := providerpostgres.VerifyRuntimeRole(ctx, pool, "desktop_provider_runtime"); err != nil {
		t.Fatal(err)
	}
	plan := sandboxidentity.Plan{ProfileDigest: desktopIdentityDigest("a"), OwnerPrincipalDigest: desktopIdentityDigest("b"),
		TemplateDigest: desktopIdentityDigest("c"), ServiceName: "postgres", ServiceIdentityDigest: desktopIdentityDigest("d"),
		OwnerDeployment: "provider-desktop-runtime", Template: "desktop-sandbox-runtime", ControllerID: controller,
		Namespace: namespace, TrustEdgeID: "provider-desktop-postgres", MaterialBindingID: "desktop-provider-runtime-dsn",
		EgressPolicyID: "provider-desktop-egress", BrokerDeployment: "egress-broker-provider-desktop",
		BrokerRoleEdgeID: "egress-role-provider-desktop", BrokerExternalEdgeID: "egress-provider-desktop-postgres",
		DatabaseName: "provider_desktop", RuntimeRole: "desktop_provider_runtime", Capacity: 1,
		Slots: []sandboxidentity.Slot{{ID: "desktop-0000", WorkloadUID: 42000, WorkloadGID: 52000,
			GatewayUID: 44000, GatewayGID: 54000}}}
	store, err := providerpostgres.New(pool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := providerpostgres.NewDesktopBoundIdentityRepository(ctx, store, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Initialize(ctx, func(check context.Context, checked sandboxidentity.Plan) error {
		if checked.Namespace != namespace || checked.ControllerID != controller {
			return errors.New("wrong Desktop identity owner")
		}
		filters := make(client.Filters).Add("label", restricted.ManagedLabel+"=true").
			Add("label", restricted.NamespaceLabel+"="+namespace)
		containers, err := api.ContainerList(check, client.ContainerListOptions{All: true, Filters: filters})
		if err != nil {
			return err
		}
		networks, err := api.NetworkList(check, client.NetworkListOptions{Filters: filters})
		if err != nil || len(containers.Items) != 0 || len(networks.Items) != 0 {
			return errors.New("Desktop bootstrap not clean")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = api.NetworkCreate(ctx, uplink, client.NetworkCreateOptions{Driver: "bridge", Labels: map[string]string{
		restricted.ManagedLabel: "true", restricted.OwnerLabel: restricteddocker.UplinkRole,
		restricted.NamespaceLabel: namespace,
	}})
	if err != nil {
		t.Fatal(err)
	}
	network, err := networkdocker.New(ctx, networkdocker.Options{GatewayImage: gatewayImage, UplinkNetwork: uplink,
		Namespace: namespace, ControllerID: controller,
		Policies:    []restricted.Policy{{Reference: policy, AllowedHosts: []string{"allowed.test"}}},
		MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
		OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := plan.ProjectRuntimeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	var accounts desktopcandidate.AccountAllowlist
	if err := json.Unmarshal([]byte(candidate.WorkloadAccounts), &accounts); err != nil {
		t.Fatal(err)
	}
	if err := authority.Validate(); err != nil {
		t.Fatalf("projected Desktop authority: %v", err)
	}
	if err := candidate.ValidateCurrent(); err != nil {
		t.Fatalf("current Desktop candidate: %v", err)
	}
	if err := accounts.Validate(); err != nil || !accounts.Supports(42000, 52000) {
		t.Fatalf("Desktop candidate workload accounts: %v", err)
	}
	options := desktopdocker.Options{Image: candidate.ImageDigest, PullPolicy: desktopdocker.PullNever,
		MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
		InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
		OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 90, PullTimeoutSeconds: 90, StopTimeoutSeconds: 10,
		DataRoot: t.TempDir(), CandidateManifestPath: filepath.Join(root, "profiles/desktop/image", desktopimage.LocalCandidateManifestPath),
		Namespace: namespace, ControllerID: controller, NetworkPolicyReference: policy,
		MaxSessionsPerSandbox: 1, MaxSessionsPerController: 1, Clock: desktopdocker.ClockFunc(time.Now),
		BridgeKeyID: "provider-desktop-v2", BridgePublicKey: publicKey}
	driver, err := desktopdocker.NewLocalCandidateBound(ctx, options, candidate, network, candidatePath, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	muxDirectory, err := os.MkdirTemp("/tmp", "sr-desktop-pg-mux-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(muxDirectory) })
	if err := os.Chmod(muxDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	mux, err := desktopdocker.NewBrokerMux(driver, desktopdocker.BrokerMuxOptions{
		SocketPath:  filepath.Join(muxDirectory, "desktop-broker-11111111111111111111111111111111.sock"),
		MaxSessions: 1, OperationTimeout: 10 * time.Second, Authority: denyDesktopMuxAuthority{}})
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Shutdown(context.Background())
	runtime, err := desktopapplication.NewDesktopIdentityRuntime(ledger, driver, desktopapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := providerpostgres.NewDesktopRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	open := providerdesktop.OpenRequest{SandboxID: "sandbox-" + token, ProviderRevisionID: "revision-" + token,
		OperationID: "operation-" + token, AttemptID: "attempt-" + token, FencingToken: 1,
		IdempotencyKey: "key-" + token, RequestDigest: desktopIdentityDigest("e"), Deadline: now.Add(4 * time.Minute),
		ExpectedGeneration: 1, DesktopSessionID: "desktop-" + token,
		CapabilityProfileID: providerdesktop.CapabilityProfileID, ExpiresAt: now.Add(4 * time.Minute)}
	if err := sessions.SynchronizeSandboxAuthority(ctx, providerdesktop.SandboxAuthority{
		SandboxID: open.SandboxID, ProviderRevisionID: open.ProviderRevisionID, Ready: true,
		Generation: 1, LeaseExpiresAt: now.Add(5 * time.Minute), FencingToken: 1,
		CapabilityProfileID: providerdesktop.CapabilityProfileID, NetworkPolicyReference: policy,
	}); err != nil {
		t.Fatal(err)
	}
	reserved, err := sessions.ReserveOpen(ctx, open, now)
	if err != nil {
		t.Fatal(err)
	}
	running, err := providerdesktop.Transition(reserved.Record, providerdesktop.StatusRunning, now.Add(time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.UpdateOpenAt(ctx, running, providerdesktop.StatusAccepted, running.ObservedAt); err != nil {
		t.Fatal(err)
	}
	allocation := providerdesktop.Allocation{Request: providerdesktop.AllocationRequest{
		SandboxID: open.SandboxID, DesktopSessionID: open.DesktopSessionID,
		OperationID: open.OperationID, AttemptID: open.AttemptID,
		FencingToken: 1, ExpectedGeneration: 1, RequestDigest: open.RequestDigest,
		NetworkPolicyReference: policy, ExpiresAt: open.ExpiresAt}, AllocatedAt: reserved.Record.AcceptedAt}
	receipt, err := runtime.Allocate(ctx, allocation)
	if err != nil {
		t.Fatalf("real PG-bound high-UID Desktop allocation: %v", err)
	}
	if replay, err := runtime.Allocate(ctx, allocation); err != nil || replay != receipt {
		t.Fatalf("PG Active replay changed Desktop allocation: %+v, %v", replay, err)
	}
	reservations, err := ledger.Reservations(ctx)
	if err != nil || len(reservations) != 1 || reservations[0].Status != sandboxidentity.Active ||
		reservations[0].Slot != plan.Slots[0] {
		t.Fatalf("Desktop PG slot after real create = %+v, %v", reservations, err)
	}
	filters := make(client.Filters).Add("label", restricted.ManagedLabel+"=true").
		Add("label", restricted.NamespaceLabel+"="+namespace)
	containers, err := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil || len(containers.Items) != 2 {
		t.Fatalf("expected exact Desktop workload and gateway: %d, %v", len(containers.Items), err)
	}
	users := []string{}
	for _, item := range containers.Items {
		inspected, err := api.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if err != nil || inspected.Container.Config == nil || inspected.Container.State == nil || !inspected.Container.State.Running {
			t.Fatalf("Desktop container state: %v", err)
		}
		users = append(users, inspected.Container.Config.User)
	}
	slices.Sort(users)
	if !slices.Equal(users, []string{"42000:52000", "44000:54000"}) {
		t.Fatalf("Desktop/gateway effective users = %v", users)
	}
	if observation, err := runtime.Observe(ctx, allocation); err != nil || observation.State != providerdesktop.AllocationRunning {
		t.Fatalf("real Desktop observation = %+v, %v", observation, err)
	}
	attached, err := sessions.AttachAllocation(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	succeeded, err := providerdesktop.Transition(attached.Record, providerdesktop.StatusSucceeded, now.Add(time.Second),
		&providerdesktop.EndpointEvidence{InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: receipt.ConnectionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.UpdateOpenAt(ctx, succeeded, providerdesktop.StatusRunning, succeeded.ObservedAt); err != nil {
		t.Fatal(err)
	}
	closeRequest := providerdesktop.CloseRequest{SandboxID: open.SandboxID, ProviderRevisionID: open.ProviderRevisionID,
		OperationID: "close-" + token, AttemptID: "close-attempt-" + token, FencingToken: 1,
		IdempotencyKey: "close-key-" + token, RequestDigest: desktopIdentityDigest("f"),
		Deadline: now.Add(4 * time.Minute), ExpectedGeneration: 1, DesktopSessionID: open.DesktopSessionID,
		ConnectionGeneration: receipt.ConnectionGeneration, Reason: "caller_complete"}
	closeReservation, err := sessions.ReserveClose(ctx, closeRequest, now.Add(2*time.Second), false)
	if err != nil || closeReservation.Record.SourceOpenOperationID != open.OperationID {
		t.Fatalf("Desktop Close source Open binding = %+v, %v", closeReservation, err)
	}
	if err := runtime.CleanupClose(ctx, closeReservation.Record); err != nil {
		t.Fatalf("real Desktop close cleanup: %v", err)
	}
	if remaining, err := ledger.Reservations(ctx); err != nil || len(remaining) != 0 {
		t.Fatalf("Desktop UID not released after exact absence: %+v, %v", remaining, err)
	}
	if complete, err := runtime.CompletedCloseRetirement(ctx, closeReservation.Record); err != nil || !complete {
		t.Fatalf("Desktop Close retirement proof = %v, %v", complete, err)
	}
	containers, err = api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil || len(containers.Items) != 0 {
		t.Fatalf("Desktop resources remained after Close: %d, %v", len(containers.Items), err)
	}
	networks, err := api.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil || len(networks.Items) != 1 || networks.Items[0].Name != uplink {
		t.Fatalf("Desktop network remained after Close: %+v, %v", networks.Items, err)
	}
}

func desktopIdentityDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }
