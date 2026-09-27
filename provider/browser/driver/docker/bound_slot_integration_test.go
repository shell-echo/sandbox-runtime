//go:build integration

package docker_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	networkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
)

// TestBrowserBoundSlotDockerIntegration is a real high-UID Browser/gateway
// component gate. The Creating/Active ticket is a fixture, not an actual
// PostgreSQL CAS; production must only supply it via the application
// coordinator and complete the separate exact-cleanup gate.
func TestBrowserBoundSlotDockerIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BROWSER_BOUND_SLOT_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_BROWSER_BOUND_SLOT_INTEGRATION=1")
	}
	gatewayImage := os.Getenv(gatewayImageEnvironment)
	if !strings.HasPrefix(gatewayImage, "sha256:") || len(gatewayImage) != len("sha256:")+64 {
		t.Fatal("set " + gatewayImageEnvironment + " to the immutable local gateway image ID")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	api, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if _, err := api.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatal(err)
	}
	tokenBytes := make([]byte, 8)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(tokenBytes)
	namespace, controller := "browser-bound-"+token, "controller-"+token
	uplink, policy := "sr-browser-bound-uplink-"+token, "browser-policy-"+token
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := cleanupIntegrationResources(cleanup, api, namespace, controller); err != nil {
			t.Errorf("cleanup exact Browser fixture resources: %v", err)
		}
		if _, err := api.NetworkRemove(cleanup, uplink, client.NetworkRemoveOptions{}); err != nil {
			t.Errorf("remove exact Browser fixture uplink: %v", err)
		}
	})
	if err := createOwnedUplink(ctx, api, uplink, namespace); err != nil {
		t.Fatal(err)
	}
	verifier, err := realProvenanceVerifier()
	if err != nil {
		t.Fatal(err)
	}
	network, err := networkdocker.New(ctx, networkdocker.Options{Host: os.Getenv("DOCKER_HOST"),
		GatewayImage: gatewayImage, UplinkNetwork: uplink, Namespace: namespace, ControllerID: controller,
		Policies:    []gateway.Policy{{Reference: policy, AllowedHosts: []string{"allowed.test"}}},
		MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
		OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	options := browserdocker.Options{Host: os.Getenv("DOCKER_HOST"), Image: browserimage.LockedPublication().Image(),
		PullPolicy: browserdocker.PullIfNotPresent, MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000,
		PidsLimit: 256, InputsBytes: 16 << 20, TmpfsBytes: 256 << 20,
		WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
		OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120,
		StopTimeoutSeconds: 10, DataRoot: t.TempDir(),
		ManifestPath: filepath.Join(root, "profiles/browser/image/manifest.json"),
		SeccompPath:  filepath.Join(root, "profiles/browser/image/chromium-seccomp.json"),
		Namespace:    namespace, ControllerID: controller, NetworkPolicyReference: policy,
		MaxSessionsPerSandbox: 1, MaxSessionsPerController: 1, Clock: browserdocker.ClockFunc(time.Now)}
	slot := sandboxidentity.Slot{ID: "browser-0000", WorkloadUID: 20000, WorkloadGID: 30000,
		GatewayUID: 20001, GatewayGID: 30001}
	authority := sandboxidentity.RuntimeAuthority{PlanDigest: "sha256:" + strings.Repeat("a", 64),
		OwnerDeployment: "provider-browser-runtime", Namespace: namespace, ControllerID: controller,
		Template: "browser-sandbox-runtime", Capacity: 1, Slots: []sandboxidentity.Slot{slot}}
	runtime, err := browserdocker.NewBound(ctx, options, verifier, network, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	now := time.Now().UTC()
	allocation := providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
		SandboxID: "sandbox-" + token, BrowserSessionID: "browser-" + token,
		OperationID: "operation-" + token, AttemptID: "attempt-" + token,
		FencingToken: 1, ExpectedGeneration: 1,
		RequestDigest: "sha256:" + strings.Repeat("b", 64), NetworkPolicyReference: policy,
		ExpiresAt: now.Add(3 * time.Minute)}, AllocatedAt: now}
	specs, err := runtime.DesiredSpecDigests(allocation)
	if err != nil || len(specs) != 1 {
		t.Fatalf("desired bound specs = %v, %v", specs, err)
	}
	ticket := sandboxidentity.Reservation{PlanDigest: authority.PlanDigest, Slot: slot,
		Claim: sandboxidentity.Claim{SandboxID: allocation.Request.SandboxID,
			SessionID: allocation.Request.BrowserSessionID, OperationID: allocation.Request.OperationID,
			AttemptID: allocation.Request.AttemptID, RequestDigest: allocation.Request.RequestDigest,
			Generation: 1, Fence: 1}, SpecDigest: specs[slot.ID], Status: sandboxidentity.Creating}
	if _, err := runtime.Allocate(ctx, allocation); !errors.Is(err, providerbrowser.ErrBrowserUnsupported) {
		t.Fatalf("legacy allocation bypass = %v", err)
	}
	receipt, err := runtime.AllocateBound(ctx, allocation, ticket)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := inspectTopology(ctx, api, allocation.Request, uplink)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]string{
		topology.browserContainer: {"20000", "30000"},
		topology.gatewayContainer: {"20001", "30001"},
	} {
		observed, err := api.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if err != nil || observed.Container.Config == nil || observed.Container.Config.User != want[0]+":"+want[1] {
			t.Fatalf("container %s user = %#v, %v", name, observed.Container, err)
		}
		processes, err := api.ContainerTop(ctx, name, client.ContainerTopOptions{Arguments: []string{"-o", "uid,gid,pid,args"}})
		if err != nil || slices.Index(processes.Titles, "UID") < 0 || slices.Index(processes.Titles, "GID") < 0 || len(processes.Processes) == 0 {
			t.Fatalf("container %s process identity unavailable: %v", name, err)
		}
		uid, gid := slices.Index(processes.Titles, "UID"), slices.Index(processes.Titles, "GID")
		for _, process := range processes.Processes {
			if len(process) != len(processes.Titles) || process[uid] != want[0] || process[gid] != want[1] {
				t.Fatalf("container %s process UID/GID drift: %v", name, process)
			}
		}
	}
	active := ticket
	active.Status = sandboxidentity.Active
	observation, err := runtime.ObserveBound(ctx, receipt, active)
	if err != nil || observation.State != providerbrowser.AllocationRunning {
		t.Fatalf("bound Browser observation = %#v, %v", observation, err)
	}
	stream, err := runtime.AttachBound(ctx, receipt, active)
	if err != nil {
		t.Fatal(err)
	}
	cdp := &cdpClient{stream: stream}
	var version struct {
		Product string `json:"product"`
	}
	if err := cdp.call(ctx, "", "Browser.getVersion", nil, &version); err != nil || !strings.HasPrefix(version.Product, "Chrome/") {
		t.Fatalf("bound high-UID CDP = %#v, %v", version, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.AllocateBound(ctx, allocation, ticket); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("Creating replay created again: %v", err)
	}
	cleaning := ticket
	cleaning.Status = sandboxidentity.Cleaning
	if err := runtime.ConfirmAbsentBound(ctx, receipt, cleaning); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("live bound resources reported absent: %v", err)
	}
	if err := runtime.CleanupBound(ctx, receipt, cleaning); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.AttachBound(ctx, receipt, active); !errors.Is(err, providerbrowser.ErrBrowserConflict) {
		t.Fatalf("late Active attach after Cleaning: %v", err)
	}
	if err := runtime.ConfirmAbsentBound(ctx, receipt, cleaning); err != nil {
		t.Fatalf("real Docker bound absence: %v", err)
	}
	// The fixture has no PostgreSQL CompleteCleanup CAS. Finalization here
	// tests only the driver's local tombstone lifecycle.
	if err := runtime.FinalizeCleanupBound(ctx, receipt, cleaning); err != nil {
		t.Fatal(err)
	}
	assertResourcesAbsent(t, ctx, api, topology)
}
