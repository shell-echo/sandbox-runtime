//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6NetworkGraphEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_NETWORK_GRAPH"
const slice6RouteDiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_ROUTE_DIAGNOSTIC"
const slice6NetworkProbeImageID = "sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

// This disposable route diagnostic probes the actual Docker Desktop/Linux
// behavior of one reviewed isolated-only controller network. It is not a
// certificate-controller deployment, Vault reachability proof or release
// scenario. The result informs whether the reviewed external edge can be
// physically realized without changing the network policy.
func TestSlice6CertificateControllerIsolatedRouteDiagnostic(t *testing.T) {
	if os.Getenv(slice6RouteDiagnosticEnv) != "1" {
		t.Skip("set " + slice6RouteDiagnosticEnv + "=1 for isolated route diagnostic")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact isolated route diagnostic cleanup: %v", err)
		}
	})
	var controllerNetwork phase6security.Network
	for _, desired := range phase6security.Slice6DesiredNetworks() {
		if len(desired.Principals) == 1 && desired.Principals[0] == "certificate-controller" {
			controllerNetwork = desired
			break
		}
	}
	if controllerNetwork.Name == "" || !controllerNetwork.Internal || controllerNetwork.GatewayModeIPv4 != "isolated" {
		t.Fatal("reviewed certificate-controller isolated network is unavailable")
	}
	created, err := createSlice6ProfileNetwork(ctx, run, controllerNetwork)
	if err != nil {
		t.Fatal(err)
	}
	output, err := run.docker(ctx, "run", "--rm", "--pull=never", "--network", created.NetworkID,
		"--label", run.label(), "--name", "sr-p6-route-"+run.id,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", "20000:30000", "--memory", "64m", "--pids-limit", "16",
		slice6NetworkProbeImageID, "ip", "route")
	if err != nil {
		t.Fatalf("disposable isolated route probe: %v: %.512s", err, output)
	}
	routes := strings.TrimSpace(string(output))
	if routes == "" || strings.Contains(routes, "default ") {
		t.Fatalf("unexpected external route on reviewed isolated network: %q", routes)
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("run-owned isolated route resources remain: %v", err)
	}
	t.Logf("reviewed isolated controller bridge has no default route: %q; external Vault path remains unproven", routes)
}

// createSlice6ProfileNetwork creates one exact profile network, refusing name
// aliasing with any pre-existing Docker network. The run label lets the caller
// clean up a create whose response was lost; a later observation must re-read
// the populated network after all actual role containers join it.
func createSlice6ProfileNetwork(ctx context.Context, run slice6DockerRun, expected phase6security.Network) (phase6security.NetworkObservation, error) {
	if ctx == nil || ctx.Err() != nil || expected.Name == "" || len(expected.Name) > 64 ||
		expected.Name[0] < 'a' || expected.Name[0] > 'z' ||
		(expected.GatewayModeIPv4 != "isolated" && expected.GatewayModeIPv4 != "nat") ||
		(expected.Internal != (expected.GatewayModeIPv4 == "isolated")) {
		return phase6security.NetworkObservation{}, errors.New("invalid Slice 6 profile network")
	}
	for _, character := range expected.Name {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
			return phase6security.NetworkObservation{}, errors.New("invalid Slice 6 network name")
		}
	}
	prefix, err := netip.ParsePrefix(expected.IPv4Subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.Bits() < 16 || prefix.Bits() > 28 {
		return phase6security.NetworkObservation{}, errors.New("invalid Slice 6 network subnet")
	}
	listed, err := run.docker(ctx, "network", "ls", "--format", "{{.Name}}")
	if err != nil || len(listed) > 2<<20 {
		return phase6security.NetworkObservation{}, errors.New("Docker network inventory is unavailable")
	}
	for _, existing := range strings.Fields(string(listed)) {
		if existing == expected.Name {
			return phase6security.NetworkObservation{}, errors.New("Slice 6 profile network name already exists")
		}
	}
	arguments := []string{"network", "create", "--driver", "bridge", "--label", run.label(),
		"--opt", "com.docker.network.bridge.gateway_mode_ipv4=" + expected.GatewayModeIPv4,
		"--subnet", expected.IPv4Subnet}
	if expected.Internal {
		arguments = append(arguments, "--internal")
	}
	arguments = append(arguments, expected.Name)
	created, err := run.docker(ctx, arguments...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return phase6security.NetworkObservation{}, errors.New("create exact Slice 6 profile network")
	}
	empty := expected
	empty.Principals = nil
	observed, err := observeSlice6ProfileNetwork(ctx, run, id, empty, map[string]string{})
	if err != nil || observed.NetworkID != id {
		return phase6security.NetworkObservation{}, errors.New("Docker network differs from Slice 6 profile")
	}
	return observed, nil
}

// observeSlice6ProfileNetwork reads Docker again after the declared members
// join. It rejects an omitted or extra member instead of trusting create-time
// topology or the in-memory list of successful connect calls.
func observeSlice6ProfileNetwork(ctx context.Context, run slice6DockerRun, id string, expected phase6security.Network, containerIDs map[string]string) (phase6security.NetworkObservation, error) {
	captured, err := captureSlice6ProfileNetwork(ctx, run, id, expected, containerIDs)
	return captured.observation, err
}

// The final gate must retain these original inspect bytes under the digest
// in the observation. Re-encoding the projection is not a raw receipt.
type slice6NetworkCapture struct {
	observation phase6security.NetworkObservation
	raw         []byte
}

func captureSlice6ProfileNetwork(ctx context.Context, run slice6DockerRun, id string, expected phase6security.Network, containerIDs map[string]string) (slice6NetworkCapture, error) {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return slice6NetworkCapture{}, errors.New("invalid Slice 6 network observation identity")
	}
	raw, err := run.docker(ctx, "network", "inspect", id)
	if err != nil {
		return slice6NetworkCapture{}, errors.New("inspect exact Slice 6 profile network")
	}
	observed, err := phase6security.ObserveDockerNetwork(raw, expected, containerIDs)
	if err != nil || observed.NetworkID != id {
		return slice6NetworkCapture{}, errors.New("Docker network differs from Slice 6 profile")
	}
	return slice6NetworkCapture{observation: observed, raw: raw}, nil
}

// This creates real Docker bridges from the same exact allocator intended for
// the full gate. It is a network component, not an authenticated role chain.
func TestPhase6Slice6ProfileNetworkCreation(t *testing.T) {
	if os.Getenv(slice6NetworkGraphEnv) != "1" {
		t.Skip("set " + slice6NetworkGraphEnv + "=1 for real Docker profile networks")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact Slice 6 network graph cleanup: %v", err)
		}
	})
	selected := map[string]bool{}
	for _, profileNetwork := range phase6security.Slice6DesiredNetworks() {
		if (profileNetwork.Kind != "role_internal" && profileNetwork.Kind != "external_uplink") || selected[profileNetwork.Kind] {
			continue
		}
		selected[profileNetwork.Kind] = true
		observed, err := createSlice6ProfileNetwork(ctx, run, profileNetwork)
		if err != nil || observed.Name != profileNetwork.Name || observed.Internal != profileNetwork.Internal ||
			observed.GatewayModeIPv4 != profileNetwork.GatewayModeIPv4 || observed.Subnet != profileNetwork.IPv4Subnet ||
			(observed.HostGateway == "") != profileNetwork.Internal {
			t.Fatalf("real profile network %s: %#v, %v", profileNetwork.Name, observed, err)
		}
		if _, err := createSlice6ProfileNetwork(ctx, run, profileNetwork); err == nil {
			t.Fatal("pre-existing exact network name was admitted")
		}
	}
	if !selected["role_internal"] || !selected["external_uplink"] {
		t.Fatal("reviewed network inventory has no isolated role or NAT uplink")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("run-owned network graph remains: %v", err)
	}
	t.Log("real isolated and NAT profile bridges observed by raw Docker inspect; no role-chain claim")
}

// The complete reviewed IPAM graph must coexist in the actual Docker daemon
// before any role is launched. Empty networks are bootstrap only, not a
// substitute for the final exact-member and live-route observations.
func TestPhase6Slice6DesiredNetworkInventoryCreation(t *testing.T) {
	if os.Getenv(slice6NetworkGraphEnv) != "1" {
		t.Skip("set " + slice6NetworkGraphEnv + "=1 for real Docker profile networks")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact reviewed Slice 6 network inventory cleanup: %v", err)
		}
	})
	desired := phase6security.Slice6DesiredNetworks()
	if len(desired) < 50 {
		t.Fatal("reviewed network inventory is incomplete")
	}
	for _, network := range desired {
		observed, err := createSlice6ProfileNetwork(ctx, run, network)
		if err != nil || observed.Name != network.Name || observed.Subnet != network.IPv4Subnet {
			t.Fatalf("reviewed Docker network %s could not coexist: %#v, %v", network.Name, observed, err)
		}
	}
	ids, err := run.labeledIDs(ctx, "network")
	if err != nil || len(ids) != len(desired) {
		t.Fatalf("reviewed Docker network inventory incomplete: %d/%d: %v", len(ids), len(desired), err)
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("reviewed Docker network inventory remains: %v", err)
	}
	t.Logf("%d reviewed isolated/NAT Docker networks coexisted and were removed; no role-chain claim", len(desired))
}

// This opt-in component exercises actual Docker membership and an undeclared
// endpoint. The disposable Alpine processes are not Product/Provider roles,
// and this test must not be projected into the release manifest.
func TestPhase6Slice6ProfileNetworkMembership(t *testing.T) {
	if os.Getenv(slice6NetworkGraphEnv) != "1" {
		t.Skip("set " + slice6NetworkGraphEnv + "=1 for real Docker profile networks")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact Slice 6 network membership cleanup: %v", err)
		}
	})
	imageDocument, err := run.docker(ctx, "image", "inspect", slice6NetworkProbeImageID)
	var images []struct {
		ID string `json:"Id"`
	}
	if err != nil || json.Unmarshal(imageDocument, &images) != nil || len(images) != 1 || images[0].ID != slice6NetworkProbeImageID {
		t.Fatal("pinned local disposable Alpine image is unavailable; no pull attempted")
	}
	seed, err := strconv.ParseUint(run.id[:2], 16, 8)
	if err != nil {
		t.Fatal(err)
	}
	profileNetwork := phase6security.Network{Name: "sr-p6-s6-members-" + run.id[:12], Kind: "role_internal",
		Internal: true, GatewayModeIPv4: "isolated", IPv4Subnet: "172.31." + strconv.Itoa(30+int(seed)%150) + ".0/24",
		Principals: []string{"declared-role"}}
	created, err := createSlice6ProfileNetwork(ctx, run, profileNetwork)
	if err != nil {
		t.Fatal(err)
	}
	createMember := func(name string) string {
		t.Helper()
		output, err := run.docker(ctx, "create", "--pull=never", "--network", created.NetworkID, "--label", run.label(),
			"--name", "sr-p6-s6-"+name+"-"+run.id[:12], slice6NetworkProbeImageID, "sleep", "60")
		id := strings.TrimSpace(string(output))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatalf("create disposable network member %s: %v: %.256s", name, err, output)
		}
		if output, err := run.docker(ctx, "start", id); err != nil {
			t.Fatalf("start disposable network member %s: %v: %.256s", name, err, output)
		}
		return id
	}
	declared := createMember("declared")
	captured, err := captureSlice6ProfileNetwork(ctx, run, created.NetworkID, profileNetwork, map[string]string{"declared-role": declared})
	observed := captured.observation
	if err != nil || len(observed.ContainerIDs) != 1 || observed.ContainerIDs[0] != declared || len(observed.Endpoints) != 1 {
		t.Fatalf("declared Docker member not observed: %#v, %v", observed, err)
	}
	rawDigest := sha256.Sum256(captured.raw)
	if observed.InspectDigest != "sha256:"+hex.EncodeToString(rawDigest[:]) {
		t.Fatal("network projection is not bound to the original Docker inspect bytes")
	}
	_ = createMember("undeclared")
	if _, err := observeSlice6ProfileNetwork(ctx, run, created.NetworkID, profileNetwork, map[string]string{"declared-role": declared}); err == nil {
		t.Fatal("undeclared Docker endpoint admitted by profile observation")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("run-owned network and members remain: %v", err)
	}
	t.Log("real Docker member observed and undeclared member rejected; disposable components only")
}
