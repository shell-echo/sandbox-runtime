//go:build phase6slice6gate

package productphase6gate

import (
	"context"
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
const slice6NetworkProbeImageID = "sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

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
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return phase6security.NetworkObservation{}, errors.New("invalid Slice 6 network observation identity")
	}
	raw, err := run.docker(ctx, "network", "inspect", id)
	if err != nil {
		return phase6security.NetworkObservation{}, errors.New("inspect exact Slice 6 profile network")
	}
	observed, err := phase6security.ObserveDockerNetwork(raw, expected, containerIDs)
	if err != nil || observed.NetworkID != id {
		return phase6security.NetworkObservation{}, errors.New("Docker network differs from Slice 6 profile")
	}
	return observed, nil
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
	seed, err := strconv.ParseUint(run.id[:2], 16, 8)
	if err != nil {
		t.Fatal(err)
	}
	third := 30 + int(seed)%150
	for index, item := range []struct {
		kind, mode string
		internal   bool
	}{
		{"role_internal", "isolated", true},
		{"external_uplink", "nat", false},
	} {
		profileNetwork := phase6security.Network{Name: "sr-p6-s6-net-" + run.id[:12] + "-" + strconv.Itoa(index),
			Kind: item.kind, Internal: item.internal, GatewayModeIPv4: item.mode,
			IPv4Subnet: "172.31." + strconv.Itoa(third+index) + ".0/24", Principals: []string{"role"}}
		observed, err := createSlice6ProfileNetwork(ctx, run, profileNetwork)
		if err != nil || observed.Name != profileNetwork.Name || observed.Internal != item.internal ||
			observed.GatewayModeIPv4 != item.mode || observed.Subnet != profileNetwork.IPv4Subnet ||
			(observed.HostGateway == "") != item.internal {
			t.Fatalf("real profile network %s: %#v, %v", profileNetwork.Name, observed, err)
		}
		if _, err := createSlice6ProfileNetwork(ctx, run, profileNetwork); err == nil {
			t.Fatal("pre-existing exact network name was admitted")
		}
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("run-owned network graph remains: %v", err)
	}
	t.Log("real isolated and NAT profile bridges observed by raw Docker inspect; no role-chain claim")
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
	observed, err := observeSlice6ProfileNetwork(ctx, run, created.NetworkID, profileNetwork, map[string]string{"declared-role": declared})
	if err != nil || len(observed.ContainerIDs) != 1 || observed.ContainerIDs[0] != declared || len(observed.Endpoints) != 1 {
		t.Fatalf("declared Docker member not observed: %#v, %v", observed, err)
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
