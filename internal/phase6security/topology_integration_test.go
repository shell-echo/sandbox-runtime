//go:build integration

package phase6security

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a topology checkpoint, not the full Slice 6 inventory gate. The
// Alpine processes are probes, not substitutes for the repository roles.
func TestDockerIsolatedNetworkAndLeastPrivilegeTopology(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_TOPOLOGY_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_TOPOLOGY_INTEGRATION=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := dockerTopology(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned probe image unavailable: %v", err)
	}
	brokerEdge, _, _, brokerNetwork, err := validProfile().BrokerBoundaryForPolicy("gateway-egress")
	if err != nil {
		t.Fatalf("profile broker boundary: %v", err)
	}
	brokerTarget, err := netip.ParseAddrPort(brokerEdge.TargetAddress)
	if err != nil {
		t.Fatalf("profile broker target: %v", err)
	}
	brokerPort := strconv.Itoa(int(brokerTarget.Port()))
	brokerIP := brokerTarget.Addr().String()
	internalPrefix, err := netip.ParsePrefix(brokerNetwork.IPv4Subnet)
	if err != nil {
		t.Fatalf("profile broker network: %v", err)
	}
	roleIP := internalPrefix.Masked().Addr().Next().Next().String()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	hostFixturePort := strconv.Itoa(20000 + int(time.Now().UnixNano()%30000))
	roleNetwork, uplinkNetwork, ordinaryNetwork := "p6-internal-net-"+suffix, "p6-uplink-net-"+suffix, "p6-ordinary-net-"+suffix
	role, broker, fixture, hostFixture, ordinaryProbe := "p6-role-"+suffix, "p6-broker-"+suffix,
		"p6-fixture-"+suffix, "p6-host-fixture-"+suffix, "p6-ordinary-probe-"+suffix
	createdNetworks, createdContainers := []string{}, []string{}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		for _, name := range []string{role, broker, fixture, hostFixture, ordinaryProbe} {
			if !containsTopology(createdContainers, name) {
				continue
			}
			if _, err := dockerTopology(cleanupCtx, "rm", "-f", name); err != nil {
				t.Errorf("remove exact container %s: %v", name, err)
			}
			if _, err := dockerTopology(cleanupCtx, "inspect", name); err == nil {
				t.Errorf("container %s remains after cleanup", name)
			}
		}
		for _, name := range []string{roleNetwork, uplinkNetwork, ordinaryNetwork} {
			if !containsTopology(createdNetworks, name) {
				continue
			}
			if _, err := dockerTopology(cleanupCtx, "network", "rm", name); err != nil {
				t.Errorf("remove exact network %s: %v", name, err)
			}
			if _, err := dockerTopology(cleanupCtx, "network", "inspect", name); err == nil {
				t.Errorf("network %s remains after cleanup", name)
			}
		}
	})
	if _, err := dockerTopology(ctx, "network", "create", "--driver", "bridge", "--internal", "--opt",
		"com.docker.network.bridge.gateway_mode_ipv4=isolated", "--subnet", brokerNetwork.IPv4Subnet, roleNetwork); err != nil {
		t.Fatal(err)
	}
	createdNetworks = append(createdNetworks, roleNetwork)
	if _, err := dockerTopology(ctx, "network", "create", "--driver", "bridge", "--opt",
		"com.docker.network.bridge.gateway_mode_ipv4=nat", uplinkNetwork); err != nil {
		t.Fatal(err)
	}
	createdNetworks = append(createdNetworks, uplinkNetwork)
	if _, err := dockerTopology(ctx, "network", "create", "--driver", "bridge", "--internal", ordinaryNetwork); err != nil {
		t.Fatal(err)
	}
	createdNetworks = append(createdNetworks, ordinaryNetwork)
	if _, err := dockerTopology(ctx, "run", "-d", "--name", hostFixture, "--network", "host",
		image, "sh", "-c", "while :; do nc -l -p "+hostFixturePort+" < /dev/null; done"); err != nil {
		t.Fatal(err)
	}
	createdContainers = append(createdContainers, hostFixture)
	if _, err := dockerTopology(ctx, "run", "-d", "--name", fixture, "--network", uplinkNetwork,
		image, "sh", "-c", "while :; do nc -l -p 8080 < /dev/null; done"); err != nil {
		t.Fatal(err)
	}
	createdContainers = append(createdContainers, fixture)
	if _, err := dockerTopology(ctx, "run", "-d", "--name", ordinaryProbe, "--network", ordinaryNetwork,
		"--user", "21003:31003", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		image, "sleep", "120"); err != nil {
		t.Fatal(err)
	}
	createdContainers = append(createdContainers, ordinaryProbe)
	for _, item := range []struct {
		name, network, user, address string
	}{
		{role, roleNetwork, "21001:31001", roleIP},
		{broker, roleNetwork, "21002:31002", brokerIP},
	} {
		command := []string{"sleep", "120"}
		if item.name == broker {
			command = []string{"sh", "-c", "while :; do nc -l -s " + brokerIP + " -p " + brokerPort + " < /dev/null; done"}
		}
		args := []string{"run", "-d", "--name", item.name, "--network", item.network,
			"--ip", item.address,
			"--user", item.user, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"--pids-limit", "32", "--memory", "64m", "--memory-swap", "64m", "--cpus", "0.25",
			"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=4m", image}
		args = append(args, command...)
		if _, err := dockerTopology(ctx, args...); err != nil {
			t.Fatal(err)
		}
		createdContainers = append(createdContainers, item.name)
	}
	if _, err := dockerTopology(ctx, "network", "connect", uplinkNetwork, broker); err != nil {
		t.Fatal(err)
	}
	var roleNetworkInspect, uplinkNetworkInspect, ordinaryNetworkInspect topologyNetworkInspect
	if err := inspectTopologyNetwork(ctx, roleNetwork, &roleNetworkInspect); err != nil {
		t.Fatal(err)
	}
	if err := inspectTopologyNetwork(ctx, uplinkNetwork, &uplinkNetworkInspect); err != nil {
		t.Fatal(err)
	}
	if err := inspectTopologyNetwork(ctx, ordinaryNetwork, &ordinaryNetworkInspect); err != nil {
		t.Fatal(err)
	}
	if !roleNetworkInspect.Internal || roleNetworkInspect.EnableIPv6 || uplinkNetworkInspect.Internal || uplinkNetworkInspect.EnableIPv6 ||
		roleNetworkInspect.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "isolated" ||
		uplinkNetworkInspect.Options["com.docker.network.bridge.gateway_mode_ipv4"] != "nat" ||
		roleNetworkInspect.Driver != "bridge" ||
		uplinkNetworkInspect.Driver != "bridge" || !ordinaryNetworkInspect.Internal || ordinaryNetworkInspect.EnableIPv6 ||
		ordinaryNetworkInspect.Options["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated" ||
		len(roleNetworkInspect.Containers) != 2 || len(uplinkNetworkInspect.Containers) != 2 || len(ordinaryNetworkInspect.Containers) != 1 {
		t.Fatal("network topology or internal/uplink property drift")
	}
	if len(roleNetworkInspect.IPAM.Config) != 1 || len(uplinkNetworkInspect.IPAM.Config) != 1 ||
		len(ordinaryNetworkInspect.IPAM.Config) != 1 {
		t.Fatal("network IPAM has no exact gateway")
	}
	if roleNetworkInspect.IPAM.Config[0].Gateway != "" {
		t.Fatal("isolated bridge unexpectedly has a host gateway address")
	}
	observedPrefix, err := netip.ParsePrefix(roleNetworkInspect.IPAM.Config[0].Subnet)
	if err != nil || !observedPrefix.Addr().Is4() || observedPrefix != internalPrefix {
		t.Fatal("isolated bridge has no bounded IPv4 subnet")
	}
	internalGatewayIP := observedPrefix.Masked().Addr().Next().String()
	uplinkGatewayIP := uplinkNetworkInspect.IPAM.Config[0].Gateway
	ordinaryGatewayIP := ordinaryNetworkInspect.IPAM.Config[0].Gateway
	if net.ParseIP(internalGatewayIP) == nil || net.ParseIP(uplinkGatewayIP) == nil || net.ParseIP(ordinaryGatewayIP) == nil {
		t.Fatal("network gateways are not numeric IPs")
	}
	var fixtureInspect topologyInspect
	if err := inspectTopology(ctx, fixture, &fixtureInspect); err != nil {
		t.Fatal(err)
	}
	fixtureIP := fixtureInspect.NetworkSettings.Networks[uplinkNetwork].IPAddress
	if fixtureIP == "" {
		t.Fatalf("fixture has no uplink IP: networks=%#v", fixtureInspect.NetworkSettings.Networks)
	}
	var roleInspect, brokerInspect topologyInspect
	if err := inspectTopology(ctx, role, &roleInspect); err != nil {
		t.Fatal(err)
	}
	if err := inspectTopology(ctx, broker, &brokerInspect); err != nil {
		t.Fatal(err)
	}
	rawRoleNetwork, err := dockerTopology(ctx, "network", "inspect", roleNetwork)
	if err != nil {
		t.Fatal(err)
	}
	roleNetworkObservation, err := ObserveDockerNetwork([]byte(rawRoleNetwork), Network{Name: roleNetwork,
		Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", IPv4Subnet: roleNetworkInspect.IPAM.Config[0].Subnet,
		Principals: []string{broker, role}},
		map[string]string{broker: brokerInspect.ID, role: roleInspect.ID})
	if err != nil || roleNetworkObservation.HostGateway != "" || len(roleNetworkObservation.ContainerIDs) != 2 {
		t.Fatalf("closed Docker inspect projection rejected or drifted: %#v, %v", roleNetworkObservation, err)
	}
	for _, observed := range []topologyInspect{roleInspect, brokerInspect} {
		expectedUser := "21001:31001"
		if observed.Name == "/"+broker {
			expectedUser = "21002:31002"
		}
		if !observed.HostConfig.ReadonlyRootfs || observed.HostConfig.Privileged || observed.HostConfig.NetworkMode == "host" ||
			observed.HostConfig.UsernsMode == "host" || observed.Config.User != expectedUser ||
			len(observed.HostConfig.CapAdd) != 0 || !containsTopology(observed.HostConfig.CapDrop, "ALL") ||
			!containsTopology(observed.HostConfig.SecurityOpt, "no-new-privileges") ||
			observed.HostConfig.PidsLimit != 32 || observed.HostConfig.Memory != 64<<20 ||
			observed.HostConfig.NanoCpus != 250_000_000 || len(observed.Mounts) != 0 ||
			len(observed.HostConfig.Binds) != 0 || len(observed.HostConfig.Devices) != 0 ||
			len(observed.HostConfig.Tmpfs) != 1 || observed.HostConfig.Tmpfs["/tmp"] != "rw,noexec,nosuid,nodev,size=4m" {
			t.Fatalf("least-privilege Docker inspect drift for %s", observed.Name)
		}
		for _, value := range observed.Config.Env {
			key, _, _ := strings.Cut(value, "=")
			if strings.HasSuffix(strings.ToLower(key), "_proxy") {
				t.Fatalf("proxy environment present for %s", observed.Name)
			}
		}
		probe := "test ! -w /etc && test ! -w /bin && test \"$(awk '/CapEff:/ {print $2}' /proc/self/status)\" = 0000000000000000 && test \"$(awk '/NoNewPrivs:/ {print $2}' /proc/self/status)\" = 1 && test \"$(awk '/Seccomp:/ {print $2}' /proc/self/status)\" = 2 && test \"$(id -u):$(id -g)\" = \"" + expectedUser + "\""
		if output, err := dockerTopology(ctx, "exec", strings.TrimPrefix(observed.Name, "/"), "sh", "-c", probe); err != nil {
			t.Fatalf("read-only/capability active probe for %s: %v: %s", observed.Name, err, output)
		}
		resourceProbe := `test "$(cat /sys/fs/cgroup/pids.max)" = 32 && test "$(cat /sys/fs/cgroup/memory.max)" = 67108864 && test "$(cat /sys/fs/cgroup/cpu.max)" = "25000 100000"`
		if output, err := dockerTopology(ctx, "exec", strings.TrimPrefix(observed.Name, "/"), "sh", "-c", resourceProbe); err != nil {
			t.Fatalf("active cgroup resource bound for %s: %v: %s", observed.Name, err, output)
		}
	}
	if roleInspect.Config.User == brokerInspect.Config.User {
		t.Fatal("role and broker share numeric UID/GID")
	}
	if len(roleInspect.NetworkSettings.Networks) != 1 || roleInspect.NetworkSettings.Networks[roleNetwork].IPAddress != roleIP ||
		len(brokerInspect.NetworkSettings.Networks) != 2 || brokerInspect.NetworkSettings.Networks[uplinkNetwork].IPAddress == "" {
		t.Fatal("network membership drift")
	}
	brokerInternalIP := brokerInspect.NetworkSettings.Networks[roleNetwork].IPAddress
	if brokerInternalIP != brokerIP || len(roleInspect.HostConfig.PortBindings) != 0 || len(brokerInspect.HostConfig.PortBindings) != 0 {
		t.Fatal("broker address ownership or host-port publication drift")
	}
	if output, err := dockerTopology(ctx, "exec", role, "nc", "-z", "-w", "2", brokerInternalIP, brokerPort); err != nil {
		t.Fatalf("protected role cannot reach declared broker positive control: %v: %s", err, output)
	}
	for _, alternate := range []string{"127.0.0.1", brokerInspect.NetworkSettings.Networks[uplinkNetwork].IPAddress} {
		if output, err := dockerTopology(ctx, "exec", broker, "nc", "-z", "-w", "2", alternate, brokerPort); err == nil {
			t.Fatalf("broker listener accepted non-profile local address %s: %s", alternate, output)
		}
	}
	if output, err := dockerTopology(ctx, "exec", broker, "nc", "-z", "-w", "2", uplinkGatewayIP, hostFixturePort); err != nil {
		t.Fatalf("host fixture not reachable from uplink positive control: %v: %s", err, output)
	}
	if output, err := dockerTopology(ctx, "exec", ordinaryProbe, "nc", "-z", "-w", "2", ordinaryGatewayIP, hostFixturePort); err != nil {
		t.Fatalf("ordinary internal bridge counterexample was not reproduced: %v: %s", err, output)
	}
	for _, alias := range []string{"host.docker.internal", "gateway.docker.internal"} {
		addresses, err := resolveDockerAlias(ctx, broker, alias)
		if err != nil {
			t.Fatalf("cannot resolve Docker host alias %s for numeric probe: %v", alias, err)
		}
		for _, address := range addresses {
			if output, probeErr := dockerTopology(ctx, "exec", role, "nc", "-z", "-w", "2", address, hostFixturePort); probeErr == nil {
				t.Fatalf("protected role reached %s (%s): %s", alias, address, output)
			}
		}
	}
	for _, target := range []struct{ address, port string }{
		{internalGatewayIP, hostFixturePort}, {ordinaryGatewayIP, hostFixturePort}, {uplinkGatewayIP, hostFixturePort},
		{"1.1.1.1", "443"}, {"169.254.169.254", "80"},
	} {
		if output, err := dockerTopology(ctx, "exec", role, "nc", "-z", "-w", "2", target.address, target.port); err == nil {
			t.Fatalf("protected role reached host/public/metadata address %s:%s directly: %s", target.address, target.port, output)
		}
	}
	if output, err := dockerTopology(ctx, "exec", role, "sh", "-c", `ip route | grep -q '^default ' || ip -6 addr show dev eth0 | grep -q inet6`); err == nil {
		t.Fatalf("protected role has default route or IPv6 address: %s", output)
	}
	if output, err := dockerTopology(ctx, "exec", role, "nc", "-z", "-w", "2", fixtureIP, "8080"); err == nil {
		t.Fatalf("protected role reached external fixture directly: %s", output)
	}
	if output, err := dockerTopology(ctx, "exec", broker, "nc", "-z", "-w", "2", fixtureIP, "8080"); err != nil {
		t.Fatalf("dual-homed broker could not reach fixture: %v: %s", err, output)
	}
	t.Logf("observed isolated-gateway denial and broker/host-fixture positive controls, distinct UID/GID, read-only roots, zero effective capabilities and broker-only uplink; role=%s broker=%s fixture=%s", roleInspect.ID, brokerInspect.ID, fixtureInspect.ID)
}

type topologyInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		User string
		Env  []string
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs bool
		Privileged     bool
		NetworkMode    string
		UsernsMode     string
		CapAdd         []string
		CapDrop        []string
		SecurityOpt    []string
		PidsLimit      int64
		Memory         int64
		NanoCpus       int64
		Binds          []string
		Tmpfs          map[string]string
		Devices        []json.RawMessage
		PortBindings   map[string][]json.RawMessage
	} `json:"HostConfig"`
	Mounts          []json.RawMessage `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string
		}
	} `json:"NetworkSettings"`
}

type topologyNetworkInspect struct {
	Internal   bool
	EnableIPv6 bool
	Driver     string
	Options    map[string]string
	IPAM       struct {
		Config []struct{ Gateway, Subnet string }
	}
	Containers map[string]json.RawMessage
}

func resolveDockerAlias(ctx context.Context, container, alias string) ([]string, error) {
	output, err := dockerTopology(ctx, "exec", container, "nslookup", alias)
	if err != nil {
		return nil, err
	}
	addresses, answer := []string{}, false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.TrimSpace(strings.TrimPrefix(line, "Name:")) == alias {
			answer = true
			continue
		}
		if !answer || !strings.HasPrefix(line, "Address:") {
			continue
		}
		address := strings.TrimSpace(strings.TrimPrefix(line, "Address:"))
		if net.ParseIP(address) != nil {
			addresses = append(addresses, address)
		}
	}
	if len(addresses) < 1 {
		return nil, fmt.Errorf("no numeric DNS answer for %s", alias)
	}
	return addresses, nil
}

func inspectTopology(ctx context.Context, name string, observation *topologyInspect) error {
	output, err := dockerTopology(ctx, "inspect", name)
	if err != nil {
		return err
	}
	var values []topologyInspect
	if err := json.Unmarshal([]byte(output), &values); err != nil || len(values) != 1 {
		return fmt.Errorf("invalid Docker inspection for %s", name)
	}
	*observation = values[0]
	return nil
}

func inspectTopologyNetwork(ctx context.Context, name string, observation *topologyNetworkInspect) error {
	output, err := dockerTopology(ctx, "network", "inspect", name)
	if err != nil {
		return err
	}
	var values []topologyNetworkInspect
	if err := json.Unmarshal([]byte(output), &values); err != nil || len(values) != 1 {
		return fmt.Errorf("invalid Docker network inspection for %s", name)
	}
	*observation = values[0]
	return nil
}

func dockerTopology(ctx context.Context, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("docker %s: %w: %s", strings.Join(args[:min(2, len(args))], " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func containsTopology(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
