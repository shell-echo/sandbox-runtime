//go:build integration

package phase6security

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// This disposable Alpine probe checks the Docker inspect/endpoint machinery.
// It is not a real PostgreSQL, role-command, mTLS or full Slice 6 gate.
func TestSlice6ServiceBridgeRawDockerObservationDiagnostic(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SERVICE_BRIDGE_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SERVICE_BRIDGE_INTEGRATION=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := dockerTopology(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned diagnostic image unavailable: %v", err)
	}
	var bridge Network
	for _, candidate := range Slice6DesiredServiceBridges() {
		if candidate.Name == "service-provider-runtime-postgres" {
			bridge = candidate
			break
		}
	}
	if bridge.Name == "" {
		t.Fatal("reviewed coding Provider service bridge missing")
	}
	if _, err := dockerTopology(ctx, "network", "inspect", bridge.Name); err == nil {
		t.Skip("reviewed service network already exists; diagnostic will not touch it")
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	dialerName, serviceName := "p6-dialer-"+suffix, "p6-service-"+suffix
	createdNetwork := false
	created := []string{}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		for _, name := range created {
			if _, err := dockerTopology(cleanupCtx, "rm", "-f", name); err != nil {
				t.Errorf("remove exact diagnostic container %s: %v", name, err)
			}
			if _, err := dockerTopology(cleanupCtx, "inspect", name); err == nil {
				t.Errorf("diagnostic container %s remains", name)
			}
		}
		if createdNetwork {
			if _, err := dockerTopology(cleanupCtx, "network", "rm", bridge.Name); err != nil {
				t.Errorf("remove exact diagnostic network: %v", err)
			}
			if _, err := dockerTopology(cleanupCtx, "network", "inspect", bridge.Name); err == nil {
				t.Error("diagnostic network remains")
			}
		}
	})
	if _, err := dockerTopology(ctx, "network", "create", "--driver", "bridge", "--internal",
		"--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
		"--subnet", bridge.IPv4Subnet, bridge.Name); err != nil {
		t.Fatal(err)
	}
	createdNetwork = true
	for _, item := range []struct{ name, member, user string }{
		{dialerName, bridge.Principals[0], "21001:31001"},
		{serviceName, bridge.ExternalServices[0], "21002:31002"},
	} {
		address, err := Slice6DesiredServiceEndpointAddress(bridge.Name, item.member)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dockerTopology(ctx, "run", "-d", "--name", item.name, "--network", bridge.Name,
			"--ip", address, "--user", item.user, "--read-only", "--cap-drop", "ALL",
			"--security-opt", "no-new-privileges", image, "sleep", "120"); err != nil {
			t.Fatal(err)
		}
		created = append(created, item.name)
	}
	var dialer, service topologyInspect
	if err := inspectTopology(ctx, dialerName, &dialer); err != nil {
		t.Fatal(err)
	}
	if err := inspectTopology(ctx, serviceName, &service); err != nil {
		t.Fatal(err)
	}
	raw, err := dockerTopology(ctx, "network", "inspect", bridge.Name)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := ObserveDockerNetworkWithExternal([]byte(raw), bridge,
		map[string]string{bridge.Principals[0]: dialer.ID}, map[string]string{bridge.ExternalServices[0]: service.ID})
	if err != nil {
		t.Fatalf("real isolated service bridge observation rejected: %v", err)
	}
	if err := VerifySlice6DesiredServiceBridgeObservation(bridge, observed, dialer.ID, service.ID); err != nil {
		t.Fatalf("real isolated service bridge endpoint rejected: %v", err)
	}
	if _, err := ObserveDockerNetwork([]byte(raw), bridge, map[string]string{bridge.Principals[0]: dialer.ID}); err == nil {
		t.Fatal("role-only inspect accepted the real external member")
	}
	if len(dialer.NetworkSettings.Networks) != 1 || len(service.NetworkSettings.Networks) != 1 ||
		len(dialer.HostConfig.PortBindings) != 0 || len(service.HostConfig.PortBindings) != 0 ||
		observed.HostGateway != "" {
		t.Fatal("diagnostic role/service acquired an alternate network, published port or host gateway")
	}
}
