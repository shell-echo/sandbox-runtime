//go:build integration

package phase6security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This is a real Docker relay/topology checkpoint. The upstream HTTP servers
// are probes, not the Product/Gateway commands or their TLS/auth gates.
func TestDockerProductionIngressRelayTopology(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_INGRESS_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_INGRESS_DOCKER=1")
	}
	const image = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	architecture, err := dockerTopology(ctx, "version", "--format", "{{.Server.Arch}}")
	architecture = strings.TrimSpace(architecture)
	if err != nil || architecture != "arm64" && architecture != "amd64" {
		t.Fatalf("Docker architecture unavailable: %q %v", architecture, err)
	}
	if _, err := dockerTopology(ctx, "image", "inspect", image); err != nil {
		t.Fatalf("pinned probe image unavailable: %v", err)
	}
	profile := validProfile()
	ports := freeIngressPorts(t)
	for index := range profile.IngressBindings {
		profile.IngressBindings[index].HostBindAddress = net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[index]))
		profile.IngressBindings[index].ConfigurationDigest = profile.IngressBindings[index].Digest()
	}
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("ingress profile: %v", err)
	}
	profileDocument, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var relay Principal
	for _, principal := range profile.Principals {
		if principal.Name == "public-ingress-relay" {
			relay = principal
		}
	}
	authorityDocument, err := json.Marshal(struct {
		Version               int    `json:"version"`
		SecurityProfilePath   string `json:"security_profile_path"`
		SecurityProfileDigest string `json:"security_profile_digest"`
		RelayPrincipalDigest  string `json:"relay_principal_digest"`
	}{1, "/work/profile.json", profile.ProfileDigest, relay.PrincipalDigest})
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	binary := filepath.Join(workspace, "phase6-ingress-relay")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./../../cmd/phase6-ingress-relay")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+architecture, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build ingress relay: %v: %.2048s", err, output)
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	networkNames := []string{"public-ingress", "ingress-gateway", "ingress-product"}
	containerNames := []string{"p6-ingress-relay-" + suffix, "p6-ingress-gateway-" + suffix, "p6-ingress-product-" + suffix}
	volume := "p6-ingress-work-" + suffix
	createdNetworks := map[string]bool{}
	createdContainers := map[string]bool{}
	volumeCreated := false
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		for _, name := range containerNames {
			if !createdContainers[name] {
				continue
			}
			if _, err := dockerTopology(cleanupCtx, "rm", "-f", name); err != nil {
				t.Errorf("remove exact ingress container %s: %v", name, err)
			}
			if _, err := dockerTopology(cleanupCtx, "inspect", name); err == nil {
				t.Errorf("ingress container %s remained", name)
			}
		}
		for _, name := range networkNames {
			if !createdNetworks[name] {
				continue
			}
			if _, err := dockerTopology(cleanupCtx, "network", "rm", name); err != nil {
				t.Errorf("remove exact ingress network %s: %v", name, err)
			}
			if _, err := dockerTopology(cleanupCtx, "network", "inspect", name); err == nil {
				t.Errorf("ingress network %s remained", name)
			}
		}
		if volumeCreated {
			if _, err := dockerTopology(cleanupCtx, "volume", "rm", volume); err != nil {
				t.Errorf("remove exact ingress volume %s: %v", volume, err)
			}
			if _, err := dockerTopology(cleanupCtx, "volume", "inspect", volume); err == nil {
				t.Errorf("ingress volume %s remained", volume)
			}
		}
	})
	for _, item := range []struct {
		name, subnet string
		internal     bool
	}{
		{"public-ingress", "10.11.0.0/24", false},
		{"ingress-gateway", "10.12.0.0/24", true},
		{"ingress-product", "10.13.0.0/24", true},
	} {
		args := []string{"network", "create", "--driver", "bridge", "--subnet", item.subnet,
			"--opt", "com.docker.network.bridge.gateway_mode_ipv4=nat"}
		if item.internal {
			args = []string{"network", "create", "--driver", "bridge", "--internal", "--subnet", item.subnet,
				"--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated"}
		}
		args = append(args, item.name)
		if _, err := dockerTopology(ctx, args...); err != nil {
			t.Fatalf("create ingress network %s: %v", item.name, err)
		}
		createdNetworks[item.name] = true
	}
	if _, err := dockerTopology(ctx, "volume", "create", volume); err != nil {
		t.Fatal(err)
	}
	volumeCreated = true
	binaryDocument, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, mode string
		document   []byte
	}{
		{"relay", "0500", binaryDocument}, {"profile.json", "0600", profileDocument},
		{"authority.json", "0600", authorityDocument},
	} {
		command := fmt.Sprintf("cat > /work/%s && chown %d:%d /work/%s && chmod %s /work/%s",
			item.name, relay.UID, relay.GID, item.name, item.mode, item.name)
		if output, err := dockerPolicyInput(ctx, item.document, "run", "--rm", "-i", "--network", "none",
			"-v", volume+":/work", image, "sh", "-c", command); err != nil {
			t.Fatalf("install relay artifact: %v: %.2048s", err, output)
		}
	}
	startTarget := func(name, network, address string, port int, body string) {
		t.Helper()
		serve := fmt.Sprintf("while :; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %d\\r\\nConnection: close\\r\\n\\r\\n%s' | nc -l -p %d; done",
			len(body), body, port)
		if _, err := dockerTopology(ctx, "run", "-d", "--name", name, "--network", network, "--ip", address,
			image, "sh", "-c", serve); err != nil {
			t.Fatalf("start upstream %s: %v", name, err)
		}
		createdContainers[name] = true
		time.Sleep(100 * time.Millisecond)
		status, err := dockerTopology(ctx, "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", name)
		if err != nil || !strings.HasPrefix(status, "running ") {
			logs, _ := dockerTopology(ctx, "logs", name)
			t.Fatalf("upstream %s failed to start: %q %v: %.2048s", name, status, err, logs)
		}
	}
	startTarget(containerNames[1], "ingress-gateway", "10.12.0.3", 8445, "gateway")
	startTarget(containerNames[2], "ingress-product", "10.13.0.3", 8444, "product")
	portFlags := []string{}
	for _, binding := range profile.IngressBindings {
		portFlags = append(portFlags, "-p", binding.HostBindAddress+":"+strconv.Itoa(
			int(stringsPort(t, binding.FrontendAddress))))
	}
	args := []string{"run", "-d", "--name", containerNames[0], "--network", "public-ingress", "--ip", "10.11.0.2",
		"--user", fmt.Sprintf("%d:%d", relay.UID, relay.GID), "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges", "--sysctl", "net.ipv4.ip_forward=0",
		"--sysctl", "net.ipv6.conf.all.forwarding=0", "--pids-limit", "32", "--memory", "64m", "--memory-swap", "64m",
		"--cpus", "0.25", "--mount", "type=volume,src=" + volume + ",dst=/work,readonly"}
	args = append(args, portFlags...)
	args = append(args, image, "/work/relay", "serve", "/work/authority.json")
	if _, err := dockerTopology(ctx, args...); err != nil {
		t.Fatalf("start production relay: %v", err)
	}
	createdContainers[containerNames[0]] = true
	if output, err := dockerTopology(ctx, "exec", containerNames[0], "sh", "-c",
		"test \"$(cat /proc/sys/net/ipv4/ip_forward)\" = 0 && test \"$(cat /proc/sys/net/ipv6/conf/all/forwarding)\" = 0"); err != nil {
		t.Fatalf("relay kernel forwarding remains enabled: %v: %s", err, output)
	}
	for _, item := range []struct{ network, address string }{{"ingress-gateway", "10.12.0.2"}, {"ingress-product", "10.13.0.2"}} {
		if _, err := dockerTopology(ctx, "network", "connect", "--ip", item.address, item.network, containerNames[0]); err != nil {
			t.Fatalf("connect relay to %s: %v", item.network, err)
		}
	}
	for index, binding := range profile.IngressBindings {
		body := []string{"gateway", "product"}[index]
		awaitIngressHTTP(t, ctx, containerNames[0], binding.HostBindAddress, body)
	}
	inspects := make(map[string]ingressContainerInspect, len(containerNames))
	for _, name := range containerNames {
		output, err := dockerTopology(ctx, "inspect", name)
		if err != nil {
			t.Fatal(err)
		}
		var values []ingressContainerInspect
		if err := json.Unmarshal([]byte(output), &values); err != nil || len(values) != 1 {
			t.Fatalf("invalid inspect for %s: %v", name, err)
		}
		inspects[name] = values[0]
	}
	observedRelay := inspects[containerNames[0]]
	if observedRelay.Config.User != fmt.Sprintf("%d:%d", relay.UID, relay.GID) ||
		!observedRelay.HostConfig.ReadonlyRootfs || observedRelay.HostConfig.Privileged ||
		len(observedRelay.HostConfig.CapAdd) != 0 || len(observedRelay.HostConfig.CapDrop) != 1 ||
		observedRelay.HostConfig.CapDrop[0] != "ALL" || observedRelay.HostConfig.PidsLimit != 32 ||
		observedRelay.HostConfig.Memory != 64<<20 || observedRelay.HostConfig.NanoCpus != 250_000_000 ||
		!slices.Contains(observedRelay.HostConfig.SecurityOpt, "no-new-privileges") ||
		len(observedRelay.NetworkSettings.Networks) != 3 ||
		len(observedRelay.NetworkSettings.Ports) != 2 {
		t.Fatal("relay least-privilege or exact network/port mapping drift")
	}
	for _, binding := range profile.IngressBindings {
		key := strconv.Itoa(int(stringsPort(t, binding.FrontendAddress))) + "/tcp"
		bindings := observedRelay.NetworkSettings.Ports[key]
		if len(bindings) != 1 || bindings[0].HostIP+":"+bindings[0].HostPort != binding.HostBindAddress {
			t.Fatalf("relay Docker publication drift for %s", binding.ID)
		}
	}
	for _, name := range containerNames[1:] {
		if len(inspects[name].NetworkSettings.Ports) != 0 || len(inspects[name].NetworkSettings.Networks) != 1 {
			t.Fatalf("target %s has host publication or extra network", name)
		}
	}
	for _, item := range []struct {
		network string
		members map[string]string
	}{
		{"public-ingress", map[string]string{"public-ingress-relay": observedRelay.ID}},
		{"ingress-gateway", map[string]string{"public-ingress-relay": observedRelay.ID, "gateway-runtime": inspects[containerNames[1]].ID}},
		{"ingress-product", map[string]string{"public-ingress-relay": observedRelay.ID, "product-runtime": inspects[containerNames[2]].ID}},
	} {
		output, err := dockerTopology(ctx, "network", "inspect", item.network)
		if err != nil {
			t.Fatal(err)
		}
		var expected Network
		for _, network := range profile.Networks {
			if network.Name == item.network {
				expected = network
			}
		}
		observation, err := ObserveDockerNetwork([]byte(output), expected, item.members)
		if err != nil || len(observation.Endpoints) != len(item.members) {
			t.Fatalf("Docker ingress network %s observation: %#v %v", item.network, observation, err)
		}
	}
	if _, err := dockerTopology(ctx, "rm", "-f", containerNames[1]); err != nil {
		t.Fatal(err)
	}
	createdContainers[containerNames[1]] = false
	if ingressHTTP(profile.IngressBindings[0].HostBindAddress, "gateway") == nil {
		t.Fatal("relay served stale gateway response after upstream loss")
	}
	startTarget(containerNames[1], "ingress-gateway", "10.12.0.3", 8445, "gateway")
	awaitIngressHTTP(t, ctx, containerNames[0], profile.IngressBindings[0].HostBindAddress, "gateway")
	t.Log("real relay command: fixed Docker NAT ingress, isolated Product/Gateway trust networks, exact host publication, upstream loss/restart, least-privilege relay and exact cleanup; upstream TLS/auth remain unproven")
}

func freeIngressPorts(t *testing.T) [2]int {
	t.Helper()
	first, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	return [2]int{first.Addr().(*net.TCPAddr).Port, second.Addr().(*net.TCPAddr).Port}
}

func stringsPort(t *testing.T, endpoint string) uint16 {
	t.Helper()
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(parsed)
}

func awaitIngressHTTP(t *testing.T, ctx context.Context, relayName, endpoint, expected string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		lastError = ingressHTTP(endpoint, expected)
		if lastError == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	logs, _ := dockerTopology(ctx, "logs", relayName)
	status, _ := dockerTopology(ctx, "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", relayName)
	upstream, upstreamErr := dockerTopology(ctx, "exec", relayName, "wget", "-qO-", "http://10.12.0.3:8445/")
	frontend, frontendErr := dockerTopology(ctx, "exec", relayName, "wget", "-qO-", "http://10.11.0.2:8445/")
	routes, _ := dockerTopology(ctx, "exec", relayName, "ip", "route")
	addresses, _ := dockerTopology(ctx, "exec", relayName, "ip", "-br", "addr")
	member, _ := dockerTopology(ctx, "network", "inspect", "--format", "{{json .Containers}}", "ingress-gateway")
	t.Fatalf("ingress endpoint %s did not route to %s: %v; relay status=%q logs=%.2048s upstream=%q/%v frontend=%q/%v routes=%q addresses=%q gateway members=%.2048s",
		endpoint, expected, lastError, status, logs, upstream, upstreamErr, frontend, frontendErr, routes, addresses, member)
}

func ingressHTTP(endpoint, expected string) error {
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + endpoint + "/")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64))
	if err != nil || response.StatusCode != http.StatusOK || string(body) != expected {
		return fmt.Errorf("unexpected ingress response: %v %q", err, body)
	}
	return nil
}

type ingressContainerInspect struct {
	ID         string `json:"Id"`
	Config     struct{ User string }
	HostConfig struct {
		ReadonlyRootfs bool
		Privileged     bool
		CapAdd         []string
		CapDrop        []string
		PidsLimit      int64
		Memory         int64
		NanoCpus       int64
		SecurityOpt    []string
	}
	NetworkSettings struct {
		Networks map[string]json.RawMessage
		Ports    map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string
		}
	}
}
