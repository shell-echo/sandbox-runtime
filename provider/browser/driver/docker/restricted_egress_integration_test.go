//go:build integration

package docker_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"

	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	networkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
	"github.com/shell-echo/sandbox-runtime/provider/browser/provenance/ghcli"
)

const (
	combinedIntegrationEnvironment = "SANDBOX_RUNTIME_BROWSER_NETWORK_INTEGRATION"
	gatewayImageEnvironment        = "SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE"
	managedLabel                   = "io.github.shell-echo.sandbox-runtime.managed"
	ownerLabel                     = "io.github.shell-echo.sandbox-runtime.owner"
	namespaceLabel                 = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel                = "io.github.shell-echo.sandbox-runtime.controller-id"
)

// TestBrowserRestrictedEgressIntegration is single-controller Docker component
// evidence. It does not compose protected Provider routes, a caller Gateway, or
// capability advertisement.
func TestBrowserRestrictedEgressIntegration(t *testing.T) {
	if os.Getenv(combinedIntegrationEnvironment) != "1" {
		t.Skip("set " + combinedIntegrationEnvironment + "=1 to test complete Browser restricted egress")
	}
	gatewayImage := os.Getenv(gatewayImageEnvironment)
	if !strings.HasPrefix(gatewayImage, "sha256:") || len(gatewayImage) != len("sha256:")+64 {
		t.Fatal("set " + gatewayImageEnvironment + " to the immutable local Gateway image ID")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	apiClient, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiClient.Close() })
	if _, err := apiClient.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatal(err)
	}

	token := strconv.FormatInt(time.Now().UnixNano(), 36)
	namespace := "browser-egress-integration-" + token
	controllerID := "controller-" + token
	uplinkName := "sandbox-runtime-browser-uplink-" + token
	policyReference := "browser-egress-policy-" + token
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_ = cleanupIntegrationResources(cleanupCtx, apiClient, namespace, controllerID)
		_, _ = apiClient.NetworkRemove(cleanupCtx, uplinkName, client.NetworkRemoveOptions{})
	}
	t.Cleanup(cleanup)

	if err := createOwnedUplink(ctx, apiClient, uplinkName, namespace); err != nil {
		t.Fatal(err)
	}
	verifier, err := realProvenanceVerifier()
	if err != nil {
		t.Fatal(err)
	}
	policy := gateway.Policy{Reference: policyReference, AllowedHosts: []string{"example.com"}}
	networkOptions := networkdocker.Options{
		Host: os.Getenv("DOCKER_HOST"), GatewayImage: gatewayImage, UplinkNetwork: uplinkName,
		Namespace: namespace, ControllerID: controllerID, Policies: []gateway.Policy{policy},
		MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
		OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10,
	}
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	driverOptions := browserdocker.Options{
		Host: os.Getenv("DOCKER_HOST"), Image: browserimage.LockedPublication().Image(), PullPolicy: browserdocker.PullIfNotPresent,
		MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
		InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
		OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
		DataRoot: t.TempDir(), ManifestPath: filepath.Join(root, "profiles/browser/image/manifest.json"),
		SeccompPath: filepath.Join(root, "profiles/browser/image/chromium-seccomp.json"),
		Namespace:   namespace, ControllerID: controllerID, NetworkPolicyReference: policyReference,
		MaxSessionsPerSandbox: 1, MaxSessionsPerController: 2, Clock: browserdocker.ClockFunc(time.Now),
	}
	allocation := providerbrowser.Allocation{
		Request: providerbrowser.AllocationRequest{
			SandboxID: "sandbox-" + token, BrowserSessionID: "browser-session-" + token,
			OperationID: "operation-" + token, AttemptID: "attempt-" + token,
			FencingToken: 1, ExpectedGeneration: 1,
			RequestDigest: "sha256:" + strings.Repeat("a", 64), NetworkPolicyReference: policyReference,
			ExpiresAt: now.Add(4 * time.Minute),
		},
		AllocatedAt: now,
	}

	networkProvisioner, err := networkdocker.New(ctx, networkOptions)
	if err != nil {
		t.Fatal(err)
	}
	var activeNetwork = networkProvisioner
	var activeDriver *browserdocker.Driver
	t.Cleanup(func() {
		if activeDriver != nil {
			_ = activeDriver.Close()
		}
		if activeNetwork != nil {
			_ = activeNetwork.Close()
		}
	})
	driver, err := browserdocker.New(ctx, driverOptions, verifier, networkProvisioner)
	if err != nil {
		t.Fatal(err)
	}
	activeDriver = driver
	if _, err := networkProvisioner.Acquire(ctx, browserdocker.NetworkRequest{
		SandboxID: allocation.Request.SandboxID, BrowserSessionID: allocation.Request.BrowserSessionID,
		Namespace: namespace, ControllerID: controllerID, PolicyReference: policyReference,
	}); err != nil {
		t.Fatalf("restricted network acquisition failed: %v; %s", err, integrationDiagnostics(ctx, apiClient, namespace, controllerID))
	}
	receipt, err := driver.Allocate(ctx, allocation)
	if err != nil {
		t.Fatal(err)
	}
	topology, err := inspectTopology(ctx, apiClient, allocation.Request, uplinkName)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := driver.Attach(ctx, receipt)
	if err != nil {
		t.Fatal(err)
	}
	cdp := &cdpClient{stream: stream}
	assertNavigationContains(t, ctx, cdp, "http://example.com/", "Example Domain")
	assertNavigationContains(t, ctx, cdp, "https://example.com/", "Example Domain")
	assertNavigationDenied(t, ctx, cdp, "http://example.net/")
	assertNavigationDenied(t, ctx, cdp, "http://169.254.169.254/latest/meta-data/")
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	activeDriver = nil
	if err := networkProvisioner.Close(); err != nil {
		t.Fatal(err)
	}
	activeNetwork = nil

	reconstructedNetwork, err := networkdocker.New(ctx, networkOptions)
	if err != nil {
		t.Fatal(err)
	}
	activeNetwork = reconstructedNetwork
	reconstructed, err := browserdocker.New(ctx, driverOptions, verifier, reconstructedNetwork)
	if err != nil {
		t.Fatal(err)
	}
	activeDriver = reconstructed
	replayed, err := reconstructed.Allocate(ctx, allocation)
	if err != nil || replayed != receipt {
		t.Fatalf("reconstructed allocation = %#v, %v", replayed, err)
	}
	if err := reconstructed.Cleanup(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	assertResourcesAbsent(t, ctx, apiClient, topology)
}

func integrationDiagnostics(ctx context.Context, apiClient *client.Client, namespace, controller string) string {
	filters := make(client.Filters).
		Add("label", managedLabel+"=true").
		Add("label", namespaceLabel+"="+namespace).
		Add("label", controllerLabel+"="+controller)
	containers, _ := apiClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	diagnostics := make([]string, 0, len(containers.Items)+1)
	for _, item := range containers.Items {
		inspected, err := apiClient.ContainerInspect(ctx, item.ID, client.ContainerInspectOptions{})
		if err != nil || inspected.Container.Config == nil || inspected.Container.HostConfig == nil || inspected.Container.NetworkSettings == nil {
			diagnostics = append(diagnostics, fmt.Sprintf("container %s inspect=%v", item.ID, err))
			continue
		}
		config, host := inspected.Container.Config, inspected.Container.HostConfig
		stopTimeout := -1
		if config.StopTimeout != nil {
			stopTimeout = *config.StopTimeout
		}
		pidsLimit := int64(-1)
		if host.PidsLimit != nil {
			pidsLimit = *host.PidsLimit
		}
		projectedNetworks := make(map[string]string, len(inspected.Container.NetworkSettings.Networks))
		for name, endpoint := range inspected.Container.NetworkSettings.Networks {
			if endpoint != nil {
				projectedNetworks[name] = endpoint.IPAddress.String()
			}
		}
		diagnostics = append(diagnostics, fmt.Sprintf(
			"container=%s image-id=%s image=%s user=%s entrypoint=%v command=%v workdir=%s env=%v stop=%d exposed=%d network=%s pid=%s ipc=%s dns=%v extra-hosts=%v cap-add=%v cap-drop=%v security=%v privileged=%t auto-remove=%t readonly=%t publish=%t ports=%d binds=%d mounts=%d memory=%d swap=%d cpu=%d pids=%d tmpfs=%v sysctls=%v log=%s/%v restart=%s networks=%v health=%v",
			item.ID, inspected.Container.Image, config.Image, config.User, config.Entrypoint, config.Cmd, config.WorkingDir,
			config.Env, stopTimeout, len(config.ExposedPorts), host.NetworkMode, host.PidMode, host.IpcMode, host.DNS, host.ExtraHosts,
			host.CapAdd, host.CapDrop, host.SecurityOpt, host.Privileged, host.AutoRemove, host.ReadonlyRootfs, host.PublishAllPorts,
			len(host.PortBindings), len(host.Binds), len(host.Mounts), host.Memory, host.MemorySwap, host.NanoCPUs, pidsLimit,
			host.Tmpfs, host.Sysctls, host.LogConfig.Type, host.LogConfig.Config, host.RestartPolicy.Name, projectedNetworks,
			inspected.Container.State.Health,
		))
	}
	networks, _ := apiClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	diagnostics = append(diagnostics, fmt.Sprintf("managed networks=%v", networks.Items))
	return strings.Join(diagnostics, "; ")
}

func createOwnedUplink(ctx context.Context, apiClient *client.Client, name, namespace string) error {
	enableIPv4, enableIPv6 := true, false
	_, err := apiClient.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge", Scope: "local", EnableIPv4: &enableIPv4, EnableIPv6: &enableIPv6,
		Labels: map[string]string{managedLabel: "true", ownerLabel: networkdocker.UplinkRole, namespaceLabel: namespace},
	})
	return err
}

func realProvenanceVerifier() (*ghcli.Verifier, error) {
	executable, err := exec.LookPath("gh")
	if err != nil {
		return nil, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(executable)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return nil, err
	}
	return ghcli.New(ghcli.Options{ExecutablePath: executable, ExecutableDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil))})
}

type dockerTopology struct {
	browserContainer string
	gatewayContainer string
	internalNetwork  string
}

func inspectTopology(ctx context.Context, apiClient *client.Client, request providerbrowser.AllocationRequest, uplink string) (dockerTopology, error) {
	digest := sha256.Sum256([]byte(request.SandboxID + "\x00" + request.BrowserSessionID))
	browserName := "sandbox-runtime-browser-" + hex.EncodeToString(digest[:16])
	browser, err := apiClient.ContainerInspect(ctx, browserName, client.ContainerInspectOptions{})
	if err != nil {
		return dockerTopology{}, err
	}
	host := browser.Container.HostConfig
	networks := browser.Container.NetworkSettings
	if host == nil || networks == nil || len(host.DNS) != 1 || len(networks.Networks) != 1 ||
		host.DNS[0].String() == "" || string(host.NetworkMode) == "none" || string(host.NetworkMode) == "bridge" ||
		host.DNS[0].IsLoopback() || !host.DNS[0].IsPrivate() {
		return dockerTopology{}, fmt.Errorf("Browser network isolation is invalid")
	}
	internalName := string(host.NetworkMode)
	if _, ok := networks.Networks[internalName]; !ok {
		return dockerTopology{}, fmt.Errorf("Browser is not attached to its configured internal network")
	}
	network, err := apiClient.NetworkInspect(ctx, internalName, client.NetworkInspectOptions{})
	if err != nil {
		return dockerTopology{}, err
	}
	if !network.Network.Internal || network.Network.EnableIPv6 || len(network.Network.Containers) != 2 {
		return dockerTopology{}, fmt.Errorf("internal network topology is invalid")
	}
	gatewayName := ""
	for _, endpoint := range network.Network.Containers {
		if endpoint.Name != browserName {
			gatewayName = endpoint.Name
		}
	}
	if gatewayName == "" {
		return dockerTopology{}, fmt.Errorf("Gateway container was not found")
	}
	gatewayContainer, err := apiClient.ContainerInspect(ctx, gatewayName, client.ContainerInspectOptions{})
	if err != nil {
		return dockerTopology{}, err
	}
	if gatewayContainer.Container.NetworkSettings == nil || len(gatewayContainer.Container.NetworkSettings.Networks) != 2 {
		return dockerTopology{}, fmt.Errorf("Gateway does not have exactly internal and uplink attachments")
	}
	if _, ok := gatewayContainer.Container.NetworkSettings.Networks[internalName]; !ok {
		return dockerTopology{}, fmt.Errorf("Gateway internal attachment is absent")
	}
	if _, ok := gatewayContainer.Container.NetworkSettings.Networks[uplink]; !ok {
		return dockerTopology{}, fmt.Errorf("Gateway uplink attachment is absent")
	}
	return dockerTopology{browserContainer: browserName, gatewayContainer: gatewayName, internalNetwork: internalName}, nil
}

func assertResourcesAbsent(t *testing.T, ctx context.Context, apiClient *client.Client, topology dockerTopology) {
	t.Helper()
	if _, err := apiClient.ContainerInspect(ctx, topology.browserContainer, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatalf("Browser container remains after cleanup: %v", err)
	}
	if _, err := apiClient.ContainerInspect(ctx, topology.gatewayContainer, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatalf("Gateway container remains after cleanup: %v", err)
	}
	if _, err := apiClient.NetworkInspect(ctx, topology.internalNetwork, client.NetworkInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatalf("internal network remains after cleanup: %v", err)
	}
}

func cleanupIntegrationResources(ctx context.Context, apiClient *client.Client, namespace, controller string) error {
	filters := make(client.Filters).
		Add("label", managedLabel+"=true").
		Add("label", namespaceLabel+"="+namespace).
		Add("label", controllerLabel+"="+controller)
	containers, err := apiClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return err
	}
	var result error
	for _, item := range containers.Items {
		if item.Labels[managedLabel] != "true" || item.Labels[namespaceLabel] != namespace || item.Labels[controllerLabel] != controller {
			continue
		}
		_, removeErr := apiClient.ContainerRemove(ctx, item.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
		result = errors.Join(result, removeErr)
	}
	networks, err := apiClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		return errors.Join(result, err)
	}
	for _, item := range networks.Items {
		if item.Labels[managedLabel] != "true" || item.Labels[namespaceLabel] != namespace || item.Labels[controllerLabel] != controller {
			continue
		}
		_, removeErr := apiClient.NetworkRemove(ctx, item.ID, client.NetworkRemoveOptions{})
		result = errors.Join(result, removeErr)
	}
	return result
}

type cdpClient struct {
	stream providerbrowser.Stream
	nextID int
}

type cdpEnvelope struct {
	ID        int             `json:"id"`
	SessionID string          `json:"sessionId"`
	Method    string          `json:"method"`
	Result    json.RawMessage `json:"result"`
	Error     *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *cdpClient) call(ctx context.Context, sessionID, method string, parameters any, result any) error {
	c.nextID++
	request := struct {
		ID        int    `json:"id"`
		SessionID string `json:"sessionId,omitempty"`
		Method    string `json:"method"`
		Params    any    `json:"params,omitempty"`
	}{ID: c.nextID, SessionID: sessionID, Method: method, Params: parameters}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := writeWebSocketFrame(ctx, c.stream, 1, payload); err != nil {
		return err
	}
	for {
		responsePayload, err := readWebSocketFrame(ctx, c.stream)
		if err != nil {
			return err
		}
		var response cdpEnvelope
		if err := json.Unmarshal(responsePayload, &response); err != nil {
			return err
		}
		if response.ID != c.nextID {
			continue
		}
		if response.Error != nil {
			return fmt.Errorf("CDP %s failed: %d %s", method, response.Error.Code, response.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(response.Result, result)
	}
}

func newPageSession(ctx context.Context, cdp *cdpClient) (string, error) {
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := cdp.call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &created); err != nil {
		return "", err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := cdp.call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil {
		return "", err
	}
	if attached.SessionID == "" {
		return "", errors.New("CDP returned an empty session ID")
	}
	if err := cdp.call(ctx, attached.SessionID, "Page.enable", nil, nil); err != nil {
		return "", err
	}
	if err := cdp.call(ctx, attached.SessionID, "Runtime.enable", nil, nil); err != nil {
		return "", err
	}
	return attached.SessionID, nil
}

func assertNavigationContains(t *testing.T, parent context.Context, cdp *cdpClient, targetURL, expected string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	sessionID, err := newPageSession(ctx, cdp)
	if err != nil {
		t.Fatal(err)
	}
	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	if err := cdp.call(ctx, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navigation); err != nil {
		t.Fatal(err)
	}
	if navigation.ErrorText != "" {
		t.Fatalf("navigation to %s failed: %s", targetURL, navigation.ErrorText)
	}
	for {
		var evaluated struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		err := cdp.call(ctx, sessionID, "Runtime.evaluate", map[string]any{
			"expression": "document.body ? document.body.innerText : ''", "returnByValue": true,
		}, &evaluated)
		if err == nil && strings.Contains(evaluated.Result.Value, expected) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("navigation to %s did not expose expected content: %v", targetURL, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func assertNavigationDenied(t *testing.T, parent context.Context, cdp *cdpClient, targetURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	sessionID, err := newPageSession(ctx, cdp)
	if err != nil {
		t.Fatal(err)
	}
	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	err = cdp.call(ctx, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navigation)
	if err == nil && navigation.ErrorText == "" {
		t.Fatalf("navigation to denied target %s succeeded", targetURL)
	}
}

func writeWebSocketFrame(ctx context.Context, stream providerbrowser.Stream, opcode byte, payload []byte) error {
	mask := [4]byte{}
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	frame := []byte{0x80 | opcode}
	switch {
	case len(payload) < 126:
		frame = append(frame, 0x80|byte(len(payload)))
	case len(payload) <= 65_535:
		frame = append(frame, 0x80|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		frame = append(frame, 0x80|127)
		length := make([]byte, 8)
		binary.BigEndian.PutUint64(length, uint64(len(payload)))
		frame = append(frame, length...)
	}
	frame = append(frame, mask[:]...)
	for index, value := range payload {
		frame = append(frame, value^mask[index%len(mask)])
	}
	return writeStream(ctx, stream, frame)
}

func readWebSocketFrame(ctx context.Context, stream providerbrowser.Stream) ([]byte, error) {
	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(streamReader{ctx: ctx, stream: stream}, header); err != nil {
			return nil, err
		}
		if header[0]&0x80 == 0 || header[1]&0x80 != 0 {
			return nil, errors.New("invalid Browser WebSocket frame")
		}
		length := uint64(header[1] & 0x7f)
		switch length {
		case 126:
			extended := make([]byte, 2)
			if _, err := io.ReadFull(streamReader{ctx: ctx, stream: stream}, extended); err != nil {
				return nil, err
			}
			length = uint64(binary.BigEndian.Uint16(extended))
		case 127:
			extended := make([]byte, 8)
			if _, err := io.ReadFull(streamReader{ctx: ctx, stream: stream}, extended); err != nil {
				return nil, err
			}
			length = binary.BigEndian.Uint64(extended)
		}
		if length > 1<<20 {
			return nil, errors.New("Browser WebSocket frame exceeds integration limit")
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(streamReader{ctx: ctx, stream: stream}, payload); err != nil {
			return nil, err
		}
		switch header[0] & 0x0f {
		case 1:
			return payload, nil
		case 8:
			return nil, io.EOF
		case 9:
			if err := writeWebSocketFrame(ctx, stream, 10, payload); err != nil {
				return nil, err
			}
		case 10:
		default:
			return nil, errors.New("unsupported Browser WebSocket opcode")
		}
	}
}

func writeStream(ctx context.Context, stream providerbrowser.Stream, value []byte) error {
	for len(value) > 0 {
		written, err := stream.Write(ctx, value)
		if written > 0 {
			value = value[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

type streamReader struct {
	ctx    context.Context
	stream providerbrowser.Stream
}

func (r streamReader) Read(value []byte) (int, error) { return r.stream.Read(r.ctx, value) }
