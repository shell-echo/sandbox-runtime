//go:build integration

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	gatewaycomposition "github.com/shell-echo/sandbox-runtime/gateway/composition"
	"github.com/shell-echo/sandbox-runtime/gateway/edge"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	providerusage "github.com/shell-echo/sandbox-runtime/provider/usage"
)

const (
	browserVerticalIntegrationEnvironment = "SANDBOX_RUNTIME_BROWSER_VERTICAL_INTEGRATION"
	browserGatewayImageEnvironment        = "SANDBOX_RUNTIME_BROWSER_GATEWAY_IMAGE"
	browserManagedLabel                   = "io.github.shell-echo.sandbox-runtime.managed"
	browserOwnerLabel                     = "io.github.shell-echo.sandbox-runtime.owner"
	browserNamespaceLabel                 = "io.github.shell-echo.sandbox-runtime.namespace"
	browserControllerLabel                = "io.github.shell-echo.sandbox-runtime.controller-id"
)

// TestProviderBrowserVerticalIntegration proves the single-controller command
// composition with a real Docker runtime and an explicit caller-owned public
// edge. It is same-repository vertical evidence, not independent-caller E2E,
// multi-tenant isolation, deployment, or production evidence.
func TestProviderBrowserVerticalIntegration(t *testing.T) {
	if os.Getenv(browserVerticalIntegrationEnvironment) != "1" {
		t.Skip("set " + browserVerticalIntegrationEnvironment + "=1 to test the complete Browser command vertical")
	}
	gatewayImage := os.Getenv(browserGatewayImageEnvironment)
	if !strings.HasPrefix(gatewayImage, "sha256:") || len(gatewayImage) != len("sha256:")+64 {
		t.Fatal("set " + browserGatewayImageEnvironment + " to the immutable local Browser egress Gateway image ID")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dockerClient.Close() })
	if _, err := dockerClient.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatal(err)
	}

	token := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano()))))[:16]
	namespace := "browser-vertical-" + token
	controllerID := "controller-" + token
	uplinkName := "sandbox-runtime-browser-uplink-" + token
	policyReference := "browser-egress-policy-" + token
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cleanupCancel()
		_ = cleanupBrowserVerticalResources(cleanupCtx, dockerClient, namespace, controllerID)
		_, _ = dockerClient.NetworkRemove(cleanupCtx, uplinkName, client.NetworkRemoveOptions{})
	})
	if err := createBrowserVerticalUplink(ctx, dockerClient, uplinkName, namespace); err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	browserConfig := browserVerticalConfig(t, directory, gatewayImage, uplinkName, namespace, controllerID, policyReference)
	lifecycleConfig := config.ProviderLifecycleConfig{
		Enabled: true, Driver: config.ProviderLifecycleBrowserDriver,
		Repository: config.ProviderLifecycleRepositoryConfig{
			Driver: config.ProviderLifecycleFileRepository,
			File:   config.ProviderLifecycleRepositoryFileConfig{Path: filepath.Join(directory, "lifecycle.json")},
		},
	}
	usageConfig := config.ProviderUsageConfig{Enabled: true, RepositoryFile: filepath.Join(directory, "usage.json")}

	lifecycleApp, browserApp, closeGraph := openBrowserVertical(t, ctx, browserConfig, lifecycleConfig, usageConfig)
	activeClose := closeGraph
	t.Cleanup(func() {
		if activeClose != nil {
			_ = activeClose()
		}
	})

	now := time.Now().UTC()
	create := lifecycle.CreateRequest{
		OperationID: "create-" + token, AttemptID: "create-attempt-" + token, FencingToken: 1,
		IdempotencyKey: "create-key-" + token, RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(2 * time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-" + token, TenantID: "tenant-" + token, WorkOrderID: "work-" + token,
			WorkspaceID: "workspace-" + token, ProviderRevisionID: "revision-" + token,
			RuntimeProfile: lifecycle.BrowserRuntimeProfile,
			Network: lifecycle.NetworkPolicy{
				Mode: lifecycle.NetworkRestricted, PolicyReference: policyReference, EgressGatewayRequired: true,
			},
			SandboxSlotKey: "primary-browser", LeaseExpiresAt: now.Add(5 * time.Minute),
		},
	}
	accepted, err := lifecycleApp.AcceptCreate(ctx, create)
	if err != nil || accepted.Operation.State != lifecycle.OperationAccepted {
		t.Fatalf("Browser lifecycle acceptance = %#v, %v", accepted, err)
	}
	waitBrowserLifecycleReady(t, ctx, lifecycleApp, create.OperationID)

	// A two-minute handoff leaves enough time for egress and reconstruction,
	// then provides a bounded expiry point for complete usage and cleanup.
	expiresAt := time.Now().UTC().Add(2 * time.Minute)
	openRequest := providerbrowser.OpenRequest{
		SandboxID: create.Spec.SandboxID, ProviderRevisionID: create.Spec.ProviderRevisionID,
		OperationID: "browser-open-" + token, AttemptID: "browser-attempt-" + token, FencingToken: 2,
		IdempotencyKey: "browser-key-" + token, RequestDigest: "sha256:" + strings.Repeat("b", 64),
		Deadline: expiresAt.Add(30 * time.Second), ExpectedGeneration: 1,
		BrowserSessionID: "browser-session-" + token, CapabilityProfileID: providerbrowser.CapabilityProfileID,
		ExpiresAt: expiresAt,
	}
	operation, err := browserApp.Open(ctx, openRequest)
	if err != nil || operation.Status != providerbrowser.StatusSucceeded {
		t.Fatalf("Browser open = %#v, %v", operation, err)
	}
	handoff, err := browserApp.GetHandoff(ctx, openRequest.OperationID)
	if err != nil || !strings.HasPrefix(handoff.InternalEndpointReference, "ref:browser-session:") {
		t.Fatalf("Browser handoff = %#v, %v", handoff, err)
	}
	assertBrowserUsage(t, ctx, browserApp.usage, openRequest.OperationID, providerusage.ReconciliationPartial)

	connect := browserGatewayConnect(create.Spec.TenantID, handoff)
	publicGateway, recorder := openBrowserPublicGateway(t, browserApp.Resolver(), connect, handoff)
	connection := dialBrowserPublicGateway(t, ctx, publicGateway.URL)
	assertBrowserVersion(t, ctx, connection)
	assertBrowserNavigationContains(t, ctx, connection, "https://example.com/", "Example Domain")
	assertBrowserNavigationDenied(t, ctx, connection, "http://example.net/")
	if encoded, err := json.Marshal(recorder.Events()); err != nil || strings.Contains(string(encoded), "Browser.getVersion") {
		t.Fatalf("Browser audit leaked payload or could not be encoded: %s, %v", encoded, err)
	}
	_ = connection.Close(websocket.StatusNormalClosure, "reconstruct")
	publicGateway.Close()

	if err := closeGraph(); err != nil {
		t.Fatalf("close initial Browser graph: %v", err)
	}
	activeClose = nil
	if remaining := time.Until(expiresAt); remaining <= 0 {
		t.Fatal("Browser handoff expired before reconstruction")
	}

	_, browserApp, closeGraph = openBrowserVertical(t, ctx, browserConfig, lifecycleConfig, usageConfig)
	activeClose = closeGraph
	reconstructed, err := browserApp.GetHandoff(ctx, openRequest.OperationID)
	if err != nil || reconstructed.InternalEndpointReference != handoff.InternalEndpointReference || reconstructed.ConnectionGeneration != handoff.ConnectionGeneration {
		t.Fatalf("reconstructed Browser handoff = %#v, %v", reconstructed, err)
	}
	connect = browserGatewayConnect(create.Spec.TenantID, reconstructed)
	publicGateway, _ = openBrowserPublicGateway(t, browserApp.Resolver(), connect, reconstructed)
	connection = dialBrowserPublicGateway(t, ctx, publicGateway.URL)
	assertBrowserVersion(t, ctx, connection)
	_ = connection.Close(websocket.StatusNormalClosure, "expiry")
	publicGateway.Close()

	wait := time.Until(expiresAt.Add(100 * time.Millisecond))
	if wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		}
	}
	assertBrowserUsage(t, ctx, browserApp.usage, openRequest.OperationID, providerusage.ReconciliationComplete)
	if err := closeGraph(); err != nil {
		t.Fatalf("close expired Browser graph: %v", err)
	}
	activeClose = nil
	assertBrowserVerticalResourcesAbsent(t, ctx, dockerClient, namespace, controllerID)
}

func openBrowserVertical(t *testing.T, ctx context.Context, browserConfig config.ProviderBrowserConfig, lifecycleConfig config.ProviderLifecycleConfig, usageConfig config.ProviderUsageConfig) (*lifecycleapplication.Application, *providerBrowserApplication, func() error) {
	t.Helper()
	graph, err := newProviderBrowserRuntime(ctx, browserConfig)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleApp, execRuntime, closeLifecycle, err := newProviderLifecycleRuntimeWithDriver(ctx, lifecycleConfig, graph.lifecycle)
	if err != nil {
		_ = graph.Close()
		t.Fatal(err)
	}
	if execRuntime != nil {
		_ = errors.Join(closeLifecycle(), graph.Close())
		t.Fatal("Browser lifecycle unexpectedly supplied the coding/shell exec runtime")
	}
	usageStore, _, closeUsage, err := newProviderUsageCollector(usageConfig)
	if err != nil {
		_ = errors.Join(closeLifecycle(), graph.Close())
		t.Fatal(err)
	}
	browserApp, _, err := newProviderBrowserApplication(ctx, browserConfig, graph, lifecycleApp, usageStore)
	if err != nil {
		_ = errors.Join(closeUsage(), closeLifecycle())
		t.Fatal(err)
	}
	var closeOnce sync.Once
	var closeErr error
	closeGraph := func() error {
		closeOnce.Do(func() {
			closeErr = errors.Join(browserApp.Close(), closeUsage(), closeLifecycle())
		})
		return closeErr
	}
	return lifecycleApp, browserApp, closeGraph
}

func browserVerticalConfig(t *testing.T, directory, gatewayImage, uplink, namespace, controllerID, policyReference string) config.ProviderBrowserConfig {
	t.Helper()
	executable, err := exec.LookPath("gh")
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return config.ProviderBrowserConfig{
		Enabled: true, SessionRepositoryFile: filepath.Join(directory, "browser-sessions.json"),
		ReferenceRegistryFile:  filepath.Join(directory, "browser-references.json"),
		ShutdownCleanupSeconds: 45, UsageRetentionSeconds: 3600,
		Docker: config.ProviderBrowserDockerConfig{
			Host: os.Getenv("DOCKER_HOST"), Image: browserimage.LockedPublication().Image(), PullPolicy: "if_not_present",
			MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
			InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
			OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
			DataRoot: filepath.Join(directory, "browser-runtime"), ManifestPath: filepath.Join(root, "profiles/browser/image/manifest.json"),
			SeccompPath: filepath.Join(root, "profiles/browser/image/chromium-seccomp.json"), Namespace: namespace,
			ControllerID: controllerID, NetworkPolicyReference: policyReference,
			MaxSessionsPerSandbox: 1, MaxSessionsPerController: 2,
		},
		Provenance: config.ProviderBrowserProvenanceConfig{ExecutablePath: executable, ExecutableDigest: "sha256:" + hex.EncodeToString(digest[:])},
		RestrictedNetwork: config.ProviderBrowserNetworkConfig{
			Host: os.Getenv("DOCKER_HOST"), GatewayImage: gatewayImage, UplinkNetwork: uplink,
			Namespace: namespace, ControllerID: controllerID,
			Policies:    []config.ProviderBrowserNetworkPolicyConfig{{Reference: policyReference, AllowedHosts: []string{"example.com"}}},
			MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
			OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10,
		},
	}
}

func waitBrowserLifecycleReady(t *testing.T, ctx context.Context, application interface {
	GetOperation(context.Context, string) (lifecycle.Operation, error)
}, operationID string) {
	t.Helper()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		operation, err := application.GetOperation(ctx, operationID)
		if err == nil && operation.State == lifecycle.OperationSucceeded {
			return
		}
		if err == nil && (operation.State == lifecycle.OperationFailed || operation.State == lifecycle.OperationOutcomeUnknown || operation.State == lifecycle.OperationCancelled) {
			t.Fatalf("Browser lifecycle operation = %#v", operation)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait Browser lifecycle: %v", ctx.Err())
		}
	}
}

func browserGatewayConnect(tenantID string, handoff browserapplication.Handoff) gateway.ConnectRequest {
	return gateway.ConnectRequest{
		CallerID: "browser-caller-1", TenantID: tenantID, SandboxID: handoff.SandboxID,
		BrowserSessionID: handoff.BrowserSessionID, CapabilityProfileID: handoff.CapabilityProfileID,
		HandoffReference: handoff.InternalEndpointReference,
	}
}

type browserVerticalAuthorizer struct {
	request gateway.ConnectRequest
	grant   gateway.Grant
}

func (a browserVerticalAuthorizer) Authorize(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
	if !reflect.DeepEqual(request, a.request) {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	return a.grant, nil
}

type browserVerticalRecorder struct {
	mu     sync.Mutex
	events []gateway.AuditEvent
}

func (r *browserVerticalRecorder) Record(_ context.Context, event gateway.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *browserVerticalRecorder) Events() []gateway.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]gateway.AuditEvent(nil), r.events...)
}

func openBrowserPublicGateway(t *testing.T, resolver gatewaycomposition.BrowserProviderResolver, connect gateway.ConnectRequest, handoff browserapplication.Handoff) (*httptest.Server, *browserVerticalRecorder) {
	t.Helper()
	const token = "browser-caller-token"
	recorder := &browserVerticalRecorder{}
	edgeGate, err := edge.NewLocalLimiter(edge.LocalOptions{
		MaxConcurrent: 4, MaxRequestsPerWindow: 64, Window: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := gatewaycomposition.NewBrowser(gatewaycomposition.BrowserOptions{
		Authorizer: browserVerticalAuthorizer{request: connect, grant: gateway.Grant{
			GrantID: "browser-grant-1", CallerID: connect.CallerID, TenantID: connect.TenantID,
			SandboxID: connect.SandboxID, BrowserSessionID: connect.BrowserSessionID,
			CapabilityProfileID: connect.CapabilityProfileID, HandoffReference: connect.HandoffReference,
			ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: handoff.ExpiresAt,
		}},
		Revocations: gateway.NewMemoryRevocations(), Recorder: recorder, Resolver: resolver,
		WebSocket: adapter.WebSocketOptions{
			Admission: func(_ context.Context, request *http.Request) error {
				if request.Header.Get("Authorization") != "Bearer "+token {
					return gateway.ErrUnauthorized
				}
				return nil
			},
			OriginPatterns: []string{"https://browser-caller.invalid"},
		},
		Edge:           edgeGate,
		MaxConnections: 4, MaxConnectionsPerSession: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/browser/connect" {
			http.NotFound(response, request)
			return
		}
		_ = service.Serve(request.Context(), response, request, connect)
	})), recorder
}

func dialBrowserPublicGateway(t *testing.T, ctx context.Context, baseURL string) *websocket.Conn {
	t.Helper()
	connection, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(baseURL, "http")+"/v1/browser/connect", &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer browser-caller-token"},
			"Origin":        []string{"https://browser-caller.invalid"},
		},
	})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial Browser public Gateway (status %d): %v", status, err)
	}
	return connection
}

type browserCDPEnvelope struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func browserCDPCall(ctx context.Context, connection *websocket.Conn, id int, sessionID, method string, parameters any, result any) error {
	request := struct {
		ID        int    `json:"id"`
		SessionID string `json:"sessionId,omitempty"`
		Method    string `json:"method"`
		Params    any    `json:"params,omitempty"`
	}{ID: id, SessionID: sessionID, Method: method, Params: parameters}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := connection.Write(ctx, websocket.MessageText, encoded); err != nil {
		return err
	}
	for {
		messageType, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageText {
			return errors.New("Browser Gateway returned a non-text CDP message")
		}
		var response browserCDPEnvelope
		if err := json.Unmarshal(payload, &response); err != nil {
			return err
		}
		if response.ID != id {
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

func assertBrowserVersion(t *testing.T, parent context.Context, connection *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	var version struct {
		Product string `json:"product"`
	}
	if err := browserCDPCall(ctx, connection, 1, "", "Browser.getVersion", nil, &version); err != nil || !strings.Contains(version.Product, "Chrome/151.0.7922.109") {
		t.Fatalf("Browser.getVersion = %#v, %v", version, err)
	}
}

func newBrowserPage(t *testing.T, ctx context.Context, connection *websocket.Conn, idBase int) string {
	t.Helper()
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := browserCDPCall(ctx, connection, idBase, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &created); err != nil {
		t.Fatal(err)
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := browserCDPCall(ctx, connection, idBase+1, "", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil || attached.SessionID == "" {
		t.Fatalf("attach Browser target = %#v, %v", attached, err)
	}
	if err := browserCDPCall(ctx, connection, idBase+2, attached.SessionID, "Page.enable", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := browserCDPCall(ctx, connection, idBase+3, attached.SessionID, "Runtime.enable", nil, nil); err != nil {
		t.Fatal(err)
	}
	return attached.SessionID
}

func assertBrowserNavigationContains(t *testing.T, parent context.Context, connection *websocket.Conn, targetURL, expected string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	sessionID := newBrowserPage(t, ctx, connection, 10)
	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	if err := browserCDPCall(ctx, connection, 14, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navigation); err != nil || navigation.ErrorText != "" {
		t.Fatalf("navigate to allowed target = %#v, %v", navigation, err)
	}
	for id := 15; ; id++ {
		var evaluated struct {
			Result struct {
				Value string `json:"value"`
			} `json:"result"`
		}
		err := browserCDPCall(ctx, connection, id, sessionID, "Runtime.evaluate", map[string]any{
			"expression": "document.body ? document.body.innerText : ''", "returnByValue": true,
		}, &evaluated)
		if err == nil && strings.Contains(evaluated.Result.Value, expected) {
			return
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("allowed Browser navigation did not expose expected content: %v", err)
		}
	}
}

func assertBrowserNavigationDenied(t *testing.T, parent context.Context, connection *websocket.Conn, targetURL string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	sessionID := newBrowserPage(t, ctx, connection, 100)
	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	err := browserCDPCall(ctx, connection, 104, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navigation)
	if err == nil && navigation.ErrorText == "" {
		t.Fatalf("navigation to denied target %s succeeded", targetURL)
	}
}

func assertBrowserUsage(t *testing.T, ctx context.Context, reader providerusage.EvidenceReader, operationID string, want providerusage.ReconciliationStatus) {
	t.Helper()
	evidence, err := reader.GetEvidence(ctx, operationID, time.Now().UTC())
	if err != nil || evidence.ReconciliationStatus != want || len(evidence.Entries) != 1 || evidence.Entries[0].Meter != providerusage.MeterBrowserSession {
		t.Fatalf("Browser usage = %#v, %v; want %s", evidence, err, want)
	}
}

func createBrowserVerticalUplink(ctx context.Context, dockerClient *client.Client, name, namespace string) error {
	enableIPv4, enableIPv6 := true, false
	_, err := dockerClient.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge", Scope: "local", EnableIPv4: &enableIPv4, EnableIPv6: &enableIPv6,
		Labels: map[string]string{
			browserManagedLabel: "true", browserOwnerLabel: "browser-egress-uplink", browserNamespaceLabel: namespace,
		},
	})
	return err
}

func cleanupBrowserVerticalResources(ctx context.Context, dockerClient *client.Client, namespace, controllerID string) error {
	filters := make(client.Filters).Add("label", browserManagedLabel+"=true").Add("label", browserNamespaceLabel+"="+namespace).Add("label", browserControllerLabel+"="+controllerID)
	containers, err := dockerClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return err
	}
	var result error
	for _, item := range containers.Items {
		_, removeErr := dockerClient.ContainerRemove(ctx, item.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
		result = errors.Join(result, removeErr)
	}
	networks, err := dockerClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		return errors.Join(result, err)
	}
	for _, item := range networks.Items {
		_, removeErr := dockerClient.NetworkRemove(ctx, item.ID, client.NetworkRemoveOptions{})
		result = errors.Join(result, removeErr)
	}
	return result
}

func assertBrowserVerticalResourcesAbsent(t *testing.T, ctx context.Context, dockerClient *client.Client, namespace, controllerID string) {
	t.Helper()
	filters := make(client.Filters).Add("label", browserManagedLabel+"=true").Add("label", browserNamespaceLabel+"="+namespace).Add("label", browserControllerLabel+"="+controllerID)
	containers, err := dockerClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		t.Fatal(err)
	}
	networks, err := dockerClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		t.Fatal(err)
	}
	if len(containers.Items) != 0 || len(networks.Items) != 0 {
		t.Fatalf("Browser resources remain after expiry cleanup: containers=%d networks=%d", len(containers.Items), len(networks.Items))
	}
}
