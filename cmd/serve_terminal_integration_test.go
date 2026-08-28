//go:build integration

package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycledocker "github.com/shell-echo/sandbox-runtime/provider/lifecycle/driver/docker"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
)

// TestProviderTerminalVerticalIntegration exercises the development-only
// terminal composition through durable handoff and a caller-owned test Gateway.
// It is local single-controller evidence, not an external caller E2E.
func TestProviderTerminalVerticalIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_DOCKER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 to run against Docker Engine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	dataRoot, err := os.MkdirTemp(".", ".provider-terminal-vertical-")
	if err != nil {
		t.Fatal(err)
	}
	dataRoot, err = filepath.Abs(dataRoot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataRoot) })
	image := f7IntegrationPinnedImage(ctx, t)
	controllerID := fmt.Sprintf("f7-controller-%d", time.Now().UnixNano())
	sandboxID := fmt.Sprintf("f7-sandbox-%d", time.Now().UnixNano())
	lifecycleConfig := f7LifecycleConfig(dataRoot, image, controllerID)
	t.Cleanup(func() { f7RemoveSandbox(t, lifecycleConfig, sandboxID) })

	lifecycleApp, runtimeDriver, closeFirstLifecycle, err := newProviderLifecycleRuntime(ctx, lifecycleConfig)
	if err != nil || lifecycleApp == nil || runtimeDriver == nil {
		t.Fatalf("newProviderLifecycleRuntime = %T, %T, %v", lifecycleApp, runtimeDriver, err)
	}
	defer func() { _ = closeFirstLifecycle() }()

	now := time.Now().UTC()
	create := f7CreateRequest(now, sandboxID)
	if _, err := lifecycleApp.AcceptCreate(ctx, create); err != nil {
		t.Fatalf("accept lifecycle create: %v", err)
	}
	if err := lifecycleApp.Recover(ctx); err != nil {
		t.Fatalf("recover lifecycle create: %v", err)
	}
	ready, err := lifecycleApp.GetSandbox(ctx, sandboxID)
	if err != nil || ready.ObservedState != lifecycle.ObservedReady || ready.ObservedGeneration != ready.Generation {
		t.Fatalf("lifecycle sandbox after recovery = %#v, %v", ready, err)
	}

	brokerPath := f7BrokerHostPath(dataRoot, sandboxID)
	f7BuildTerminalBroker(ctx, t, brokerPath)
	terminalConfig := f7TerminalConfig(dataRoot)
	terminalApp, closeFirstTerminal, err := newProviderTerminalApplication(ctx, terminalConfig, lifecycleApp, runtimeDriver)
	if err != nil || terminalApp == nil {
		t.Fatalf("newProviderTerminalApplication = %T, %v", terminalApp, err)
	}
	defer func() { _ = closeFirstTerminal() }()

	open := f7SessionOpenRequest(now, sandboxID)
	operation, err := terminalApp.Open(ctx, open)
	if err != nil || operation.Status != session.StatusSucceeded {
		t.Fatalf("open composed terminal = %#v, %v", operation, err)
	}
	handoff, err := terminalApp.GetHandoff(ctx, open.OperationID)
	if err != nil || !strings.HasPrefix(handoff.InternalEndpointReference, "ref:session:") {
		t.Fatalf("get composed terminal handoff = %#v, %v", handoff, err)
	}
	f7GatewayTerminalRoundTrip(t, terminalApp, handoff, "P2F7-FIRST:retained", "P2F7_VALUE=retained; printf 'P2F7-FIRST:%s\\n' \"$P2F7_VALUE\"\n")
	if err := closeFirstTerminal(); err != nil {
		t.Fatalf("close first terminal composition: %v", err)
	}
	if err := closeFirstLifecycle(); err != nil {
		t.Fatalf("close first lifecycle composition: %v", err)
	}

	lifecycleApp, runtimeDriver, closeSecondLifecycle, err := newProviderLifecycleRuntime(ctx, lifecycleConfig)
	if err != nil || lifecycleApp == nil || runtimeDriver == nil {
		t.Fatalf("restart lifecycle composition = %T, %T, %v", lifecycleApp, runtimeDriver, err)
	}
	defer func() { _ = closeSecondLifecycle() }()
	terminalApp, closeSecondTerminal, err := newProviderTerminalApplication(ctx, terminalConfig, lifecycleApp, runtimeDriver)
	if err != nil || terminalApp == nil {
		t.Fatalf("restart terminal composition = %T, %v", terminalApp, err)
	}
	defer func() { _ = closeSecondTerminal() }()

	recovered, err := terminalApp.GetHandoff(ctx, open.OperationID)
	if err != nil || recovered.InternalEndpointReference != handoff.InternalEndpointReference || recovered.ConnectionGeneration != handoff.ConnectionGeneration {
		t.Fatalf("recovered terminal handoff = %#v, %v", recovered, err)
	}
	f7GatewayTerminalRoundTrip(t, terminalApp, recovered, "P2F7-RECONNECT:retained", "printf 'P2F7-RECONNECT:%s\\n' \"$P2F7_VALUE\"\n")
}

func f7LifecycleConfig(dataRoot, image, controllerID string) config.ProviderLifecycleConfig {
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid = 65532
	}
	if gid == 0 {
		gid = 65532
	}
	return config.ProviderLifecycleConfig{
		Enabled: true, Driver: config.ProviderLifecycleDockerDriver,
		Repository: config.ProviderLifecycleRepositoryConfig{
			Driver: config.ProviderLifecycleFileRepository,
			File:   config.ProviderLifecycleRepositoryFileConfig{Path: filepath.Join(dataRoot, "lifecycle.json")},
		},
		Docker: config.ProviderLifecycleDockerConfig{
			Host: os.Getenv("DOCKER_HOST"), Image: image, PullPolicy: string(lifecycledocker.PullIfNotPresent),
			MemoryBytes: 128 << 20, NanoCPUs: 250_000_000, PidsLimit: 64, TmpfsBytes: 32 << 20,
			OperationTimeoutSeconds: 30, PullTimeoutSeconds: 90, StopTimeoutSeconds: 5,
			User:     fmt.Sprintf("%d:%d", uid, gid),
			Command:  []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"},
			DataRoot: dataRoot, Namespace: "provider-f7", ControllerID: controllerID,
		},
	}
}

func f7TerminalConfig(dataRoot string) config.ProviderTerminalConfig {
	return config.ProviderTerminalConfig{
		Enabled:               true,
		SessionRepositoryFile: filepath.Join(dataRoot, "terminal-sessions.json"),
		ReferenceRegistryFile: filepath.Join(dataRoot, "terminal-references.json"),
		RuntimeProfileID:      lifecycledocker.CodingShellRuntimeProfile, CapabilityProfileID: "coding-shell-terminal-v1",
		BrokerPath: "/workspace/.sandbox-runtime/bin/terminal-broker", ShellPath: "/bin/sh",
		MaxSessionsPerSandbox: 2, MaxSessionsPerController: 4, ShutdownCleanupSeconds: 5,
	}
}

func f7CreateRequest(now time.Time, sandboxID string) lifecycle.CreateRequest {
	return lifecycle.CreateRequest{
		OperationID: "f7-create", AttemptID: "f7-create-attempt", FencingToken: 1,
		IdempotencyKey: "f7-create-key", RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: now.Add(2 * time.Minute),
		Spec: lifecycle.SandboxSpec{
			SandboxID: sandboxID, TenantID: "tenant-f7", WorkOrderID: "work-order-f7", WorkspaceID: "workspace-f7",
			ProviderRevisionID: "provider-revision-f7", RuntimeProfile: lifecycledocker.CodingShellRuntimeProfile,
			SandboxSlotKey: "slots/f7", LeaseExpiresAt: now.Add(3 * time.Minute),
		},
	}
}

func f7SessionOpenRequest(now time.Time, sandboxID string) session.OpenRequest {
	return session.OpenRequest{
		SandboxID: sandboxID, ProviderRevisionID: "provider-revision-f7",
		OperationID: "f7-terminal", AttemptID: "f7-terminal-attempt", FencingToken: 1,
		IdempotencyKey: "f7-terminal-key", RequestDigest: "sha256:" + strings.Repeat("b", 64),
		Deadline: now.Add(2 * time.Minute), ExpectedGeneration: 1, RuntimeSessionID: "f7-session",
		RuntimeType: session.RuntimeTerminal, CapabilityProfileID: "coding-shell-terminal-v1", ExpiresAt: now.Add(2 * time.Minute),
	}
}

func f7BrokerHostPath(dataRoot, sandboxID string) string {
	sum := sha256.Sum256([]byte(sandboxID))
	return filepath.Join(dataRoot, hex.EncodeToString(sum[:]), "workspace", ".sandbox-runtime", "bin", "terminal-broker")
}

func f7BuildTerminalBroker(ctx context.Context, t *testing.T, destination string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", destination, "./cmd/terminal-broker")
	command.Dir = repositoryRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOCACHE="+filepath.Join(t.TempDir(), "go-cache"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Linux terminal broker: %v: %s", err, output)
	}
	if err := os.Chmod(destination, 0o755); err != nil {
		t.Fatal(err)
	}
}

func f7GatewayTerminalRoundTrip(t *testing.T, terminalApp *providerTerminalApplication, handoff sessionapplication.Handoff, marker, command string) {
	t.Helper()
	resolver, err := sessionreference.NewResolver(terminalApp.references, terminalApp.authority, terminalApp.runtime, systemAdmissionClock{})
	if err != nil {
		t.Fatalf("construct persisted terminal resolver: %v", err)
	}
	request := gateway.ConnectRequest{
		CallerID: "caller-f7", TenantID: "tenant-f7", SandboxID: handoff.SandboxID,
		RuntimeSessionID: handoff.RuntimeSessionID, CapabilityProfileID: handoff.CapabilityProfileID,
		HandoffReference: handoff.InternalEndpointReference,
	}
	recorder := &f7GatewayRecorder{}
	service, err := gatewaycomposition.New(gatewaycomposition.Options{
		Authorizer:  f7GatewayAuthorizer{expiresAt: handoff.ExpiresAt, connectionGeneration: handoff.ConnectionGeneration},
		Revocations: gateway.NewMemoryRevocations(),
		Recorder:    recorder, Resolver: resolver,
		WebSocket: adapter.WebSocketOptions{Admission: func(context.Context, *http.Request) error { return nil }},
	})
	if err != nil {
		t.Fatalf("compose caller-owned test Gateway: %v", err)
	}
	results := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, httpRequest *http.Request) {
		results <- service.Serve(httpRequest.Context(), response, httpRequest, request)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial local Gateway: %v", err)
	}
	if err := connection.Write(ctx, websocket.MessageBinary, []byte(command)); err != nil {
		_ = connection.CloseNow()
		t.Fatalf("write terminal command through Gateway: %v", err)
	}
	var output strings.Builder
	for output.Len() < 64<<10 {
		messageType, payload, readErr := connection.Read(ctx)
		if readErr != nil {
			_ = connection.CloseNow()
			t.Fatalf("read terminal output through Gateway: %v (%q)", readErr, output.String())
		}
		if messageType != websocket.MessageBinary {
			_ = connection.CloseNow()
			t.Fatalf("Gateway message type = %v, want binary", messageType)
		}
		output.Write(payload)
		if strings.Contains(output.String(), marker) {
			break
		}
	}
	if !strings.Contains(output.String(), marker) {
		_ = connection.CloseNow()
		t.Fatalf("terminal output lacks %q: %q", marker, output.String())
	}
	if err := connection.CloseNow(); err != nil {
		t.Fatalf("close local Gateway client: %v", err)
	}
	select {
	case serveErr := <-results:
		if serveErr != nil {
			t.Fatalf("serve local Gateway: %v", serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("local Gateway did not stop after client disconnect")
	}
	if !recorder.has(gateway.AuditAuthorized) || !recorder.has(gateway.AuditConnected) {
		t.Fatalf("Gateway audit events = %#v", recorder.eventsCopy())
	}
}

type f7GatewayAuthorizer struct {
	expiresAt            time.Time
	connectionGeneration int64
}

func (a f7GatewayAuthorizer) Authorize(_ context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
	return gateway.Grant{
		GrantID: "grant-f7", CallerID: request.CallerID, TenantID: request.TenantID, SandboxID: request.SandboxID,
		RuntimeSessionID: request.RuntimeSessionID, CapabilityProfileID: request.CapabilityProfileID,
		HandoffReference: request.HandoffReference, ConnectionGeneration: a.connectionGeneration, ExpiresAt: a.expiresAt,
	}, nil
}

type f7GatewayRecorder struct {
	mu     sync.Mutex
	events []gateway.AuditEvent
}

func (r *f7GatewayRecorder) Record(_ context.Context, event gateway.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *f7GatewayRecorder) has(want gateway.AuditEventType) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, event := range r.events {
		if event.Type == want {
			return true
		}
	}
	return false
}

func (r *f7GatewayRecorder) eventsCopy() []gateway.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]gateway.AuditEvent(nil), r.events...)
}

func f7IntegrationPinnedImage(ctx context.Context, t *testing.T) string {
	t.Helper()
	configured := os.Getenv("SANDBOX_RUNTIME_PROVIDER_DOCKER_TEST_IMAGE")
	if configured != "" && f7IsSHA256PinnedImage(configured) {
		return configured
	}
	image := configured
	if image == "" {
		image = "alpine:3.23"
	}
	apiClient, err := client.New(client.FromEnv)
	if err != nil {
		t.Fatalf("create image preparation client: %v", err)
	}
	defer apiClient.Close()
	if _, err := apiClient.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		t.Fatalf("ping Docker Engine: %v", err)
	}
	pull, err := apiClient.ImagePull(ctx, image, client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull integration image %q: %v", image, err)
	}
	if err := pull.Wait(ctx); err != nil {
		_ = pull.Close()
		t.Fatalf("wait for integration image %q: %v", image, err)
	}
	if err := pull.Close(); err != nil {
		t.Fatalf("close integration image response: %v", err)
	}
	inspection, err := apiClient.ImageInspect(ctx, image)
	if err != nil {
		t.Fatalf("inspect integration image %q: %v", image, err)
	}
	for _, digest := range inspection.RepoDigests {
		if f7IsSHA256PinnedImage(digest) {
			return digest
		}
	}
	t.Fatalf("image %q has no sha256 repository digest", image)
	return ""
}

func f7IsSHA256PinnedImage(image string) bool {
	prefix := strings.LastIndex(image, "@sha256:")
	if prefix <= 0 || len(image) != prefix+len("@sha256:")+64 {
		return false
	}
	for _, value := range image[prefix+len("@sha256:"):] {
		if !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')) {
			return false
		}
	}
	return true
}

func f7RemoveSandbox(t *testing.T, lifecycleConfig config.ProviderLifecycleConfig, sandboxID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config := lifecycleConfig.Docker
	driver, err := lifecycledocker.New(ctx, lifecycledocker.Options{
		Host: config.Host, Image: config.Image, PullPolicy: lifecycledocker.PullPolicy(config.PullPolicy),
		MemoryBytes: config.MemoryBytes, NanoCPUs: config.NanoCPUs, PidsLimit: config.PidsLimit, TmpfsBytes: config.TmpfsBytes,
		OperationTimeoutSeconds: config.OperationTimeoutSeconds, PullTimeoutSeconds: config.PullTimeoutSeconds,
		StopTimeoutSeconds: config.StopTimeoutSeconds, User: config.User, Command: config.Command,
		DataRoot: config.DataRoot, Namespace: config.Namespace, ControllerID: config.ControllerID,
	})
	if err != nil {
		t.Errorf("construct terminal integration cleanup driver: %v", err)
		return
	}
	defer driver.Close()
	if err := driver.Remove(ctx, sandboxID); err != nil {
		t.Errorf("remove terminal integration sandbox: %v", err)
	}
}
