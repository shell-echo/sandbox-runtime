//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopremote "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/remote"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type desktopGateState struct {
	client  *protectedClient
	handoff providerv1.DesktopSessionHandoff
	open    desktophandoff.OpenRequest
}

func runProviderDesktopScenarios(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	client := newGateProtectedClient(environment)
	createDesktopSandbox(t, client, environment)

	first := openDesktopSession(t, client, "desktop-session-phase6-1", "desktop-open-1", "desktop-open-attempt-1", 2)
	first.open = desktopPrivateOpen(t, first.handoff, "desktop-media-open-1")
	media, acceptedFirstOpen := openDesktopMedia(t, ctx, environment, first.open)
	first.open = acceptedFirstOpen
	assertDesktopMediaAndInput(t, ctx, environment, media, 1, "initial Desktop session")
	waitHTTPStatus(t, environment.roles["desktop"], http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.desktopProbe), http.StatusNoContent, 30*time.Second)
	markReady(environment.roles["desktop"])

	replay := dialDesktopMedia(t, ctx, environment, first.open)
	assertDesktopRejected(t, ctx, replay, first.open.RequestID)

	drift := first.open
	drift.RequestID = "desktop-media-drift-1"
	drift.ConnectionGeneration++
	drift.ConnectionEpoch = "desktop-epoch-drift"
	drift.ControllerFence = strings.Repeat("d", handoff.MinFenceBytes)
	drift.AuthorityDigest = desktophandoff.AuthorityDigest(drift)
	drift.RequestDigest = desktophandoff.RequestDigest(drift)
	driftConnection := dialDesktopMedia(t, ctx, environment, drift)
	assertDesktopRejected(t, ctx, driftConnection, drift.RequestID)

	policyDrift := first.open
	policyDrift.RequestID = "desktop-media-policy-drift-1"
	policyDrift.MediaPolicy.RecordingMode = "required"
	policyDrift.MediaPolicy.MaxRecordingBytes = desktopmedia.DefaultMaxRecordingBytes
	policyDrift.AuthorityDigest = desktophandoff.AuthorityDigest(policyDrift)
	policyDrift.RequestDigest = desktophandoff.RequestDigest(policyDrift)
	policyConnection := dialDesktopMedia(t, ctx, environment, policyDrift)
	assertDesktopRejected(t, ctx, policyConnection, policyDrift.RequestID)

	_ = media.Close(websocket.StatusNormalClosure, "restart real broker session")
	var restartedBrokerMedia *websocket.Conn
	attempt := 0
	waitFor(t, 10*time.Second, "Desktop executor session release", func() bool {
		attempt++
		requestID := fmt.Sprintf("desktop-media-open-2-%d", attempt)
		connection := dialDesktopMedia(t, ctx, environment, withDesktopRequestID(first.open, requestID))
		response, accepted := readDesktopOpenResponse(ctx, connection)
		if !accepted {
			connection.CloseNow()
			return false
		}
		if response.RequestID != requestID {
			connection.CloseNow()
			t.Fatalf("Desktop broker restart response=%#v", response)
		}
		restartedBrokerMedia = connection
		return true
	})
	assertDesktopMediaAndInput(t, ctx, environment, restartedBrokerMedia, 2, "broker session restart")
	_ = restartedBrokerMedia.Close(websocket.StatusNormalClosure, "broker restart verified")

	stopGateProcess(t, environment.roles["desktop"], 15*time.Second)
	restartedDesktop := startConfiguredRole(t, ctx, environment, "desktop", environment.paths.desktopConfig, "desktop", "serve")
	waitHTTPStatus(t, restartedDesktop, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.desktopProbe), http.StatusNoContent, 30*time.Second)
	markReady(restartedDesktop)
	restartedMedia, _ := openDesktopMedia(t, ctx, environment, withDesktopRequestID(first.open, "desktop-media-after-executor-restart"))
	assertDesktopMediaAndInput(t, ctx, environment, restartedMedia, 3, "Desktop role restart")
	_ = restartedMedia.Close(websocket.StatusNormalClosure, "executor restart verified")

	closeDesktopSession(t, client, first.handoff, "desktop-close-1", "desktop-close-attempt-1", 3)
	waitForDesktopResources(t, environment, 0, 45*time.Second)

	restartProvider(t, ctx, environment)
	second := openDesktopSession(t, client, "desktop-session-phase6-2", "desktop-open-2", "desktop-open-attempt-2", 4)
	second.open = desktopPrivateOpen(t, second.handoff, "desktop-media-after-provider-restart")
	secondMedia, acceptedSecondOpen := openDesktopMedia(t, ctx, environment, second.open)
	second.open = acceptedSecondOpen
	assertDesktopMediaAndInput(t, ctx, environment, secondMedia, 4, "Provider restart")
	_ = secondMedia.Close(websocket.StatusNormalClosure, "Provider restart verified")
	closeDesktopSession(t, client, second.handoff, "desktop-close-2", "desktop-close-attempt-2", 5)
	waitForDesktopResources(t, environment, 0, 45*time.Second)
}

func newGateProtectedClient(environment *gateEnvironment) *protectedClient {
	return &protectedClient{
		client: providerClient(environment), origin: fmt.Sprintf("https://127.0.0.1:%d", environment.ports.provider),
		privateKey: environment.admissionKey, issuer: providerIssuer, keyID: providerKeyID, caller: providerCaller,
		audience: providerAudience, revision: providerRevision, tenantID: gateTenantID, workOrder: gateWorkOrderID,
	}
}

func createDesktopSandbox(t *testing.T, client *protectedClient, environment *gateEnvironment) {
	t.Helper()
	now := time.Now().UTC()
	deadline := now.Add(2 * time.Minute)
	architecture := runtime.GOARCH
	body := map[string]any{
		"operation_id": "desktop-create-1", "attempt_id": "desktop-create-attempt-1", "fencing_token": int64(1),
		"idempotency_key": "phase6-create-desktop-1", "deadline_at": deadline.Format(time.RFC3339Nano), "protocol_version": "v1",
		"spec": map[string]any{
			"sandbox_id": gateSandboxID, "tenant_id": gateTenantID, "work_order_id": gateWorkOrderID,
			"workspace_id": "workspace-phase6-slice4", "branch_id": "branch-phase6-slice4",
			"provider_resolution_id": "provider-resolution-phase6-slice4", "provider_revision_id": providerRevision,
			"image":                 map[string]any{"reference": "local.phase6.invalid/desktop", "digest": environment.candidate.ImageDigest, "architecture": architecture},
			"runtime_profile":       "sandbox-runtime-desktop-v1",
			"resources":             map[string]any{"cpu_millis": int64(1000), "memory_bytes": int64(1 << 30), "ephemeral_storage_bytes": int64(1 << 30), "workspace_bytes": int64(256 << 20), "pids_limit": int64(256)},
			"required_capabilities": []map[string]any{{"id": "sandbox.desktop", "version": "1.0.0", "profile": "desktop-v1"}},
			"network":               map[string]any{"mode": "restricted", "policy_reference": "desktop-egress-policy-1", "egress_gateway_required": true},
			"workspace":             map[string]any{"mode": "ephemeral", "base_revision_id": "workspace-revision-phase6", "base_revision_digest": sha256Digest([]byte("phase6-workspace")), "base_workspace_head_version": int64(0), "commit_mode": "read_only", "mount_path": "/workspace"},
			"lease":                 map[string]any{"expires_at": now.Add(20 * time.Minute).Format(time.RFC3339Nano), "max_extension_seconds": int64(600)},
			"placement_constraints": map[string]any{"resource_class": "desktop", "architecture": architecture},
			"security":              map[string]any{"privilege_level": "unprivileged", "root_filesystem": "read_only", "service_account_mode": "none", "allow_privilege_escalation": false, "host_namespace_access": false, "seccomp_profile": "runtime-default"},
			"sandbox_slot_key":      "desktop",
		},
	}
	status, document := client.do(t, protectedRequest{Method: http.MethodPost, Path: "/v1/sandboxes", Operation: admission.OperationCreate, SandboxID: gateSandboxID, OperationID: "desktop-create-1", AttemptID: "desktop-create-attempt-1", Fence: 1, Deadline: deadline, Body: body})
	if status != http.StatusAccepted {
		t.Fatalf("Desktop sandbox create status=%d body=%s", status, document)
	}
	var operation providerv1.Operation
	if json.Unmarshal(document, &operation) != nil || operation.OperationID != "desktop-create-1" {
		t.Fatalf("Desktop create operation=%s", document)
	}
	waitProviderOperation(t, client, gateSandboxID, "desktop-create-1", "desktop-create-attempt-1", 1, providerv1.OperationSucceeded)
}

func openDesktopSession(t *testing.T, client *protectedClient, sessionID, operationID, attemptID string, fence int64) desktopGateState {
	t.Helper()
	now := time.Now().UTC()
	deadline, expires := now.Add(2*time.Minute), now.Add(90*time.Second)
	body := map[string]any{
		"operation_id": operationID, "attempt_id": attemptID, "fencing_token": fence,
		"idempotency_key": operationID + "-idempotency", "deadline_at": deadline.Format(time.RFC3339Nano),
		"expected_generation": int64(1), "desktop_session_id": sessionID,
		"capability_profile_id": "desktop-v1", "expires_at": expires.Format(time.RFC3339Nano),
	}
	status, document := client.do(t, protectedRequest{Method: http.MethodPost, Path: "/v1/sandboxes/" + gateSandboxID + "/desktop-sessions", Operation: admission.OperationOpenDesktopSession, SandboxID: gateSandboxID, OperationID: operationID, AttemptID: attemptID, Fence: fence, Deadline: deadline, Body: body})
	if status != http.StatusAccepted {
		t.Fatalf("Desktop session open status=%d body=%s", status, document)
	}
	var operation providerv1.Operation
	if json.Unmarshal(document, &operation) != nil || operation.OperationID != operationID || operation.Status != providerv1.OperationSucceeded {
		t.Fatalf("Desktop session open operation=%s", document)
	}
	status, document = client.do(t, protectedRequest{Method: http.MethodGet, Path: "/v1/operations/" + operationID + "/desktop-session", Operation: admission.OperationReadDesktopSession, SandboxID: gateSandboxID, OperationID: operationID, AttemptID: attemptID, Fence: fence, Deadline: time.Now().UTC().Add(time.Minute)})
	if status != http.StatusOK {
		t.Fatalf("Desktop handoff status=%d body=%s", status, document)
	}
	var result providerv1.DesktopSessionHandoff
	if json.Unmarshal(document, &result) != nil || result.DesktopSessionID != sessionID || result.InternalEndpointReference == "" || result.ConnectionGeneration < 1 {
		t.Fatalf("Desktop handoff=%s", document)
	}
	return desktopGateState{client: client, handoff: result}
}

func desktopPrivateOpen(t *testing.T, handoffDocument providerv1.DesktopSessionHandoff, requestID string) desktophandoff.OpenRequest {
	t.Helper()
	handoffExpiry, err := time.Parse(time.RFC3339Nano, handoffDocument.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	authorityExpiry := time.Now().UTC().Add(45 * time.Second)
	if !authorityExpiry.Before(handoffExpiry) {
		authorityExpiry = handoffExpiry.Add(-time.Second)
	}
	policy := desktopmedia.MediaPolicy{
		VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000,
		MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs,
		MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only",
	}
	open := desktophandoff.OpenRequest{
		BindingVersion: desktophandoff.BindingVersion, BindingIssuer: desktophandoff.BindingIssuer,
		Protocol: desktophandoff.ProtocolID, RequestID: requestID, Resource: desktophandoff.ResourceDesktop,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: providerRevision,
		SandboxID: handoffDocument.SandboxID, DesktopSessionID: handoffDocument.DesktopSessionID,
		CapabilityProfileID: handoffDocument.CapabilityProfileID, MediaProfileID: handoffDocument.MediaProfileID, ControlProfileID: handoffDocument.ControlProfileID,
		HandoffReference: handoffDocument.InternalEndpointReference, HandoffDigest: desktophandoff.ReferenceDigest(handoffDocument.InternalEndpointReference),
		ConnectionGeneration: handoffDocument.ConnectionGeneration, ConnectionEpoch: "desktop-epoch-1",
		AuthorityExpiresAt: authorityExpiry.Format(time.RFC3339Nano), HandoffExpiresAt: handoffExpiry.Format(time.RFC3339Nano),
		ControllerFence: strings.Repeat("c", handoff.MinFenceBytes), MediaPolicy: policy,
	}
	open.AuthorityDigest = desktophandoff.AuthorityDigest(open)
	open.RequestDigest = desktophandoff.RequestDigest(open)
	if err := open.Validate(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return open
}

func withDesktopRequestID(open desktophandoff.OpenRequest, requestID string) desktophandoff.OpenRequest {
	open.RequestID = requestID
	return open
}

func dialDesktopMedia(t *testing.T, ctx context.Context, environment *gateEnvironment, open desktophandoff.OpenRequest) *websocket.Conn {
	t.Helper()
	connection, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://127.0.0.1:%d/desktop", environment.ports.providerPrivate), &websocket.DialOptions{HTTPClient: providerPrivateClient(environment), Subprotocols: []string{desktophandoff.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(open)
	if err != nil || connection.Write(ctx, websocket.MessageText, document) != nil {
		connection.CloseNow()
		t.Fatalf("write Desktop private open: %v", err)
	}
	return connection
}

func openDesktopMedia(t *testing.T, ctx context.Context, environment *gateEnvironment, open desktophandoff.OpenRequest) (*websocket.Conn, desktophandoff.OpenRequest) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	baseRequestID := open.RequestID
	lastResponse := desktophandoff.OpenResponse{}
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		candidate := open
		if attempt > 0 {
			candidate.RequestID = fmt.Sprintf("%s-retry-%d", baseRequestID, attempt)
		}
		connection := dialDesktopMedia(t, ctx, environment, candidate)
		response, accepted := readDesktopOpenResponse(ctx, connection)
		lastResponse = response
		if accepted && response.RequestID == candidate.RequestID {
			return connection, candidate
		}
		connection.CloseNow()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("Desktop private open remained unavailable last_response=%#v layer_diagnostics=%s diagnostics=%s", lastResponse, diagnoseDesktopLayers(ctx, environment, open), desktopGateDiagnostics(environment))
	return nil, desktophandoff.OpenRequest{}
}

func desktopGateDiagnostics(environment *gateEnvironment) string {
	containers, _ := exec.Command("docker", "ps", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4", "--format", "{{.ID}} {{.Names}} {{.Status}}").Output()
	logs := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(containers)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		output, _ := exec.Command("docker", "logs", "--tail", "40", fields[0]).CombinedOutput()
		logs = append(logs, fields[1]+":"+string(output))
	}
	dependencyLogs := make([]string, 0, len(environment.dependencies))
	for _, process := range environment.dependencies {
		dependencyLogs = append(dependencyLogs, process.name+":"+gateLog(process))
	}
	return fmt.Sprintf("provider_log=%q desktop_log=%q dependency_logs=%q containers=%q container_logs=%q", gateLog(environment.roles["provider"]), gateLog(environment.roles["desktop"]), dependencyLogs, containers, logs)
}

func diagnoseDesktopLayers(ctx context.Context, environment *gateEnvironment, open desktophandoff.OpenRequest) string {
	state, err := providerpostgres.New(environment.providerDB.admin, 2*time.Second)
	if err != nil {
		return "provider-state:" + err.Error()
	}
	references, err := providerpostgres.NewDesktopReferenceStore(state)
	if err != nil {
		return "reference-store:" + err.Error()
	}
	record, err := references.Get(ctx, open.HandoffReference)
	if err != nil {
		return "reference-read:" + err.Error()
	}
	if record.Binding == nil {
		return "binding:not-persisted"
	}
	key, err := os.ReadFile(environment.paths.bridgeKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return "bridge-key:unavailable"
	}
	binding := record.Binding
	authority := providerdesktop.MediaAuthority{
		TenantBindingDigest: binding.TenantBindingDigest, ProviderRevisionID: binding.ProviderRevisionID,
		SandboxID: binding.SandboxID, DesktopSessionID: binding.DesktopSessionID,
		HandoffReference: binding.HandoffReference, HandoffReferenceDigest: desktophandoff.ReferenceDigest(binding.HandoffReference),
		AllocationReference: record.Receipt.Reference, ConnectionGeneration: binding.ConnectionGeneration,
		ConnectionEpoch: binding.ConnectionEpoch, ControllerFence: binding.ControllerFence,
		MediaProfileID: desktophandoff.MediaProfileID, ControlProfileID: desktophandoff.ControlProfileID,
		AuthorityExpiresAt: binding.AuthorityExpiresAt, HandoffExpiresAt: binding.HandoffExpiresAt,
	}
	attachment := providerdesktop.Attachment{DesktopSessionID: binding.DesktopSessionID, ConnectionGeneration: binding.ConnectionGeneration, MediaProfileID: desktophandoff.MediaProfileID, ControlProfileID: desktophandoff.ControlProfileID}
	type target struct {
		name, endpoint, serverName, certificate, privateKey string
	}
	targets := []target{
		{"desktop-role", fmt.Sprintf("wss://127.0.0.1:%d/executor", environment.ports.desktop), "desktop-role.phase6.test", environment.tls.providerExecutorCert, environment.tls.providerExecutorKey},
		{"desktop-backend", fmt.Sprintf("wss://127.0.0.1:%d/executor", environment.ports.desktopBackend), "desktop-backend.phase6.test", environment.tls.desktopRoleClientCert, environment.tls.desktopRoleClientKey},
	}
	results := make([]string, 0, len(targets))
	for _, target := range targets {
		client := environment.tls.ca.client(target.serverName, mustLoadCertificateForDiagnostic(target.certificate, target.privateKey))
		driver, driverErr := desktopremote.New(desktopremote.Options{URL: target.endpoint, HTTPClient: client, OperationTimeout: 10 * time.Second, BridgeKeyID: "provider-desktop-v2", ExecutorIdentity: "executor-desktop-1", BridgePrivateKey: ed25519.PrivateKey(key)})
		if driverErr != nil {
			results = append(results, target.name+":construct-error")
			continue
		}
		diagnosticContext, cancel := context.WithTimeout(ctx, 12*time.Second)
		session, openErr := driver.OpenMedia(diagnosticContext, authority, attachment, binding.MediaPolicy)
		cancel()
		if openErr != nil {
			results = append(results, target.name+":rejected")
			continue
		}
		_ = session.Close()
		results = append(results, target.name+":accepted")
		break
	}
	return strings.Join(results, ",")
}

func mustLoadCertificateForDiagnostic(certificatePath, privateKeyPath string) tls.Certificate {
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		return tls.Certificate{}
	}
	return certificate
}

func readDesktopOpenResponse(ctx context.Context, connection *websocket.Conn) (desktophandoff.OpenResponse, bool) {
	readContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	messageType, document, err := connection.Read(readContext)
	if err != nil || messageType != websocket.MessageText {
		return desktophandoff.OpenResponse{}, false
	}
	var response desktophandoff.OpenResponse
	if handoff.Decode(document, &response) != nil || response.Validate() != nil {
		return desktophandoff.OpenResponse{}, false
	}
	return response, response.Status == desktophandoff.StatusAccepted
}

func assertDesktopRejected(t *testing.T, ctx context.Context, connection *websocket.Conn, requestID string) {
	t.Helper()
	defer connection.CloseNow()
	response, accepted := readDesktopOpenResponse(ctx, connection)
	if accepted || response.RequestID != requestID || response.Status != desktophandoff.StatusRejected {
		t.Fatalf("Desktop request %s was not rejected: %#v", requestID, response)
	}
}

func assertDesktopMediaAndInput(t *testing.T, ctx context.Context, environment *gateEnvironment, connection *websocket.Conn, requestID int64, stage string) {
	t.Helper()
	readContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for {
		messageType, payload, err := connection.Read(readContext)
		if err != nil {
			t.Fatalf("%s read initial Desktop media: %v; diagnostics=%s", stage, err, desktopGateDiagnostics(environment))
		}
		if messageType == websocket.MessageBinary && len(payload) >= 13 && payload[0] == desktopmedia.VideoPacket && payload[1]>>6 == 2 {
			t.Logf("phase6 Desktop milestone: %s emitted RTP media", stage)
			break
		}
	}
	command := desktopmedia.Command{Type: "input", RequestID: requestID, Input: &desktopmedia.Input{Sequence: requestID, Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "phase6-control-lease", ControlFence: requestID}}
	document, err := json.Marshal(command)
	if err != nil || connection.Write(ctx, websocket.MessageText, document) != nil {
		t.Fatalf("write Desktop input: %v", err)
	}
	for {
		messageType, payload, err := connection.Read(readContext)
		if err != nil {
			t.Fatalf("%s read Desktop input result: %v; diagnostics=%s", stage, err, desktopGateDiagnostics(environment))
		}
		if messageType != websocket.MessageText {
			continue
		}
		var result desktopmedia.Result
		if json.Unmarshal(payload, &result) == nil && result.Type == "result" && result.RequestID == requestID && result.OK {
			t.Logf("phase6 Desktop milestone: %s accepted input", stage)
			return
		}
		t.Fatalf("Desktop input result=%s", payload)
	}
}

func closeDesktopSession(t *testing.T, client *protectedClient, handoffDocument providerv1.DesktopSessionHandoff, operationID, attemptID string, fence int64) {
	t.Helper()
	deadline := time.Now().UTC().Add(2 * time.Minute)
	body := map[string]any{
		"operation_id": operationID, "attempt_id": attemptID, "fencing_token": fence,
		"idempotency_key": operationID + "-idempotency", "deadline_at": deadline.Format(time.RFC3339Nano),
		"expected_generation": int64(1), "desktop_session_id": handoffDocument.DesktopSessionID,
		"connection_generation": handoffDocument.ConnectionGeneration, "reason": "caller_complete",
	}
	path := "/v1/sandboxes/" + gateSandboxID + "/desktop-sessions/" + handoffDocument.DesktopSessionID + ":close"
	status, document := client.do(t, protectedRequest{Method: http.MethodPost, Path: path, Operation: admission.OperationCloseDesktopSession, SandboxID: gateSandboxID, OperationID: operationID, AttemptID: attemptID, Fence: fence, Deadline: deadline, Body: body})
	if status != http.StatusAccepted {
		t.Fatalf("Desktop close status=%d body=%s", status, document)
	}
	var operation providerv1.Operation
	if json.Unmarshal(document, &operation) != nil || operation.Status != providerv1.OperationSucceeded {
		t.Fatalf("Desktop close operation=%s", document)
	}
}

func waitProviderOperation(t *testing.T, client *protectedClient, sandboxID, operationID, attemptID string, fence int64, wanted providerv1.OperationState) providerv1.Operation {
	t.Helper()
	var result providerv1.Operation
	waitFor(t, 45*time.Second, "Provider operation "+operationID, func() bool {
		status, document := client.do(t, protectedRequest{Method: http.MethodGet, Path: "/v1/operations/" + operationID, Operation: admission.OperationReadOperation, SandboxID: sandboxID, OperationID: operationID, AttemptID: attemptID, Fence: fence, Deadline: time.Now().UTC().Add(time.Minute)})
		if status != http.StatusOK || json.Unmarshal(document, &result) != nil {
			return false
		}
		if result.Status == providerv1.OperationFailed || result.Status == providerv1.OperationOutcomeUnknown || result.Status == providerv1.OperationCancelled {
			t.Fatalf("Provider operation %s terminal status=%s body=%s", operationID, result.Status, document)
		}
		return result.Status == wanted
	})
	return result
}

func restartProvider(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	stopGateProcess(t, environment.roles["provider"], 20*time.Second)
	waitFor(t, 10*time.Second, "old Provider broker mux removal", func() bool {
		_, err := os.Lstat(environment.paths.brokerSocket)
		return errors.Is(err, os.ErrNotExist)
	})
	provider := startConfiguredRole(t, ctx, environment, "provider", environment.paths.providerConfig, "provider", "serve")
	waitHTTPStatus(t, provider, http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.providerProbe), http.StatusNoContent, 45*time.Second)
	markReady(provider)
	waitFor(t, 30*time.Second, "restarted Provider Desktop broker mux socket", func() bool {
		info, err := os.Lstat(environment.paths.brokerSocket)
		return err == nil && info.Mode()&os.ModeSocket != 0
	})
	waitHTTPStatus(t, environment.roles["gateway"], http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.gatewayProbe), http.StatusNoContent, 30*time.Second)
}

func waitForDesktopResources(t *testing.T, environment *gateEnvironment, wanted int, timeout time.Duration) {
	t.Helper()
	waitFor(t, timeout, fmt.Sprintf("Desktop resource count %d", wanted), func() bool {
		count, err := managedResourceCount(environment)
		return err == nil && count == wanted
	})
}

func managedResourceCount(environment *gateEnvironment) (int, error) {
	containerOutput, err := exec.Command("docker", "ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4").Output()
	if err != nil {
		return 0, err
	}
	count := len(strings.Fields(string(containerOutput)))
	networkOutput, err := exec.Command("docker", "network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4").Output()
	if err != nil {
		return 0, err
	}
	for _, identifier := range strings.Fields(string(networkOutput)) {
		name, inspectErr := exec.Command("docker", "network", "inspect", "--format", "{{.Name}}", identifier).Output()
		if inspectErr != nil {
			return 0, inspectErr
		}
		if strings.TrimSpace(string(name)) != environment.uplinkNetwork {
			count++
		}
	}
	return count, nil
}
