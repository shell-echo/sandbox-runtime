//go:build phase4browsergate

package productphase4gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/productphase4evidence"
	"github.com/shell-echo/sandbox-runtime/product"
	productprovider "github.com/shell-echo/sandbox-runtime/product/adapter/provider"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	releaseOwnerBearer   = "phase4-release-owner-bearer-00000000000001"
	releaseForeignBearer = "phase4-release-foreign-bearer-0000000001"
	releaseOrigin        = "https://product.example.test"
)

func TestProductPhase4BrowserReleaseGate(t *testing.T) { //nolint:cyclop
	if os.Getenv(phase4NodeRole) != "" {
		t.Skip("parent-only release gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	directory := t.TempDir()
	postgresName := fmt.Sprintf("codex-product-phase4-postgres-%d", os.Getpid())
	valkeyName := fmt.Sprintf("codex-product-phase4-valkey-%d", os.Getpid())
	dsn, removePostgres := startReleasePostgres(t, ctx, postgresName)
	redisAddress, removeValkey := startReleaseValkey(t, ctx, valkeyName)
	containersRemoved := false
	defer func() {
		if !containersRemoved {
			removeValkey()
			removePostgres()
		}
	}()

	_, signingKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := nodeConfig{
		ProviderAddress: freeAddress(t), ProviderAPI: freeAddress(t), GatewayAddress: freeAddress(t), ProductAddress: freeAddress(t),
		DSN: dsn, RedisAddress: redisAddress, ProviderSigning: base64.RawStdEncoding.EncodeToString(signingKey),
		GrantKey: base64.RawStdEncoding.EncodeToString(releaseRandom(t, 32)), RecordingKey: base64.RawStdEncoding.EncodeToString(releaseRandom(t, 32)),
		RecordingRoot: filepath.Join(directory, "recording-objects"), GateKey: base64.RawURLEncoding.EncodeToString(releaseRandom(t, 32)),
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	}
	if err := os.Mkdir(config.RecordingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	writeNodeCertificates(t, directory, &config)
	configPath := filepath.Join(directory, "release-nodes.json")
	releaseWriteConfig(t, configPath, config)

	nodes := make([]*childNode, 0, 4)
	stopAll := func() bool {
		ok := true
		for index := len(nodes) - 1; index >= 0; index-- {
			if !releaseStopNode(nodes[index]) {
				ok = false
			}
		}
		nodes = nil
		return ok
	}
	defer stopAll()

	providerNode := startNode(t, "release-provider", configPath)
	nodes = append(nodes, providerNode)
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.ProviderAPI+"/healthz", http.StatusOK, providerNode)
	browserNode := startNode(t, "release-browser", configPath)
	nodes = append(nodes, browserNode)
	browserHealth := mutualTLSClient(t, config.CACertificate, config.GatewayCert, config.GatewayKey, "phase4-provider")
	waitHTTP(t, ctx, browserHealth, "https://"+config.ProviderAddress+"/healthz", http.StatusOK, browserNode)
	gatewayNode := startNode(t, "release-gateway", configPath)
	nodes = append(nodes, gatewayNode)
	publicClient := tlsClient(t, config.CACertificate, "phase4-edge")
	waitHTTP(t, ctx, publicClient, "https://"+config.GatewayAddress+"/healthz", http.StatusOK, gatewayNode)
	productNode := startNode(t, "release-product", configPath)
	nodes = append(nodes, productNode)
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.ProductAddress+"/healthz", http.StatusOK, productNode)
	productBase := "http://" + config.ProductAddress

	response := releaseAPI(t, http.MethodPost, productBase+"/api/v1/workspaces", "Bearer invalid", "bad-auth", `{}`)
	releaseRequireStatus(t, response, http.StatusUnauthorized)

	create := releaseAPI(t, http.MethodPost, productBase+"/api/v1/workspaces", "Bearer "+releaseOwnerBearer, "release-workspace", `{"display_name":"phase4 browser release","lifetime_seconds":3600,"primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}}`)
	releaseRequireStatus(t, create, http.StatusAccepted)
	var workspaceOperation productapiv1.ProductOperation
	releaseDecode(t, create, &workspaceOperation)
	workspace := releaseWaitWorkspace(t, productBase, workspaceOperation.WorkspaceID, "active")
	releaseSetProviderMode(t, config.ProviderAPI, "browser")
	releaseWaitCapability(t, productBase, "product.browser", "ready")

	putSlot := releaseAPI(t, http.MethodPut, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID+"/slots/browser-main", "Bearer "+releaseOwnerBearer, "release-browser-slot", fmt.Sprintf(`{"expected_workspace_version":%d,"kind":"browser","profile_id":"sandbox-runtime-browser-v1","required_capabilities":[{"capability_id":"sandbox.browser","version":"1.0.0","profile_id":"browser-v1"}],"desired_state":"ready"}`, workspace.Version))
	releaseRequireStatus(t, putSlot, http.StatusAccepted)
	var slotOperation productapiv1.ProductOperation
	releaseDecode(t, putSlot, &slotOperation)
	releaseWaitOperation(t, productBase, slotOperation.OperationID, "succeeded")
	workspace = releaseWaitSlot(t, productBase, workspace.WorkspaceID, "browser-main", "ready")

	foreign := releaseAPI(t, http.MethodGet, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID, "Bearer "+releaseForeignBearer, "", "")
	releaseRequireStatus(t, foreign, http.StatusNotFound)

	automation := releaseCreateSession(t, productBase, workspace, "browser_automation", product.SessionProfileBrowserAutomation, "metadata_only", "release-automation-1")
	releaseAutomationRejected(t, publicClient, config.GatewayAddress, strings.Repeat("x", 43))
	lease := releaseLease(t, productBase, workspace.WorkspaceID, automation.SessionID, workspace.Version, "release-controller-1")
	controlGrant := releaseGrant(t, productBase, automation, &lease, product.GrantAccessControl, "release-control-grant")
	releaseAutomationRoundTrip(t, publicClient, config.GatewayAddress, controlGrant.ConnectionTicket, false)
	releaseAutomationRejected(t, publicClient, config.GatewayAddress, controlGrant.ConnectionTicket)

	if !releaseStopNode(productNode) {
		t.Fatalf("product did not stop cleanly: %s", productNode.log.String())
	}
	nodes = releaseRemoveNode(nodes, productNode)
	productNode = startNode(t, "release-product", configPath)
	nodes = append(nodes, productNode)
	waitHTTP(t, ctx, http.DefaultClient, productBase+"/healthz", http.StatusOK, productNode)
	automation = releaseWaitSession(t, productBase, automation.SessionID, "ready")
	releaseWaitCapability(t, productBase, "product.browser", "ready")
	releaseCloseSession(t, productBase, automation, "release-automation-close")

	liveWorkspace := releaseWaitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	live := releaseCreateSession(t, productBase, liveWorkspace, "browser_live", product.SessionProfileBrowserLive, "required", "release-live-1")
	liveViewGrant := releaseGrant(t, productBase, live, nil, product.GrantAccessView, "release-live-view-grant")
	releaseLiveRejected(t, publicClient, config.GatewayAddress, liveViewGrant.ConnectionTicket)
	liveLease := releaseLease(t, productBase, liveWorkspace.WorkspaceID, live.SessionID, liveWorkspace.Version, "release-live-controller")
	liveGrant := releaseGrant(t, productBase, live, &liveLease, product.GrantAccessControl, "release-live-grant")
	releaseLiveRoundTrip(t, publicClient, config.GatewayAddress, liveGrant.ConnectionTicket)
	recordingID := releaseWaitRecording(t, productBase, workspace.WorkspaceID)
	releaseReplayRecording(t, productBase, config.GateKey, recordingID)
	live = releaseWaitSession(t, productBase, live.SessionID, "ready")
	releaseCloseSession(t, productBase, live, "release-live-close")

	if !releaseStopNode(gatewayNode) {
		t.Fatalf("gateway did not stop cleanly: %s", gatewayNode.log.String())
	}
	nodes = releaseRemoveNode(nodes, gatewayNode)
	gatewayNode = startNode(t, "release-gateway", configPath)
	nodes = append(nodes, gatewayNode)
	waitHTTP(t, ctx, publicClient, "https://"+config.GatewayAddress+"/healthz", http.StatusOK, gatewayNode)
	workspace = releaseWaitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	backpressure := releaseCreateSession(t, productBase, workspace, "browser_automation", product.SessionProfileBrowserAutomation, "disabled", "release-automation-2")
	backpressureLease := releaseLease(t, productBase, workspace.WorkspaceID, backpressure.SessionID, workspace.Version, "release-controller-2")
	backpressureGrant := releaseGrant(t, productBase, backpressure, &backpressureLease, product.GrantAccessControl, "release-backpressure-grant")
	releaseAutomationRoundTrip(t, publicClient, config.GatewayAddress, backpressureGrant.ConnectionTicket, true)

	closeResponse := releaseAPI(t, http.MethodPost, productBase+"/api/v1/sessions/"+backpressure.SessionID+":close", "Bearer "+releaseOwnerBearer, "release-session-close", fmt.Sprintf(`{"expected_version":%d,"reason":"release gate cleanup"}`, backpressure.Version))
	releaseRequireStatus(t, closeResponse, http.StatusAccepted)
	var closeOperation productapiv1.ProductOperation
	releaseDecode(t, closeResponse, &closeOperation)
	releaseWaitOperation(t, productBase, closeOperation.OperationID, "succeeded")
	releaseWaitSession(t, productBase, backpressure.SessionID, "closed")

	if !releaseStopNode(providerNode) {
		t.Fatalf("provider did not stop cleanly: %s", providerNode.log.String())
	}
	nodes = releaseRemoveNode(nodes, providerNode)
	releaseWaitCapability(t, productBase, "product.browser", "unavailable")

	if !stopAll() {
		t.Fatal("not all Phase 4 child processes were reaped")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA sandbox_runtime_product CASCADE`); err != nil {
		t.Fatal(err)
	}
	var schema *string
	if err := pool.QueryRow(ctx, `SELECT to_regnamespace('sandbox_runtime_product')::text`).Scan(&schema); err != nil || schema != nil {
		t.Fatalf("Product rows remain: schema=%v err=%v", schema, err)
	}
	pool.Close()
	redisClient := releaseRedisClient(redisAddress)
	activeKeys, err := redisClient.Keys(ctx, "sandbox-runtime:*:capacity:leases").Result()
	if err != nil {
		t.Fatal(err)
	}
	coordinationDrained := true
	for _, key := range activeKeys {
		if count := redisClient.ZCard(ctx, key).Val(); count != 0 {
			coordinationDrained = false
		}
	}
	_ = redisClient.Close()
	if !coordinationDrained {
		t.Fatal("shared capacity leases remain after Gateway shutdown")
	}
	if err := os.RemoveAll(config.RecordingRoot); err != nil {
		t.Fatal(err)
	}
	_, objectErr := os.Stat(config.RecordingRoot)
	objectRemoved := errors.Is(objectErr, os.ErrNotExist)
	removeValkey()
	removePostgres()
	containersRemoved = true
	for _, name := range []string{postgresName, valkeyName} {
		if exec.CommandContext(ctx, "docker", "inspect", name).Run() == nil {
			t.Fatalf("container %s remains after cleanup", name)
		}
	}

	evidencePath := releaseWriteEvidence(t, started, time.Now().UTC(), objectRemoved, coordinationDrained)
	manifest, err := productphase4evidence.VerifyFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Product Phase 4 Browser evidence: %s (%d scenarios, %d processes)", evidencePath, len(manifest.Scenarios), len(manifest.Processes))
}

type releaseProviderFixture struct {
	mu         sync.RWMutex
	mode       string
	operations map[string]releaseProviderOperation
}

type releaseProviderOperation struct {
	operation providerv1.Operation
	sessionID string
	reference string
	expiresAt string
}

func runReleaseProviderNode(config nodeConfig) error {
	fixture := &releaseProviderFixture{mode: "code", operations: make(map[string]releaseProviderOperation)}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/control/mode/", fixture.setMode)
	mux.HandleFunc("/v1/capabilities", fixture.capabilities)
	mux.HandleFunc("/v1/sandboxes", fixture.createSandbox)
	mux.HandleFunc("/v1/sandboxes/", fixture.sandboxMutation)
	mux.HandleFunc("/v1/operations/", fixture.operationRead)
	return serveUntilSignal(config.ProviderAPI, mux, nil)
}

func (f *releaseProviderFixture) setMode(writer http.ResponseWriter, request *http.Request) {
	mode := strings.TrimPrefix(request.URL.Path, "/control/mode/")
	if request.Method != http.MethodPost || (mode != "code" && mode != "browser") {
		http.Error(writer, "invalid", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
	writer.WriteHeader(http.StatusNoContent)
}

func (f *releaseProviderFixture) capabilities(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	f.mu.RLock()
	mode := f.mode
	f.mu.RUnlock()
	if mode == "browser" {
		releaseWriteJSON(writer, http.StatusOK, providerv1.Capabilities{
			ProviderRevisionID: productprovider.LockedProviderRevision, APIVersion: providerv1.APIVersionV1,
			Capabilities:           []providerv1.Capability{{ID: providerv1.CapabilityBrowser, Versions: []string{product.BrowserCapabilityVersion}, Profiles: []string{product.BrowserCapabilityProfile}}},
			RuntimeProfiles:        []providerv1.RuntimeProfile{{ID: product.BrowserSlotProfile, IsolationClass: providerv1.IsolationContainer, Architecture: []providerv1.Architecture{releaseArchitecture()}, CapabilityProfileIDs: []string{product.BrowserCapabilityProfile}}},
			SnapshotRestoreProfile: []providerv1.SnapshotRestoreProfile{}, Limits: providerv1.ProviderLimits{MaxCPUMillis: 4000, MaxMemoryBytes: 8 << 30, MaxEphemeralStorageBytes: 16 << 30, MaxLeaseSeconds: 86400, MaxExecSeconds: 3600},
		})
		return
	}
	releaseWriteJSON(writer, http.StatusOK, providerv1.Capabilities{
		ProviderRevisionID: productprovider.LockedProviderRevision, APIVersion: providerv1.APIVersionV1,
		Capabilities: []providerv1.Capability{
			{ID: providerv1.CapabilityExec, Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}},
			{ID: providerv1.CapabilityTerminal, Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}},
			{ID: providerv1.CapabilityTerminalControl, Versions: []string{"1.0.0"}, Profiles: []string{"terminal-control-v1"}},
		},
		RuntimeProfiles:        []providerv1.RuntimeProfile{{ID: "coding-shell-v1", IsolationClass: providerv1.IsolationContainer, Architecture: []providerv1.Architecture{releaseArchitecture()}, CapabilityProfileIDs: []string{"exec-v1", "terminal-v1", "terminal-control-v1"}}},
		SnapshotRestoreProfile: []providerv1.SnapshotRestoreProfile{}, Limits: providerv1.ProviderLimits{MaxCPUMillis: 4000, MaxMemoryBytes: 8 << 30, MaxEphemeralStorageBytes: 16 << 30, MaxLeaseSeconds: 86400, MaxExecSeconds: 3600},
	})
}

func (f *releaseProviderFixture) createSandbox(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !releaseProtected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input providerv1.CreateRequest
	if json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&input) != nil {
		http.Error(writer, "invalid", http.StatusBadRequest)
		return
	}
	operation := providerv1.Operation{OperationID: input.OperationID, AttemptID: input.AttemptID, FencingToken: input.FencingToken, SandboxID: input.Spec.SandboxID, Type: providerv1.OperationCreate, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + input.OperationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	f.mu.Lock()
	f.operations[input.OperationID] = releaseProviderOperation{operation: operation}
	f.mu.Unlock()
	releaseWriteJSON(writer, http.StatusAccepted, operation)
}

func (f *releaseProviderFixture) sandboxMutation(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !releaseProtected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	sandboxID := strings.TrimSuffix(strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/sandboxes/"), "/")[0], ":terminate")
	if strings.HasSuffix(request.URL.Path, "/browser-sessions") {
		var input providerv1.BrowserSessionOpenRequest
		if json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&input) != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		operation := providerv1.Operation{OperationID: input.OperationID, AttemptID: input.AttemptID, FencingToken: input.FencingToken, SandboxID: sandboxID, Type: providerv1.OperationOpenBrowserSession, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + input.OperationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		f.mu.Lock()
		f.operations[input.OperationID] = releaseProviderOperation{operation: operation, sessionID: input.BrowserSessionID, reference: "ref:browser-session:" + sandboxID + "." + input.BrowserSessionID, expiresAt: input.ExpiresAt}
		f.mu.Unlock()
		releaseWriteJSON(writer, http.StatusAccepted, operation)
		return
	}
	if strings.HasSuffix(request.URL.Path, ":terminate") {
		var input providerv1.TerminateRequest
		if json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&input) != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		operation := providerv1.Operation{OperationID: input.OperationID, AttemptID: input.AttemptID, FencingToken: input.FencingToken, SandboxID: sandboxID, Type: providerv1.OperationTerminate, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + input.OperationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		f.mu.Lock()
		f.operations[input.OperationID] = releaseProviderOperation{operation: operation}
		f.mu.Unlock()
		releaseWriteJSON(writer, http.StatusAccepted, operation)
		return
	}
	http.Error(writer, "not found", http.StatusNotFound)
}

func (f *releaseProviderFixture) operationRead(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !releaseProtected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	value := strings.TrimPrefix(request.URL.Path, "/v1/operations/")
	handoff := strings.HasSuffix(value, "/browser-session")
	operationID := strings.TrimSuffix(value, "/browser-session")
	f.mu.RLock()
	record, ok := f.operations[operationID]
	f.mu.RUnlock()
	if !ok {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	if handoff {
		releaseWriteJSON(writer, http.StatusOK, providerv1.BrowserSessionHandoff{
			OperationID: record.operation.OperationID, AttemptID: record.operation.AttemptID, FencingToken: record.operation.FencingToken,
			SandboxID: record.operation.SandboxID, BrowserSessionID: record.sessionID, CapabilityProfileID: product.BrowserCapabilityProfile,
			Protocol: providerv1.BrowserProtocolWebSocket, InternalEndpointReference: record.reference, ConnectionGeneration: 1, ExpiresAt: record.expiresAt,
		})
		return
	}
	record.operation.Status = providerv1.OperationSucceeded
	record.operation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	releaseWriteJSON(writer, http.StatusOK, record.operation)
}

func releaseProtected(request *http.Request) bool {
	return strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") && request.Header.Get("X-Sandbox-Runtime-Admission-Context") != ""
}
