//go:build phase5desktopgate

package productphase5gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/guestagent/development"
	"github.com/shell-echo/sandbox-runtime/internal/productcontract"
	"github.com/shell-echo/sandbox-runtime/internal/productphase5evidence"
	"github.com/shell-echo/sandbox-runtime/product"
	bloblocal "github.com/shell-echo/sandbox-runtime/product/adapter/blob/local"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
)

func TestProductPhase5DesktopReleaseGate(t *testing.T) { //nolint:cyclop,maintidx
	if os.Getenv(phase5NodeRole) != "" {
		t.Skip("parent-only release gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	directory := t.TempDir()
	postgresName := fmt.Sprintf("codex-product-phase5-postgres-%d", os.Getpid())
	desktopName := fmt.Sprintf("codex-product-phase5-desktop-%d", os.Getpid())
	dsn, removePostgres := startPostgres(t, ctx, postgresName)
	containersRemoved := false
	defer func() {
		if !containersRemoved {
			removeDesktopRuntime(desktopName)
			removePostgres()
		}
	}()
	config := nodeConfig{
		ProviderAddress: freeAddress(t), DesktopProviderAddress: freeAddress(t), DesktopPrivateAddress: freeAddress(t),
		DesktopControlAddress: freeAddress(t), GatewayAddress: freeAddress(t), ProductAddress: freeAddress(t), DSN: dsn,
		ProviderSigning: base64Key(t), GrantKey: base64.RawStdEncoding.EncodeToString(randomBytes(t, 32)),
		RecordingKey: base64.RawStdEncoding.EncodeToString(randomBytes(t, 32)), RecordingRoot: filepath.Join(directory, "recording-objects"),
		BlobRoot: filepath.Join(directory, "content-objects"), GateKey: base64.RawURLEncoding.EncodeToString(randomBytes(t, 32)),
		DesktopContainer: desktopName, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		GuestRoot: filepath.Join(directory, "guest-workspace"), GuestState: filepath.Join(directory, "guest-state"),
	}
	for _, path := range []string{config.RecordingRoot, config.BlobRoot, config.GuestRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeCertificates(t, directory, &config)
	configPath := filepath.Join(directory, "phase5-nodes.json")
	writeConfig(t, configPath, config)

	nodes := make([]*childNode, 0, 8)
	stopAll := func() bool {
		ok := true
		for index := len(nodes) - 1; index >= 0; index-- {
			if !stopNode(nodes[index]) {
				ok = false
			}
		}
		nodes = nil
		return ok
	}
	defer stopAll()

	providerNode := startNode(t, "provider", configPath)
	nodes = append(nodes, providerNode)
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.ProviderAddress+"/healthz", http.StatusOK, providerNode)
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.DesktopProviderAddress+"/healthz", http.StatusOK, providerNode)
	desktopNode := startNode(t, "desktop", configPath)
	nodes = append(nodes, desktopNode)
	waitHTTP(t, ctx, http.DefaultClient, "http://"+config.DesktopControlAddress+"/healthz", http.StatusOK, desktopNode)
	gatewayNode := startNode(t, "gateway", configPath)
	nodes = append(nodes, gatewayNode)
	publicClient := tlsClient(config.CACertificate, "phase5-edge")
	waitHTTP(t, ctx, publicClient, "https://"+config.GatewayAddress+"/healthz", http.StatusOK, gatewayNode)
	productNode := startNode(t, "product", configPath)
	nodes = append(nodes, productNode)
	productBase := "http://" + config.ProductAddress
	waitHTTP(t, ctx, http.DefaultClient, productBase+"/healthz", http.StatusOK, productNode)

	response := api(t, http.MethodPost, productBase+"/api/v1/workspaces", "Bearer invalid", "phase5-bad-auth", `{}`)
	requireStatus(t, response, http.StatusUnauthorized)
	waitCapability(t, productBase, "product.desktop", "ready")
	waitCapability(t, productBase, "product.development", "unavailable")

	create := api(t, http.MethodPost, productBase+"/api/v1/workspaces", "Bearer "+ownerBearer, "phase5-workspace-create",
		`{"display_name":"phase5 desktop release","lifetime_seconds":3600,"primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}}`)
	requireStatus(t, create, http.StatusAccepted)
	var workspaceOperation productapiv1.ProductOperation
	decode(t, create, &workspaceOperation)
	workspace := waitWorkspace(t, productBase, workspaceOperation.WorkspaceID, "active")

	putSlot := api(t, http.MethodPut, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID+"/slots/desktop-main", "Bearer "+ownerBearer, "phase5-desktop-slot",
		fmt.Sprintf(`{"expected_workspace_version":%d,"kind":"desktop","profile_id":"sandbox-runtime-desktop-v1","required_capabilities":[{"capability_id":"sandbox.desktop","version":"1.0.0","profile_id":"desktop-v1"}],"desired_state":"ready"}`, workspace.Version))
	requireStatus(t, putSlot, http.StatusAccepted)
	var slotOperation productapiv1.ProductOperation
	decode(t, putSlot, &slotOperation)
	waitOperation(t, productBase, slotOperation.OperationID, "succeeded")
	workspace = waitSlot(t, productBase, workspace.WorkspaceID, "desktop-main", "ready")

	foreign := api(t, http.MethodGet, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID, "Bearer "+foreignBearer, "", "")
	requireStatus(t, foreign, http.StatusNotFound)
	putDesktopPolicy(t, productBase, config.GateKey, workspace.WorkspaceID, "phase5-policy-v1", 0)

	desktopSession := createDesktopSession(t, productBase, workspace, "required", "phase5-desktop-session-1")
	lease := acquireControlLease(t, productBase, workspace.WorkspaceID, desktopSession.SessionID, workspace.Version, "phase5-control-1")
	grant := createDesktopGrant(t, productBase, desktopSession, lease, "phase5-grant-1")
	before := readDesktopSnapshot(t, config)
	desktopOriginRejected(t, publicClient, config.GatewayAddress, grant.ConnectionTicket)
	desktopRoundTrip(t, publicClient, config.GatewayAddress, grant.ConnectionTicket, 111, 222, true)
	after := readDesktopSnapshot(t, config)
	if before.SizeBytes < 1024 || after.SizeBytes < 1024 || before.ImageDigest != productphase5evidence.DesktopImageDigest || after.X != 111 || after.Y != 222 {
		t.Fatalf("real Desktop capture/control mismatch before=%#v after=%#v", before, after)
	}
	desktopTicketRejected(t, publicClient, config.GatewayAddress, grant.ConnectionTicket)
	recordingID := waitRecording(t, productBase, workspace.WorkspaceID)
	replayRecording(t, productBase, config.GateKey, recordingID)
	closeDesktopSession(t, productBase, desktopSession, "phase5-close-session-1")

	if !stopNode(productNode) {
		t.Fatalf("Product did not stop cleanly: %s", nodeLog(productNode))
	}
	nodes = removeNode(nodes, productNode)
	productNode = startNode(t, "product", configPath)
	nodes = append(nodes, productNode)
	waitHTTP(t, ctx, http.DefaultClient, productBase+"/healthz", http.StatusOK, productNode)
	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	waitCapability(t, productBase, "product.desktop", "ready")

	if !stopNode(gatewayNode) {
		t.Fatalf("Gateway did not stop cleanly: %s", nodeLog(gatewayNode))
	}
	nodes = removeNode(nodes, gatewayNode)
	gatewayNode = startNode(t, "gateway", configPath)
	nodes = append(nodes, gatewayNode)
	waitHTTP(t, ctx, publicClient, "https://"+config.GatewayAddress+"/healthz", http.StatusOK, gatewayNode)
	time.Sleep(350 * time.Millisecond)
	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	restartedSession := createDesktopSession(t, productBase, workspace, "metadata_only", "phase5-desktop-session-2")
	restartedLease := acquireControlLease(t, productBase, workspace.WorkspaceID, restartedSession.SessionID, workspace.Version, "phase5-control-2")
	restartedGrant := createDesktopGrant(t, productBase, restartedSession, restartedLease, "phase5-grant-2")
	desktopRoundTrip(t, publicClient, config.GatewayAddress, restartedGrant.ConnectionTicket, 333, 244, false)
	closeDesktopSession(t, productBase, restartedSession, "phase5-close-session-2")

	guestNode, firstRevision := startReleaseGuest(t, ctx, &config, configPath, productBase, workspace.WorkspaceID, nodes)
	nodes = append(nodes, guestNode)
	waitCapability(t, productBase, "product.development", "ready")
	startDevelopment(t, productBase, config.GateKey, workspace.WorkspaceID, firstRevision, "phase5-development-1")
	requireMaterializedFile(t, config.GuestRoot, "phase5 development materialization one\n")
	if !stopNode(guestNode) {
		t.Fatalf("Guest did not stop cleanly: %s", nodeLog(guestNode))
	}
	nodes = removeNode(nodes, guestNode)
	guestNode = startNode(t, "guest", configPath)
	nodes = append(nodes, guestNode)
	waitCapability(t, productBase, "product.development", "ready")
	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	secondRevision := createRevision(t, config, workspace.WorkspaceID, workspace.Version, firstRevision, "phase5 development materialization two\n", "two")
	startDevelopment(t, productBase, config.GateKey, workspace.WorkspaceID, secondRevision, "phase5-development-2")
	requireMaterializedFile(t, config.GuestRoot, "phase5 development materialization two\n")

	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	faultSession := createDesktopSession(t, productBase, workspace, "metadata_only", "phase5-desktop-session-fault")
	faultLease := acquireControlLease(t, productBase, workspace.WorkspaceID, faultSession.SessionID, workspace.Version, "phase5-control-fault")
	faultGrant := createDesktopGrant(t, productBase, faultSession, faultLease, "phase5-grant-fault")
	if !stopNode(providerNode) {
		t.Fatalf("Provider did not stop cleanly: %s", nodeLog(providerNode))
	}
	nodes = removeNode(nodes, providerNode)
	waitCapability(t, productBase, "product.desktop", "unavailable")
	desktopDependencyRejected(t, publicClient, config.GatewayAddress, faultGrant.ConnectionTicket)

	if !stopAll() {
		t.Fatal("not all Phase 5 child processes were reaped")
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
	if err := os.RemoveAll(config.RecordingRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(config.BlobRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(config.GuestRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(config.GuestState); err != nil {
		t.Fatal(err)
	}
	objectsRemoved := pathsAbsent(config.RecordingRoot, config.BlobRoot)
	guestRemoved := pathsAbsent(config.GuestRoot, config.GuestState)
	removeDesktopRuntime(desktopName)
	removePostgres()
	containersRemoved = true
	for _, name := range []string{postgresName, desktopName} {
		if exec.CommandContext(ctx, "docker", "inspect", name).Run() == nil {
			t.Fatalf("container %s remains after cleanup", name)
		}
	}
	evidencePath := writePhase5Evidence(t, started, time.Now().UTC(), objectsRemoved, guestRemoved)
	manifest, err := productphase5evidence.VerifyFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Product Phase 5 Desktop evidence: %s (%d scenarios, %d processes)", evidencePath, len(manifest.Scenarios), len(manifest.Processes))
}

func waitSlot(t *testing.T, base, workspaceID, slotKey, state string) productapiv1.Workspace {
	t.Helper()
	var result productapiv1.Workspace
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/workspaces/"+workspaceID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decode(t, response, &result)
		for _, slot := range result.Slots {
			if slot.SlotKey == slotKey && slot.ObservedState == state {
				return true
			}
		}
		return false
	}, "slot "+slotKey+" "+state)
	return result
}

func waitCapability(t *testing.T, base, capabilityID, state string) {
	t.Helper()
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/capabilities", "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		var document productapiv1.CapabilityDocument
		decode(t, response, &document)
		if len(document.Capabilities) != 2 {
			return false
		}
		for _, capability := range document.Capabilities {
			if capability.CapabilityID == capabilityID {
				return capability.Readiness == state
			}
		}
		return false
	}, capabilityID+" "+state)
}

func putDesktopPolicy(t *testing.T, base, gateKey, workspaceID, key string, expected int64) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"WorkspaceID": workspaceID, "IdempotencyKey": key, "ExpectedRevision": expected})
	request, _ := http.NewRequest(http.MethodPost, base+"/gate/policy", bytes.NewReader(body))
	request.Header.Set("X-Gate-Key", gateKey)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, response, http.StatusOK)
	response.Body.Close()
}

func createDesktopSession(t *testing.T, base string, workspace productapiv1.Workspace, recording, key string) productapiv1.RuntimeSession {
	t.Helper()
	body := fmt.Sprintf(`{"expected_workspace_version":%d,"slot_key":"desktop-main","kind":"desktop","protocol_profile":"product-desktop.v1","expires_in_seconds":900,"recording_policy":%q}`, workspace.Version, recording)
	response := api(t, http.MethodPost, base+"/api/v1/workspaces/"+workspace.WorkspaceID+"/sessions", "Bearer "+ownerBearer, key, body)
	requireStatus(t, response, http.StatusAccepted)
	var operation productapiv1.ProductOperation
	decode(t, response, &operation)
	waitOperation(t, base, operation.OperationID, "succeeded")
	return waitSession(t, base, operation.SessionID, "ready")
}

func closeDesktopSession(t *testing.T, base string, session productapiv1.RuntimeSession, key string) {
	t.Helper()
	response := api(t, http.MethodPost, base+"/api/v1/sessions/"+session.SessionID+":close", "Bearer "+ownerBearer, key,
		fmt.Sprintf(`{"expected_version":%d,"reason":"phase5 release gate cleanup"}`, session.Version))
	requireStatus(t, response, http.StatusAccepted)
	var operation productapiv1.ProductOperation
	decode(t, response, &operation)
	waitOperation(t, base, operation.OperationID, "succeeded")
	waitSession(t, base, session.SessionID, "closed")
}

func acquireControlLease(t *testing.T, base, workspaceID, sessionID string, workspaceVersion int64, key string) productapiv1.ControlLease {
	t.Helper()
	workspaceVersion = waitWorkspace(t, base, workspaceID, "active").Version
	body := fmt.Sprintf(`{"expected_workspace_version":%d,"scope":{"scope_type":"session","scope_id":%q},"duration_seconds":120}`, workspaceVersion, sessionID)
	response := api(t, http.MethodPost, base+"/api/v1/workspaces/"+workspaceID+"/control-leases", "Bearer "+ownerBearer, key, body)
	requireStatus(t, response, http.StatusCreated)
	var lease productapiv1.ControlLease
	decode(t, response, &lease)
	return lease
}

func createDesktopGrant(t *testing.T, base string, session productapiv1.RuntimeSession, lease productapiv1.ControlLease, key string) productapiv1.ConnectionGrant {
	t.Helper()
	body := fmt.Sprintf(`{"expected_session_version":%d,"protocol_profile":"product-desktop.v1","access_mode":"control","control_lease_id":%q,"control_fence":%d}`, session.Version, lease.LeaseID, lease.Fence)
	response := api(t, http.MethodPost, base+"/api/v1/sessions/"+session.SessionID+"/connections", "Bearer "+ownerBearer, key, body)
	requireStatus(t, response, http.StatusCreated)
	var grant productapiv1.ConnectionGrant
	decode(t, response, &grant)
	return grant
}

type desktopSignalResponse struct {
	Answer struct {
		Type string `json:"type"`
		SDP  string `json:"sdp"`
	} `json:"answer"`
	ConnectionID  string                                `json:"connection_id"`
	AccessMode    string                                `json:"access_mode"`
	Media         productgateway.DesktopLiveMediaPolicy `json:"media"`
	RecordingMode string                                `json:"recording_mode"`
}

func desktopOffer(t *testing.T) (*webrtc.PeerConnection, *webrtc.DataChannel, webrtc.SessionDescription) {
	t.Helper()
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	channel, err := peer.CreateDataChannel(productgateway.DesktopLiveControlDataChannel, nil)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := peer.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(peer)
	if err := peer.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gathered:
	case <-time.After(4 * time.Second):
		t.Fatal("Desktop ICE gathering timed out")
	}
	return peer, channel, *peer.LocalDescription()
}

func desktopSignalBody(t *testing.T, offer webrtc.SessionDescription, recording bool) []byte {
	t.Helper()
	consent := ""
	if recording {
		consent = "consent-phase5-release"
	}
	document, err := json.Marshal(map[string]any{
		"offer":                map[string]string{"type": "offer", "sdp": offer.SDP},
		"media":                map[string]any{"video_codec": "video/VP8", "width": 1280, "height": 720, "max_fps": 30, "max_video_bitrate_kbps": 2000},
		"control_data_channel": true, "recording_consent_reference": consent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func desktopOriginRejected(t *testing.T, client *http.Client, gateway, ticket string) {
	t.Helper()
	peer, _, offer := desktopOffer(t)
	defer peer.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://"+gateway+"/desktop/connect", bytes.NewReader(desktopSignalBody(t, offer, true)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://evil.example.test")
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", response.StatusCode)
	}
}

func desktopRoundTrip(t *testing.T, client *http.Client, gateway, ticket string, x, y int, recording bool) {
	t.Helper()
	peer, channel, offer := desktopOffer(t)
	packets := make(chan *rtp.Packet, 1)
	peer.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		packet, _, err := track.ReadRTP()
		if err == nil {
			packets <- packet
		}
	})
	opened := make(chan struct{})
	results := make(chan webrtc.DataChannelMessage, 1)
	channel.OnOpen(func() { close(opened) })
	channel.OnMessage(func(message webrtc.DataChannelMessage) { results <- message })
	request, _ := http.NewRequest(http.MethodPost, "https://"+gateway+"/desktop/connect", bytes.NewReader(desktopSignalBody(t, offer, recording)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", publicOrigin)
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := client.Do(request)
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		peer.Close()
		t.Fatalf("Desktop signal status=%d body=%s", response.StatusCode, body)
	}
	var signal desktopSignalResponse
	decode(t, response, &signal)
	if signal.Answer.Type != "answer" || signal.ConnectionID == "" || signal.AccessMode != product.GrantAccessControl {
		peer.Close()
		t.Fatalf("Desktop signal=%#v", signal)
	}
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.Answer.SDP}); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return peer.ConnectionState() == webrtc.PeerConnectionStateConnected }, "Desktop WebRTC connected")
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		peer.Close()
		t.Fatal("Desktop control channel timed out")
	}
	message := fmt.Sprintf(`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":%d,"y":%d,"button":0,"delta_x":0,"delta_y":0,"user_activation":true}}`, x, y)
	if err := channel.SendText(message); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	select {
	case result := <-results:
		if !result.IsString || !bytes.Contains(result.Data, []byte(`"ok":true`)) {
			peer.Close()
			t.Fatalf("Desktop input result=%s", result.Data)
		}
	case <-time.After(5 * time.Second):
		peer.Close()
		t.Fatal("Desktop input timed out")
	}
	select {
	case packet := <-packets:
		if packet.PayloadType != 96 || len(packet.Payload) == 0 {
			peer.Close()
			t.Fatalf("invalid Desktop RTP=%#v", packet)
		}
	case <-time.After(5 * time.Second):
		peer.Close()
		t.Fatal("Desktop display packet timed out")
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
}

func desktopTicketRejected(t *testing.T, client *http.Client, gateway, ticket string) {
	t.Helper()
	peer, _, offer := desktopOffer(t)
	defer peer.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://"+gateway+"/desktop/connect", bytes.NewReader(desktopSignalBody(t, offer, true)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", publicOrigin)
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ticket replay status=%d", response.StatusCode)
	}
}

func desktopDependencyRejected(t *testing.T, client *http.Client, gateway, ticket string) {
	t.Helper()
	peer, _, offer := desktopOffer(t)
	defer peer.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://"+gateway+"/desktop/connect", bytes.NewReader(desktopSignalBody(t, offer, false)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", publicOrigin)
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("Desktop dependency fault did not fail closed")
	}
}

func readDesktopSnapshot(t *testing.T, config nodeConfig) desktopSnapshot {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, "http://"+config.DesktopControlAddress+"/gate/display", nil)
	request.Header.Set("X-Gate-Key", config.GateKey)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, response, http.StatusOK)
	var snapshot desktopSnapshot
	decode(t, response, &snapshot)
	return snapshot
}

func waitRecording(t *testing.T, base, workspaceID string) string {
	t.Helper()
	var recordingID string
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/workspaces/"+workspaceID+"/recordings?limit=50", "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		var page productapiv1.RecordingPage
		decode(t, response, &page)
		for _, item := range page.Items {
			if item.RecordingType == "media" && item.State == "available" && item.SizeBytes != nil && *item.SizeBytes > 0 {
				recordingID = item.RecordingID
				return true
			}
		}
		return false
	}, "available Desktop recording")
	return recordingID
}

func replayRecording(t *testing.T, base, key, recordingID string) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, base+"/gate/replay/"+recordingID, nil)
	request.Header.Set("X-Gate-Key", key)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("Desktop replay status=%d body=%s", response.StatusCode, body)
	}
}

func startReleaseGuest(t *testing.T, ctx context.Context, config *nodeConfig, configPath, productBase, workspaceID string, _ []*childNode) (*childNode, string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := productpostgres.New(pool, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	guestService, err := product.NewGuestService(store, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	workspace := waitWorkspace(t, productBase, workspaceID, "active")
	capabilities := []string{development.CapabilityHealth, development.CapabilityPrepare, development.CapabilityWrite, development.CapabilityCommit, development.CapabilityFinalize, development.CapabilityRollback}
	sort.Strings(capabilities)
	binding, _, err := guestService.Provision(ctx, releaseTenantID, releaseActor(), workspaceID, "phase5-guest-provision", product.ProvisionGuestRequest{
		ExpectedWorkspaceVersion: workspace.Version, SlotKey: "primary-code", ProtocolVersion: "1.0.0", Capabilities: capabilities, PublicKey: publicKey, LifetimeSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	config.GuestID, config.GuestGeneration, config.GuestPrivateKey = binding.GuestID, binding.BindingGeneration, base64.RawStdEncoding.EncodeToString(privateKey)
	writeConfig(t, configPath, *config)
	guestNode := startNode(t, "guest", configPath)
	waitCapability(t, productBase, "product.development", "ready")
	workspace = waitWorkspace(t, productBase, workspaceID, "active")
	revision := createRevision(t, *config, workspaceID, workspace.Version, "", "phase5 development materialization one\n", "one")
	return guestNode, revision
}

func createRevision(t *testing.T, config nodeConfig, workspaceID string, workspaceVersion int64, expectedHead, content, suffix string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := productpostgres.New(pool, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	blobs, err := bloblocal.New(config.BlobRoot)
	if err != nil {
		t.Fatal(err)
	}
	transfers, err := product.NewTransferService(store, blobs, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	fileDigest := digestBytes([]byte(content))
	fileTransfer, _, err := transfers.BeginUpload(ctx, releaseTenantID, releaseActor(), workspaceID, "phase5-file-upload-"+suffix, product.BeginUploadRequest{ExpectedWorkspaceVersion: workspaceVersion, Digest: fileDigest, SizeBytes: int64(len(content)), ExpiresInSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Append(ctx, releaseTenantID, releaseActor(), fileTransfer.ID, 0, []byte(content)); err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Complete(ctx, releaseTenantID, releaseActor(), fileTransfer.ID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2`, releaseTenantID, workspaceID).Scan(&workspaceVersion); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(product.RevisionManifest{Entries: []product.RevisionManifestEntry{{Path: "README.md", Type: "file", Mode: 0o644, SizeBytes: int64(len(content)), Digest: fileDigest}}})
	manifestTransfer, _, err := transfers.BeginUpload(ctx, releaseTenantID, releaseActor(), workspaceID, "phase5-manifest-upload-"+suffix, product.BeginUploadRequest{ExpectedWorkspaceVersion: workspaceVersion, Digest: digestBytes(manifest), SizeBytes: int64(len(manifest)), ExpiresInSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Append(ctx, releaseTenantID, releaseActor(), manifestTransfer.ID, 0, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := transfers.Complete(ctx, releaseTenantID, releaseActor(), manifestTransfer.ID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2`, releaseTenantID, workspaceID).Scan(&workspaceVersion); err != nil {
		t.Fatal(err)
	}
	revision, _, err := transfers.CommitRevision(ctx, releaseTenantID, releaseActor(), workspaceID, "phase5-revision-commit-"+suffix, product.CommitRevisionRequest{ExpectedWorkspaceVersion: workspaceVersion, ExpectedHeadRevisionID: expectedHead, UploadTransferID: manifestTransfer.ID})
	if err != nil {
		t.Fatal(err)
	}
	return revision.ID
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func startDevelopment(t *testing.T, base, key, workspaceID, revisionID, idempotencyKey string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"WorkspaceID": workspaceID, "RevisionID": revisionID, "IdempotencyKey": idempotencyKey})
	request, _ := http.NewRequest(http.MethodPost, base+"/gate/development", bytes.NewReader(body))
	request.Header.Set("X-Gate-Key", key)
	response, err := (&http.Client{Timeout: 40 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		document, _ := io.ReadAll(response.Body)
		t.Fatalf("development status=%d body=%s", response.StatusCode, document)
	}
	var result struct {
		EnvironmentID string `json:"environment_id"`
		RevisionID    string `json:"revision_id"`
		State         string `json:"state"`
		Replay        bool   `json:"replay"`
	}
	decode(t, response, &result)
	if result.EnvironmentID == "" || result.RevisionID != revisionID || result.State != "ready" || result.Replay {
		t.Fatalf("development result=%#v", result)
	}
}

func requireMaterializedFile(t *testing.T, root, expected string) {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(document) != expected {
		t.Fatalf("materialized content=%q", document)
	}
}

func pathsAbsent(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func writePhase5Evidence(t *testing.T, started, completed time.Time, objectsRemoved, guestRemoved bool) string {
	t.Helper()
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	report, err := productcontract.Verify(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(executable)
	executableDigest := "sha256:" + hex.EncodeToString(sum[:])
	roles := []string{"desktop", "gateway", "guest", "product", "provider"}
	processes := make([]productphase5evidence.ProcessEvidence, 0, len(roles))
	for _, role := range roles {
		processes = append(processes, productphase5evidence.ProcessEvidence{Role: role, ExecutableDigest: executableDigest, IndependentOSProcess: true})
	}
	cases := []string{"capability-advertisement", "contract-identities", "desktop-recording-integrity", "desktop-slot-session-lifecycle", "desktop-ticket-replay-origin-denial", "exact-cleanup", "gateway-restart-recovery", "guest-development-materialization", "guest-restart-recovery", "product-authentication", "product-restart-recovery", "provider-dependency-fault-closure", "real-desktop-display-control", "tenant-nondisclosure"}
	scenarios := make([]productphase5evidence.ScenarioEvidence, 0, len(cases))
	for _, id := range cases {
		scenarios = append(scenarios, productphase5evidence.ScenarioEvidence{ID: id, Status: "passed"})
	}
	platform, platformDigest := releasePlatform()
	manifest := productphase5evidence.Manifest{
		SchemaVersion: 1, RunID: started.Format("20060102T150405.000000000Z"), Result: "passed", EvidenceTier: "same-repository-independent-process",
		SourceRevision: strings.TrimSpace(string(revision)), StartedAt: started.Format(time.RFC3339Nano), CompletedAt: completed.Format(time.RFC3339Nano),
		BaseProvider:    productphase5evidence.ProviderIdentity{Revision: productphase5evidence.BaseProviderRevision, Tree: productphase5evidence.BaseProviderTree},
		DesktopProvider: productphase5evidence.ProviderIdentity{Revision: productphase5evidence.DesktopProviderRevision, Tree: productphase5evidence.DesktopProviderTree},
		Product:         productphase5evidence.ProductIdentity{Tree: report.TreeDigest, ResourceCount: report.ResourceCount, OperationCount: report.OperationCount, ConformanceCases: report.ConformanceCases},
		PostgreSQL:      productphase5evidence.ServiceIdentity{Profile: productphase5evidence.PostgresImage, Fresh: true}, ObjectStorage: productphase5evidence.ServiceIdentity{Profile: productphase5evidence.ObjectStore, Fresh: true},
		DesktopRuntime:      productphase5evidence.RuntimeIdentity{Profile: productphase5evidence.DesktopProfile, Image: productphase5evidence.DesktopImage, IndexDigest: productphase5evidence.DesktopImageDigest, Platform: platform, PlatformDigest: platformDigest, SourceRevision: productphase5evidence.DesktopSourceRevision, Signed: true},
		DevelopmentTemplate: productphase5evidence.TemplateIdentity{TemplateID: productphase5evidence.DevelopmentTemplate, Image: productphase5evidence.DevelopmentImage, IndexDigest: productphase5evidence.DevelopmentImageDigest, Selected: true},
		Processes:           processes, Scenarios: scenarios, Cleanup: productphase5evidence.CleanupEvidence{ChildProcessesReaped: true, ContainersRemoved: true, ScopedRowsRemoved: true, ObjectContentRemoved: objectsRemoved, GuestStateRemoved: guestRemoved, RuntimeRemoved: true},
		NonClaims: []string{"deployment-qualified", "ha-qualified", "hostile-multi-tenant-qualified", "independent-caller-qualified", "production-ready"},
	}
	directory := os.Getenv(phase5EvidenceOutput)
	if directory == "" {
		directory, err = os.MkdirTemp("", "product-phase5-evidence-")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "product-phase-5-desktop-evidence.json")
	document, _ := json.MarshalIndent(manifest, "", "  ")
	document = append(document, '\n')
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
