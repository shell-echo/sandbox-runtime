//go:build phase4browsergate

package productphase4gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/internal/productcontract"
	"github.com/shell-echo/sandbox-runtime/internal/productphase4evidence"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
)

func startReleasePostgres(t *testing.T, ctx context.Context, name string) (string, func()) {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=phase4", "-e", "POSTGRES_DB=phase4", "-p", "127.0.0.1::5432", productphase4evidence.PostgresImage)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("start pinned PostgreSQL: %v: %s", err, output)
	}
	remove := func() { _ = exec.Command("docker", "rm", "-f", name).Run() }
	portOutput, err := exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").Output()
	if err != nil {
		remove()
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		remove()
		t.Fatal(err)
	}
	dsn := "postgres://postgres:phase4@127.0.0.1:" + port + "/phase4?sslmode=disable"
	releaseWaitFor(t, 20*time.Second, func() bool {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return false
		}
		defer pool.Close()
		return pool.Ping(ctx) == nil
	}, "fresh PostgreSQL")
	return dsn, remove
}

func startReleaseValkey(t *testing.T, ctx context.Context, name string) (string, func()) {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::6379", productphase4evidence.ValkeyImage, "valkey-server", "--save", "", "--appendonly", "no")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("start pinned Valkey: %v: %s", err, output)
	}
	remove := func() { _ = exec.Command("docker", "rm", "-f", name).Run() }
	portOutput, err := exec.CommandContext(ctx, "docker", "port", name, "6379/tcp").Output()
	if err != nil {
		remove()
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		remove()
		t.Fatal(err)
	}
	address := "127.0.0.1:" + port
	client := releaseRedisClient(address)
	releaseWaitFor(t, 20*time.Second, func() bool { return client.Ping(ctx).Err() == nil }, "fresh Valkey")
	_ = client.Close()
	return address, remove
}

func releaseRedisClient(address string) *goredis.Client {
	return goredis.NewClient(&goredis.Options{
		Addr: address, Protocol: 2, MaxRetries: -1, ContextTimeoutEnabled: true, DisableIdentity: true,
		DialTimeout: 100 * time.Millisecond, ReadTimeout: 100 * time.Millisecond, WriteTimeout: 100 * time.Millisecond, PoolTimeout: 100 * time.Millisecond,
	})
}

func releaseTLSClient(caPath, serverName string) *http.Client {
	document, err := os.ReadFile(caPath)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(document) {
		return nil
	}
	return &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName}}}
}

func releaseRandom(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func releaseWriteConfig(t *testing.T, path string, config nodeConfig) {
	t.Helper()
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
}

func releaseStopNode(node *childNode) bool {
	if node == nil || node.cmd == nil || node.cmd.Process == nil {
		return true
	}
	select {
	case <-node.done:
		node.waitMu.Lock()
		err := node.waitErr
		node.waitMu.Unlock()
		return err == nil && node.cmd.ProcessState != nil && node.cmd.ProcessState.Success()
	default:
	}
	if err := node.cmd.Process.Signal(os.Interrupt); err != nil {
		return false
	}
	select {
	case <-node.done:
		node.waitMu.Lock()
		err := node.waitErr
		node.waitMu.Unlock()
		return err == nil && node.cmd.ProcessState != nil && node.cmd.ProcessState.Success()
	case <-time.After(5 * time.Second):
		_ = node.cmd.Process.Kill()
		<-node.done
		return false
	}
}

func releaseRemoveNode(nodes []*childNode, target *childNode) []*childNode {
	result := nodes[:0]
	for _, node := range nodes {
		if node != target {
			result = append(result, node)
		}
	}
	return result
}

func releaseAPI(t *testing.T, method, target, authorization, idempotencyKey, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func releaseRequireStatus(t *testing.T, response *http.Response, wanted int) {
	t.Helper()
	if response.StatusCode != wanted {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, wanted, body)
	}
}

func releaseDecode(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

func releaseWaitWorkspace(t *testing.T, base, workspaceID, state string) productapiv1.Workspace {
	t.Helper()
	var result productapiv1.Workspace
	releaseWaitFor(t, 10*time.Second, func() bool {
		response := releaseAPI(t, http.MethodGet, base+"/api/v1/workspaces/"+workspaceID, "Bearer "+releaseOwnerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		releaseDecode(t, response, &result)
		return result.ObservedState == state
	}, "workspace "+state)
	return result
}

func releaseWaitOperation(t *testing.T, base, operationID, state string) productapiv1.ProductOperation {
	t.Helper()
	var result productapiv1.ProductOperation
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response := releaseAPI(t, http.MethodGet, base+"/api/v1/operations/"+operationID, "Bearer "+releaseOwnerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		releaseDecode(t, response, &result)
		if result.State == "failed" {
			t.Fatalf("operation %s failed: %#v", operationID, result)
		}
		if result.State == state {
			return result
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for operation %s state %s; last=%#v", operationID, state, result)
	return result
}

func releaseWaitSlot(t *testing.T, base, workspaceID, slotKey, state string) productapiv1.Workspace {
	t.Helper()
	var workspace productapiv1.Workspace
	releaseWaitFor(t, 10*time.Second, func() bool {
		workspace = releaseWaitWorkspace(t, base, workspaceID, "active")
		for _, slot := range workspace.Slots {
			if slot.SlotKey == slotKey && slot.ObservedState == state {
				return true
			}
		}
		return false
	}, "slot "+state)
	return workspace
}

func releaseWaitSession(t *testing.T, base, sessionID, state string) productapiv1.RuntimeSession {
	t.Helper()
	var result productapiv1.RuntimeSession
	releaseWaitFor(t, 10*time.Second, func() bool {
		response := releaseAPI(t, http.MethodGet, base+"/api/v1/sessions/"+sessionID, "Bearer "+releaseOwnerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		releaseDecode(t, response, &result)
		if result.State == "failed" {
			t.Fatalf("session %s failed: %#v", sessionID, result)
		}
		return result.State == state
	}, "session "+state)
	return result
}

func releaseWaitCapability(t *testing.T, base, capabilityID, state string) {
	t.Helper()
	releaseWaitFor(t, 10*time.Second, func() bool {
		response := releaseAPI(t, http.MethodGet, base+"/api/v1/capabilities", "Bearer "+releaseOwnerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		var document productapiv1.CapabilityDocument
		releaseDecode(t, response, &document)
		for _, capability := range document.Capabilities {
			if capability.CapabilityID == capabilityID {
				return capability.Readiness == state
			}
		}
		return false
	}, "capability "+state)
}

func releaseSetProviderMode(t *testing.T, address, mode string) {
	t.Helper()
	response, err := http.Post("http://"+address+"/control/mode/"+mode, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("provider mode status=%d", response.StatusCode)
	}
}

func releaseCreateSession(t *testing.T, base string, workspace productapiv1.Workspace, kind, profile, recording, key string) productapiv1.RuntimeSession {
	t.Helper()
	workspace = releaseWaitWorkspace(t, base, workspace.WorkspaceID, "active")
	body := fmt.Sprintf(`{"expected_workspace_version":%d,"slot_key":"browser-main","kind":%q,"protocol_profile":%q,"expires_in_seconds":300,"recording_policy":%q}`, workspace.Version, kind, profile, recording)
	response := releaseAPI(t, http.MethodPost, base+"/api/v1/workspaces/"+workspace.WorkspaceID+"/sessions", "Bearer "+releaseOwnerBearer, key, body)
	releaseRequireStatus(t, response, http.StatusAccepted)
	var operation productapiv1.ProductOperation
	releaseDecode(t, response, &operation)
	releaseWaitOperation(t, base, operation.OperationID, "succeeded")
	return releaseWaitSession(t, base, operation.SessionID, "ready")
}

func releaseCloseSession(t *testing.T, base string, session productapiv1.RuntimeSession, key string) {
	t.Helper()
	response := releaseAPI(t, http.MethodPost, base+"/api/v1/sessions/"+session.SessionID+":close", "Bearer "+releaseOwnerBearer, key, fmt.Sprintf(`{"expected_version":%d,"reason":"release gate transition"}`, session.Version))
	releaseRequireStatus(t, response, http.StatusAccepted)
	var operation productapiv1.ProductOperation
	releaseDecode(t, response, &operation)
	releaseWaitOperation(t, base, operation.OperationID, "succeeded")
	releaseWaitSession(t, base, session.SessionID, "closed")
}

func releaseLease(t *testing.T, base, workspaceID, sessionID string, _ int64, key string) productapiv1.ControlLease {
	t.Helper()
	workspace := releaseWaitWorkspace(t, base, workspaceID, "active")
	body := fmt.Sprintf(`{"expected_workspace_version":%d,"scope":{"scope_type":"session","scope_id":%q},"duration_seconds":120}`, workspace.Version, sessionID)
	response := releaseAPI(t, http.MethodPost, base+"/api/v1/workspaces/"+workspaceID+"/control-leases", "Bearer "+releaseOwnerBearer, key, body)
	releaseRequireStatus(t, response, http.StatusCreated)
	var lease productapiv1.ControlLease
	releaseDecode(t, response, &lease)
	return lease
}

func releaseGrant(t *testing.T, base string, session productapiv1.RuntimeSession, lease *productapiv1.ControlLease, access, key string) productapiv1.ConnectionGrant {
	t.Helper()
	control := ""
	if lease != nil {
		control = fmt.Sprintf(`,"control_lease_id":%q,"control_fence":%d`, lease.LeaseID, lease.Fence)
	}
	body := fmt.Sprintf(`{"expected_session_version":%d,"protocol_profile":%q,"access_mode":%q%s}`, session.Version, session.ProtocolProfile, access, control)
	response := releaseAPI(t, http.MethodPost, base+"/api/v1/sessions/"+session.SessionID+"/connections", "Bearer "+releaseOwnerBearer, key, body)
	releaseRequireStatus(t, response, http.StatusCreated)
	var grant productapiv1.ConnectionGrant
	releaseDecode(t, response, &grant)
	return grant
}

func releaseAutomationRejected(t *testing.T, client *http.Client, gatewayAddress, ticket string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(ctx, "wss://"+gatewayAddress+"/browser/connect", &websocket.DialOptions{
		HTTPClient: client, HTTPHeader: http.Header{"Origin": []string{releaseOrigin}, "Authorization": []string{"Ticket " + ticket}},
		Subprotocols: []string{productgateway.BrowserAutomationSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if connection != nil {
		connection.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("automation rejection response=%v err=%v", response, err)
	}
	response.Body.Close()
}

func releaseAutomationRoundTrip(t *testing.T, client *http.Client, gatewayAddress, ticket string, oversized bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(ctx, "wss://"+gatewayAddress+"/browser/connect", &websocket.DialOptions{
		HTTPClient: client, HTTPHeader: http.Header{"Origin": []string{releaseOrigin}, "Authorization": []string{"Ticket " + ticket}},
		Subprotocols: []string{productgateway.BrowserAutomationSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("automation dial response=%v err=%v", response, err)
	}
	defer connection.CloseNow()
	if err := connection.Write(ctx, websocket.MessageText, []byte(`{"type":"action","action_id":"release-action","sequence":1,"name":"page.info","parameters":{}}`)); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageText || !bytes.Contains(payload, []byte(`"action_id":"release-action"`)) || !bytes.Contains(payload, []byte(`"title":"phase4-release"`)) || bytes.Contains(payload, []byte("Runtime.evaluate")) || bytes.Contains(payload, []byte("ref:browser-session:")) {
		t.Fatalf("automation result type=%v payload=%s err=%v", kind, payload, err)
	}
	if !oversized {
		_ = connection.Close(websocket.StatusNormalClosure, "done")
		return
	}
	large := `{"type":"action","action_id":"too-large","sequence":2,"name":"page.text","parameters":{"max_characters":1,"padding":"` + strings.Repeat("x", 40<<10) + `"}}`
	_ = connection.Write(ctx, websocket.MessageText, []byte(large))
	if _, _, err := connection.Read(ctx); err == nil {
		t.Fatal("oversized Browser automation action remained open")
	}
}

type releaseLiveSignalResponse struct {
	Answer struct {
		Type string `json:"type"`
		SDP  string `json:"sdp"`
	} `json:"answer"`
	ConnectionID  string                                `json:"connection_id"`
	AccessMode    string                                `json:"access_mode"`
	Video         productgateway.BrowserLiveVideoPolicy `json:"video"`
	RecordingMode string                                `json:"recording_mode"`
}

func releaseLiveOffer(t *testing.T, control bool) (*webrtc.PeerConnection, *webrtc.DataChannel, webrtc.SessionDescription) {
	t.Helper()
	peer, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := peer.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	var channel *webrtc.DataChannel
	if control {
		channel, err = peer.CreateDataChannel(productgateway.BrowserLiveDataChannel, nil)
		if err != nil {
			t.Fatal(err)
		}
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
		t.Fatal("WebRTC gathering timed out")
	}
	return peer, channel, *peer.LocalDescription()
}

func releaseLiveSignalBody(t *testing.T, offer webrtc.SessionDescription, control bool, consent string) []byte {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"offer":                map[string]any{"type": "offer", "sdp": offer.SDP},
		"video":                map[string]any{"codec": "video/VP8", "width": 640, "height": 480, "max_fps": 30, "max_bitrate_kbps": 1000},
		"control_data_channel": control, "recording_consent_reference": consent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func releaseLiveRejected(t *testing.T, client *http.Client, gatewayAddress, ticket string) {
	t.Helper()
	peer, _, offer := releaseLiveOffer(t, true)
	defer peer.Close()
	request, _ := http.NewRequest(http.MethodPost, "https://"+gatewayAddress+"/browser/connect", bytes.NewReader(releaseLiveSignalBody(t, offer, true, "")))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", releaseOrigin)
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("viewer control status=%d", response.StatusCode)
	}
}

func releaseLiveRoundTrip(t *testing.T, client *http.Client, gatewayAddress, ticket string) {
	t.Helper()
	peer, channel, offer := releaseLiveOffer(t, true)
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
	request, _ := http.NewRequest(http.MethodPost, "https://"+gatewayAddress+"/browser/connect", bytes.NewReader(releaseLiveSignalBody(t, offer, true, "consent-phase4-release")))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", releaseOrigin)
	request.Header.Set("Authorization", "Ticket "+ticket)
	response, err := client.Do(request)
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		peer.Close()
		t.Fatalf("live signal status=%d body=%s", response.StatusCode, body)
	}
	var signal releaseLiveSignalResponse
	releaseDecode(t, response, &signal)
	if signal.Answer.Type != "answer" || signal.AccessMode != product.GrantAccessControl || signal.RecordingMode != "required" || signal.ConnectionID == "" {
		peer.Close()
		t.Fatalf("live signal=%#v", signal)
	}
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.Answer.SDP}); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	releaseWaitFor(t, 5*time.Second, func() bool { return peer.ConnectionState() == webrtc.PeerConnectionStateConnected }, "WebRTC connected")
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		peer.Close()
		t.Fatal("control data channel did not open")
	}
	if err := channel.SendText(`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":20,"y":30,"button":0,"delta_x":0,"delta_y":0,"user_activation":true}}`); err != nil {
		peer.Close()
		t.Fatal(err)
	}
	select {
	case message := <-results:
		if !message.IsString || !bytes.Contains(message.Data, []byte(`"type":"input.result"`)) || !bytes.Contains(message.Data, []byte(`"ok":true`)) {
			peer.Close()
			t.Fatalf("input result=%s", message.Data)
		}
	case <-time.After(5 * time.Second):
		peer.Close()
		t.Fatal("input result timed out")
	}
	select {
	case packet := <-packets:
		if packet.PayloadType != 96 || len(packet.Payload) == 0 {
			peer.Close()
			t.Fatalf("invalid RTP packet %#v", packet)
		}
	case <-time.After(5 * time.Second):
		peer.Close()
		t.Fatal("RTP packet timed out")
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
}

func releaseWaitRecording(t *testing.T, base, workspaceID string) string {
	t.Helper()
	var recordingID string
	releaseWaitFor(t, 10*time.Second, func() bool {
		response := releaseAPI(t, http.MethodGet, base+"/api/v1/workspaces/"+workspaceID+"/recordings?limit=50", "Bearer "+releaseOwnerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		var page productapiv1.RecordingPage
		releaseDecode(t, response, &page)
		for _, item := range page.Items {
			if item.RecordingType == "media" && item.State == "available" && item.SizeBytes != nil && *item.SizeBytes > 0 && strings.HasPrefix(item.Digest, "sha256:") {
				recordingID = item.RecordingID
				return true
			}
		}
		return false
	}, "available Browser recording")
	return recordingID
}

func releaseReplayRecording(t *testing.T, base, key, recordingID string) {
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
		t.Fatalf("recording replay status=%d body=%s", response.StatusCode, body)
	}
}

func releaseWaitFor(t *testing.T, timeout time.Duration, check func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func releaseWriteEvidence(t *testing.T, started, completed time.Time, objectRemoved, coordinationDrained bool) string {
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
	digest := "sha256:" + hex.EncodeToString(sum[:])
	roles := []string{"browser", "gateway", "product", "provider"}
	processes := make([]productphase4evidence.ProcessEvidence, 0, len(roles))
	for _, role := range roles {
		processes = append(processes, productphase4evidence.ProcessEvidence{Role: role, ExecutableDigest: digest, IndependentOSProcess: true})
	}
	cases := []string{
		"automation-roundtrip", "bounded-backpressure", "browser-live-recording-integrity", "browser-slot-session-lifecycle",
		"contract-identities", "exact-cleanup", "gateway-restart-recovery", "product-authentication",
		"product-restart-recovery", "provider-fault-closure", "tenant-nondisclosure", "viewer-controller-fencing",
	}
	scenarios := make([]productphase4evidence.ScenarioEvidence, 0, len(cases))
	for _, id := range cases {
		scenarios = append(scenarios, productphase4evidence.ScenarioEvidence{ID: id, Status: "passed"})
	}
	manifest := productphase4evidence.Manifest{
		SchemaVersion: 1, RunID: started.Format("20060102T150405.000000000Z"), Result: "passed", EvidenceTier: "same-repository-separate-process",
		SourceRevision: strings.TrimSpace(string(revision)), StartedAt: started.Format(time.RFC3339Nano), CompletedAt: completed.Format(time.RFC3339Nano),
		Provider:      productphase4evidence.ProviderIdentity{Revision: productphase4evidence.ProviderRevision, Tree: productphase4evidence.ProviderTree},
		Product:       productphase4evidence.ProductIdentity{Tree: report.TreeDigest, ResourceCount: report.ResourceCount, OperationCount: report.OperationCount, ConformanceCases: report.ConformanceCases},
		PostgreSQL:    productphase4evidence.ServiceIdentity{Profile: productphase4evidence.PostgresImage, Fresh: true},
		Coordination:  productphase4evidence.ServiceIdentity{Profile: productphase4evidence.ValkeyImage, Fresh: true},
		ObjectStorage: productphase4evidence.ServiceIdentity{Profile: productphase4evidence.ObjectStore, Fresh: true},
		Processes:     processes, Scenarios: scenarios,
		Cleanup:   productphase4evidence.CleanupEvidence{ChildProcessesReaped: true, ContainersRemoved: true, ScopedRowsRemoved: true, ObjectContentRemoved: objectRemoved, CoordinationDrained: coordinationDrained},
		NonClaims: []string{"deployment-qualified", "ha-qualified", "hostile-multi-tenant-qualified", "independent-caller-qualified", "production-ready"},
	}
	directory := os.Getenv("PRODUCT_PHASE4_EVIDENCE_OUTPUT")
	if directory == "" {
		directory, err = os.MkdirTemp("", "product-phase4-evidence-")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "product-phase-4-browser-evidence.json")
	document, _ := json.MarshalIndent(manifest, "", "  ")
	document = append(document, '\n')
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func releaseWriteJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
