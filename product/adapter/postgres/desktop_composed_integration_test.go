//go:build integration

package productpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productrecordinglocal "github.com/shell-echo/sandbox-runtime/product/adapter/recording/local"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopgateway "github.com/shell-echo/sandbox-runtime/provider/desktop/gateway"
	desktopreference "github.com/shell-echo/sandbox-runtime/provider/desktop/reference"
)

// TestIntegrationComposedDesktopProductFaultSecurityAndCleanup is the Slice 14
// cross-layer gate. It joins durable Product authority, the public WebRTC edge,
// the private Provider bridge, required recording, continuous policy authority,
// capacity recovery, and exact row/object/session cleanup.
func TestIntegrationComposedDesktopProductFaultSecurityAndCleanup(t *testing.T) { //nolint:cyclop
	pool := integrationProductPool(t)
	applyProductMigrations(t, pool)
	const tenantID = "tenant-desktop-composed-gate"
	cleanupProductTenant(t, pool, tenantID)
	ctx := context.Background()
	store, err := New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ids := product.CryptoIDGenerator{}
	application, _ := product.NewApplication(store, allowPrimarySlot{}, ids)
	slots, _ := product.NewSlotService(store, allowDesktopSlot{}, ids)
	sessions, _ := product.NewSessionService(store, allowDesktopSession{}, ids)
	controls, _ := product.NewControlService(store, ids)
	actor := product.ActorRef{Type: product.ActorHuman, ID: "desktop-composed-owner"}
	created, err := application.CreateWorkspace(ctx, tenantID, actor, "desktop-composed-workspace", integrationCreateWorkspaceRequest("Desktop composed gate"))
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE sandbox_runtime_product.workspaces SET observed_state='active' WHERE tenant_id=$1`,
		`UPDATE sandbox_runtime_product.workspace_slots SET observed_state='ready',observed_generation=generation WHERE tenant_id=$1 AND slot_key='primary-code'`,
		`UPDATE sandbox_runtime_product.outbox SET state='delivered' WHERE tenant_id=$1 AND message_type='workspace.reconcile'`,
	} {
		if _, err := pool.Exec(ctx, statement, tenantID); err != nil {
			t.Fatal(err)
		}
	}
	ready := prepareReadyDesktopGrantSession(t, store, application, slots, sessions, tenantID, actor, created.Operation.WorkspaceID, "desktop-main", "composed-gate")
	if _, err := pool.Exec(ctx, `UPDATE sandbox_runtime_product.runtime_sessions SET recording_policy='required' WHERE tenant_id=$1 AND session_id=$2`, tenantID, ready.ID); err != nil {
		t.Fatal(err)
	}
	workspace, err := application.GetWorkspace(ctx, tenantID, actor, created.Operation.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	lease, _, err := controls.Acquire(ctx, tenantID, actor, workspace.ID, "desktop-composed-control", product.AcquireControlLeaseRequest{
		ExpectedWorkspaceVersion: workspace.Version, Scope: product.ControlScope{Type: "session", ID: ready.ID}, DurationSeconds: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	policyService, _ := product.NewDesktopPolicyService(store, ids)
	if _, _, err := policyService.Put(ctx, tenantID, actor, workspace.ID, "desktop-composed-policy-v1", 0, integrationDesktopPolicy(1)); err != nil {
		t.Fatal(err)
	}

	grantRepository, err := NewGrantRepository(store, "desktop-composed-grant-v1", bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := product.NewGrantService(grantRepository, ids, product.CryptoTicketGenerator{}, "https://desktop.example.test/connect", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	grant, _, err := grants.Create(ctx, tenantID, actor, ready.ID, "desktop-composed-grant", product.CreateConnectionRequest{
		ExpectedSessionVersion: ready.Version, ProtocolProfile: product.SessionProfileDesktop,
		AccessMode: product.GrantAccessControl, ControlLeaseID: lease.ID, ControlFence: lease.Fence,
	})
	if err != nil {
		t.Fatal(err)
	}

	expires := ready.ExpiresAt.UTC()
	binding := product.GatewayBinding{SessionID: ready.ID, SandboxID: "provider-desktop-grant-composed-gate",
		HandoffReference: "ref:desktop-session:opaque-composed-gate", ConnectionGeneration: 7,
		HandoffExpiresAt: expires, ProviderRevisionID: strings.Repeat("d", 40)}
	resolver := &composedDesktopResolver{binding: binding}
	providerMedia := newComposedDesktopMedia()
	privateHandler, err := desktopgateway.New(desktopgateway.Options{
		Resolver: resolver, Media: providerMedia, MaxSessions: 1, MaxSessionsPerDesktop: 1,
		AuthorityPollInterval: 10 * time.Millisecond, OperationTimeout: time.Second, AllowInsecureHTTPForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	privateServer := httptest.NewServer(privateHandler)
	defer privateServer.Close()
	privateSource, err := productgateway.NewPrivateDesktopMediaSource(productgateway.PrivateDesktopMediaOptions{
		Origin: strings.Replace(privateServer.URL, "http://", "ws://", 1), HTTPClient: privateServer.Client(),
		AllowHTTPForTests: true, ExpectedProviderID: strings.Repeat("d", 40), OpenTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	recordingRoot := filepath.Join(t.TempDir(), "objects")
	content, err := productrecordinglocal.New(recordingRoot, bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	redactor, _ := product.NewPatternRedactor([]string{"SECRET"})
	recordings, _ := product.NewRecordingService(store, content, redactor, ids, nil)
	recorder, _ := productgateway.NewProductDesktopLiveRecorder(recordings, 3600)
	audit, _ := NewGatewayAuditRepository(store, ids)
	publicHandler, err := productgateway.NewDesktopLiveHandler(productgateway.DesktopLiveOptions{
		Grants: grantRepository, Media: privateSource, Policy: store,
		Transfers: &productgateway.ProductTransferDesktopAuthority{Store: store}, Audit: audit, Recorder: recorder,
		AllowedOrigins: []string{"https://app.example.test"}, MaxPeers: 1, MaxPeersPerSession: 1,
		AuthorityPollInterval: 10 * time.Millisecond, ConnectionTimeout: 5 * time.Second,
		DisconnectGrace: 200 * time.Millisecond, MinKeyframeInterval: 50 * time.Millisecond,
		MinResyncInterval: 50 * time.Millisecond, AllowInsecureHTTPForTests: true, AllowHostCandidatesForTests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicServer := httptest.NewServer(publicHandler)
	defer publicServer.Close()

	badRequest, _ := http.NewRequest(http.MethodPost, publicServer.URL, strings.NewReader(`{}`))
	badRequest.Header.Set("Origin", "https://evil.example.test")
	badRequest.Header.Set("Authorization", "Ticket "+grant.Ticket)
	badResponse, err := publicServer.Client().Do(badRequest)
	if err != nil {
		t.Fatal(err)
	}
	badResponse.Body.Close()
	if badResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", badResponse.StatusCode)
	}

	peer, channel, offer := composedDesktopOffer(t)
	defer peer.Close()
	trackPackets := make(chan struct{}, 1)
	peer.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if _, _, err := track.ReadRTP(); err == nil {
			trackPackets <- struct{}{}
		}
	})
	inputResult := make(chan []byte, 1)
	channel.OnOpen(func() {
		_ = channel.SendText(`{"type":"input","sequence":1,"action":{"kind":"pointer","event":"move","x":100,"y":120,"button":0,"delta_x":0,"delta_y":0,"user_activation":true}}`)
	})
	channel.OnMessage(func(message webrtc.DataChannelMessage) { inputResult <- append([]byte(nil), message.Data...) })
	signal := composedDesktopSignal(t, publicServer, grant.Ticket, offer)
	if signal.RecordingMode != "required" || signal.AccessMode != product.GrantAccessControl {
		t.Fatalf("signal=%#v", signal)
	}
	if err := peer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: signal.Answer.SDP}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-trackPackets:
	case <-time.After(5 * time.Second):
		t.Fatal("composed Desktop display packet timed out")
	}
	select {
	case response := <-inputResult:
		if !bytes.Contains(response, []byte(`"ok":true`)) {
			t.Fatalf("input response=%s", response)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("composed Desktop input timed out")
	}
	select {
	case input := <-providerMedia.inputs:
		if input.Kind != "pointer" || input.ControlLeaseID != lease.ID || input.ControlFence != lease.Fence {
			t.Fatalf("private input=%#v", input)
		}
	case <-time.After(time.Second):
		t.Fatal("private Provider input not observed")
	}

	replayedRequest, _ := http.NewRequest(http.MethodPost, publicServer.URL, bytes.NewReader(composedDesktopSignalBody(t, offer)))
	replayedRequest.Header.Set("Origin", "https://app.example.test")
	replayedRequest.Header.Set("Authorization", "Ticket "+grant.Ticket)
	replayedResponse, err := publicServer.Client().Do(replayedRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedResponse.Body.Close()
	if replayedResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ticket replay status=%d", replayedResponse.StatusCode)
	}

	if _, _, err := policyService.Put(ctx, tenantID, actor, workspace.ID, "desktop-composed-policy-v2", 1, integrationDesktopPolicy(2)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !providerMedia.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !providerMedia.closed.Load() {
		t.Fatal("policy replacement did not close private Provider media")
	}

	catalog, _ := product.NewCatalogService(store, ids)
	var recording product.Recording
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		page, listErr := catalog.ListRecordings(ctx, tenantID, actor, workspace.ID, "", 10)
		if listErr == nil && len(page.Items) == 1 && page.Items[0].State == "available" {
			recording = page.Items[0]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if recording.ID == "" {
		t.Fatal("required Desktop recording did not finalize")
	}
	if _, err := recordings.Replay(ctx, tenantID, product.ActorRef{Type: product.ActorHuman, ID: "foreign-owner"}, recording.ID); !errors.Is(err, product.ErrNotFound) {
		t.Fatalf("cross-owner replay err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sandbox_runtime_product.recordings SET started_at=clock_timestamp()-interval '2 hours',retention_expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND recording_id=$2`, tenantID, recording.ID); err != nil {
		t.Fatal(err)
	}
	if cleaned, err := recordings.CleanupExpired(ctx, 10); err != nil || cleaned != 1 {
		t.Fatalf("recording cleanup=%d err=%v", cleaned, err)
	}
	entries, err := os.ReadDir(filepath.Join(recordingRoot, "recordings"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("recording objects remain=%v err=%v", entries, err)
	}

	deleteComposedDesktopTenant(t, pool, tenantID)
	for _, table := range []string{"workspaces", "runtime_sessions", "connection_grants", "desktop_policy_revisions", "recordings", "security_audit"} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.`+table+` WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("retained %s rows=%d err=%v", table, count, err)
		}
	}
}

type composedDesktopDescription struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type composedDesktopSignalResponse struct {
	Answer        composedDesktopDescription `json:"answer"`
	AccessMode    string                     `json:"access_mode"`
	RecordingMode string                     `json:"recording_mode"`
}

func composedDesktopOffer(t *testing.T) (*webrtc.PeerConnection, *webrtc.DataChannel, webrtc.SessionDescription) {
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
	case <-time.After(3 * time.Second):
		t.Fatal("Desktop ICE gathering timed out")
	}
	return peer, channel, *peer.LocalDescription()
}

func composedDesktopSignal(t *testing.T, server *httptest.Server, ticket string, offer webrtc.SessionDescription) composedDesktopSignalResponse {
	t.Helper()
	body := composedDesktopSignalBody(t, offer)
	request, _ := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(body))
	request.Header.Set("Origin", "https://app.example.test")
	request.Header.Set("Authorization", "Ticket "+ticket)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	document, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Desktop signal status=%d body=%s", response.StatusCode, document)
	}
	var result composedDesktopSignalResponse
	if err := json.Unmarshal(document, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func composedDesktopSignalBody(t *testing.T, offer webrtc.SessionDescription) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"offer":                map[string]string{"type": "offer", "sdp": offer.SDP},
		"media":                map[string]any{"video_codec": "video/VP8", "width": 1280, "height": 720, "max_fps": 30, "max_video_bitrate_kbps": 2000},
		"control_data_channel": true, "recording_consent_reference": "consent-desktop-composed-gate",
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type composedDesktopResolver struct {
	binding product.GatewayBinding
	revoked atomic.Bool
}

func (r *composedDesktopResolver) Resolve(_ context.Context, reference string) (desktopreference.Endpoint, error) {
	if r.revoked.Load() || reference != r.binding.HandoffReference {
		return desktopreference.Endpoint{}, desktopreference.ErrRevoked
	}
	return desktopreference.Endpoint{Reference: reference, SandboxID: r.binding.SandboxID, DesktopSessionID: r.binding.SessionID,
		CapabilityProfileID: product.DesktopCapabilityProfile, ConnectionGeneration: r.binding.ConnectionGeneration,
		ExpiresAt: r.binding.HandoffExpiresAt,
		Attach: func(context.Context) (providerdesktop.Attachment, error) {
			return providerdesktop.Attachment{DesktopSessionID: r.binding.SessionID, ConnectionGeneration: r.binding.ConnectionGeneration,
				MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID,
				DisplayReference: "ref:desktop-display:primary", Width: 1280, Height: 720, Depth: 24,
				PrivateInputModes: []string{"keyboard", "pointer"}, AttachedAt: time.Now().UTC()}, nil
		}}, nil
}

type composedDesktopMedia struct {
	inputs    chan desktopgateway.Input
	closed    atomic.Bool
	closeOnce sync.Once
	stop      chan struct{}
	sequence  atomic.Uint32
	timestamp atomic.Uint32
}

func newComposedDesktopMedia() *composedDesktopMedia {
	return &composedDesktopMedia{inputs: make(chan desktopgateway.Input, 4), stop: make(chan struct{})}
}

func (m *composedDesktopMedia) Open(context.Context, desktopreference.Endpoint, providerdesktop.Attachment, desktopgateway.MediaPolicy) (desktopgateway.Session, error) {
	return m, nil
}

func (m *composedDesktopMedia) ReadVideoRTP(ctx context.Context) ([]byte, error) {
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.stop:
		return nil, io.EOF
	case <-timer.C:
	}
	packet := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: uint16(m.sequence.Add(1)), Timestamp: m.timestamp.Add(3000), SSRC: 0x50354431, Marker: true}, Payload: []byte{0x10, 0x00, 0x01}}
	return packet.Marshal()
}

func (m *composedDesktopMedia) ReadAudioRTP(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.stop:
		return nil, io.EOF
	}
}

func (m *composedDesktopMedia) HandleInput(ctx context.Context, input desktopgateway.Input) (desktopgateway.InputResult, error) {
	select {
	case m.inputs <- input:
		return desktopgateway.InputResult{}, nil
	case <-ctx.Done():
		return desktopgateway.InputResult{}, ctx.Err()
	}
}

func (*composedDesktopMedia) UpdateStream(context.Context, desktopgateway.DisplayPolicy, string) error {
	return nil
}
func (*composedDesktopMedia) Resynchronize(context.Context) error   { return nil }
func (*composedDesktopMedia) RequestKeyframe(context.Context) error { return nil }
func (m *composedDesktopMedia) Close() error {
	m.closeOnce.Do(func() { m.closed.Store(true); close(m.stop) })
	return nil
}

func deleteComposedDesktopTenant(t *testing.T, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	for _, statement := range []string{
		`DELETE FROM sandbox_runtime_product.recording_segments WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.recordings WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.connection_grants WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.control_lease_fences WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.provider_bindings WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.product_operation_attempts WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.security_audit WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.idempotency_records WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.outbox WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.workspace_events WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.workspace_slots WHERE tenant_id=$1`,
		`DELETE FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1`,
	} {
		if _, err := pool.Exec(context.Background(), statement, tenantID); err != nil {
			t.Fatalf("cleanup composed Desktop tenant: %v", err)
		}
	}
}

var (
	_ desktopgateway.Resolver    = (*composedDesktopResolver)(nil)
	_ desktopgateway.MediaSource = (*composedDesktopMedia)(nil)
	_ desktopgateway.Session     = (*composedDesktopMedia)(nil)
)
