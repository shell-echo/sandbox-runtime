package productprovider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func TestDesktopClientProvisionLifecycleSessionObservationAndClose(t *testing.T) {
	now := time.Date(2026, 9, 19, 8, 0, 0, 0, time.UTC)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	var sandboxID string
	var openBodies [][]byte
	expiresAt := now.Add(10 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/capabilities" &&
			(request.Header.Get("Authorization") == "" || request.Header.Get("X-Sandbox-Runtime-Admission-Context") == "") {
			t.Fatal("Desktop Provider request was not protected")
		}
		switch request.URL.Path {
		case "/v1/capabilities":
			writeJSON(t, writer, desktopCapabilities())
		case "/v1/sandboxes":
			var body providerv1.CreateRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			workspaceBytes := body.Spec.Resources.WorkspaceBytes
			if body.Spec.RuntimeProfile != product.DesktopSlotProfile || len(body.Spec.RequiredCapabilities) != 1 ||
				body.Spec.RequiredCapabilities[0] != (providerv1.CapabilityRequirement{ID: product.DesktopCapabilityID, Version: product.DesktopCapabilityVersion, Profile: product.DesktopCapabilityProfile}) ||
				body.Spec.Network.Mode != providerv1.NetworkRestricted || body.Spec.Network.PolicyReference != "desktop-egress-policy-1" ||
				body.Spec.Network.EgressGatewayRequired == nil || !*body.Spec.Network.EgressGatewayRequired ||
				body.Spec.PlacementConstraints == nil || body.Spec.PlacementConstraints.ResourceClass != providerv1.ResourceDesktop ||
				workspaceBytes == nil || *workspaceBytes != 4<<30 || body.Spec.Image.Reference != desktopimage.LockedPublication().Image() ||
				body.Spec.Security.PrivilegeLevel != providerv1.PrivilegeUnprivileged || body.Spec.Security.RootFilesystem != providerv1.RootFilesystemReadOnly {
				t.Fatalf("Desktop create shape=%#v", body.Spec)
			}
			sandboxID = body.Spec.SandboxID
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerOperation(body.OperationID, body.AttemptID, sandboxID, body.FencingToken, providerv1.OperationCreate, "provider-create", now))
		case "/v1/sandboxes/desktop-sandbox-1/desired-state":
			var body providerv1.DesiredStateRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedGeneration != 7 || body.FencingToken != 4 || body.DesiredState != providerv1.RequestedStateReady {
				t.Fatalf("Desktop lifecycle confused Provider/Product generations: %#v", body)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerOperation(body.OperationID, body.AttemptID, "desktop-sandbox-1", body.FencingToken, providerv1.OperationResume, "provider-resume", now))
		case "/v1/sandboxes/desktop-sandbox-1/desktop-sessions":
			var raw json.RawMessage
			if err := json.NewDecoder(request.Body).Decode(&raw); err != nil {
				t.Fatal(err)
			}
			mutex.Lock()
			openBodies = append(openBodies, append([]byte(nil), raw...))
			mutex.Unlock()
			var body providerv1.DesktopSessionOpenRequest
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedGeneration != 7 || body.FencingToken != 3 || body.CapabilityProfileID != product.DesktopCapabilityProfile {
				t.Fatalf("Desktop open body=%#v", body)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerOperation(body.OperationID, body.AttemptID, "desktop-sandbox-1", body.FencingToken, providerv1.OperationOpenDesktopSession, "provider-open", now))
		case "/v1/operations/op-desktop-open":
			operation := providerOperation("op-desktop-open", "out-desktop-open", "desktop-sandbox-1", 3, providerv1.OperationOpenDesktopSession, "provider-open", now.Add(time.Second))
			operation.Status = providerv1.OperationSucceeded
			writeJSON(t, writer, operation)
		case "/v1/operations/op-desktop-open/desktop-session":
			if request.Header.Get("Authorization") == "" || request.Header.Get("X-Sandbox-Runtime-Admission-Context") == "" {
				t.Fatal("Desktop handoff read was not protected")
			}
			writeJSON(t, writer, providerv1.DesktopSessionHandoff{OperationID: "op-desktop-open", AttemptID: "out-desktop-open",
				FencingToken: 3, SandboxID: "desktop-sandbox-1", DesktopSessionID: "ses-desktop-1",
				CapabilityProfileID: product.DesktopCapabilityProfile, Protocol: providerv1.DesktopProtocolWebRTC,
				MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1",
				InternalEndpointReference: "ref:desktop-session:opaque-1", ConnectionGeneration: 11,
				ExpiresAt: expiresAt.Format(time.RFC3339Nano)})
		case "/v1/sandboxes/desktop-sandbox-1/desktop-sessions/ses-desktop-1:close":
			var body providerv1.DesktopSessionCloseRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedGeneration != 7 || body.FencingToken != 3 || body.ConnectionGeneration != 11 || body.Reason != "owner_requested_close" {
				t.Fatalf("Desktop close body=%#v", body)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerOperation(body.OperationID, body.AttemptID, "desktop-sandbox-1", body.FencingToken, providerv1.OperationCloseDesktopSession, "provider-close", now))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	client := newDesktopTestClient(t, server, key, now, 0)
	work := desktopTestWork(now)
	if err := client.AuthorizeSlot(context.Background(), work.Slot); err != nil {
		t.Fatal(err)
	}
	created, err := client.ProvisionDesktopSlot(context.Background(), work)
	if err != nil || created.State != "accepted" || created.SandboxID != sandboxID {
		t.Fatalf("created=%#v sandbox=%q err=%v", created, sandboxID, err)
	}

	lifecycle := work
	lifecycle.Action, lifecycle.PreviousGeneration, lifecycle.SlotGeneration, lifecycle.FencingToken = "resume", 3, 4, 4
	lifecycle.ProviderGeneration, lifecycle.ProviderRevisionID, lifecycle.SandboxID = 7, LockedDesktopProviderRevision, "desktop-sandbox-1"
	if evidence, err := client.ControlDesktopSlot(context.Background(), lifecycle); err != nil || evidence.ProviderOperationID != "provider-resume" {
		t.Fatalf("lifecycle=%#v err=%v", evidence, err)
	}

	session := product.SessionControlWork{TenantID: "tenant-1", WorkspaceID: "wrk-1", SlotKey: "desktop-main",
		SessionID: "ses-desktop-1", OperationID: "op-desktop-open", AttemptID: "out-desktop-open",
		SlotGeneration: 3, FencingToken: 3, ProviderGeneration: 7, RuntimeProfileID: product.DesktopSlotProfile,
		SandboxID: "desktop-sandbox-1", ProviderRevisionID: LockedDesktopProviderRevision,
		Kind: product.SessionKindDesktop, ProtocolProfile: product.SessionProfileDesktop, ExpiresAt: expiresAt, Action: "open"}
	first, err := client.ExecuteDesktopSessionControl(context.Background(), session)
	if err != nil || first.State != "accepted" {
		t.Fatalf("open=%#v err=%v", first, err)
	}
	second, err := client.ExecuteDesktopSessionControl(context.Background(), session)
	if err != nil || second.RequestDigest != first.RequestDigest {
		t.Fatalf("replay=%#v first=%#v err=%v", second, first, err)
	}
	mutex.Lock()
	if len(openBodies) != 2 || string(openBodies[0]) != string(openBodies[1]) {
		t.Fatalf("Desktop replay changed wire body: %q != %q", openBodies[0], openBodies[1])
	}
	mutex.Unlock()

	observed, err := client.ObserveOperation(context.Background(), product.ProviderObservationWork{TenantID: session.TenantID,
		WorkspaceID: session.WorkspaceID, OperationID: session.OperationID, AttemptID: session.AttemptID,
		SlotKey: session.SlotKey, SlotGeneration: session.SlotGeneration, FencingToken: session.FencingToken,
		RuntimeProfileID: session.RuntimeProfileID, SandboxID: session.SandboxID, ProviderOperationID: first.ProviderOperationID,
		ProviderRevisionID: session.ProviderRevisionID, ProviderGeneration: session.ProviderGeneration, SessionID: session.SessionID,
		OperationType: "create_session", ProviderAction: "open_desktop_session", SessionKind: session.Kind,
		ProtocolProfile: session.ProtocolProfile, SessionExpiresAt: session.ExpiresAt})
	if err != nil || observed.State != "succeeded" || observed.HandoffReference != "ref:desktop-session:opaque-1" ||
		observed.ConnectionGeneration != 11 || !observed.HandoffExpiresAt.Equal(expiresAt) {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	encoded, _ := json.Marshal(observed)
	if strings.Contains(string(encoded), "webrtc://") || strings.Contains(string(encoded), "127.0.0.1") {
		t.Fatalf("private Desktop coordinate leaked: %s", encoded)
	}

	session.Action, session.OperationID, session.AttemptID = "close", "op-desktop-close", "out-desktop-close"
	session.ConnectionGeneration, session.Reason = 11, "owner_requested_close"
	closed, err := client.ExecuteDesktopSessionControl(context.Background(), session)
	if err != nil || closed.ProviderOperationID != "provider-close" {
		t.Fatalf("close=%#v err=%v", closed, err)
	}
}

func TestDesktopClientFailsClosedOnLockDriftCancellationAndTimeout(t *testing.T) {
	now := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/capabilities" {
			http.NotFound(writer, request)
			return
		}
		time.Sleep(50 * time.Millisecond)
		writeJSON(t, writer, desktopCapabilities())
	}))
	defer server.Close()
	config := desktopTestConfig(server, key, now, 0)
	config.ExpectedTree = LockedProviderTree
	if _, err := NewDesktop(config); !errorsIs(err, product.ErrInvalid) {
		t.Fatalf("legacy Contract tree accepted for Desktop: %v", err)
	}
	config = desktopTestConfig(server, key, now, 0)
	config.Profiles[0].ImageReference = "registry.invalid/desktop:latest"
	if _, err := NewDesktop(config); !errorsIs(err, product.ErrInvalid) {
		t.Fatalf("mutable Desktop image accepted: %v", err)
	}

	client := newDesktopTestClient(t, server, key, now, 10*time.Millisecond)
	if err := client.AuthorizeSlot(context.Background(), desktopTestWork(now).Slot); !errorsIs(err, product.ErrStoreUnavailable) {
		t.Fatalf("request timeout err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.AuthorizeSession(ctx, product.SessionKindDesktop, product.SessionProfileDesktop); err != context.Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
}

func TestDesktopClientRejectsCapabilityAndHandoffDrift(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		snapshot := desktopCapabilities()
		snapshot.RuntimeProfiles[0].RuntimeClassName = "unexpected-runtime"
		writeJSON(t, writer, snapshot)
	}))
	defer server.Close()
	client := newDesktopTestClient(t, server, key, now, 0)
	if err := client.AuthorizeSlot(context.Background(), desktopTestWork(now).Slot); !errorsIs(err, product.ErrCapabilityUnsupported) {
		t.Fatalf("Desktop runtime drift err=%v", err)
	}
}

func newDesktopTestClient(t *testing.T, server *httptest.Server, key ed25519.PrivateKey, now time.Time, requestTimeout time.Duration) *Client {
	t.Helper()
	client, err := NewDesktop(desktopTestConfig(server, key, now, requestTimeout))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func desktopTestConfig(server *httptest.Server, key ed25519.PrivateKey, now time.Time, requestTimeout time.Duration) Config {
	publication := desktopimage.LockedPublication()
	return Config{Origin: server.URL, HTTPClient: server.Client(), ExpectedRevisionID: LockedDesktopProviderRevision,
		ExpectedTree: LockedDesktopProviderTree, ProviderResolutionID: "provider-desktop", AllowHTTPForTests: true,
		Clock: fixedClock{now}, RequestTimeout: requestTimeout,
		Authority: Authority{Issuer: "https://product.example.test/controller", Subject: "spiffe://product/controller",
			Audience: "urn:shell-echo:sandbox-runtime:provider-instance:test", KeyID: "product-key-1", PrivateKey: key},
		Profiles: []Profile{{ProductProfileID: product.DesktopSlotProfile, RuntimeProfileID: product.DesktopSlotProfile,
			ImageReference: publication.Image(), ImageDigest: publication.Digest, Architecture: providerv1.ArchitectureAMD64,
			CPUMillis: 4000, MemoryBytes: 4 << 30, EphemeralBytes: 8 << 30, WorkspaceBytes: 4 << 30, PIDsLimit: 512,
			BaseRevisionID: "revision-empty", BaseRevisionDigest: "sha256:" + strings.Repeat("e", 64),
			PolicyDigest: "sha256:" + strings.Repeat("b", 64), NetworkPolicyReference: "desktop-egress-policy-1"}}}
}

func desktopCapabilities() providerv1.Capabilities {
	workspaceBytes := int64(16 << 30)
	return providerv1.Capabilities{ProviderRevisionID: LockedDesktopProviderRevision, APIVersion: providerv1.APIVersionV1,
		Capabilities: []providerv1.Capability{{ID: providerv1.CapabilityDesktop, Versions: []string{product.DesktopCapabilityVersion}, Profiles: []string{product.DesktopCapabilityProfile}}},
		RuntimeProfiles: []providerv1.RuntimeProfile{{ID: product.DesktopSlotProfile, IsolationClass: providerv1.IsolationContainer,
			RuntimeClassName: desktopimage.RuntimeClassName, Architecture: []providerv1.Architecture{providerv1.ArchitectureAMD64, providerv1.ArchitectureARM64},
			CapabilityProfileIDs: []string{product.DesktopCapabilityProfile}}},
		Limits: providerv1.ProviderLimits{MaxCPUMillis: 16000, MaxMemoryBytes: 16 << 30, MaxEphemeralStorageBytes: 32 << 30,
			MaxWorkspaceBytes: &workspaceBytes, MaxLeaseSeconds: 86400}}
}

func desktopTestWork(now time.Time) product.ReconcileWork {
	return product.ReconcileWork{TenantID: "tenant-1", OutboxID: "desktop-out-1", AttemptID: "desktop-out-1", LeaseOwner: "desktop-worker",
		WorkspaceID: "wrk-1", OperationID: "desktop-op-1", SlotKey: "desktop-main", SlotGeneration: 1, FencingToken: 1,
		WorkspaceExpiry: now.Add(time.Hour), Slot: product.SlotSpec{SlotKey: "desktop-main", Kind: product.DesktopSlotKind,
			ProfileID: product.DesktopSlotProfile, DesiredState: "ready", RequiredCapabilities: []product.CapabilityRequirement{{
				CapabilityID: product.DesktopCapabilityID, Version: product.DesktopCapabilityVersion, ProfileID: product.DesktopCapabilityProfile}}}}
}

func providerOperation(operationID, attemptID, sandboxID string, fence int64, operationType providerv1.OperationType, providerOperationID string, observedAt time.Time) providerv1.Operation {
	return providerv1.Operation{OperationID: operationID, AttemptID: attemptID, FencingToken: fence, SandboxID: sandboxID,
		Type: operationType, Status: providerv1.OperationAccepted, ProviderOperationID: providerOperationID,
		ObservedAt: observedAt.Format(time.RFC3339Nano)}
}
