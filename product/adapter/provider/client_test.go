package productprovider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

func TestClientDiscoversExactProfileAndSendsProtectedCreate(t *testing.T) {
	now := time.Date(2026, 9, 18, 4, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var sawCreate bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			if request.Header.Get("Authorization") != "" || request.Body == nil {
				t.Errorf("discovery request carried protected metadata")
			}
			writeJSON(t, writer, providerv1.Capabilities{ProviderRevisionID: LockedProviderRevision, APIVersion: providerv1.APIVersionV1,
				Capabilities:    []providerv1.Capability{{ID: providerv1.CapabilityExec, Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}}},
				RuntimeProfiles: []providerv1.RuntimeProfile{{ID: "provider-shell-v1", IsolationClass: providerv1.IsolationContainer, CapabilityProfileIDs: []string{"exec-v1"}}}})
		case "/v1/sandboxes":
			sawCreate = true
			if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
				t.Error("missing bearer")
			}
			parts := strings.Split(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "), ".")
			if len(parts) != 3 {
				t.Fatalf("JWS parts = %d", len(parts))
			}
			signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
			if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
				t.Error("invalid JWS signature")
			}
			contextBytes, err := base64.RawURLEncoding.DecodeString(request.Header.Get("X-Sandbox-Runtime-Admission-Context"))
			if err != nil {
				t.Fatal(err)
			}
			var contextValue admissionContext
			if err := json.Unmarshal(contextBytes, &contextValue); err != nil {
				t.Fatal(err)
			}
			if contextValue.ProviderRevisionID != LockedProviderRevision || contextValue.Operation != "create" || contextValue.RequestDigest == "" {
				t.Fatalf("context = %#v", contextValue)
			}
			var body providerv1.CreateRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			digest, err := requestDigest(body)
			if err != nil || digest != string(body.RequestDigest) || digest != contextValue.RequestDigest {
				t.Fatalf("digest = %q body=%q context=%q err=%v", digest, body.RequestDigest, contextValue.RequestDigest, err)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerv1.Operation{OperationID: body.OperationID, AttemptID: body.AttemptID,
				FencingToken: body.FencingToken, SandboxID: body.Spec.SandboxID, Type: providerv1.OperationCreate,
				Status: providerv1.OperationAccepted, ProviderOperationID: "provider-op-1", ObservedAt: now.Format(time.RFC3339Nano)})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	client := newTestClient(t, server, privateKey, now)
	work := testWork(now)
	if err := client.AuthorizePrimarySlot(context.Background(), work.Slot); err != nil {
		t.Fatal(err)
	}
	evidence, err := client.ProvisionPrimarySlot(context.Background(), work)
	if err != nil {
		t.Fatal(err)
	}
	if !sawCreate || evidence.State != "accepted" || evidence.ProviderOperationID != "provider-op-1" || evidence.SandboxID == "" {
		t.Fatalf("evidence = %#v", evidence)
	}
}

func TestClientFailsClosedOnRevisionAndAmbiguousResponse(t *testing.T) {
	now := time.Date(2026, 9, 18, 4, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	t.Run("revision", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, providerv1.Capabilities{ProviderRevisionID: "different", APIVersion: providerv1.APIVersionV1})
		}))
		defer server.Close()
		client := newTestClient(t, server, key, now)
		if err := client.AuthorizePrimarySlot(context.Background(), testWork(now).Slot); err == nil {
			t.Fatal("revision drift accepted")
		}
	})
	t.Run("ambiguous", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/capabilities" {
				writeJSON(t, w, providerv1.Capabilities{ProviderRevisionID: LockedProviderRevision, APIVersion: providerv1.APIVersionV1,
					Capabilities:    []providerv1.Capability{{ID: providerv1.CapabilityExec, Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}}},
					RuntimeProfiles: []providerv1.RuntimeProfile{{ID: "provider-shell-v1", IsolationClass: providerv1.IsolationContainer, CapabilityProfileIDs: []string{"exec-v1"}}}})
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"operation_id":"substituted"}`))
		}))
		defer server.Close()
		client := newTestClient(t, server, key, now)
		evidence, err := client.ProvisionPrimarySlot(context.Background(), testWork(now))
		if !errorsIs(err, product.ErrDispatchOutcomeUnknown) || !evidence.OutcomeUnknown {
			t.Fatalf("evidence=%#v err=%v", evidence, err)
		}
	})
}

func TestClientBrowserSlotUsesLockedRestrictedProviderShape(t *testing.T) {
	now := time.Date(2026, 9, 18, 5, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	var sawCreate bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			writeJSON(t, writer, browserCapabilities())
		case "/v1/sandboxes":
			sawCreate = true
			var body providerv1.CreateRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Spec.RuntimeProfile != product.BrowserSlotProfile || len(body.Spec.RequiredCapabilities) != 1 ||
				body.Spec.RequiredCapabilities[0] != (providerv1.CapabilityRequirement{ID: product.BrowserCapabilityID, Version: product.BrowserCapabilityVersion, Profile: product.BrowserCapabilityProfile}) ||
				body.Spec.Network.Mode != providerv1.NetworkRestricted || body.Spec.Network.PolicyReference != "browser-egress-policy-1" ||
				body.Spec.Network.EgressGatewayRequired == nil || !*body.Spec.Network.EgressGatewayRequired ||
				body.Spec.PlacementConstraints == nil || body.Spec.PlacementConstraints.ResourceClass != providerv1.ResourceBrowser {
				t.Fatalf("browser create shape=%#v", body.Spec)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerv1.Operation{OperationID: body.OperationID, AttemptID: body.AttemptID,
				FencingToken: body.FencingToken, SandboxID: body.Spec.SandboxID, Type: providerv1.OperationCreate,
				Status: providerv1.OperationAccepted, ProviderOperationID: "provider-browser-create-1", ObservedAt: now.Format(time.RFC3339Nano)})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	client := newBrowserTestClient(t, server, key, now)
	work := browserTestWork(now)
	if err := client.AuthorizeSlot(context.Background(), work.Slot); err != nil {
		t.Fatal(err)
	}
	evidence, err := client.ProvisionBrowserSlot(context.Background(), work)
	if err != nil || !sawCreate || evidence.State != "accepted" || evidence.ProviderOperationID != "provider-browser-create-1" {
		t.Fatalf("evidence=%#v sawCreate=%v err=%v", evidence, sawCreate, err)
	}
}

func TestClientBrowserSessionOpenAndOpaqueHandoff(t *testing.T) {
	now := time.Date(2026, 9, 18, 5, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	work := product.SessionControlWork{TenantID: "tenant-1", WorkspaceID: "wrk-1", SlotKey: "browser-main",
		SessionID: "browser-session-1", OperationID: "browser-operation-1", AttemptID: "browser-attempt-1",
		SlotGeneration: 1, RuntimeProfileID: product.BrowserSlotProfile, SandboxID: "browser-sandbox-1",
		ProviderRevisionID: LockedProviderRevision, Kind: product.SessionKindBrowserAutomation,
		ProtocolProfile: product.SessionProfileBrowserAutomation, ExpiresAt: now.Add(time.Minute), Action: "open"}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			writeJSON(t, writer, browserCapabilities())
		case "/v1/sandboxes/browser-sandbox-1/browser-sessions":
			var body providerv1.BrowserSessionOpenRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.BrowserSessionID != work.SessionID || body.CapabilityProfileID != product.BrowserCapabilityProfile || body.ExpectedGeneration != work.SlotGeneration {
				t.Fatalf("open body=%#v", body)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerv1.Operation{OperationID: work.OperationID, AttemptID: work.AttemptID,
				FencingToken: work.SlotGeneration, SandboxID: work.SandboxID, Type: providerv1.OperationOpenBrowserSession,
				Status: providerv1.OperationAccepted, ProviderOperationID: "provider-browser-open-1", ObservedAt: now.Format(time.RFC3339Nano)})
		case "/v1/operations/browser-operation-1":
			writeJSON(t, writer, providerv1.Operation{OperationID: work.OperationID, AttemptID: work.AttemptID,
				FencingToken: work.SlotGeneration, SandboxID: work.SandboxID, Type: providerv1.OperationOpenBrowserSession,
				Status: providerv1.OperationSucceeded, ProviderOperationID: "provider-browser-open-1", ObservedAt: now.Add(time.Second).Format(time.RFC3339Nano)})
		case "/v1/operations/browser-operation-1/browser-session":
			writeJSON(t, writer, providerv1.BrowserSessionHandoff{OperationID: work.OperationID, AttemptID: work.AttemptID,
				FencingToken: work.SlotGeneration, SandboxID: work.SandboxID, BrowserSessionID: work.SessionID,
				CapabilityProfileID: product.BrowserCapabilityProfile, Protocol: providerv1.BrowserProtocolWebSocket,
				InternalEndpointReference: "ref:browser-session:opaque-1", ConnectionGeneration: 1,
				ExpiresAt: work.ExpiresAt.Format(time.RFC3339Nano)})
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	client := newBrowserTestClient(t, server, key, now)
	if err := client.AuthorizeSession(context.Background(), work.Kind, work.ProtocolProfile); err != nil {
		t.Fatal(err)
	}
	dispatched, err := client.ExecuteBrowserSessionControl(context.Background(), work)
	if err != nil || dispatched.State != "accepted" {
		t.Fatalf("dispatch=%#v err=%v", dispatched, err)
	}
	observed, err := client.ObserveOperation(context.Background(), product.ProviderObservationWork{
		TenantID: work.TenantID, WorkspaceID: work.WorkspaceID, OperationID: work.OperationID, AttemptID: work.AttemptID,
		SlotKey: work.SlotKey, SlotGeneration: work.SlotGeneration, RuntimeProfileID: work.RuntimeProfileID,
		SandboxID: work.SandboxID, ProviderOperationID: dispatched.ProviderOperationID, ProviderRevisionID: work.ProviderRevisionID,
		SessionID: work.SessionID, OperationType: "create_session", SessionKind: work.Kind, ProtocolProfile: work.ProtocolProfile,
		SessionExpiresAt: work.ExpiresAt,
	})
	if err != nil || observed.State != "succeeded" || observed.HandoffReference != "ref:browser-session:opaque-1" ||
		observed.ConnectionGeneration != 1 || !observed.HandoffExpiresAt.Equal(work.ExpiresAt) {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	encoded, _ := json.Marshal(observed)
	if strings.Contains(string(encoded), "127.0.0.1") || strings.Contains(string(encoded), "ws://") || strings.Contains(string(encoded), "container") {
		t.Fatalf("private coordinate leaked: %s", encoded)
	}
}

func TestClientBrowserFailsClosedOnCapabilityDriftAndMissingPolicy(t *testing.T) {
	now := time.Date(2026, 9, 18, 5, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		snapshot := browserCapabilities()
		requests++
		if requests > 1 {
			snapshot.Capabilities[0].Versions = []string{"2.0.0"}
		}
		writeJSON(t, writer, snapshot)
	}))
	defer server.Close()
	client := newBrowserTestClient(t, server, key, now)
	if err := client.AuthorizeSlot(context.Background(), browserTestWork(now).Slot); err != nil {
		t.Fatalf("initial readiness err=%v", err)
	}
	if err := client.AuthorizeSlot(context.Background(), browserTestWork(now).Slot); !errorsIs(err, product.ErrCapabilityUnsupported) {
		t.Fatalf("capability drift err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.AuthorizeSession(ctx, product.SessionKindBrowserLive, product.SessionProfileBrowserLive); err != context.Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
	config := browserTestConfig(server, key, now)
	config.Profiles[0].NetworkPolicyReference = ""
	if _, err := New(config); !errorsIs(err, product.ErrInvalid) {
		t.Fatalf("missing network policy err=%v", err)
	}
}

func TestClientBrowserLifecycleUsesSeparateProviderGenerationAndProductFence(t *testing.T) {
	now := time.Date(2026, 9, 18, 6, 0, 0, 0, time.UTC)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/capabilities":
			writeJSON(t, writer, browserCapabilities())
		case "/v1/sandboxes/browser-sandbox-1/desired-state":
			var body providerv1.DesiredStateRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedGeneration != 3 || body.FencingToken != 8 || body.DesiredState != providerv1.RequestedStateReady {
				t.Fatalf("resume body=%#v", body)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerv1.Operation{OperationID: body.OperationID, AttemptID: body.AttemptID, FencingToken: body.FencingToken, SandboxID: "browser-sandbox-1", Type: providerv1.OperationResume, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-resume", ObservedAt: now.Format(time.RFC3339Nano)})
		case "/v1/sandboxes/browser-sandbox-1:terminate":
			var body providerv1.TerminateRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedGeneration != 3 || body.FencingToken != 9 || body.PreserveWorkspaceSnapshot {
				t.Fatalf("terminate body=%#v", body)
			}
			writer.WriteHeader(http.StatusAccepted)
			writeJSON(t, writer, providerv1.Operation{OperationID: body.OperationID, AttemptID: body.AttemptID, FencingToken: body.FencingToken, SandboxID: "browser-sandbox-1", Type: providerv1.OperationTerminate, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-terminate", ObservedAt: now.Format(time.RFC3339Nano)})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := newBrowserTestClient(t, server, key, now)
	work := browserTestWork(now)
	work.Action = "resume"
	work.PreviousGeneration = 7
	work.SlotGeneration = 8
	work.FencingToken = 8
	work.ProviderGeneration = 3
	work.ProviderRevisionID = LockedProviderRevision
	work.SandboxID = "browser-sandbox-1"
	if evidence, err := client.ControlBrowserSlot(context.Background(), work); err != nil || evidence.ProviderOperationID != "provider-resume" {
		t.Fatalf("resume=%#v err=%v", evidence, err)
	}
	session := product.SessionControlWork{TenantID: "tenant-1", WorkspaceID: "wrk-1", SlotKey: "browser-main", SessionID: "ses-browser", OperationID: "op-close", AttemptID: "out-close", SlotGeneration: 8, FencingToken: 9, ProviderGeneration: 3, RuntimeProfileID: product.BrowserSlotProfile, SandboxID: "browser-sandbox-1", ProviderRevisionID: LockedProviderRevision, Kind: product.SessionKindBrowserLive, ProtocolProfile: product.SessionProfileBrowserLive, ExpiresAt: now.Add(time.Minute), Action: "close", Reason: "owner_requested_close"}
	if evidence, err := client.ExecuteBrowserSessionControl(context.Background(), session); err != nil || evidence.ProviderOperationID != "provider-terminate" {
		t.Fatalf("terminate=%#v err=%v", evidence, err)
	}
}

func newTestClient(t *testing.T, server *httptest.Server, key ed25519.PrivateKey, now time.Time) *Client {
	t.Helper()
	client, err := New(Config{Origin: server.URL, HTTPClient: server.Client(), ExpectedRevisionID: LockedProviderRevision,
		ExpectedTree: LockedProviderTree, ProviderResolutionID: "provider-main", AllowHTTPForTests: true, Clock: fixedClock{now},
		Authority: Authority{Issuer: "https://product.example.test/controller", Subject: "spiffe://product/controller",
			Audience: "urn:shell-echo:sandbox-runtime:provider-instance:test", KeyID: "product-key-1", PrivateKey: key},
		Profiles: []Profile{{ProductProfileID: "coding-shell-v1", RuntimeProfileID: "provider-shell-v1", ImageReference: "registry.invalid/sandbox",
			ImageDigest: "sha256:" + strings.Repeat("d", 64), CPUMillis: 1000, MemoryBytes: 1 << 30, EphemeralBytes: 1 << 30, PIDsLimit: 128,
			BaseRevisionID: "revision-empty", BaseRevisionDigest: "sha256:" + strings.Repeat("e", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64)}}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func newBrowserTestClient(t *testing.T, server *httptest.Server, key ed25519.PrivateKey, now time.Time) *Client {
	t.Helper()
	client, err := New(browserTestConfig(server, key, now))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func browserTestConfig(server *httptest.Server, key ed25519.PrivateKey, now time.Time) Config {
	return Config{Origin: server.URL, HTTPClient: server.Client(), ExpectedRevisionID: LockedProviderRevision,
		ExpectedTree: LockedProviderTree, ProviderResolutionID: "provider-browser", AllowHTTPForTests: true, Clock: fixedClock{now},
		Authority: Authority{Issuer: "https://product.example.test/controller", Subject: "spiffe://product/controller",
			Audience: "urn:shell-echo:sandbox-runtime:provider-instance:test", KeyID: "product-key-1", PrivateKey: key},
		Profiles: []Profile{{ProductProfileID: product.BrowserSlotProfile, RuntimeProfileID: product.BrowserSlotProfile,
			ImageReference: "registry.invalid/sandbox-browser", ImageDigest: "sha256:" + strings.Repeat("d", 64),
			Architecture: providerv1.ArchitectureAMD64, CPUMillis: 2000, MemoryBytes: 2 << 30, EphemeralBytes: 2 << 30, PIDsLimit: 256,
			BaseRevisionID: "revision-empty", BaseRevisionDigest: "sha256:" + strings.Repeat("e", 64),
			PolicyDigest: "sha256:" + strings.Repeat("b", 64), NetworkPolicyReference: "browser-egress-policy-1"}}}
}

func browserCapabilities() providerv1.Capabilities {
	return providerv1.Capabilities{ProviderRevisionID: LockedProviderRevision, APIVersion: providerv1.APIVersionV1,
		Capabilities: []providerv1.Capability{{ID: providerv1.CapabilityBrowser, Versions: []string{product.BrowserCapabilityVersion}, Profiles: []string{product.BrowserCapabilityProfile}}},
		RuntimeProfiles: []providerv1.RuntimeProfile{{ID: product.BrowserSlotProfile, IsolationClass: providerv1.IsolationContainer,
			Architecture: []providerv1.Architecture{providerv1.ArchitectureAMD64}, CapabilityProfileIDs: []string{product.BrowserCapabilityProfile}}}}
}

func browserTestWork(now time.Time) product.ReconcileWork {
	return product.ReconcileWork{TenantID: "tenant-1", OutboxID: "browser-out-1", AttemptID: "browser-out-1", LeaseOwner: "browser-worker-1",
		WorkspaceID: "wrk-1", OperationID: "browser-op-1", SlotKey: "browser-main", SlotGeneration: 1, WorkspaceExpiry: now.Add(time.Hour),
		Slot: product.SlotSpec{SlotKey: "browser-main", Kind: "browser", ProfileID: product.BrowserSlotProfile, DesiredState: "ready",
			RequiredCapabilities: []product.CapabilityRequirement{{CapabilityID: product.BrowserCapabilityID, Version: product.BrowserCapabilityVersion, ProfileID: product.BrowserCapabilityProfile}}}}
}

func testWork(now time.Time) product.ReconcileWork {
	return product.ReconcileWork{TenantID: "tenant-1", OutboxID: "out-1", AttemptID: "out-1", LeaseOwner: "worker-1",
		WorkspaceID: "wrk-1", OperationID: "op-1", SlotKey: product.PrimarySlotKey, SlotGeneration: 1, WorkspaceExpiry: now.Add(time.Hour),
		Slot: product.SlotSpec{SlotKey: product.PrimarySlotKey, Kind: "code", ProfileID: "coding-shell-v1", DesiredState: "ready",
			RequiredCapabilities: []product.CapabilityRequirement{{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"}}}}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		t.Fatal(err)
	}
}

func errorsIs(err, target error) bool {
	return err != nil && strings.Contains(err.Error(), target.Error())
}
