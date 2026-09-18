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
