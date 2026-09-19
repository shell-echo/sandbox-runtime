//go:build phase5desktopgate

package productphase5gate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
	bloblocal "github.com/shell-echo/sandbox-runtime/product/adapter/blob/local"
	productdevelopment "github.com/shell-echo/sandbox-runtime/product/adapter/development"
	productguest "github.com/shell-echo/sandbox-runtime/product/adapter/guest"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	productprovider "github.com/shell-echo/sandbox-runtime/product/adapter/provider"
	recordinglocal "github.com/shell-echo/sandbox-runtime/product/adapter/recording/local"
	"github.com/shell-echo/sandbox-runtime/productapi"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func runProductNode(config nodeConfig) error { //nolint:cyclop,maintidx
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := productpostgres.ApplyMigrations(ctx, pool); err != nil {
		return err
	}
	store, err := productpostgres.New(pool, 3*time.Second)
	if err != nil {
		return err
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(config.ProviderSigning)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("invalid Provider signing key")
	}
	authority := productprovider.Authority{Issuer: "phase5-release-product", Subject: "phase5-release-product", Audience: "phase5-release-provider", KeyID: "phase5-release-signing", PrivateKey: ed25519.PrivateKey(privateKey)}
	codeClient, err := productprovider.New(productprovider.Config{
		Origin: "http://" + config.ProviderAddress, HTTPClient: &http.Client{Timeout: time.Second},
		ExpectedRevisionID: productprovider.LockedProviderRevision, ExpectedTree: productprovider.LockedProviderTree,
		ProviderResolutionID: "phase5-release-code-provider", AllowHTTPForTests: true, Authority: authority,
		Profiles: []productprovider.Profile{{ProductProfileID: "coding-shell-v1", RuntimeProfileID: "coding-shell-v1",
			ImageReference: "registry.example.test/coding-shell@" + releaseDigest("phase5-code-image"), ImageDigest: releaseDigest("phase5-code-image"),
			Architecture: releaseArchitecture(), CPUMillis: 1000, MemoryBytes: 512 << 20, EphemeralBytes: 1 << 30, PIDsLimit: 128,
			BaseRevisionID: "phase5-code-base", BaseRevisionDigest: releaseDigest("phase5-code-base"), PolicyDigest: releaseDigest("phase5-code-policy")}},
	})
	if err != nil {
		return err
	}
	publication := desktopimage.LockedPublication()
	desktopClient, err := productprovider.NewDesktop(productprovider.Config{
		Origin: "http://" + config.DesktopProviderAddress, HTTPClient: &http.Client{Timeout: time.Second},
		ExpectedRevisionID: productprovider.LockedDesktopProviderRevision, ExpectedTree: productprovider.LockedDesktopProviderTree,
		ProviderResolutionID: "phase5-release-desktop-provider", AllowHTTPForTests: true, Authority: authority,
		Profiles: []productprovider.Profile{{ProductProfileID: product.DesktopSlotProfile, RuntimeProfileID: product.DesktopSlotProfile,
			ImageReference: publication.Image(), ImageDigest: publication.Digest, Architecture: releaseArchitecture(),
			CPUMillis: 4000, MemoryBytes: 4 << 30, EphemeralBytes: 8 << 30, WorkspaceBytes: 4 << 30, PIDsLimit: 512,
			BaseRevisionID: "phase5-desktop-base", BaseRevisionDigest: releaseDigest("phase5-desktop-base"),
			PolicyDigest: releaseDigest("phase5-desktop-policy"), NetworkPolicyReference: "phase5-desktop-egress"}},
	})
	if err != nil {
		return err
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, codeClient, ids)
	if err != nil {
		return err
	}
	slots, err := product.NewSlotService(store, desktopClient, ids)
	if err != nil {
		return err
	}
	controls, err := product.NewControlService(store, ids)
	if err != nil {
		return err
	}
	sessions, err := product.NewSessionService(store, desktopClient, ids)
	if err != nil {
		return err
	}
	grantKey, err := base64.RawStdEncoding.DecodeString(config.GrantKey)
	if err != nil {
		return err
	}
	grantRepository, err := productpostgres.NewGrantRepository(store, "phase5-release-grant", grantKey)
	if err != nil {
		return err
	}
	grants, err := product.NewGrantService(grantRepository, ids, product.CryptoTicketGenerator{}, "https://"+config.GatewayAddress+"/desktop/connect", 30*time.Second)
	if err != nil {
		return err
	}
	catalog, err := product.NewCatalogService(store, ids)
	if err != nil {
		return err
	}
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{
		{Token: ownerBearer, Principal: productapi.Principal{TenantID: releaseTenantID, Actor: releaseActor(), Role: productapi.RoleOwner}},
		{Token: foreignBearer, Principal: productapi.Principal{TenantID: "tenant-phase5-foreign", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-phase5-foreign"}, Role: productapi.RoleOwner}},
	})
	if err != nil {
		return err
	}
	readiness := &phase5Readiness{pool: pool, desktopProviderURL: "http://" + config.DesktopProviderAddress,
		desktopControlURL: "http://" + config.DesktopControlAddress, gatewayURL: "https://" + config.GatewayAddress,
		gatewayClient: tlsClient(config.CACertificate, "phase5-edge")}
	apiHandler, err := productapiv1.NewHandlerWithSlots(application, controls, sessions, grants, catalog, slots, readiness, authenticator, ids)
	if err != nil {
		return err
	}
	recordingKey, err := base64.RawStdEncoding.DecodeString(config.RecordingKey)
	if err != nil {
		return err
	}
	content, err := recordinglocal.New(config.RecordingRoot, recordingKey)
	if err != nil {
		return err
	}
	redactor, err := product.NewPatternRedactor([]string{"SECRET"})
	if err != nil {
		return err
	}
	recordings, err := product.NewRecordingService(store, content, redactor, ids, nil)
	if err != nil {
		return err
	}
	guestAuthenticator, err := productguest.NewAuthenticator(store)
	if err != nil {
		return err
	}
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: guestAuthenticator, AuthorityPollPeriod: 25 * time.Millisecond})
	if err != nil {
		return err
	}
	developmentClient, err := productguest.NewDevelopmentClient(hub, 3*time.Second)
	if err != nil {
		return err
	}
	blobs, err := bloblocal.New(config.BlobRoot)
	if err != nil {
		return err
	}
	development, err := product.NewDevelopmentService(store, productdevelopment.LockedCatalog{}, developmentClient, blobs, ids)
	if err != nil {
		return err
	}
	policy, err := product.NewDesktopPolicyService(store, ids)
	if err != nil {
		return err
	}
	workers, err := newPhase5Workers(store, codeClient, desktopClient, ids)
	if err != nil {
		return err
	}
	go workers.run(ctx)
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/guest", hub)
	mux.HandleFunc("/gate/policy", phase5PolicyHandler(policy, config.GateKey))
	mux.HandleFunc("/gate/development", phase5DevelopmentHandler(development, config.GateKey))
	mux.HandleFunc("/gate/replay/", phase5ReplayHandler(recordings, config.GateKey))
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || pool.Ping(request.Context()) != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return serveUntilSignal(config.ProductAddress, mux, nil)
}

type phase5Workers struct {
	primary          *product.Dispatcher
	desktop          *product.DesktopDispatcher
	lifecycle        *product.DesktopLifecycleDispatcher
	sessions         *product.DesktopSessionDispatcher
	reconcile        *product.Reconciler
	desktopReconcile *product.DesktopReconciler
	expiry           *product.DesktopExpiryWorker
}

func newPhase5Workers(store *productpostgres.Store, codeClient, desktopClient *productprovider.Client, ids product.IDGenerator) (*phase5Workers, error) {
	primary, err := product.NewDispatcher(store, codeClient, "phase5-primary-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	desktop, err := product.NewDesktopDispatcher(store, desktopClient, "phase5-desktop-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	lifecycle, err := product.NewDesktopLifecycleDispatcher(store, desktopClient, "phase5-lifecycle-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	sessions, err := product.NewDesktopSessionDispatcher(store, desktopClient, "phase5-session-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	reconcile, err := product.NewReconciler(store, codeClient, ids, "phase5-primary-observer", 2*time.Second, 20*time.Millisecond, 10)
	if err != nil {
		return nil, err
	}
	desktopReconcile, err := product.NewDesktopReconciler(store, desktopClient, ids, "phase5-desktop-observer", 2*time.Second, 20*time.Millisecond, 10)
	if err != nil {
		return nil, err
	}
	expiry, err := product.NewDesktopExpiryWorker(store, ids, 10)
	if err != nil {
		return nil, err
	}
	return &phase5Workers{primary: primary, desktop: desktop, lifecycle: lifecycle, sessions: sessions, reconcile: reconcile, desktopReconcile: desktopReconcile, expiry: expiry}, nil
}

func (w *phase5Workers) run(ctx context.Context) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = w.primary.DispatchOnce(ctx)
			_, _ = w.desktop.DispatchOnce(ctx)
			_, _ = w.lifecycle.DispatchOnce(ctx)
			_, _ = w.sessions.DispatchOnce(ctx)
			_, _ = w.reconcile.ReconcileOnce(ctx)
			_, _ = w.desktopReconcile.ReconcileOnce(ctx)
			_, _ = w.expiry.ExpireOnce(ctx)
		}
	}
}

type phase5Readiness struct {
	pool                                              *pgxpool.Pool
	desktopProviderURL, desktopControlURL, gatewayURL string
	gatewayClient                                     *http.Client
}

func (r *phase5Readiness) Snapshot(ctx context.Context, principal productapi.Principal) ([]productapiv1.ProductCapability, error) {
	desktopReady := exactDesktopProviderReady(ctx, r.desktopProviderURL) && healthReady(ctx, http.DefaultClient, r.desktopControlURL+"/healthz") && healthReady(ctx, r.gatewayClient, r.gatewayURL+"/healthz")
	var guestReady bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.guest_bindings WHERE tenant_id=$1 AND state='connected' AND expires_at>clock_timestamp())`, principal.TenantID).Scan(&guestReady); err != nil {
		return nil, err
	}
	state := func(ready bool) string {
		if ready {
			return "ready"
		}
		return "unavailable"
	}
	return []productapiv1.ProductCapability{
		{CapabilityID: "product.desktop", Version: "1.0.0", Readiness: state(desktopReady), ProtocolProfiles: []string{product.SessionProfileDesktop}, MaxSessionSeconds: 3600},
		{CapabilityID: "product.development", Version: "1.0.0", Readiness: state(guestReady), ProtocolProfiles: []string{product.DevelopmentTemplateID}},
	}, nil
}

func exactDesktopProviderReady(ctx context.Context, origin string) bool {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/capabilities", nil)
	response, err := (&http.Client{Timeout: 500 * time.Millisecond}).Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var snapshot providerv1.Capabilities
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&snapshot) != nil ||
		snapshot.ProviderRevisionID != productprovider.LockedDesktopProviderRevision || snapshot.APIVersion != providerv1.APIVersionV1 || len(snapshot.Capabilities) != 1 || len(snapshot.RuntimeProfiles) != 1 {
		return false
	}
	capability, profile := snapshot.Capabilities[0], snapshot.RuntimeProfiles[0]
	return capability.ID == product.DesktopCapabilityID && len(capability.Versions) == 1 && capability.Versions[0] == product.DesktopCapabilityVersion &&
		len(capability.Profiles) == 1 && capability.Profiles[0] == product.DesktopCapabilityProfile && profile.ID == product.DesktopSlotProfile
}

func phase5PolicyHandler(service *product.DesktopPolicyService, key string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("X-Gate-Key") != key {
			http.NotFound(writer, request)
			return
		}
		var input struct {
			WorkspaceID, IdempotencyKey string
			ExpectedRevision            int64
		}
		if decodeStrictBody(request.Body, &input) != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		value, _, err := service.Put(request.Context(), releaseTenantID, releaseActor(), input.WorkspaceID, input.IdempotencyKey, input.ExpectedRevision,
			product.DesktopPolicy{Revision: input.ExpectedRevision + 1, Input: product.DesktopInputPolicy{Keyboard: true, Pointer: true, RequireActivation: true}})
		if err != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"revision": value.Revision})
	}
}

func phase5DevelopmentHandler(service *product.DevelopmentService, key string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("X-Gate-Key") != key {
			http.NotFound(writer, request)
			return
		}
		var input struct{ WorkspaceID, RevisionID, IdempotencyKey string }
		if decodeStrictBody(request.Body, &input) != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		environment, replay, err := service.Start(request.Context(), releaseTenantID, releaseActor(), input.WorkspaceID, input.IdempotencyKey,
			product.StartDevelopmentRequest{TemplateID: product.DevelopmentTemplateID, RevisionID: input.RevisionID, StartupTimeoutSeconds: 30})
		if err != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"environment_id": environment.ID, "revision_id": environment.RevisionID, "state": environment.State, "replay": replay})
	}
}

func phase5ReplayHandler(service *product.RecordingService, key string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("X-Gate-Key") != key {
			http.NotFound(writer, request)
			return
		}
		recordingID := strings.TrimPrefix(request.URL.Path, "/gate/replay/")
		segments, err := service.Replay(request.Context(), releaseTenantID, releaseActor(), recordingID)
		if err != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		values := make([]string, len(segments))
		for index := range segments {
			values[index] = string(segments[index])
		}
		joined := strings.Join(values, "")
		if !strings.Contains(joined, `"type":"stream.start"`) || !strings.Contains(joined, `"type":"video.rtp"`) || !strings.Contains(joined, `"type":"input"`) || !strings.Contains(joined, `"type":"stream.end"`) || strings.Contains(joined, "SECRET") || strings.Contains(joined, "consent") {
			http.Error(writer, "integrity failure", http.StatusServiceUnavailable)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"segments": len(segments), "bytes": len(joined)})
	}
}
