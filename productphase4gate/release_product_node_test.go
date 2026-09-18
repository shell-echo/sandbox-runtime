//go:build phase4browsergate

package productphase4gate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/product"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	productprovider "github.com/shell-echo/sandbox-runtime/product/adapter/provider"
	recordinglocal "github.com/shell-echo/sandbox-runtime/product/adapter/recording/local"
	"github.com/shell-echo/sandbox-runtime/productapi"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	releaseTenantID = "tenant-phase4-release"
	releaseActorID  = "actor-phase4-release"
)

func runReleaseProductNode(config nodeConfig) error { //nolint:cyclop
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
	if err != nil {
		return err
	}
	providerClient, err := productprovider.New(productprovider.Config{
		Origin: "http://" + config.ProviderAPI, HTTPClient: &http.Client{Timeout: time.Second},
		ExpectedRevisionID: productprovider.LockedProviderRevision, ExpectedTree: productprovider.LockedProviderTree,
		ProviderResolutionID: "phase4-release-provider", AllowHTTPForTests: true,
		Authority: productprovider.Authority{Issuer: "phase4-release-product", Subject: "phase4-release-product", Audience: "phase4-release-provider", KeyID: "phase4-release-signing", PrivateKey: ed25519.PrivateKey(privateKey)},
		Profiles: []productprovider.Profile{
			{ProductProfileID: "coding-shell-v1", RuntimeProfileID: "coding-shell-v1", ImageReference: "registry.example.test/coding-shell:phase4", ImageDigest: releaseDigest("code-image"), Architecture: releaseArchitecture(), CPUMillis: 1000, MemoryBytes: 512 << 20, EphemeralBytes: 1 << 30, PIDsLimit: 128, BaseRevisionID: "base-phase4-code", BaseRevisionDigest: releaseDigest("code-base"), PolicyDigest: releaseDigest("code-policy")},
			{ProductProfileID: product.BrowserSlotProfile, RuntimeProfileID: product.BrowserSlotProfile, ImageReference: "registry.example.test/browser@" + releaseDigest("browser-image"), ImageDigest: releaseDigest("browser-image"), Architecture: releaseArchitecture(), CPUMillis: 1000, MemoryBytes: 512 << 20, EphemeralBytes: 1 << 30, PIDsLimit: 128, BaseRevisionID: "base-phase4-browser", BaseRevisionDigest: releaseDigest("browser-base"), PolicyDigest: releaseDigest("browser-policy"), NetworkPolicyReference: "browser-egress-policy"},
		},
	})
	if err != nil {
		return err
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, providerClient, ids)
	if err != nil {
		return err
	}
	slots, err := product.NewSlotService(store, providerClient, ids)
	if err != nil {
		return err
	}
	controls, err := product.NewControlService(store, ids)
	if err != nil {
		return err
	}
	sessions, err := product.NewSessionService(store, providerClient, ids)
	if err != nil {
		return err
	}
	grantKey, err := base64.RawStdEncoding.DecodeString(config.GrantKey)
	if err != nil {
		return err
	}
	grantRepository, err := productpostgres.NewGrantRepository(store, "phase4-release-grant", grantKey)
	if err != nil {
		return err
	}
	grants, err := product.NewGrantService(grantRepository, ids, product.CryptoTicketGenerator{}, "https://"+config.GatewayAddress+"/browser/connect", 30*time.Second)
	if err != nil {
		return err
	}
	catalog, err := product.NewCatalogService(store, ids)
	if err != nil {
		return err
	}
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{
		{Token: releaseOwnerBearer, Principal: productapi.Principal{TenantID: releaseTenantID, Actor: releaseActor(), Role: productapi.RoleOwner}},
		{Token: releaseForeignBearer, Principal: productapi.Principal{TenantID: "tenant-phase4-foreign", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-phase4-foreign"}, Role: productapi.RoleOwner}},
	})
	if err != nil {
		return err
	}
	readiness := &releaseReadiness{providerURL: "http://" + config.ProviderAPI, gatewayURL: "https://" + config.GatewayAddress, gatewayClient: releaseTLSClient(config.CACertificate, "phase4-edge")}
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
	workers, err := newReleaseWorkers(store, providerClient, ids)
	if err != nil {
		return err
	}
	go workers.run(ctx)
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.HandleFunc("/gate/replay/", func(writer http.ResponseWriter, request *http.Request) {
		releaseReplayHandler(recordings, config.GateKey, writer, request)
	})
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || pool.Ping(request.Context()) != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return serveUntilSignal(config.ProductAddress, mux, nil)
}

type releaseWorkers struct {
	primary   *product.Dispatcher
	browser   *product.BrowserDispatcher
	lifecycle *product.BrowserLifecycleDispatcher
	sessions  *product.BrowserSessionDispatcher
	reconcile *product.Reconciler
	expiry    *product.BrowserExpiryWorker
}

func newReleaseWorkers(store *productpostgres.Store, providerClient *productprovider.Client, ids product.IDGenerator) (*releaseWorkers, error) {
	primary, err := product.NewDispatcher(store, providerClient, "phase4-primary-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	browser, err := product.NewBrowserDispatcher(store, providerClient, "phase4-browser-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	lifecycle, err := product.NewBrowserLifecycleDispatcher(store, providerClient, "phase4-lifecycle-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	sessions, err := product.NewBrowserSessionDispatcher(store, providerClient, "phase4-session-worker", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return nil, err
	}
	reconcile, err := product.NewReconciler(store, providerClient, ids, "phase4-observer-worker", 2*time.Second, 20*time.Millisecond, 10)
	if err != nil {
		return nil, err
	}
	expiry, err := product.NewBrowserExpiryWorker(store, ids, 10)
	if err != nil {
		return nil, err
	}
	return &releaseWorkers{primary: primary, browser: browser, lifecycle: lifecycle, sessions: sessions, reconcile: reconcile, expiry: expiry}, nil
}

func (w *releaseWorkers) run(ctx context.Context) {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = w.primary.DispatchOnce(ctx)
			_, _ = w.browser.DispatchOnce(ctx)
			_, _ = w.lifecycle.DispatchOnce(ctx)
			_, _ = w.sessions.DispatchOnce(ctx)
			_, _ = w.reconcile.ReconcileOnce(ctx)
			_, _ = w.expiry.ExpireOnce(ctx)
		}
	}
}

type releaseReadiness struct {
	providerURL   string
	gatewayURL    string
	gatewayClient *http.Client
}

func (r *releaseReadiness) Snapshot(ctx context.Context, _ productapi.Principal) ([]productapiv1.ProductCapability, error) {
	ready := releaseBrowserProviderReady(ctx, r.providerURL) && releaseHealthReady(ctx, r.gatewayClient, r.gatewayURL+"/healthz")
	state := "unavailable"
	if ready {
		state = "ready"
	}
	return []productapiv1.ProductCapability{{CapabilityID: "product.browser", Version: "1.0.0", Readiness: state, ProtocolProfiles: []string{product.SessionProfileBrowserAutomation, product.SessionProfileBrowserLive}, MaxSessionSeconds: 3600}}, nil
}

func releaseBrowserProviderReady(ctx context.Context, origin string) bool {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/capabilities", nil)
	response, err := (&http.Client{Timeout: 500 * time.Millisecond}).Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var snapshot providerv1.Capabilities
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&snapshot) != nil || snapshot.ProviderRevisionID != productprovider.LockedProviderRevision || snapshot.APIVersion != providerv1.APIVersionV1 || len(snapshot.Capabilities) != 1 || len(snapshot.RuntimeProfiles) != 1 {
		return false
	}
	capability, profile := snapshot.Capabilities[0], snapshot.RuntimeProfiles[0]
	return capability.ID == product.BrowserCapabilityID && len(capability.Versions) == 1 && capability.Versions[0] == product.BrowserCapabilityVersion && len(capability.Profiles) == 1 && capability.Profiles[0] == product.BrowserCapabilityProfile && profile.ID == product.BrowserSlotProfile && len(profile.Architecture) == 1 && profile.Architecture[0] == releaseArchitecture()
}

func releaseHealthReady(ctx context.Context, client *http.Client, target string) bool {
	if client == nil {
		return false
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func releaseReplayHandler(service *product.RecordingService, key string, writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.Header.Get("X-Gate-Key") != key {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	recordingID := strings.TrimPrefix(request.URL.Path, "/gate/replay/")
	segments, err := service.Replay(request.Context(), releaseTenantID, releaseActor(), recordingID)
	if err != nil {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		return
	}
	joined := strings.Join(func() []string {
		values := make([]string, len(segments))
		for index := range segments {
			values[index] = string(segments[index])
		}
		return values
	}(), "")
	if !strings.Contains(joined, `"type":"stream.start"`) || !strings.Contains(joined, `"type":"media.rtp"`) || !strings.Contains(joined, `"type":"stream.end"`) || strings.Contains(joined, "consent") || strings.Contains(joined, "SECRET") {
		http.Error(writer, "integrity failure", http.StatusServiceUnavailable)
		return
	}
	releaseWriteJSON(writer, http.StatusOK, map[string]any{"segments": len(segments), "bytes": len(joined)})
}

func releaseActor() product.ActorRef {
	return product.ActorRef{Type: product.ActorHuman, ID: releaseActorID}
}

func releaseArchitecture() providerv1.Architecture {
	if runtime.GOARCH == "arm64" {
		return providerv1.ArchitectureARM64
	}
	return providerv1.ArchitectureAMD64
}

func releaseDigest(value string) string {
	digest := sha256Sum(value)
	return "sha256:" + digest
}

func sha256Sum(value string) string {
	return fmt.Sprintf("%x", sha256Bytes([]byte(value)))
}

func sha256Bytes(value []byte) [32]byte {
	return sha256.Sum256(value)
}
