//go:build phase3gate

package productphase3gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestfiles "github.com/shell-echo/sandbox-runtime/guestagent/files"
	"github.com/shell-echo/sandbox-runtime/internal/productcontract"
	"github.com/shell-echo/sandbox-runtime/internal/productphase3evidence"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productguest "github.com/shell-echo/sandbox-runtime/product/adapter/guest"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	productprovider "github.com/shell-echo/sandbox-runtime/product/adapter/provider"
	"github.com/shell-echo/sandbox-runtime/productapi"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
	"github.com/shell-echo/sandbox-runtime/productweb"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	ownerBearer   = "phase3-owner-bearer-00000000000000000001"
	foreignBearer = "phase3-foreign-bearer-0000000000000001"
	publicOrigin  = "https://product.example.test"
	privateToken  = "phase3-private-provider-token"
)

type nodeConfig struct {
	DSN                string `json:"dsn"`
	ProductAddress     string `json:"product_address"`
	GatewayAddress     string `json:"gateway_address"`
	ProviderAddress    string `json:"provider_address"`
	ProviderPrivateKey string `json:"provider_private_key"`
	GrantKey           string `json:"grant_key"`
	WebKey             string `json:"web_key"`
	GuestID            string `json:"guest_id,omitempty"`
	GuestGeneration    int64  `json:"guest_generation,omitempty"`
	GuestPrivateKey    string `json:"guest_private_key,omitempty"`
	GuestRoot          string `json:"guest_root,omitempty"`
}

type childNode struct {
	role string
	cmd  *exec.Cmd
	log  bytes.Buffer
}

func TestPhase3Node(t *testing.T) {
	role := os.Getenv("PRODUCT_PHASE3_NODE_ROLE")
	if role == "" {
		t.Skip("standalone node helper")
	}
	document, err := os.ReadFile(os.Getenv("PRODUCT_PHASE3_NODE_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	var config nodeConfig
	if err := json.Unmarshal(document, &config); err != nil {
		t.Fatal(err)
	}
	switch role {
	case "provider":
		err = runProviderNode(config)
	case "product":
		err = runProductNode(config)
	case "gateway":
		err = runGatewayNode(config)
	case "guest":
		err = runGuestNode(config)
	default:
		err = fmt.Errorf("unknown node role %q", role)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestStandalonePhase3ReleaseGate(t *testing.T) {
	if os.Getenv("PRODUCT_PHASE3_NODE_ROLE") != "" {
		t.Skip("parent-only gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	started := time.Now().UTC()
	container := fmt.Sprintf("codex-product-phase3-gate-%d", os.Getpid())
	dsn, removeContainer := startPostgreSQL(t, ctx, container)
	containerRemoved := false
	defer func() {
		if !containerRemoved {
			removeContainer()
		}
	}()

	providerAddress := freeAddress(t)
	productAddress := freeAddress(t)
	gatewayAddress := freeAddress(t)
	_, providerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grantKey := randomBytes(t, 32)
	webKey := randomBytes(t, 32)
	base := nodeConfig{
		DSN: dsn, ProductAddress: productAddress, GatewayAddress: gatewayAddress, ProviderAddress: providerAddress,
		ProviderPrivateKey: base64.RawStdEncoding.EncodeToString(providerPrivateKey),
		GrantKey:           base64.RawStdEncoding.EncodeToString(grantKey), WebKey: base64.RawStdEncoding.EncodeToString(webKey),
	}

	nodes := make([]*childNode, 0, 4)
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
	providerNode := startNode(t, "provider", base)
	nodes = append(nodes, providerNode)
	waitHTTP(t, "http://"+providerAddress+"/healthz", "", http.StatusOK)
	productNode := startNode(t, "product", base)
	nodes = append(nodes, productNode)
	waitHTTP(t, "http://"+productAddress+"/healthz", "", http.StatusOK)
	gatewayNode := startNode(t, "gateway", base)
	nodes = append(nodes, gatewayNode)
	waitHTTP(t, "http://"+gatewayAddress+"/healthz", "", http.StatusOK)

	productBase := "http://" + productAddress
	response := api(t, http.MethodPost, productBase+"/api/v1/workspaces", "Bearer invalid", "bad", `{"unknown":true}`)
	requireStatus(t, response, http.StatusUnauthorized)

	capabilities := getCapabilities(t, productBase)
	requireCapability(t, capabilities, "product.workspace", "ready")
	requireCapability(t, capabilities, "product.terminal", "ready")
	requireCapability(t, capabilities, "product.files", "unavailable")

	create := api(t, http.MethodPost, productBase+"/api/v1/workspaces", "Bearer "+ownerBearer, "workspace-create-1", `{"display_name":"phase3 gate","lifetime_seconds":3600,"primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}}`)
	requireStatus(t, create, http.StatusAccepted)
	var workspaceOperation productapiv1.ProductOperation
	decodeResponse(t, create, &workspaceOperation)
	workspace := waitWorkspace(t, productBase, workspaceOperation.WorkspaceID, "active")
	operation := waitOperation(t, productBase, workspaceOperation.OperationID, "succeeded")
	if operation.ReconciliationState != "complete" {
		t.Fatalf("workspace operation reconciliation = %q", operation.ReconciliationState)
	}

	foreign := api(t, http.MethodGet, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID, "Bearer "+foreignBearer, "", "")
	requireStatus(t, foreign, http.StatusNotFound)

	if !stopNode(productNode) {
		t.Fatalf("product process did not stop cleanly: %s", productNode.log.String())
	}
	nodes = removeNode(nodes, productNode)
	productNode = startNode(t, "product", base)
	nodes = append(nodes, productNode)
	waitHTTP(t, productBase+"/healthz", "", http.StatusOK)
	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	store, err := productpostgres.New(pool, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	guestService, err := product.NewGuestService(store, product.CryptoIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	guestPublicKey, guestPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding, _, err := guestService.Provision(ctx, "tenant-phase3", product.ActorRef{Type: product.ActorHuman, ID: "actor-phase3"}, workspace.WorkspaceID, "guest-provision-1", product.ProvisionGuestRequest{
		ExpectedWorkspaceVersion: workspace.Version, SlotKey: product.PrimarySlotKey, ProtocolVersion: guestagent.ProtocolVersion,
		Capabilities: []string{guestfiles.CapabilityList, guestfiles.CapabilitySnapshot, guestfiles.CapabilityStat}, PublicKey: guestPublicKey, LifetimeSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	guestRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(guestRoot, "hello.txt"), []byte("phase3 guest file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	guestConfig := base
	guestConfig.GuestID = binding.GuestID
	guestConfig.GuestGeneration = binding.BindingGeneration
	guestConfig.GuestPrivateKey = base64.RawStdEncoding.EncodeToString(guestPrivateKey)
	guestConfig.GuestRoot = guestRoot
	guestNode := startNode(t, "guest", guestConfig)
	nodes = append(nodes, guestNode)
	waitFor(t, 10*time.Second, func() bool {
		return guestState(pool, binding.GuestID) == "connected"
	}, "guest connection")
	capabilities = getCapabilities(t, productBase)
	requireCapability(t, capabilities, "product.files", "ready")
	testWebFiles(t, productBase, workspace.WorkspaceID, guestRoot)

	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	sessionCreate := api(t, http.MethodPost, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID+"/sessions", "Bearer "+ownerBearer, "session-create-1", fmt.Sprintf(`{"expected_workspace_version":%d,"slot_key":"primary-code","kind":"terminal","protocol_profile":"product-terminal.v1","expires_in_seconds":600,"recording_policy":"metadata_only"}`, workspace.Version))
	requireStatus(t, sessionCreate, http.StatusAccepted)
	var sessionOperation productapiv1.ProductOperation
	decodeResponse(t, sessionCreate, &sessionOperation)
	waitOperation(t, productBase, sessionOperation.OperationID, "succeeded")
	session := waitSession(t, productBase, sessionOperation.SessionID, "ready")

	workspace = waitWorkspace(t, productBase, workspace.WorkspaceID, "active")
	leaseResponse := api(t, http.MethodPost, productBase+"/api/v1/workspaces/"+workspace.WorkspaceID+"/control-leases", "Bearer "+ownerBearer, "control-acquire-1", fmt.Sprintf(`{"expected_workspace_version":%d,"scope":{"scope_type":"session","scope_id":%q},"duration_seconds":60}`, workspace.Version, session.SessionID))
	requireStatus(t, leaseResponse, http.StatusCreated)
	var lease productapiv1.ControlLease
	decodeResponse(t, leaseResponse, &lease)
	grantResponse := api(t, http.MethodPost, productBase+"/api/v1/sessions/"+session.SessionID+"/connections", "Bearer "+ownerBearer, "connection-1", fmt.Sprintf(`{"expected_session_version":%d,"protocol_profile":"product-terminal.v1","control_lease_id":%q,"control_fence":%d}`, session.Version, lease.LeaseID, lease.Fence))
	requireStatus(t, grantResponse, http.StatusCreated)
	var grant productapiv1.ConnectionGrant
	decodeResponse(t, grantResponse, &grant)
	terminalRoundTrip(t, gatewayAddress, grant.ConnectionTicket, true)
	terminalRoundTrip(t, gatewayAddress, grant.ConnectionTicket, false)

	if !stopNode(providerNode) {
		t.Fatalf("provider process did not stop cleanly: %s", providerNode.log.String())
	}
	nodes = removeNode(nodes, providerNode)
	waitFor(t, 5*time.Second, func() bool {
		return capabilityState(getCapabilities(t, productBase), "product.terminal") == "unavailable"
	}, "Provider fault readiness closure")

	if !stopAll() {
		t.Fatal("not all child processes were reaped")
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA sandbox_runtime_product CASCADE`); err != nil {
		t.Fatal(err)
	}
	var schema *string
	if err := pool.QueryRow(ctx, `SELECT to_regnamespace('sandbox_runtime_product')::text`).Scan(&schema); err != nil || schema != nil {
		t.Fatalf("scoped Product rows were not removed: schema=%v err=%v", schema, err)
	}
	pool.Close()
	removeContainer()
	containerRemoved = true
	if output, err := exec.CommandContext(ctx, "docker", "inspect", container).CombinedOutput(); err == nil {
		t.Fatalf("PostgreSQL container remains after cleanup: %s", output)
	}

	evidencePath := writeEvidence(t, started, time.Now().UTC())
	manifest, err := productphase3evidence.VerifyFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("standalone Product Phase 3 evidence: %s (%d scenarios, %d processes)", evidencePath, len(manifest.Scenarios), len(manifest.Processes))
}

func runProductNode(config nodeConfig) error {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := productpostgres.ApplyMigrations(ctx, pool); err != nil {
		return err
	}
	store, err := productpostgres.New(pool, 5*time.Second)
	if err != nil {
		return err
	}
	privateKey, err := base64.RawStdEncoding.DecodeString(config.ProviderPrivateKey)
	if err != nil {
		return err
	}
	providerClient, err := productprovider.New(productprovider.Config{
		Origin: "http://" + config.ProviderAddress, HTTPClient: &http.Client{Timeout: 3 * time.Second},
		ExpectedRevisionID: productprovider.LockedProviderRevision, ExpectedTree: productprovider.LockedProviderTree,
		ProviderResolutionID: "phase3-provider", AllowHTTPForTests: true,
		Authority: productprovider.Authority{Issuer: "phase3-product", Subject: "phase3-product", Audience: "phase3-provider", KeyID: "phase3-key", PrivateKey: ed25519.PrivateKey(privateKey)},
		Profiles: []productprovider.Profile{{
			ProductProfileID: "coding-shell-v1", RuntimeProfileID: "coding-shell-v1", ImageReference: "registry.example.test/coding-shell:phase3",
			ImageDigest: digestOf("phase3-image"), Architecture: providerArchitecture(), CPUMillis: 1000, MemoryBytes: 512 << 20, EphemeralBytes: 1 << 30, PIDsLimit: 128,
			BaseRevisionID: "base-phase3", BaseRevisionDigest: digestOf("phase3-base"), PolicyDigest: digestOf("phase3-policy"),
		}},
	})
	if err != nil {
		return err
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, providerClient, ids)
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
	grantStore, err := productpostgres.NewGrantRepository(store, "phase3-grant-key", grantKey)
	if err != nil {
		return err
	}
	grants, err := product.NewGrantService(grantStore, ids, product.CryptoTicketGenerator{}, "https://gateway.example.test/connect", 30*time.Second)
	if err != nil {
		return err
	}
	catalog, err := product.NewCatalogService(store, ids)
	if err != nil {
		return err
	}
	guestAuthenticator, err := productguest.NewAuthenticator(store)
	if err != nil {
		return err
	}
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: guestAuthenticator, AuthorityPollPeriod: 100 * time.Millisecond})
	if err != nil {
		return err
	}
	fileClient, err := productguest.NewFileClient(hub, 3*time.Second)
	if err != nil {
		return err
	}
	files, err := product.NewFileService(store, fileClient)
	if err != nil {
		return err
	}
	authenticator, err := productapi.NewStaticAuthenticator([]productapi.StaticToken{
		{Token: ownerBearer, Principal: productapi.Principal{TenantID: "tenant-phase3", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-phase3"}, Role: productapi.RoleOwner}},
		{Token: foreignBearer, Principal: productapi.Principal{TenantID: "tenant-foreign", Actor: product.ActorRef{Type: product.ActorHuman, ID: "actor-foreign"}, Role: productapi.RoleOwner}},
	})
	if err != nil {
		return err
	}
	readiness := &integratedReadiness{pool: pool, providerURL: "http://" + config.ProviderAddress, gatewayURL: "http://" + config.GatewayAddress}
	apiHandler, err := productapiv1.NewHandlerWithCapabilities(application, controls, sessions, grants, catalog, readiness, authenticator, ids)
	if err != nil {
		return err
	}
	webKey, err := base64.RawStdEncoding.DecodeString(config.WebKey)
	if err != nil {
		return err
	}
	web, err := productweb.New(productweb.Options{ProductAPI: apiHandler, Authenticator: authenticator, Files: files, SessionEncryptionKey: webKey, PublicOrigin: publicOrigin, SessionTTL: time.Hour, IdleTTL: 10 * time.Minute, MaxSessions: 100})
	if err != nil {
		return err
	}
	dispatcher, err := product.NewDispatcher(store, providerClient, "phase3-dispatcher", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return err
	}
	sessionDispatcher, err := product.NewSessionDispatcher(store, providerClient, "phase3-session-dispatcher", 2*time.Second, 20*time.Millisecond, 10, 10)
	if err != nil {
		return err
	}
	reconciler, err := product.NewReconciler(store, providerClient, ids, "phase3-reconciler", 2*time.Second, 20*time.Millisecond, 10)
	if err != nil {
		return err
	}
	go func() {
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			_, _ = dispatcher.DispatchOnce(ctx)
			_, _ = sessionDispatcher.DispatchOnce(ctx)
			_, _ = reconciler.ReconcileOnce(ctx)
		}
	}()
	mux := http.NewServeMux()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/guest", hub)
	mux.Handle("/web/", web)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || pool.Ping(request.Context()) != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return http.ListenAndServe(config.ProductAddress, mux)
}

type integratedReadiness struct {
	pool                    *pgxpool.Pool
	providerURL, gatewayURL string
}

func (r *integratedReadiness) Snapshot(ctx context.Context, principal productapi.Principal) ([]productapiv1.ProductCapability, error) {
	providerReady := exactProviderReady(ctx, r.providerURL)
	gatewayReady := healthReady(ctx, r.gatewayURL)
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
		{CapabilityID: "product.workspace", Version: "1.0.0", Readiness: state(providerReady), ProtocolProfiles: []string{"coding-shell-v1"}},
		{CapabilityID: "product.terminal", Version: "1.0.0", Readiness: state(providerReady && gatewayReady), ProtocolProfiles: []string{"product-terminal.v1"}, MaxSessionSeconds: 86400},
		{CapabilityID: "product.files", Version: "1.0.0", Readiness: state(providerReady && guestReady), ProtocolProfiles: []string{"guest-files.v1"}},
	}, nil
}

func exactProviderReady(ctx context.Context, origin string) bool {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/capabilities", nil)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var snapshot providerv1.Capabilities
	return response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&snapshot) == nil && snapshot.ProviderRevisionID == productprovider.LockedProviderRevision && snapshot.APIVersion == providerv1.APIVersionV1
}

func healthReady(ctx context.Context, target string) bool {
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target+"/healthz", nil)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func runGatewayNode(config nodeConfig) error {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := productpostgres.New(pool, 5*time.Second)
	if err != nil {
		return err
	}
	key, err := base64.RawStdEncoding.DecodeString(config.GrantKey)
	if err != nil {
		return err
	}
	grants, err := productpostgres.NewGrantRepository(store, "phase3-grant-key", key)
	if err != nil {
		return err
	}
	audit, err := productpostgres.NewGatewayAuditRepository(store, product.CryptoIDGenerator{})
	if err != nil {
		return err
	}
	handler, err := productgateway.NewHandler(productgateway.Options{
		Grants: grants, Resolver: &postgresResolver{pool: pool, providerAddress: config.ProviderAddress}, Audit: audit,
		OriginPatterns: []string{"product.example.test"}, AuthorityPollInterval: 50 * time.Millisecond, MaxReconnects: 0, MaxConnections: 20, MaxConnectionsPerSession: 2,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/connect", handler)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || pool.Ping(request.Context()) != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	return http.ListenAndServe(config.GatewayAddress, mux)
}

type postgresResolver struct {
	pool            *pgxpool.Pool
	providerAddress string
}

func (r *postgresResolver) Resolve(ctx context.Context, reference string) (gateway.Endpoint, error) {
	var endpoint gateway.Endpoint
	err := r.pool.QueryRow(ctx, `SELECT b.sandbox_id,s.session_id,s.protocol_profile,s.provider_connection_generation,s.provider_handoff_expires_at FROM sandbox_runtime_product.runtime_sessions s JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id AND b.slot_key=s.slot_key AND b.slot_generation=s.slot_generation AND b.current WHERE s.provider_handoff_reference=$1 AND s.state='ready' AND s.provider_handoff_expires_at>clock_timestamp()`, reference).Scan(&endpoint.SandboxID, &endpoint.RuntimeSessionID, &endpoint.CapabilityProfileID, &endpoint.ConnectionGeneration, &endpoint.ExpiresAt)
	if err != nil {
		return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
	}
	endpoint.Reference = reference
	endpoint.Dial = func(dialCtx context.Context) (gateway.Stream, error) {
		header := http.Header{}
		header.Set("Authorization", "Bearer "+privateToken)
		connection, _, err := websocket.Dial(dialCtx, "ws://"+r.providerAddress+"/private/terminal/"+url.PathEscape(reference), &websocket.DialOptions{HTTPHeader: header})
		if err != nil {
			return nil, gateway.ErrReferenceUnavailable
		}
		connection.SetReadLimit(64 << 10)
		return &gatewayWebSocket{connection: connection}, nil
	}
	return endpoint, nil
}

type gatewayWebSocket struct{ connection *websocket.Conn }

func (s *gatewayWebSocket) Receive(ctx context.Context) (gateway.Frame, error) {
	typeValue, payload, err := s.connection.Read(ctx)
	if err != nil {
		return gateway.Frame{}, err
	}
	if typeValue != websocket.MessageBinary {
		return gateway.Frame{}, gateway.ErrProxyUnavailable
	}
	return gateway.Frame{Type: gateway.BinaryFrame, Payload: payload}, nil
}

func (s *gatewayWebSocket) Send(ctx context.Context, frame gateway.Frame) error {
	if frame.Type != gateway.BinaryFrame {
		return gateway.ErrProxyUnavailable
	}
	return s.connection.Write(ctx, websocket.MessageBinary, frame.Payload)
}

func (s *gatewayWebSocket) Close(ctx context.Context) error {
	return s.connection.Close(websocket.StatusNormalClosure, "closed")
}

func runGuestNode(config nodeConfig) error {
	privateKey, err := base64.RawStdEncoding.DecodeString(config.GuestPrivateKey)
	if err != nil {
		return err
	}
	files, err := guestfiles.New(config.GuestRoot)
	if err != nil {
		return err
	}
	defer files.Close()
	agent, err := guestagent.NewAgent(guestagent.AgentOptions{
		URL: "ws://" + config.ProductAddress + "/guest", GuestID: config.GuestID, BindingGeneration: config.GuestGeneration,
		PrivateKey: ed25519.PrivateKey(privateKey), Handlers: files.Handlers(), ReconnectBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		return err
	}
	return agent.Run(context.Background())
}

type providerFixture struct {
	mu         sync.RWMutex
	operations map[string]providerOperation
	references map[string]time.Time
}

type providerOperation struct {
	operation providerv1.Operation
	sessionID string
	reference string
	expiresAt time.Time
}

func runProviderNode(config nodeConfig) error {
	fixture := &providerFixture{operations: make(map[string]providerOperation), references: make(map[string]time.Time)}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/v1/capabilities", fixture.capabilities)
	mux.HandleFunc("/v1/sandboxes", fixture.createSandbox)
	mux.HandleFunc("/v1/sandboxes/", fixture.sessionControl)
	mux.HandleFunc("/v1/operations/", fixture.operationRead)
	mux.HandleFunc("/private/terminal/", fixture.terminal)
	return http.ListenAndServe(config.ProviderAddress, mux)
}

func (f *providerFixture) capabilities(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(writer, http.StatusOK, providerv1.Capabilities{
		ProviderRevisionID: productprovider.LockedProviderRevision, APIVersion: providerv1.APIVersionV1,
		Capabilities: []providerv1.Capability{
			{ID: providerv1.CapabilityExec, Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}},
			{ID: providerv1.CapabilityTerminal, Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}},
			{ID: providerv1.CapabilityTerminalControl, Versions: []string{"1.0.0"}, Profiles: []string{"terminal-control-v1"}},
		},
		RuntimeProfiles:        []providerv1.RuntimeProfile{{ID: "coding-shell-v1", IsolationClass: providerv1.IsolationContainer, Architecture: []providerv1.Architecture{providerArchitecture()}, CapabilityProfileIDs: []string{"exec-v1", "terminal-v1", "terminal-control-v1"}}},
		SnapshotRestoreProfile: []providerv1.SnapshotRestoreProfile{},
		Limits:                 providerv1.ProviderLimits{MaxCPUMillis: 4000, MaxMemoryBytes: 4 << 30, MaxEphemeralStorageBytes: 10 << 30, MaxLeaseSeconds: 86400, MaxExecSeconds: 3600},
	})
}

func (f *providerFixture) createSandbox(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !protected(request) {
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
	f.operations[input.OperationID] = providerOperation{operation: operation}
	f.mu.Unlock()
	writeJSON(writer, http.StatusAccepted, operation)
}

func (f *providerFixture) sessionControl(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || !protected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	if strings.HasSuffix(request.URL.Path, ":close") {
		var input providerv1.RuntimeSessionCloseRequest
		if json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&input) != nil {
			http.Error(writer, "invalid", http.StatusBadRequest)
			return
		}
		sandboxID := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/sandboxes/"), "/")[0]
		operation := providerv1.Operation{OperationID: input.OperationID, AttemptID: input.AttemptID, FencingToken: input.FencingToken, SandboxID: sandboxID, Type: providerv1.OperationCloseRuntimeSession, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + input.OperationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		f.mu.Lock()
		f.operations[input.OperationID] = providerOperation{operation: operation, sessionID: input.RuntimeSessionID}
		f.mu.Unlock()
		writeJSON(writer, http.StatusAccepted, operation)
		return
	}
	var input providerv1.RuntimeSessionOpenRequest
	if json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&input) != nil {
		http.Error(writer, "invalid", http.StatusBadRequest)
		return
	}
	sandboxID := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/sandboxes/"), "/")[0]
	reference := "ref:session:" + input.RuntimeSessionID
	expiresAt, _ := time.Parse(time.RFC3339Nano, input.ExpiresAt)
	operation := providerv1.Operation{OperationID: input.OperationID, AttemptID: input.AttemptID, FencingToken: input.FencingToken, SandboxID: sandboxID, Type: providerv1.OperationOpenRuntimeSession, Status: providerv1.OperationAccepted, ProviderOperationID: "provider-" + input.OperationID, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	f.mu.Lock()
	f.operations[input.OperationID] = providerOperation{operation: operation, sessionID: input.RuntimeSessionID, reference: reference, expiresAt: expiresAt}
	f.references[reference] = expiresAt
	f.mu.Unlock()
	writeJSON(writer, http.StatusAccepted, operation)
}

func (f *providerFixture) operationRead(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !protected(request) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	value := strings.TrimPrefix(request.URL.Path, "/v1/operations/")
	handoff := strings.HasSuffix(value, "/runtime-session")
	operationID := strings.TrimSuffix(value, "/runtime-session")
	f.mu.RLock()
	record, ok := f.operations[operationID]
	f.mu.RUnlock()
	if !ok {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	if handoff {
		writeJSON(writer, http.StatusOK, providerv1.RuntimeSessionHandoff{
			OperationID: record.operation.OperationID, AttemptID: record.operation.AttemptID, FencingToken: record.operation.FencingToken,
			SandboxID: record.operation.SandboxID, RuntimeSessionID: record.sessionID, RuntimeType: providerv1.TerminalRuntimeTerminal,
			CapabilityProfileID: "terminal-v1", Protocol: providerv1.TerminalProtocolWebSocket, InternalEndpointReference: record.reference,
			ConnectionGeneration: 1, ExpiresAt: record.expiresAt.UTC().Format(time.RFC3339Nano),
		})
		return
	}
	record.operation.Status = providerv1.OperationSucceeded
	record.operation.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	writeJSON(writer, http.StatusOK, record.operation)
}

func (f *providerFixture) terminal(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer "+privateToken || request.Header.Get("Origin") != "" {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	reference, err := url.PathUnescape(strings.TrimPrefix(request.URL.Path, "/private/terminal/"))
	if err != nil {
		http.Error(writer, "invalid", http.StatusBadRequest)
		return
	}
	f.mu.RLock()
	expires, ok := f.references[reference]
	f.mu.RUnlock()
	if !ok || !expires.After(time.Now()) {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(64 << 10)
	for {
		messageType, payload, err := connection.Read(request.Context())
		if err != nil {
			return
		}
		if messageType != websocket.MessageBinary || connection.Write(request.Context(), websocket.MessageBinary, payload) != nil {
			return
		}
	}
}

func protected(request *http.Request) bool {
	return strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") && request.Header.Get("X-Sandbox-Runtime-Admission-Context") != ""
}

func startNode(t *testing.T, role string, config nodeConfig) *childNode {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "node.json")
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	node := &childNode{role: role}
	node.cmd = exec.Command(os.Args[0], "-test.run=^TestPhase3Node$", "-test.v")
	node.cmd.Env = append(os.Environ(), "PRODUCT_PHASE3_NODE_ROLE="+role, "PRODUCT_PHASE3_NODE_CONFIG="+path)
	node.cmd.Stdout, node.cmd.Stderr = &node.log, &node.log
	if err := node.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return node
}

func stopNode(node *childNode) bool {
	if node == nil || node.cmd == nil || node.cmd.Process == nil {
		return true
	}
	if node.cmd.ProcessState != nil {
		return true
	}
	_ = node.cmd.Process.Kill()
	return node.cmd.Wait() != nil && node.cmd.ProcessState != nil
}

func removeNode(nodes []*childNode, target *childNode) []*childNode {
	result := nodes[:0]
	for _, node := range nodes {
		if node != target {
			result = append(result, node)
		}
	}
	return result
}

func startPostgreSQL(t *testing.T, ctx context.Context, container string) (string, func()) {
	t.Helper()
	image := productphase3evidence.PostgresImage
	command := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container, "-e", "POSTGRES_PASSWORD=phase3", "-e", "POSTGRES_DB=phase3", "-p", "127.0.0.1::5432", image)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("start pinned PostgreSQL: %v: %s", err, output)
	}
	remove := func() { _ = exec.Command("docker", "rm", "-f", container).Run() }
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		remove()
		t.Fatal(err)
	}
	address := strings.TrimSpace(string(portOutput))
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		remove()
		t.Fatalf("parse PostgreSQL port %q: %v", address, err)
	}
	dsn := "postgres://postgres:phase3@127.0.0.1:" + port + "/phase3?sslmode=disable"
	waitFor(t, 20*time.Second, func() bool {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			return false
		}
		defer pool.Close()
		return pool.Ping(ctx) == nil
	}, "fresh PostgreSQL")
	return dsn, remove
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitHTTP(t *testing.T, target, authorization string, status int) {
	t.Helper()
	waitFor(t, 15*time.Second, func() bool {
		request, _ := http.NewRequest(http.MethodGet, target, nil)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, err := (&http.Client{Timeout: 500 * time.Millisecond}).Do(request)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		return response.StatusCode == status
	}, target)
}

func waitFor(t *testing.T, timeout time.Duration, check func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func api(t *testing.T, method, target, authorization, idempotencyKey, body string) *http.Response {
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

func requireStatus(t *testing.T, response *http.Response, expected int) {
	t.Helper()
	if response.StatusCode != expected {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, expected, body)
	}
}

func decodeResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func waitOperation(t *testing.T, base, operationID, state string) productapiv1.ProductOperation {
	t.Helper()
	var result productapiv1.ProductOperation
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/operations/"+operationID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decodeResponse(t, response, &result)
		return result.State == state
	}, "Product operation "+operationID+" state "+state)
	return result
}

func waitWorkspace(t *testing.T, base, workspaceID, state string) productapiv1.Workspace {
	t.Helper()
	var result productapiv1.Workspace
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/workspaces/"+workspaceID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decodeResponse(t, response, &result)
		return result.ObservedState == state
	}, "Workspace "+workspaceID+" state "+state)
	return result
}

func waitSession(t *testing.T, base, sessionID, state string) productapiv1.RuntimeSession {
	t.Helper()
	var result productapiv1.RuntimeSession
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/sessions/"+sessionID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decodeResponse(t, response, &result)
		return result.State == state
	}, "session "+sessionID+" state "+state)
	return result
}

func getCapabilities(t *testing.T, base string) productapiv1.CapabilityDocument {
	t.Helper()
	response := api(t, http.MethodGet, base+"/api/v1/capabilities", "Bearer "+ownerBearer, "", "")
	requireStatus(t, response, http.StatusOK)
	var document productapiv1.CapabilityDocument
	decodeResponse(t, response, &document)
	return document
}

func requireCapability(t *testing.T, document productapiv1.CapabilityDocument, id, state string) {
	t.Helper()
	if got := capabilityState(document, id); got != state {
		t.Fatalf("capability %s readiness=%q want=%q: %#v", id, got, state, document.Capabilities)
	}
}

func capabilityState(document productapiv1.CapabilityDocument, id string) string {
	for _, capability := range document.Capabilities {
		if capability.CapabilityID == id {
			return capability.Readiness
		}
	}
	return ""
}

func guestState(pool *pgxpool.Pool, guestID string) string {
	var state string
	_ = pool.QueryRow(context.Background(), `SELECT state FROM sandbox_runtime_product.guest_bindings WHERE guest_id=$1`, guestID).Scan(&state)
	return state
}

func testWebFiles(t *testing.T, base, workspaceID, guestRoot string) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, base+"/web/session", nil)
	request.Header.Set("Origin", publicOrigin)
	request.Header.Set("Authorization", "Bearer "+ownerBearer)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, response, http.StatusCreated)
	var session map[string]any
	decodeResponse(t, response, &session)
	var cookie *http.Cookie
	for _, candidate := range response.Cookies() {
		if candidate.Name == "__Host-product_session" {
			cookie = candidate
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("secure Product Web session cookie missing: %#v", response.Cookies())
	}
	fileRequest, _ := http.NewRequest(http.MethodGet, base+"/web/data/workspaces/"+workspaceID+"/slots/primary-code/files?path=&limit=10", nil)
	fileRequest.AddCookie(cookie)
	fileResponse, err := (&http.Client{Timeout: 5 * time.Second}).Do(fileRequest)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, fileResponse, http.StatusOK)
	body, _ := io.ReadAll(fileResponse.Body)
	fileResponse.Body.Close()
	if !bytes.Contains(body, []byte("hello.txt")) || bytes.Contains(body, []byte(guestRoot)) {
		t.Fatalf("unexpected file projection: %s", body)
	}
	unsafeRequest, _ := http.NewRequest(http.MethodGet, base+"/web/data/workspaces/"+workspaceID+"/slots/primary-code/files?path=..&limit=10", nil)
	unsafeRequest.AddCookie(cookie)
	unsafeResponse, err := (&http.Client{Timeout: 5 * time.Second}).Do(unsafeRequest)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, unsafeResponse, http.StatusBadRequest)
	unsafeResponse.Body.Close()
}

func terminalRoundTrip(t *testing.T, gatewayAddress, ticket string, shouldSucceed bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	header := http.Header{}
	header.Set("Origin", publicOrigin)
	connection, response, err := websocket.Dial(ctx, "ws://"+gatewayAddress+"/connect", &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{productgateway.Subprotocol, productgateway.TicketSubprotocolPrefix + ticket}})
	if !shouldSucceed {
		if connection != nil {
			connection.CloseNow()
		}
		if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("replayed ticket result: response=%v err=%v", response, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("dial Product Gateway: %v status=%v", err, response)
	}
	defer connection.CloseNow()
	marker := []byte("phase3-terminal-roundtrip")
	if err := connection.Write(ctx, websocket.MessageBinary, marker); err != nil {
		t.Fatal(err)
	}
	typeValue, payload, err := connection.Read(ctx)
	if err != nil || typeValue != websocket.MessageBinary || !bytes.Equal(payload, marker) {
		t.Fatalf("terminal echo type=%v payload=%q err=%v", typeValue, payload, err)
	}
}

func writeEvidence(t *testing.T, started, completed time.Time) string {
	t.Helper()
	repositoryRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	report, err := productcontract.Verify(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	revisionOutput, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	executableSum := sha256.Sum256(executable)
	executableDigest := "sha256:" + hex.EncodeToString(executableSum[:])
	roles := []string{"product", "gateway", "guest", "provider"}
	processes := make([]productphase3evidence.ProcessEvidence, 0, len(roles))
	for _, role := range roles {
		processes = append(processes, productphase3evidence.ProcessEvidence{Role: role, ExecutableDigest: executableDigest, IndependentOSProcess: true})
	}
	cases := []string{"capability-readiness", "guest-file-boundary", "process-cleanup", "product-authentication", "product-restart-recovery", "provider-fault-closure", "terminal-ticket-replay", "terminal-websocket-roundtrip", "tenant-nondisclosure"}
	scenarios := make([]productphase3evidence.ScenarioEvidence, 0, len(cases))
	for _, id := range cases {
		scenarios = append(scenarios, productphase3evidence.ScenarioEvidence{ID: id, Status: "passed"})
	}
	manifest := productphase3evidence.Manifest{
		SchemaVersion: 1, RunID: started.Format("20060102T150405.000000000Z"), Result: "passed", EvidenceTier: "same-repository-separate-process",
		SourceRevision: strings.TrimSpace(string(revisionOutput)), StartedAt: started.Format(time.RFC3339Nano), CompletedAt: completed.Format(time.RFC3339Nano),
		Provider:   productphase3evidence.ProviderIdentity{Revision: productphase3evidence.ProviderRevision, Tree: productphase3evidence.ProviderTree},
		Product:    productphase3evidence.ProductIdentity{Tree: report.TreeDigest, ResourceCount: report.ResourceCount, OperationCount: report.OperationCount, ConformanceCases: report.ConformanceCases},
		PostgreSQL: productphase3evidence.PostgreSQLIdentity{Image: productphase3evidence.PostgresImage, FreshSchema: true},
		Processes:  processes, Scenarios: scenarios,
		Cleanup:   productphase3evidence.CleanupEvidence{ChildProcessesReaped: true, ContainerRemoved: true, ScopedRowsRemoved: true},
		NonClaims: []string{"deployment-qualified", "ha-qualified", "hostile-multi-tenant-qualified", "production-ready"},
	}
	directory := os.Getenv("PRODUCT_PHASE3_EVIDENCE_OUTPUT")
	if directory == "" {
		directory, err = os.MkdirTemp("", "product-phase3-evidence-")
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "manifest.json")
	document, _ := json.MarshalIndent(manifest, "", "  ")
	document = append(document, '\n')
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func providerArchitecture() providerv1.Architecture {
	if runtime.GOARCH == "arm64" {
		return providerv1.ArchitectureARM64
	}
	return providerv1.ArchitectureAMD64
}

var (
	_ gateway.ReferenceResolver     = (*postgresResolver)(nil)
	_ gateway.Stream                = (*gatewayWebSocket)(nil)
	_ productapiv1.CapabilitySource = (*integratedReadiness)(nil)
)
