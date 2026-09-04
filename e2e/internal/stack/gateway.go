package stack

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	gatewaycomposition "github.com/shell-echo/sandbox-runtime/gateway/composition"
	gatewayedge "github.com/shell-echo/sandbox-runtime/gateway/edge"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	sessionreference "github.com/shell-echo/sandbox-runtime/provider/session/reference"
)

type principalContextKey struct{}
type grantContextKey struct{}

type grantInput struct {
	GrantID              string
	ConnectionGeneration int64
	ExpiresAt            time.Time
}

type referenceGateway struct {
	terminal    *gatewaycomposition.Service
	browser     *gatewaycomposition.BrowserService
	revocations *gateway.MemoryRevocations
	principals  map[string]GatewayPrincipal
	adminToken  string
	recorder    *jsonlRecorder
}

func newReferenceGateway(config Config, terminalResolver *sessionreference.Resolver, browserResolver *browserreference.Resolver) (*referenceGateway, error) {
	principals := make(map[string]GatewayPrincipal, len(config.GatewayPrincipals))
	for _, principal := range config.GatewayPrincipals {
		principals[principal.Token] = principal
	}
	revocations := gateway.NewMemoryRevocations()
	recorder, err := newJSONLRecorder(config.GatewayAuditFile)
	if err != nil {
		return nil, err
	}
	result := &referenceGateway{revocations: revocations, principals: principals, adminToken: config.GatewayAdminToken, recorder: recorder}
	webSocket := adapter.WebSocketOptions{
		Admission: result.admitWebSocket, OriginPatterns: []string{"https://reference-caller.invalid"},
	}
	if terminalResolver != nil {
		service, err := gatewaycomposition.New(gatewaycomposition.Options{
			Authorizer: result, Revocations: revocations, Recorder: recorder, Resolver: terminalResolver,
			WebSocket: webSocket, MaxReconnects: 1, ReconnectBackoff: 10 * time.Millisecond,
		})
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		result.terminal = service
	}
	if browserResolver != nil {
		edgeGate, err := gatewayedge.NewLocalLimiter(gatewayedge.LocalOptions{
			MaxConcurrent: 32, MaxRequestsPerWindow: 8, Window: time.Second,
		})
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		service, err := gatewaycomposition.NewBrowser(gatewaycomposition.BrowserOptions{
			Authorizer: result, Revocations: revocations, Recorder: recorder, Resolver: browserResolver,
			WebSocket: webSocket, MaxReconnects: 1, ReconnectBackoff: 10 * time.Millisecond,
			Edge:           edgeGate,
			MaxConnections: 16, MaxConnectionsPerSession: 1,
		})
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		result.browser = service
	}
	if result.terminal == nil && result.browser == nil {
		_ = recorder.Close()
		return nil, errors.New("reference Gateway requires a terminal or Browser resolver")
	}
	return result, nil
}

func (g *referenceGateway) Close() error {
	if g == nil || g.recorder == nil {
		return nil
	}
	err := g.recorder.Close()
	g.recorder = nil
	return err
}

func (g *referenceGateway) Handler() http.Handler {
	mux := http.NewServeMux()
	if g.terminal != nil {
		mux.HandleFunc("GET /v1/connect", g.connect)
	}
	if g.browser != nil {
		mux.HandleFunc("GET /v1/browser/connect", g.connectBrowser)
	}
	mux.HandleFunc("POST /v1/revoke/{grant_id}", g.revoke)
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte("{\"status\":\"ready\"}\n"))
	})
	return mux
}

func (g *referenceGateway) connect(response http.ResponseWriter, request *http.Request) {
	principal, ok := g.authenticate(request.Header.Get("Authorization"))
	if !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	generation, err := strconv.ParseInt(request.URL.Query().Get("connection_generation"), 10, 64)
	if err != nil || generation < 1 {
		http.Error(response, "invalid connection generation", http.StatusBadRequest)
		return
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.URL.Query().Get("expires_at"))
	if err != nil {
		http.Error(response, "invalid expiry", http.StatusBadRequest)
		return
	}
	connect := gateway.ConnectRequest{
		CallerID:            request.URL.Query().Get("caller_id"),
		TenantID:            request.URL.Query().Get("tenant_id"),
		SandboxID:           request.URL.Query().Get("sandbox_id"),
		RuntimeSessionID:    request.URL.Query().Get("runtime_session_id"),
		CapabilityProfileID: request.URL.Query().Get("capability_profile_id"),
		HandoffReference:    request.URL.Query().Get("handoff_reference"),
	}
	ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
	ctx = context.WithValue(ctx, grantContextKey{}, grantInput{
		GrantID: request.URL.Query().Get("grant_id"), ConnectionGeneration: generation, ExpiresAt: expiresAt.UTC(),
	})
	request = request.WithContext(ctx)
	if err := g.terminal.Serve(ctx, response, request, connect); err != nil {
		// A successful WebSocket upgrade owns its close status. Pre-upgrade
		// failures use bounded HTTP status without leaking Provider details.
		if !errors.Is(err, context.Canceled) {
			return
		}
	}
}

func (g *referenceGateway) connectBrowser(response http.ResponseWriter, request *http.Request) {
	principal, ok := g.authenticate(request.Header.Get("Authorization"))
	if !ok {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	generation, err := strconv.ParseInt(request.URL.Query().Get("connection_generation"), 10, 64)
	if err != nil || generation < 1 {
		http.Error(response, "invalid connection generation", http.StatusBadRequest)
		return
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.URL.Query().Get("expires_at"))
	if err != nil {
		http.Error(response, "invalid expiry", http.StatusBadRequest)
		return
	}
	connect := gateway.ConnectRequest{
		CallerID: request.URL.Query().Get("caller_id"), TenantID: request.URL.Query().Get("tenant_id"),
		SandboxID: request.URL.Query().Get("sandbox_id"), BrowserSessionID: request.URL.Query().Get("browser_session_id"),
		CapabilityProfileID: request.URL.Query().Get("capability_profile_id"), HandoffReference: request.URL.Query().Get("handoff_reference"),
	}
	ctx := context.WithValue(request.Context(), principalContextKey{}, principal)
	ctx = context.WithValue(ctx, grantContextKey{}, grantInput{
		GrantID: request.URL.Query().Get("grant_id"), ConnectionGeneration: generation, ExpiresAt: expiresAt.UTC(),
	})
	request = request.WithContext(ctx)
	if err := g.browser.Serve(ctx, response, request, connect); err != nil {
		if !errors.Is(err, context.Canceled) {
			return
		}
	}
}

func (g *referenceGateway) revoke(response http.ResponseWriter, request *http.Request) {
	if !constantEqual(request.Header.Get("X-E2E-Admin-Token"), g.adminToken) {
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	grantID := request.PathValue("grant_id")
	if err := g.revocations.Revoke(request.Context(), grantID); err != nil {
		http.Error(response, "unavailable", http.StatusServiceUnavailable)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (g *referenceGateway) admitWebSocket(_ context.Context, request *http.Request) error {
	if _, ok := g.authenticate(request.Header.Get("Authorization")); !ok {
		return gateway.ErrUnauthorized
	}
	return nil
}

func (g *referenceGateway) Authorize(ctx context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
	principal, ok := ctx.Value(principalContextKey{}).(GatewayPrincipal)
	if !ok || principal.CallerID != request.CallerID || principal.TenantID != request.TenantID {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	input, ok := ctx.Value(grantContextKey{}).(grantInput)
	if !ok || !input.ExpiresAt.After(time.Now().UTC()) {
		return gateway.Grant{}, gateway.ErrExpired
	}
	return gateway.Grant{
		GrantID: input.GrantID, CallerID: request.CallerID,
		TenantID: request.TenantID, SandboxID: request.SandboxID, RuntimeSessionID: request.RuntimeSessionID, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: input.ConnectionGeneration, ExpiresAt: input.ExpiresAt,
	}, nil
}

func (g *referenceGateway) authenticate(header string) (GatewayPrincipal, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return GatewayPrincipal{}, false
	}
	token := strings.TrimPrefix(header, prefix)
	for candidate, principal := range g.principals {
		if constantEqual(token, candidate) {
			return principal, true
		}
	}
	return GatewayPrincipal{}, false
}

func constantEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

type jsonlRecorder struct {
	mu   sync.Mutex
	file *os.File
	buf  *bufio.Writer
}

func newJSONLRecorder(path string) (*jsonlRecorder, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &jsonlRecorder{file: file, buf: bufio.NewWriter(file)}, nil
}

func (r *jsonlRecorder) Record(_ context.Context, event gateway.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(r.buf, "%s\n", encoded); err != nil {
		return err
	}
	return r.buf.Flush()
}

func (r *jsonlRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return errors.Join(r.buf.Flush(), r.file.Close())
}
