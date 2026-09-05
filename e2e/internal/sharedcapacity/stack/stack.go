package stack

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	gatewaycomposition "github.com/shell-echo/sandbox-runtime/gateway/composition"
	gatewayedge "github.com/shell-echo/sandbox-runtime/gateway/edge"
)

const maxGrantLifetime = 15 * time.Minute

type principalContextKey struct{}
type connectionContextKey struct{}

type connectionInput struct {
	grantID              string
	connectionGeneration int64
	expiresAt            time.Time
	request              gateway.ConnectRequest
}

type Stack struct {
	server       *gatewayedge.TLSServer
	client       *goredis.Client
	audit        *evidenceWriter
	observations *evidenceWriter
	controller   *controller
	cancel       context.CancelFunc
	closeOnce    sync.Once
	closeErr     error
}

func Open(ctx context.Context, input wire.GatewayConfig) (_ *Stack, resultErr error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ValidateConfig(input); err != nil {
		return nil, err
	}
	config := cloneConfig(input)
	processCtx, cancel := context.WithCancel(ctx)
	stack := &Stack{cancel: cancel}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, stack.Close())
		}
	}()

	client, err := newRedisClient(config.RedisURL, policyOperationTimeout(config.Policy))
	if err != nil {
		return nil, err
	}
	stack.client = client
	capacity, err := rediscapacity.New(rediscapacity.Options{
		Client: client, Namespace: config.CapacityNamespace,
		MaxTotal: config.Policy.MaxTotal, MaxPerTenant: config.Policy.MaxPerTenant,
		MaxPerSession:       config.Policy.MaxPerSession,
		LeaseTTL:            time.Duration(config.Policy.LeaseTTLMillis) * time.Millisecond,
		RenewInterval:       time.Duration(config.Policy.RenewIntervalMillis) * time.Millisecond,
		RenewalSafetyMargin: time.Duration(config.Policy.RenewalSafetyMarginMillis) * time.Millisecond,
		OperationTimeout:    policyOperationTimeout(config.Policy),
	})
	if err != nil {
		return nil, fmt.Errorf("construct shared capacity: %w", err)
	}
	if err := capacity.Verify(ctx); err != nil {
		return nil, fmt.Errorf("verify shared capacity policy: %w", err)
	}

	auditWriter, err := newEvidenceWriter(config.AuditFile)
	if err != nil {
		return nil, fmt.Errorf("open Gateway audit: %w", err)
	}
	stack.audit = auditWriter
	observationWriter, err := newEvidenceWriter(config.ObservationFile)
	if err != nil {
		return nil, fmt.Errorf("open Gateway observations: %w", err)
	}
	stack.observations = observationWriter

	controller := newController(config.Principals, config.Endpoints)
	stack.controller = controller
	resolver := newExactResolver(config.Endpoints, &observationRecorder{writer: observationWriter})
	edgeGate, err := gatewayedge.NewLocalLimiter(gatewayedge.LocalOptions{
		MaxConcurrent:        gatewayedge.MaxConcurrentConnections,
		MaxRequestsPerWindow: gatewayedge.MaxRequestsPerWindow,
		Window:               gatewayedge.MaxWindow,
	})
	if err != nil {
		return nil, fmt.Errorf("construct local edge limiter: %w", err)
	}
	service, err := gatewaycomposition.NewBrowser(gatewaycomposition.BrowserOptions{
		Authorizer: controller, Revocations: gateway.NewMemoryRevocations(),
		Recorder: &auditRecorder{writer: auditWriter}, Resolver: resolver,
		WebSocket: adapter.WebSocketOptions{
			Admission: controller.admit, OriginPatterns: []string{"https://reference-caller.invalid"},
			MaxFrameBytes: adapter.DefaultMaxFrameBytes,
		},
		Edge: edgeGate, Capacity: capacity,
		MaxReconnects: 1, ReconnectBackoff: 10 * time.Millisecond,
		CapacityReleaseTimeout: capacityReleaseTimeout(config.Policy),
		MaxConnections:         gateway.MaxConnectionCapacity, MaxConnectionsPerSession: gateway.MaxConnectionCapacity,
	})
	if err != nil {
		return nil, fmt.Errorf("construct Browser Gateway: %w", err)
	}
	controller.service = service
	server, err := gatewayedge.NewTLSServer(gatewayedge.ServerOptions{
		Address: config.Address, Handler: controller.handler(processCtx),
		ServerCertificateFile: config.ServerCertificateFile,
		ServerPrivateKeyFile:  config.ServerPrivateKeyFile,
		MaxConnections:        gatewayedge.MaxAcceptedConnections,
		ReadHeaderTimeout:     time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10,
	})
	if err != nil {
		return nil, fmt.Errorf("construct Browser TLS server: %w", err)
	}
	stack.server = server
	return stack, nil
}

func (s *Stack) Run(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return errors.New("shared-capacity Gateway is unavailable")
	}
	return s.server.Startup(ctx)
}

func (s *Stack) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.closeErr = errors.Join(s.closeErr, s.server.Shutdown(ctx))
			cancel()
		}
		if s.controller != nil {
			s.closeErr = errors.Join(s.closeErr, s.controller.wait())
		}
		if s.observations != nil {
			s.closeErr = errors.Join(s.closeErr, s.observations.Close())
		}
		if s.audit != nil {
			s.closeErr = errors.Join(s.closeErr, s.audit.Close())
		}
		if s.client != nil {
			s.closeErr = errors.Join(s.closeErr, s.client.Close())
		}
	})
	return s.closeErr
}

func newRedisClient(endpoint string, operationTimeout time.Duration) (*goredis.Client, error) {
	options, err := goredis.ParseURL(endpoint)
	if err != nil {
		return nil, errors.New("parse Redis configuration")
	}
	options.Protocol = 2
	options.MaxRetries = -1
	options.ContextTimeoutEnabled = true
	options.DisableIdentity = true
	options.DialTimeout = operationTimeout
	options.ReadTimeout = operationTimeout
	options.WriteTimeout = operationTimeout
	options.PoolTimeout = operationTimeout
	return goredis.NewClient(options), nil
}

func policyOperationTimeout(policy wire.CapacityPolicy) time.Duration {
	return time.Duration(policy.OperationTimeoutMillis) * time.Millisecond
}

func capacityReleaseTimeout(policy wire.CapacityPolicy) time.Duration {
	timeout := 2 * policyOperationTimeout(policy)
	if timeout < gateway.MinCapacityReleaseTimeout {
		return gateway.MinCapacityReleaseTimeout
	}
	if timeout > 5*time.Second {
		return 5 * time.Second
	}
	return timeout
}

type controller struct {
	principalsByToken map[string]wire.Principal
	endpoints         map[string]wire.Endpoint
	service           browserService
	handlers          sync.WaitGroup
}

type browserService interface {
	Serve(context.Context, http.ResponseWriter, *http.Request, gateway.ConnectRequest) error
}

func newController(principals []wire.Principal, endpoints []wire.Endpoint) *controller {
	result := &controller{
		principalsByToken: make(map[string]wire.Principal, len(principals)),
		endpoints:         make(map[string]wire.Endpoint, len(endpoints)),
	}
	for _, principal := range principals {
		result.principalsByToken[principal.Token] = principal
	}
	for _, endpoint := range endpoints {
		result.endpoints[endpoint.HandoffReference] = endpoint
	}
	return result
}

func (c *controller) handler(processCtx context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/browser/connect", func(response http.ResponseWriter, request *http.Request) {
		c.handlers.Add(1)
		defer c.handlers.Done()
		c.connect(processCtx, response, request)
	})
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte("{\"status\":\"ready\"}\n"))
	})
	return mux
}

func (c *controller) wait() error {
	done := make(chan struct{})
	go func() {
		c.handlers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("Gateway connections did not stop")
	}
}

func (c *controller) connect(processCtx context.Context, response http.ResponseWriter, request *http.Request) {
	principal, ok := c.authenticate(request.Header.Get("Authorization"))
	if !ok {
		http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	connectRequest, input, err := c.parseConnect(request.URL.RawQuery)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	requestCtx := context.WithValue(request.Context(), principalContextKey{}, principal)
	requestCtx = context.WithValue(requestCtx, connectionContextKey{}, input)
	connectionCtx, cancel := context.WithCancel(requestCtx)
	stop := context.AfterFunc(processCtx, cancel)
	defer func() {
		cancel()
		stop()
	}()
	request = request.WithContext(connectionCtx)
	// BrowserService owns every response after Upgrade. In particular, shared
	// capacity rejection is a WebSocket close and never a late HTTP error.
	_ = c.service.Serve(connectionCtx, response, request, connectRequest)
}

func (c *controller) parseConnect(rawQuery string) (gateway.ConnectRequest, connectionInput, error) {
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return gateway.ConnectRequest{}, connectionInput{}, err
	}
	allowed := map[string]bool{
		"grant_id": true, "caller_id": true, "tenant_id": true, "sandbox_id": true,
		"browser_session_id": true, "capability_profile_id": true, "handoff_reference": true,
		"connection_generation": true, "expires_at": true,
	}
	for name, values := range query {
		if !allowed[name] || len(values) != 1 || values[0] == "" {
			return gateway.ConnectRequest{}, connectionInput{}, errors.New("invalid Gateway query")
		}
	}
	if len(query) != len(allowed) {
		return gateway.ConnectRequest{}, connectionInput{}, errors.New("incomplete Gateway query")
	}
	generation, err := strconv.ParseInt(query.Get("connection_generation"), 10, 64)
	if err != nil || generation < 1 {
		return gateway.ConnectRequest{}, connectionInput{}, errors.New("invalid connection generation")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, query.Get("expires_at"))
	if err != nil {
		return gateway.ConnectRequest{}, connectionInput{}, errors.New("invalid grant expiry")
	}
	request := gateway.ConnectRequest{
		CallerID: query.Get("caller_id"), TenantID: query.Get("tenant_id"),
		SandboxID: query.Get("sandbox_id"), BrowserSessionID: query.Get("browser_session_id"),
		CapabilityProfileID: query.Get("capability_profile_id"), HandoffReference: query.Get("handoff_reference"),
	}
	if err := request.Validate(); err != nil {
		return gateway.ConnectRequest{}, connectionInput{}, errors.New("invalid Gateway identity")
	}
	return request, connectionInput{
		grantID: query.Get("grant_id"), connectionGeneration: generation,
		expiresAt: expiresAt.UTC(), request: request,
	}, nil
}

func (c *controller) admit(_ context.Context, request *http.Request) error {
	if request == nil {
		return gateway.ErrUnauthorized
	}
	if _, ok := c.authenticate(request.Header.Get("Authorization")); !ok {
		return gateway.ErrUnauthorized
	}
	return nil
}

func (c *controller) Authorize(ctx context.Context, request gateway.ConnectRequest) (gateway.Grant, error) {
	principal, principalOK := ctx.Value(principalContextKey{}).(wire.Principal)
	input, inputOK := ctx.Value(connectionContextKey{}).(connectionInput)
	now := time.Now().UTC()
	endpoint, endpointOK := c.endpoints[request.HandoffReference]
	if !principalOK || !inputOK || request.CallerID != principal.CallerID || request.TenantID != principal.TenantID ||
		input.request != request || !endpointOK || !endpointMatchesRequest(endpoint, request) ||
		endpoint.ConnectionGeneration != input.connectionGeneration ||
		!input.expiresAt.After(now) || input.expiresAt.After(now.Add(maxGrantLifetime)) {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	grant := gateway.Grant{
		GrantID: input.grantID, CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: input.connectionGeneration, ExpiresAt: input.expiresAt.UTC(),
	}
	if err := grant.Validate(now); err != nil {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	return grant, nil
}

func (c *controller) authenticate(header string) (wire.Principal, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return wire.Principal{}, false
	}
	token := strings.TrimPrefix(header, prefix)
	var matched wire.Principal
	found := 0
	for candidate, principal := range c.principalsByToken {
		if len(token) == len(candidate) && subtle.ConstantTimeCompare([]byte(token), []byte(candidate)) == 1 {
			matched = principal
			found++
		}
	}
	return matched, found == 1
}

var _ gateway.Authorizer = (*controller)(nil)
