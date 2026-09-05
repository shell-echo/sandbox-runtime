package gatewaystack

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

type principalContextKey struct{}
type connectionContextKey struct{}

type connectionInput struct {
	grantID              string
	expiresAtRaw         string
	connectionGeneration int64
	expiresAt            time.Time
	request              gateway.ConnectRequest
}

type preparedGrantBinding struct {
	binding   GrantBinding
	principal Principal
	endpoint  Endpoint
	expiresAt time.Time
}

type browserService interface {
	Serve(context.Context, http.ResponseWriter, *http.Request, gateway.ConnectRequest) error
}

type controller struct {
	principalsByToken map[string]Principal
	endpoints         map[string]Endpoint
	bindingsByGrant   map[string]preparedGrantBinding
	service           browserService
	handlers          sync.WaitGroup
}

func newController(principals []Principal, endpoints []Endpoint, bindings []GrantBinding) (*controller, error) {
	result := &controller{
		principalsByToken: make(map[string]Principal, len(principals)),
		endpoints:         make(map[string]Endpoint, len(endpoints)),
		bindingsByGrant:   make(map[string]preparedGrantBinding, len(bindings)),
	}
	principalsByID := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		result.principalsByToken[principal.Token] = principal
		principalsByID[principal.ID] = principal
	}
	endpointsByID := make(map[string]Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		result.endpoints[endpoint.HandoffReference] = endpoint
		endpointsByID[endpoint.ID] = endpoint
	}
	for _, binding := range bindings {
		expiresAt, err := parseCanonicalExpiry(binding.ExpiresAt)
		principal, principalOK := principalsByID[binding.PrincipalID]
		endpoint, endpointOK := endpointsByID[binding.EndpointID]
		if err != nil || !principalOK || !endpointOK {
			return nil, errors.New("construct pre-issued grant authority")
		}
		if _, exists := result.bindingsByGrant[binding.GrantID]; exists {
			return nil, errors.New("construct unique pre-issued grant authority")
		}
		result.bindingsByGrant[binding.GrantID] = preparedGrantBinding{
			binding: binding, principal: principal, endpoint: endpoint, expiresAt: expiresAt,
		}
	}
	return result, nil
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
	_ = c.service.Serve(connectionCtx, response, request.WithContext(connectionCtx), connectRequest)
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
	expiresAtRaw := query.Get("expires_at")
	expiresAt, err := parseCanonicalExpiry(expiresAtRaw)
	if err != nil {
		return gateway.ConnectRequest{}, connectionInput{}, errors.New("invalid grant expiry")
	}
	request := gateway.ConnectRequest{
		CallerID: query.Get("caller_id"), TenantID: query.Get("tenant_id"), SandboxID: query.Get("sandbox_id"),
		BrowserSessionID: query.Get("browser_session_id"), CapabilityProfileID: query.Get("capability_profile_id"),
		HandoffReference: query.Get("handoff_reference"),
	}
	if err := request.Validate(); err != nil || !identifierPattern.MatchString(query.Get("grant_id")) {
		return gateway.ConnectRequest{}, connectionInput{}, errors.New("invalid Gateway identity")
	}
	return request, connectionInput{
		grantID: query.Get("grant_id"), expiresAtRaw: expiresAtRaw, connectionGeneration: generation,
		expiresAt: expiresAt, request: request,
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
	principal, principalOK := ctx.Value(principalContextKey{}).(Principal)
	input, inputOK := ctx.Value(connectionContextKey{}).(connectionInput)
	binding, bindingOK := c.bindingsByGrant[input.grantID]
	endpoint, endpointOK := c.endpoints[request.HandoffReference]
	now := time.Now().UTC()
	if !principalOK || !inputOK || !bindingOK || !endpointOK || input.request != request ||
		binding.principal.ID != principal.ID || binding.binding.PrincipalID != principal.ID ||
		binding.endpoint.ID != endpoint.ID || binding.binding.EndpointID != endpoint.ID ||
		binding.binding.GrantID != input.grantID || binding.binding.ExpiresAt != input.expiresAtRaw ||
		!binding.expiresAt.Equal(input.expiresAt) || request.CallerID != principal.CallerID ||
		request.TenantID != principal.TenantID || !endpointMatchesRequest(endpoint, request) ||
		endpoint.ConnectionGeneration != input.connectionGeneration || !input.expiresAt.After(now) ||
		input.expiresAt.After(now.Add(durationMillis(lockedRevocationMaxGrantLifetimeMillis))) {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	grant := gateway.Grant{
		GrantID: input.grantID, CallerID: request.CallerID, TenantID: request.TenantID,
		SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
		CapabilityProfileID: request.CapabilityProfileID, HandoffReference: request.HandoffReference,
		ConnectionGeneration: input.connectionGeneration, ExpiresAt: input.expiresAt,
	}
	if err := grant.Validate(now); err != nil {
		return gateway.Grant{}, gateway.ErrUnauthorized
	}
	return grant, nil
}

func (c *controller) authenticate(header string) (Principal, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return Principal{}, false
	}
	token := strings.TrimPrefix(header, prefix)
	var matched Principal
	found := 0
	for candidate, principal := range c.principalsByToken {
		if len(token) == len(candidate) && subtle.ConstantTimeCompare([]byte(token), []byte(candidate)) == 1 {
			matched = principal
			found++
		}
	}
	return matched, found == 1
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

func endpointMatchesRequest(endpoint Endpoint, request gateway.ConnectRequest) bool {
	return endpoint.TenantID == request.TenantID && endpoint.SandboxID == request.SandboxID &&
		endpoint.BrowserSessionID == request.BrowserSessionID && endpoint.CapabilityProfileID == request.CapabilityProfileID &&
		endpoint.HandoffReference == request.HandoffReference
}

var _ gateway.Authorizer = (*controller)(nil)
