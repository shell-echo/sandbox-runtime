package stack

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

func TestControllerAuthorizerRequiresExactPreissuedGrantBinding(t *testing.T) {
	config := validConfig(t)
	controller, err := newController(config.Principals, config.Endpoints, config.GrantBindings, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := endpointRequest(config)
	expiresAt, err := parseCanonicalExpiry(config.GrantBindings[0].ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	input := connectionInput{
		grantID: config.GrantBindings[0].GrantID, expiresAtRaw: config.GrantBindings[0].ExpiresAt,
		connectionGeneration: config.Endpoints[0].ConnectionGeneration,
		expiresAt:            expiresAt,
		request:              request,
	}
	ctx := authorizationContext(config.Principals[0], input)
	grant, err := controller.Authorize(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantID != input.grantID || grant.ConnectionGeneration != input.connectionGeneration || !grant.ExpiresAt.Equal(input.expiresAt) {
		t.Fatalf("grant = %#v", grant)
	}

	for _, test := range []struct {
		name      string
		principal wire.Principal
		mutate    func(*gateway.ConnectRequest, *connectionInput)
	}{
		{name: "principal", principal: wire.Principal{ID: "principal-other", CallerID: config.Principals[0].CallerID, TenantID: config.Principals[0].TenantID}, mutate: func(*gateway.ConnectRequest, *connectionInput) {}},
		{name: "raw grant", principal: config.Principals[0], mutate: func(_ *gateway.ConnectRequest, input *connectionInput) { input.grantID = "grant-other" }},
		{name: "raw expiry", principal: config.Principals[0], mutate: func(_ *gateway.ConnectRequest, input *connectionInput) {
			input.expiresAtRaw = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
		}},
		{name: "expiry value", principal: config.Principals[0], mutate: func(_ *gateway.ConnectRequest, input *connectionInput) {
			input.expiresAt = input.expiresAt.Add(time.Second)
		}},
		{name: "generation", principal: config.Principals[0], mutate: func(_ *gateway.ConnectRequest, input *connectionInput) { input.connectionGeneration++ }},
		{name: "caller", principal: config.Principals[0], mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.CallerID = "caller-other" }},
		{name: "tenant", principal: config.Principals[0], mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.TenantID = "tenant-other" }},
		{name: "endpoint", principal: config.Principals[0], mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.SandboxID = "sandbox-other" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedRequest, changedInput := request, input
			test.mutate(&changedRequest, &changedInput)
			changedCtx := authorizationContext(test.principal, changedInput)
			if _, err := controller.Authorize(changedCtx, changedRequest); !errors.Is(err, gateway.ErrUnauthorized) {
				t.Fatalf("Authorize() error = %v, want unauthorized", err)
			}
		})
	}
}

func TestControllerParsesOnlyExactCanonicalQuery(t *testing.T) {
	config := validConfig(t)
	controller, err := newController(config.Principals, config.Endpoints, config.GrantBindings, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	query := validConnectQuery(config)
	request, input, err := controller.parseConnect(query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if request != input.request || request != endpointRequest(config) || input.expiresAtRaw != config.GrantBindings[0].ExpiresAt {
		t.Fatalf("parsed request/input = %#v / %#v", request, input)
	}
	query.Add("caller_id", "caller-other")
	if _, _, err := controller.parseConnect(query.Encode()); err == nil {
		t.Fatal("parseConnect() accepted duplicate query input")
	}
	query = validConnectQuery(config)
	query.Set("expires_at", time.Now().Format(time.RFC3339Nano))
	if _, _, err := controller.parseConnect(query.Encode()); err == nil {
		t.Fatal("parseConnect() accepted non-UTC expiry input")
	}
}

func TestControllerHandlerUsesOnlyGenericReadyAndAdmissionResponses(t *testing.T) {
	config := validConfig(t)
	controller, err := newController(config.Principals, config.Endpoints, config.GrantBindings, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	handler := controller.handler(context.Background())
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.String() != "{\"status\":\"ready\"}\n" {
		t.Fatalf("health response = %d %q", health.Code, health.Body.String())
	}
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/v1/browser/connect", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Body.String() != "Unauthorized\n" {
		t.Fatalf("unauthorized response = %d %q", unauthorized.Code, unauthorized.Body.String())
	}
}

func TestRedisClientMeetsDurableRevocationSafetyOptions(t *testing.T) {
	client, err := newRedisClient("redis://127.0.0.1:1/0", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := redisrevocation.New(redisrevocation.Options{
		Client: client, Namespace: "durable-revocation-test", MaxGrantLifetime: 15 * time.Minute,
		PollInterval: 100 * time.Millisecond, OperationTimeout: 100 * time.Millisecond,
	}); err != nil {
		t.Fatalf("strict Redis client rejected by revocation adapter: %v", err)
	}
}

func authorizationContext(principal wire.Principal, input connectionInput) context.Context {
	ctx := context.WithValue(context.Background(), principalContextKey{}, principal)
	return context.WithValue(ctx, connectionContextKey{}, input)
}

func validConnectQuery(config wire.GatewayConfig) url.Values {
	request := endpointRequest(config)
	return url.Values{
		"grant_id": {config.GrantBindings[0].GrantID}, "caller_id": {request.CallerID}, "tenant_id": {request.TenantID},
		"sandbox_id": {request.SandboxID}, "browser_session_id": {request.BrowserSessionID},
		"capability_profile_id": {request.CapabilityProfileID}, "handoff_reference": {request.HandoffReference},
		"connection_generation": {strconv.FormatInt(config.Endpoints[0].ConnectionGeneration, 10)},
		"expires_at":            {config.GrantBindings[0].ExpiresAt},
	}
}

func endpointRequest(config wire.GatewayConfig) gateway.ConnectRequest {
	principal, endpoint := config.Principals[0], config.Endpoints[0]
	return gateway.ConnectRequest{
		CallerID: principal.CallerID, TenantID: principal.TenantID, SandboxID: endpoint.SandboxID,
		BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
		HandoffReference: endpoint.HandoffReference,
	}
}
