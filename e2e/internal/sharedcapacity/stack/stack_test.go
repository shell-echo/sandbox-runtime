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

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

func TestControllerAuthorizerBindsEveryRequestField(t *testing.T) {
	config := validConfig(t)
	controller := newController(config.Principals, config.Endpoints)
	request := endpointRequest(config)
	input := connectionInput{
		grantID: "grant-1", connectionGeneration: config.Endpoints[0].ConnectionGeneration,
		expiresAt: time.Now().UTC().Add(time.Minute), request: request,
	}
	ctx := context.WithValue(context.Background(), principalContextKey{}, config.Principals[0])
	ctx = context.WithValue(ctx, connectionContextKey{}, input)
	grant, err := controller.Authorize(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantID != input.grantID || grant.ConnectionGeneration != input.connectionGeneration || !grant.ExpiresAt.Equal(input.expiresAt) {
		t.Fatalf("grant = %#v", grant)
	}

	for _, test := range []struct {
		name   string
		mutate func(*gateway.ConnectRequest, *connectionInput)
	}{
		{name: "caller", mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.CallerID = "caller-other" }},
		{name: "tenant", mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.TenantID = "tenant-other" }},
		{name: "sandbox", mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.SandboxID = "sandbox-other" }},
		{name: "session", mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.BrowserSessionID = "browser-other" }},
		{name: "profile", mutate: func(request *gateway.ConnectRequest, _ *connectionInput) { request.CapabilityProfileID = "browser-v2" }},
		{name: "reference", mutate: func(request *gateway.ConnectRequest, _ *connectionInput) {
			request.HandoffReference = "ref:browser-session:22222222222222222222222222222222"
		}},
		{name: "generation", mutate: func(_ *gateway.ConnectRequest, input *connectionInput) { input.connectionGeneration++ }},
		{name: "grant", mutate: func(_ *gateway.ConnectRequest, input *connectionInput) { input.grantID = "bad grant" }},
		{name: "expiry", mutate: func(_ *gateway.ConnectRequest, input *connectionInput) {
			input.expiresAt = time.Now().Add(-time.Second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changedRequest, changedInput := request, input
			test.mutate(&changedRequest, &changedInput)
			changedCtx := context.WithValue(context.Background(), principalContextKey{}, config.Principals[0])
			changedCtx = context.WithValue(changedCtx, connectionContextKey{}, changedInput)
			if _, err := controller.Authorize(changedCtx, changedRequest); !errors.Is(err, gateway.ErrUnauthorized) {
				t.Fatalf("Authorize() error = %v, want unauthorized", err)
			}
		})
	}
}

func TestControllerParsesOnlyExactQuery(t *testing.T) {
	config := validConfig(t)
	controller := newController(config.Principals, config.Endpoints)
	query := validConnectQuery(config)
	request, input, err := controller.parseConnect(query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if request != input.request || request != endpointRequest(config) {
		t.Fatalf("parsed request/input = %#v / %#v", request, input)
	}
	query.Add("caller_id", "caller-other")
	if _, _, err := controller.parseConnect(query.Encode()); err == nil {
		t.Fatal("parseConnect() accepted duplicate query input")
	}
	query = validConnectQuery(config)
	query.Set("unknown", "value")
	if _, _, err := controller.parseConnect(query.Encode()); err == nil {
		t.Fatal("parseConnect() accepted unknown query input")
	}
}

func TestControllerHandlerPropagatesProcessCancellation(t *testing.T) {
	config := validConfig(t)
	controller := newController(config.Principals, config.Endpoints)
	entered := make(chan struct{})
	exited := make(chan struct{})
	controller.service = browserServeFunc(func(ctx context.Context, _ http.ResponseWriter, request *http.Request, connect gateway.ConnectRequest) error {
		if request.Context() != ctx || connect != endpointRequest(config) {
			t.Errorf("Serve() binding = %p/%p %#v", request.Context(), ctx, connect)
		}
		close(entered)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	})
	processCtx, cancelProcess := context.WithCancel(context.Background())
	handler := controller.handler(processCtx)
	request := httptest.NewRequest(http.MethodGet, "/v1/browser/connect?"+validConnectQuery(config).Encode(), nil)
	request.Header.Set("Authorization", "Bearer "+config.Principals[0].Token)
	result := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		close(result)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter Browser service")
	}
	cancelProcess()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("process cancellation did not reach Browser service")
	}
	select {
	case <-result:
	case <-time.After(time.Second):
		t.Fatal("handler did not return")
	}
	if err := controller.wait(); err != nil {
		t.Fatal(err)
	}
}

func TestControllerHealthAndPreUpgradeErrorsAreGeneric(t *testing.T) {
	config := validConfig(t)
	controller := newController(config.Principals, config.Endpoints)
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

func validConnectQuery(config wire.GatewayConfig) url.Values {
	request := endpointRequest(config)
	return url.Values{
		"grant_id": {"grant-1"}, "caller_id": {request.CallerID}, "tenant_id": {request.TenantID},
		"sandbox_id": {request.SandboxID}, "browser_session_id": {request.BrowserSessionID},
		"capability_profile_id": {request.CapabilityProfileID}, "handoff_reference": {request.HandoffReference},
		"connection_generation": {strconv.FormatInt(config.Endpoints[0].ConnectionGeneration, 10)},
		"expires_at":            {time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)},
	}
}

type browserServeFunc func(context.Context, http.ResponseWriter, *http.Request, gateway.ConnectRequest) error

func (f browserServeFunc) Serve(ctx context.Context, response http.ResponseWriter, request *http.Request, connect gateway.ConnectRequest) error {
	return f(ctx, response, request, connect)
}
