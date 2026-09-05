package gatewaystack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
	"github.com/shell-echo/sandbox-runtime/gateway"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

func TestPrivateClientTLSUsesExactGatewayRole(t *testing.T) {
	material, err := testenv.GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(t).PrivateIngress
	config.ClientCertificateFile = material.GatewayA.CertificateFile
	config.ClientPrivateKeyFile = material.GatewayA.PrivateKeyFile
	config.ServerCAFile = material.CAFile
	tlsConfig, err := loadPrivateClientTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tlsConfig.MaxVersion || len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "http/1.1" ||
		tlsConfig.ServerName != "localhost" || tlsConfig.VerifyConnection == nil {
		t.Fatalf("private TLS config = %#v", tlsConfig)
	}
	config.GatewayRoleURI = "spiffe://downstream-fencing/gateway-b"
	if _, err := loadPrivateClientTLSConfig(config); err == nil {
		t.Fatal("loadPrivateClientTLSConfig() accepted a mismatched URI-SAN role")
	}
}

func TestPublicTLSConsumesOnlyNoFollowPrivateMaterial(t *testing.T) {
	root := t.TempDir()
	material, err := testenv.GeneratePKI(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config := validConfig(t)
	config.ServerCertificateFile = material.GatewayCertificateFile
	config.ServerPrivateKeyFile = material.GatewayPrivateKeyFile
	tlsConfig, err := loadPublicServerTLSConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tlsConfig.MaxVersion || tlsConfig.MinVersion == 0 ||
		len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("public TLS config = %#v", tlsConfig)
	}
	if err := os.Chmod(material.GatewayPrivateKeyFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPublicServerTLSConfig(config); err == nil {
		t.Fatal("loadPublicServerTLSConfig() accepted a group-readable private key")
	}
	if err := os.Chmod(material.GatewayPrivateKeyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "public-key-link.pem")
	if err := os.Symlink(material.GatewayPrivateKeyFile, link); err != nil {
		t.Fatal(err)
	}
	config.ServerPrivateKeyFile = link
	if _, err := loadPublicServerTLSConfig(config); err == nil {
		t.Fatal("loadPublicServerTLSConfig() accepted a private-key symlink")
	}
}

func TestControllerRequiresExactPreissuedGrantAndCanonicalQuery(t *testing.T) {
	config := validConfig(t)
	controller, err := newController(config.Principals, config.Endpoints, config.GrantBindings)
	if err != nil {
		t.Fatal(err)
	}
	query := validConnectQuery(config)
	request, input, err := controller.parseConnect(query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), principalContextKey{}, config.Principals[0])
	ctx = context.WithValue(ctx, connectionContextKey{}, input)
	grant, err := controller.Authorize(ctx, request)
	if err != nil || grant.GrantID != config.GrantBindings[0].GrantID {
		t.Fatalf("Authorize() = %#v, %v", grant, err)
	}
	query.Add("caller_id", "caller-other")
	if _, _, err := controller.parseConnect(query.Encode()); err == nil {
		t.Fatal("parseConnect() accepted duplicate input")
	}
	input.grantID = "grant-other"
	ctx = context.WithValue(context.Background(), principalContextKey{}, config.Principals[0])
	ctx = context.WithValue(ctx, connectionContextKey{}, input)
	if _, err := controller.Authorize(ctx, request); !errors.Is(err, gateway.ErrUnauthorized) {
		t.Fatalf("Authorize() error = %v, want unauthorized", err)
	}
}

func TestControllerPreUpgradeResponsesAreGeneric(t *testing.T) {
	config := validConfig(t)
	controller, err := newController(config.Principals, config.Endpoints, config.GrantBindings)
	if err != nil {
		t.Fatal(err)
	}
	handler := controller.handler(context.Background())
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.String() != "{\"status\":\"ready\"}\n" {
		t.Fatalf("health = %d %q", health.Code, health.Body.String())
	}
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/v1/browser/connect", nil))
	if denied.Code != http.StatusUnauthorized || denied.Body.String() != "Unauthorized\n" {
		t.Fatalf("denied = %d %q", denied.Code, denied.Body.String())
	}
}

func TestRedisClientsMeetCapacityAndRevocationSafetyOptions(t *testing.T) {
	capacityClient, err := newRedisClient("redis://e2e:secret@127.0.0.1:1/0", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer capacityClient.Close()
	if _, err := rediscapacity.New(rediscapacity.Options{
		Client: capacityClient, Namespace: "capacity", MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1,
		LeaseTTL: 3 * time.Second, RenewInterval: 400 * time.Millisecond,
		RenewalSafetyMargin: 500 * time.Millisecond, OperationTimeout: 200 * time.Millisecond,
	}); err != nil {
		t.Fatalf("capacity client rejected: %v", err)
	}
	revocationClient, err := newRedisClient("redis://e2e:secret@127.0.0.1:1/0", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer revocationClient.Close()
	if _, err := redisrevocation.New(redisrevocation.Options{
		Client: revocationClient, Namespace: "revocation", MaxGrantLifetime: 15 * time.Minute,
		PollInterval: 100 * time.Millisecond, OperationTimeout: 100 * time.Millisecond,
	}); err != nil {
		t.Fatalf("revocation client rejected: %v", err)
	}
}

func TestAuditIsMetadataOnlyAndSupportsDownstreamTermination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	secret := "v1.private-fence-and-handoff"
	recorder := &auditRecorder{writer: writer}
	if err := recorder.Record(context.Background(), gateway.AuditEvent{
		Type: gateway.AuditDownstreamFenceLost, GrantID: secret, CallerID: secret,
		TenantID: secret, SandboxID: secret, BrowserSessionID: secret, Reason: secret,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), secret) {
		t.Fatal("audit leaked private identity or claim material")
	}
	var record auditRecord
	if err := json.Unmarshal(content, &record); err != nil || record.ReasonCode != "downstream_fence_lost" {
		t.Fatalf("audit record = %#v, %v", record, err)
	}
}

func validConnectQuery(config Config) url.Values {
	principal, endpoint, binding := config.Principals[0], config.Endpoints[0], config.GrantBindings[0]
	return url.Values{
		"grant_id": {binding.GrantID}, "caller_id": {principal.CallerID}, "tenant_id": {principal.TenantID},
		"sandbox_id": {endpoint.SandboxID}, "browser_session_id": {endpoint.BrowserSessionID},
		"capability_profile_id": {endpoint.CapabilityProfileID}, "handoff_reference": {endpoint.HandoffReference},
		"connection_generation": {strconv.FormatInt(endpoint.ConnectionGeneration, 10)}, "expires_at": {binding.ExpiresAt},
	}
}
