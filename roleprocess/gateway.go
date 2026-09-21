package roleprocess

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
)

const (
	gatewayAuthorityVersion = 2
	maxGatewayAuthoritySize = 64 << 10
	maxGatewayDSNSize       = 8 << 10

	gatewayCapabilityEnabled              = "enabled"
	gatewayCapabilityAuthorityUnavailable = "authority_unavailable"
	gatewayDeferredAuthorityReason        = "phase6-slice5-6-authority-required"
)

// GatewayCredentialAuthority is the private role-owned input for the Product
// grant repository and the Provider handoff client. It contains paths, never
// inline secrets or Provider DTOs.
type GatewayCredentialAuthority struct {
	Version                       int    `json:"version"`
	Role                          string `json:"role"`
	ProductRuntimeDSNFile         string `json:"product_runtime_dsn_file"`
	GrantKeyID                    string `json:"grant_key_id"`
	GrantKeyFile                  string `json:"grant_key_file"`
	ProviderOrigin                string `json:"provider_origin"`
	ProviderCABundleFile          string `json:"provider_ca_bundle_file"`
	ProviderClientCertificateFile string `json:"provider_client_certificate_file"`
	ProviderClientPrivateKeyFile  string `json:"provider_client_private_key_file"`
}

type GatewayDependencyAuthority struct {
	Version                  int      `json:"version"`
	Role                     string   `json:"role"`
	OperationTimeoutMillis   int      `json:"operation_timeout_millis"`
	MaxConnections           int      `json:"max_connections"`
	MaxConnectionsPerSession int      `json:"max_connections_per_session"`
	OriginPatterns           []string `json:"origin_patterns"`
}

type GatewayPolicyAuthority struct {
	Version                 int    `json:"version"`
	Role                    string `json:"role"`
	Terminal                string `json:"terminal"`
	BrowserAutomation       string `json:"browser_automation"`
	BrowserLive             string `json:"browser_live"`
	DesktopLive             string `json:"desktop_live"`
	DeferredAuthorityReason string `json:"deferred_authority_reason"`
}

type GatewayAuthority struct {
	Credential GatewayCredentialAuthority
	Dependency GatewayDependencyAuthority
	Policy     GatewayPolicyAuthority
}

// LoadGatewayAuthority validates the complete Gateway-owned authority graph.
// Every file is bounded, private, non-symlinked and strict JSON; no
// Provider-local repository or engine is accepted here.
func LoadGatewayAuthority(cfg *config.DataPlaneProcessConfig) (GatewayAuthority, error) {
	if cfg == nil || cfg.Role != config.DataPlaneGateway || !cfg.Enabled {
		return GatewayAuthority{}, errors.New("enabled Gateway configuration is required")
	}
	if err := cfg.Validate(); err != nil {
		return GatewayAuthority{}, err
	}
	var credential GatewayCredentialAuthority
	var dependency GatewayDependencyAuthority
	var policy GatewayPolicyAuthority
	if err := readAuthority(cfg.Authority.CredentialFile, &credential); err != nil {
		return GatewayAuthority{}, fmt.Errorf("load Gateway credential authority: %w", err)
	}
	if err := readAuthority(cfg.Authority.DependencyFile, &dependency); err != nil {
		return GatewayAuthority{}, fmt.Errorf("load Gateway dependency authority: %w", err)
	}
	if err := readAuthority(cfg.Authority.PolicyFile, &policy); err != nil {
		return GatewayAuthority{}, fmt.Errorf("load Gateway policy authority: %w", err)
	}
	if credential.Version != gatewayAuthorityVersion || credential.Role != string(config.DataPlaneGateway) ||
		!absoluteAuthorityPath(credential.ProductRuntimeDSNFile) || credential.GrantKeyID == "" ||
		!absoluteAuthorityPath(credential.GrantKeyFile) || !validProviderOrigin(credential.ProviderOrigin) ||
		!absoluteAuthorityPath(credential.ProviderCABundleFile) || !absoluteAuthorityPath(credential.ProviderClientCertificateFile) ||
		!absoluteAuthorityPath(credential.ProviderClientPrivateKeyFile) {
		return GatewayAuthority{}, errors.New("invalid Gateway credential authority")
	}
	if dependency.Version != gatewayAuthorityVersion || dependency.Role != string(config.DataPlaneGateway) ||
		dependency.OperationTimeoutMillis < 10 || dependency.OperationTimeoutMillis > 30_000 ||
		dependency.MaxConnections < 1 || dependency.MaxConnections > 10_000 || dependency.MaxConnectionsPerSession < 1 || dependency.MaxConnectionsPerSession > dependency.MaxConnections || len(dependency.OriginPatterns) > 32 {
		return GatewayAuthority{}, errors.New("invalid Gateway dependency authority")
	}
	for _, pattern := range dependency.OriginPatterns {
		if strings.TrimSpace(pattern) != pattern || pattern == "" || len(pattern) > 512 || strings.ContainsAny(pattern, "\r\n") {
			return GatewayAuthority{}, errors.New("invalid Gateway origin policy")
		}
	}
	if policy.Version != gatewayAuthorityVersion || policy.Role != string(config.DataPlaneGateway) ||
		policy.Terminal != gatewayCapabilityEnabled || policy.BrowserAutomation != gatewayCapabilityAuthorityUnavailable ||
		policy.BrowserLive != gatewayCapabilityAuthorityUnavailable || policy.DesktopLive != gatewayCapabilityAuthorityUnavailable ||
		policy.DeferredAuthorityReason != gatewayDeferredAuthorityReason {
		return GatewayAuthority{}, errors.New("invalid Gateway policy authority")
	}
	return GatewayAuthority{Credential: credential, Dependency: dependency, Policy: policy}, nil
}

// NewGatewayApplicationGraph constructs the public Gateway with Product-owned
// grant/audit repositories and the private opaque Provider handoff adapter.
func NewGatewayApplicationGraph(ctx context.Context, cfg *config.DataPlaneProcessConfig) (ApplicationGraph, error) {
	if ctx == nil {
		return ApplicationGraph{}, errors.New("Gateway construction context is required")
	}
	authority, err := LoadGatewayAuthority(cfg)
	if err != nil {
		return ApplicationGraph{}, err
	}
	dsn, err := readGatewayDSN(authority.Credential.ProductRuntimeDSNFile)
	if err != nil {
		return ApplicationGraph{}, err
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return ApplicationGraph{}, errors.New("invalid Gateway Product database authority")
	}
	poolConfig.MaxConns = int32(authority.Dependency.MaxConnections)
	poolConfig.MinConns = 0
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return ApplicationGraph{}, errors.New("open Gateway Product database")
	}
	closePool := func() {
		pool.Close()
	}
	store, err := productpostgres.New(pool, time.Duration(authority.Dependency.OperationTimeoutMillis)*time.Millisecond)
	if err != nil {
		closePool()
		return ApplicationGraph{}, fmt.Errorf("construct Gateway Product store: %w", err)
	}
	grantKey, err := secretfile.Read(authority.Credential.GrantKeyFile, 32)
	if err != nil || len(grantKey) != 32 {
		closePool()
		clear(grantKey)
		return ApplicationGraph{}, errors.New("load Gateway grant key")
	}
	grantRepository, err := productpostgres.NewGrantRepository(store, authority.Credential.GrantKeyID, grantKey)
	clear(grantKey)
	if err != nil {
		closePool()
		return ApplicationGraph{}, fmt.Errorf("construct Gateway grant repository: %w", err)
	}
	audit, err := productpostgres.NewGatewayAuditRepository(store, product.CryptoIDGenerator{})
	if err != nil {
		closePool()
		return ApplicationGraph{}, fmt.Errorf("construct Gateway audit repository: %w", err)
	}
	providerClient, err := gatewayProviderHTTPClient(cfg, authority.Credential)
	if err != nil {
		closePool()
		return ApplicationGraph{}, err
	}
	resolver, err := productgateway.NewPrivateTerminalResolver(productgateway.PrivateTerminalResolverOptions{Origin: authority.Credential.ProviderOrigin, HTTPClient: providerClient})
	if err != nil {
		closePool()
		return ApplicationGraph{}, fmt.Errorf("construct Gateway Provider handoff adapter: %w", err)
	}
	terminal, err := productgateway.NewHandler(productgateway.Options{
		Grants: grantRepository, BoundResolver: resolver, Audit: audit,
		OriginPatterns: authority.Dependency.OriginPatterns,
		MaxConnections: authority.Dependency.MaxConnections, MaxConnectionsPerSession: authority.Dependency.MaxConnectionsPerSession,
	})
	if err != nil {
		closePool()
		return ApplicationGraph{}, fmt.Errorf("construct Gateway public handler: %w", err)
	}
	handler := newGatewayPublicHandler(terminal, authority.Policy)
	return ApplicationGraph{
		Public: handler,
		Ready: func(checkContext context.Context) error {
			if checkContext == nil {
				return errors.New("Gateway readiness context is required")
			}
			if err := pool.Ping(checkContext); err != nil {
				return err
			}
			return gatewayProviderReachable(checkContext, providerClient, authority.Credential.ProviderOrigin)
		},
		Shutdown: func(context.Context) error { closePool(); return nil },
	}, nil
}

type gatewayCapabilityProjection struct {
	SchemaVersion     string `json:"schema_version"`
	Terminal          string `json:"terminal"`
	BrowserAutomation string `json:"browser_automation"`
	BrowserLive       string `json:"browser_live"`
	DesktopLive       string `json:"desktop_live"`
	Reason            string `json:"reason"`
}

func newGatewayPublicHandler(terminal http.Handler, policy GatewayPolicyAuthority) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/terminal/connect", terminal)
	unavailable := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"code":"PRODUCT_CAPABILITY_UNAVAILABLE","message":"capability authority is unavailable"}`))
	})
	for _, path := range []string{"/browser/automation", "/browser/live", "/desktop/connect"} {
		mux.Handle(path, unavailable)
	}
	mux.HandleFunc("/capabilities", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if request == nil || request.Method != http.MethodGet {
			http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(gatewayCapabilityProjection{
			SchemaVersion: "sandbox-runtime.gateway-capabilities.v1", Terminal: policy.Terminal,
			BrowserAutomation: policy.BrowserAutomation, BrowserLive: policy.BrowserLive,
			DesktopLive: policy.DesktopLive, Reason: policy.DeferredAuthorityReason,
		})
	})
	return mux
}

func gatewayProviderReachable(ctx context.Context, client *http.Client, origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "wss" {
		return errors.New("Gateway Provider dependency is invalid")
	}
	parsed.Scheme = "https"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return errors.New("Gateway Provider dependency is invalid")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Gateway Provider dependency is unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return errors.New("Gateway Provider dependency is unavailable")
	}
	return nil
}

func readGatewayDSN(path string) (string, error) {
	document, err := secretfile.Read(path, maxGatewayDSNSize)
	if err != nil {
		return "", errors.New("load Gateway Product database authority")
	}
	defer clear(document)
	dsn := strings.TrimSuffix(string(document), "\n")
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" || parsed.User == nil || strings.TrimSpace(dsn) != dsn || strings.ContainsAny(dsn, "\x00\r\n") {
		return "", errors.New("invalid Gateway Product database authority")
	}
	return dsn, nil
}

func gatewayProviderHTTPClient(cfg *config.DataPlaneProcessConfig, authority GatewayCredentialAuthority) (*http.Client, error) {
	caDocument, err := secretfile.Read(authority.ProviderCABundleFile, 256<<10)
	if err != nil {
		return nil, errors.New("load Gateway Provider trust bundle")
	}
	defer clear(caDocument)
	pool := x509.NewCertPool()
	remaining := bytes.TrimSpace(caDocument)
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid Gateway Provider trust bundle")
		}
		certificate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil || !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("invalid Gateway Provider CA certificate")
		}
		pool.AddCert(certificate)
		count++
		remaining = bytes.TrimSpace(rest)
	}
	if count == 0 {
		return nil, errors.New("Gateway Provider trust bundle is empty")
	}
	certificatePEM, err := secretfile.Read(authority.ProviderClientCertificateFile, 64<<10)
	if err != nil {
		return nil, errors.New("load Gateway Provider client certificate")
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := secretfile.Read(authority.ProviderClientPrivateKeyFile, 64<<10)
	if err != nil {
		return nil, errors.New("load Gateway Provider client key")
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load Gateway Provider client identity")
	}
	parsed, err := url.Parse(authority.ProviderOrigin)
	if err != nil || parsed.Hostname() == "" {
		return nil, errors.New("invalid Gateway Provider origin")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}, ServerName: parsed.Hostname()}}, Timeout: time.Duration(cfg.Drain.DependencyTimeouts) * time.Second}, nil
}

func validProviderOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "wss" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.Path != "" && parsed.String() == value && strings.TrimSpace(value) == value
}

func absoluteAuthorityPath(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n") && filepath.IsAbs(value) && filepath.Clean(value) == value
}
