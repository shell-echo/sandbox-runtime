package gatewaystack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

const maxConfigBytes = 1 << 20

const (
	lockedCapacityMaxTotal                  = 4
	lockedCapacityMaxPerTenant              = 2
	lockedCapacityMaxPerSession             = 1
	lockedCapacityLeaseTTLMillis            = 3000
	lockedCapacityRenewIntervalMillis       = 400
	lockedCapacityRenewalSafetyMarginMillis = 500
	lockedCapacityOperationTimeoutMillis    = 200
	lockedRevocationMaxGrantLifetimeMillis  = 900_000
	lockedRevocationPollIntervalMillis      = 100
	lockedRevocationOperationTimeoutMillis  = 100
	lockedResolveTimeoutMillis              = 1000
	lockedConnectAndIOTimeoutMillis         = 2000
	lockedMaxMessageBytes                   = 64 << 10
	lockedReconnects                        = 1
	lockedReconnectBackoffMillis            = 10
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	referencePattern  = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
	namespacePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Config belongs only to one caller-owned Gateway process. It intentionally
// contains no Provider configuration, Browser runtime, Chromium address, raw
// Provider resolver, or private-ingress server resource.
type Config struct {
	GatewayID             string               `json:"gateway_id"`
	Address               string               `json:"address"`
	ServerCertificateFile string               `json:"server_certificate_file"`
	ServerPrivateKeyFile  string               `json:"server_private_key_file"`
	AuditFile             string               `json:"audit_file"`
	Authority             AuthorityConfig      `json:"authority"`
	PrivateIngress        PrivateIngressConfig `json:"private_ingress"`
	Principals            []Principal          `json:"principals"`
	Endpoints             []Endpoint           `json:"endpoints"`
	GrantBindings         []GrantBinding       `json:"grant_bindings"`
}

type AuthorityConfig struct {
	RedisURL            string           `json:"redis_url"`
	CapacityNamespace   string           `json:"capacity_namespace"`
	RevocationNamespace string           `json:"revocation_namespace"`
	CapacityPolicy      CapacityPolicy   `json:"capacity_policy"`
	RevocationPolicy    RevocationPolicy `json:"revocation_policy"`
}

type CapacityPolicy struct {
	MaxTotal                  int   `json:"max_total"`
	MaxPerTenant              int   `json:"max_per_tenant"`
	MaxPerSession             int   `json:"max_per_session"`
	LeaseTTLMillis            int64 `json:"lease_ttl_millis"`
	RenewIntervalMillis       int64 `json:"renew_interval_millis"`
	RenewalSafetyMarginMillis int64 `json:"renewal_safety_margin_millis"`
	OperationTimeoutMillis    int64 `json:"operation_timeout_millis"`
}

type RevocationPolicy struct {
	MaxGrantLifetimeMillis int64 `json:"max_grant_lifetime_millis"`
	PollIntervalMillis     int64 `json:"poll_interval_millis"`
	OperationTimeoutMillis int64 `json:"operation_timeout_millis"`
}

type PrivateIngressConfig struct {
	Address                   string `json:"address"`
	ServerName                string `json:"server_name"`
	ClientCertificateFile     string `json:"client_certificate_file"`
	ClientPrivateKeyFile      string `json:"client_private_key_file"`
	ServerCAFile              string `json:"server_ca_file"`
	GatewayRoleURI            string `json:"gateway_role_uri"`
	ResolveTimeoutMillis      int64  `json:"resolve_timeout_millis"`
	ConnectAndIOTimeoutMillis int64  `json:"connect_and_io_timeout_millis"`
	MaxMessageBytes           int64  `json:"max_message_bytes"`
}

type Principal struct {
	ID       string `json:"id"`
	Token    string `json:"token"`
	CallerID string `json:"caller_id"`
	TenantID string `json:"tenant_id"`
}

// Endpoint contains only the identity projected by the private ingress. It is
// not a network endpoint and cannot be used to attach directly to Chromium.
type Endpoint struct {
	ID                   string `json:"id"`
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	ConnectionGeneration int64  `json:"connection_generation"`
}

type GrantBinding struct {
	ID          string `json:"id"`
	GrantID     string `json:"grant_id"`
	PrincipalID string `json:"principal_id"`
	EndpointID  string `json:"endpoint_id"`
	ExpiresAt   string `json:"expires_at"`
}

func LoadConfig(path string) (Config, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return Config{}, errors.New("Gateway configuration path must be absolute")
	}
	contents, err := readBoundedRegularFile(path, maxConfigBytes, true)
	if err != nil {
		return Config{}, errors.New("read bounded Gateway configuration")
	}
	if err := validateUniqueJSONFields(contents); err != nil {
		return Config{}, errors.New("Gateway configuration contains duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("decode Gateway configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("Gateway configuration has trailing input")
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	return cloneConfig(config), nil
}

func ValidateConfig(config Config) error {
	if config.GatewayID != "gateway-a" && config.GatewayID != "gateway-b" {
		return errors.New("gateway_id must select exactly Gateway A or Gateway B")
	}
	publicPort, err := validateLoopbackAddress(config.Address)
	if err != nil {
		return fmt.Errorf("public address: %w", err)
	}
	privatePort, err := validateLoopbackAddress(config.PrivateIngress.Address)
	if err != nil {
		return fmt.Errorf("private ingress address: %w", err)
	}
	if publicPort == privatePort {
		return errors.New("public and private listeners must be distinct")
	}
	if err := validatePaths(config); err != nil {
		return err
	}
	if err := validateAuthority(config.Authority); err != nil {
		return err
	}
	if err := validatePrivateIngress(config.GatewayID, config.PrivateIngress); err != nil {
		return err
	}
	if err := validatePrincipals(config.Principals); err != nil {
		return err
	}
	if err := validateEndpoints(config.Endpoints, config.Principals); err != nil {
		return err
	}
	if err := validateGrantBindings(config.GrantBindings, config.Principals, config.Endpoints); err != nil {
		return err
	}
	return nil
}

func validatePaths(config Config) error {
	paths := map[string]string{
		"public server certificate":  config.ServerCertificateFile,
		"public server private key":  config.ServerPrivateKeyFile,
		"Gateway audit":              config.AuditFile,
		"private client certificate": config.PrivateIngress.ClientCertificateFile,
		"private client key":         config.PrivateIngress.ClientPrivateKeyFile,
		"private ingress CA":         config.PrivateIngress.ServerCAFile,
	}
	seen := make(map[string]string, len(paths))
	for name, path := range paths {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("%s path must be absolute", name)
		}
		clean := filepath.Clean(path)
		if previous, exists := seen[clean]; exists {
			return fmt.Errorf("critical paths for %s and %s must be distinct", previous, name)
		}
		seen[clean] = name
	}
	return nil
}

func validateAuthority(config AuthorityConfig) error {
	if err := validateRedisURL(config.RedisURL); err != nil {
		return err
	}
	if !namespacePattern.MatchString(config.CapacityNamespace) || !namespacePattern.MatchString(config.RevocationNamespace) ||
		config.CapacityNamespace == config.RevocationNamespace {
		return errors.New("capacity and revocation namespaces must be valid and distinct")
	}
	wantCapacity := CapacityPolicy{
		MaxTotal: lockedCapacityMaxTotal, MaxPerTenant: lockedCapacityMaxPerTenant,
		MaxPerSession: lockedCapacityMaxPerSession, LeaseTTLMillis: lockedCapacityLeaseTTLMillis,
		RenewIntervalMillis:       lockedCapacityRenewIntervalMillis,
		RenewalSafetyMarginMillis: lockedCapacityRenewalSafetyMarginMillis,
		OperationTimeoutMillis:    lockedCapacityOperationTimeoutMillis,
	}
	if config.CapacityPolicy != wantCapacity {
		return errors.New("capacity policy differs from the locked downstream-fencing profile")
	}
	wantRevocation := RevocationPolicy{
		MaxGrantLifetimeMillis: lockedRevocationMaxGrantLifetimeMillis,
		PollIntervalMillis:     lockedRevocationPollIntervalMillis,
		OperationTimeoutMillis: lockedRevocationOperationTimeoutMillis,
	}
	if config.RevocationPolicy != wantRevocation {
		return errors.New("revocation policy differs from the locked durable-revocation profile")
	}
	return nil
}

func validatePrivateIngress(gatewayID string, config PrivateIngressConfig) error {
	wantRole := wire.GatewayARoleURI
	if gatewayID == "gateway-b" {
		wantRole = wire.GatewayBRoleURI
	}
	if config.GatewayRoleURI != wantRole {
		return errors.New("Gateway role does not match the selected process identity")
	}
	if !validServerName(config.ServerName) {
		return errors.New("private ingress server_name is invalid")
	}
	if config.ResolveTimeoutMillis != lockedResolveTimeoutMillis ||
		config.ConnectAndIOTimeoutMillis != lockedConnectAndIOTimeoutMillis ||
		config.MaxMessageBytes != lockedMaxMessageBytes {
		return errors.New("private transport differs from the locked downstream-fencing profile")
	}
	return nil
}

func validateLoopbackAddress(address string) (int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return 0, errors.New("an explicit TCP host and port are required")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return 0, errors.New("only a loopback listener is permitted")
		}
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 1 || parsed > 65_535 {
		return 0, errors.New("an explicit nonzero TCP port is required")
	}
	return parsed, nil
}

func validateRedisURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/0" || parsed.User == nil {
		return errors.New("Redis authority URL must select database zero with explicit credentials")
	}
	port, err := strconv.Atoi(parsed.Port())
	password, hasPassword := parsed.User.Password()
	if err != nil || port < 1 || port > 65_535 || parsed.User.Username() == "" || !hasPassword || password == "" {
		return errors.New("Redis authority URL credentials are incomplete")
	}
	if parsed.Hostname() != "localhost" {
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return errors.New("Redis authority must use an explicit loopback endpoint in this E2E process")
		}
	}
	return nil
}

func validServerName(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/:@[]") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	parsed, err := url.Parse("https://" + value)
	return err == nil && parsed.Hostname() == value
}

func validatePrincipals(principals []Principal) error {
	if len(principals) == 0 || len(principals) > 32 {
		return errors.New("principals must contain between 1 and 32 entries")
	}
	ids, tokens, bindings := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, principal := range principals {
		binding := principal.CallerID + "\x00" + principal.TenantID
		if !identifierPattern.MatchString(principal.ID) || !identifierPattern.MatchString(principal.CallerID) ||
			!identifierPattern.MatchString(principal.TenantID) || !validBearerToken(principal.Token) ||
			ids[principal.ID] || tokens[principal.Token] || bindings[binding] {
			return errors.New("principal fields and bindings must be valid and unique")
		}
		ids[principal.ID], tokens[principal.Token], bindings[binding] = true, true, true
	}
	return nil
}

func validBearerToken(value string) bool {
	if len(value) < 32 || len(value) > 512 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validateEndpoints(endpoints []Endpoint, principals []Principal) error {
	if len(endpoints) == 0 || len(endpoints) > 128 {
		return errors.New("endpoints must contain between 1 and 128 entries")
	}
	tenants := make(map[string]bool, len(principals))
	for _, principal := range principals {
		tenants[principal.TenantID] = true
	}
	ids, references, sessions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, endpoint := range endpoints {
		session := endpoint.TenantID + "\x00" + endpoint.SandboxID + "\x00" + endpoint.BrowserSessionID
		request := gateway.ConnectRequest{
			CallerID: "fixture", TenantID: endpoint.TenantID, SandboxID: endpoint.SandboxID,
			BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
			HandoffReference: endpoint.HandoffReference,
		}
		if !identifierPattern.MatchString(endpoint.ID) || endpoint.CapabilityProfileID != providerbrowser.CapabilityProfileID ||
			!referencePattern.MatchString(endpoint.HandoffReference) || endpoint.ConnectionGeneration < 1 || !tenants[endpoint.TenantID] ||
			request.Validate() != nil || ids[endpoint.ID] || references[endpoint.HandoffReference] || sessions[session] {
			return errors.New("endpoint fields and bindings must be valid and unique")
		}
		ids[endpoint.ID], references[endpoint.HandoffReference], sessions[session] = true, true, true
	}
	return nil
}

func validateGrantBindings(bindings []GrantBinding, principals []Principal, endpoints []Endpoint) error {
	if len(bindings) == 0 || len(bindings) > 256 {
		return errors.New("grant_bindings must contain between 1 and 256 entries")
	}
	principalsByID := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		principalsByID[principal.ID] = principal
	}
	endpointsByID := make(map[string]Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		endpointsByID[endpoint.ID] = endpoint
	}
	ids, grants := map[string]bool{}, map[string]bool{}
	for _, binding := range bindings {
		expiresAt, err := parseCanonicalExpiry(binding.ExpiresAt)
		principal, principalOK := principalsByID[binding.PrincipalID]
		endpoint, endpointOK := endpointsByID[binding.EndpointID]
		if !identifierPattern.MatchString(binding.ID) || !identifierPattern.MatchString(binding.GrantID) || err != nil ||
			!principalOK || !endpointOK || principal.TenantID != endpoint.TenantID || ids[binding.ID] || grants[binding.GrantID] ||
			(gateway.RevocationSubject{GrantID: binding.GrantID, ExpiresAt: expiresAt}).Validate() != nil {
			return errors.New("grant binding fields and identities must be valid and unique")
		}
		ids[binding.ID], grants[binding.GrantID] = true, true
	}
	return nil
}

func parseCanonicalExpiry(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("expiry must be canonical UTC RFC3339Nano")
	}
	return parsed.UTC(), nil
}

func validateUniqueJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := validateUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing input")
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("JSON object key is invalid or duplicated")
			}
			seen[key] = true
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is incomplete")
		}
	default:
		return errors.New("JSON delimiter is invalid")
	}
	return nil
}

func cloneConfig(config Config) Config {
	config.Principals = append([]Principal(nil), config.Principals...)
	config.Endpoints = append([]Endpoint(nil), config.Endpoints...)
	config.GrantBindings = append([]GrantBinding(nil), config.GrantBindings...)
	return config
}

func durationMillis(value int64) time.Duration {
	return time.Duration(value) * time.Millisecond
}
