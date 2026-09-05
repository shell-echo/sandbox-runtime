package stack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
)

const maxConfigBytes = 1 << 20

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	referencePattern  = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
	namespacePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

func LoadConfig(path string) (wire.GatewayConfig, error) {
	if strings.TrimSpace(path) == "" {
		return wire.GatewayConfig{}, errors.New("Gateway configuration path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return wire.GatewayConfig{}, fmt.Errorf("open Gateway configuration: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return wire.GatewayConfig{}, fmt.Errorf("inspect Gateway configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxConfigBytes {
		return wire.GatewayConfig{}, errors.New("Gateway configuration must be a bounded private regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return wire.GatewayConfig{}, fmt.Errorf("read Gateway configuration: %w", err)
	}
	if len(content) > maxConfigBytes {
		return wire.GatewayConfig{}, errors.New("Gateway configuration exceeds the size limit")
	}
	if err := validateUniqueJSONFields(content); err != nil {
		return wire.GatewayConfig{}, errors.New("Gateway configuration contains duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config wire.GatewayConfig
	if err := decoder.Decode(&config); err != nil {
		return wire.GatewayConfig{}, fmt.Errorf("decode Gateway configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wire.GatewayConfig{}, errors.New("Gateway configuration has trailing input")
	}
	if err := ValidateConfig(config); err != nil {
		return wire.GatewayConfig{}, err
	}
	return cloneConfig(config), nil
}

func ValidateConfig(config wire.GatewayConfig) error {
	if err := validateLoopbackAddress(config.Address); err != nil {
		return fmt.Errorf("address: %w", err)
	}
	for name, path := range map[string]string{
		"server_certificate_file": config.ServerCertificateFile,
		"server_private_key_file": config.ServerPrivateKeyFile,
		"audit_file":              config.AuditFile,
		"observation_file":        config.ObservationFile,
	} {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	paths := []string{config.ServerCertificateFile, config.ServerPrivateKeyFile, config.AuditFile, config.ObservationFile}
	seenPaths := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		clean := filepath.Clean(path)
		if _, exists := seenPaths[clean]; exists {
			return errors.New("Gateway certificate, key, audit, and observation paths must be distinct")
		}
		seenPaths[clean] = struct{}{}
	}
	if err := validateRedisURL(config.RedisURL); err != nil {
		return err
	}
	if !namespacePattern.MatchString(config.RevocationNamespace) {
		return errors.New("revocation_namespace is invalid")
	}
	if err := validateRevocationPolicy(config.RevocationPolicy); err != nil {
		return err
	}
	if err := validateLocalCapacity(config.LocalCapacity); err != nil {
		return err
	}
	if err := validateReconnectPolicy(config.ReconnectPolicy); err != nil {
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
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("JSON object key is duplicated")
			}
			seen[key] = struct{}{}
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

func validateLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return errors.New("an explicit TCP host and port are required")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("the E2E Gateway may listen only on loopback")
		}
	}
	parsed, err := net.LookupPort("tcp", port)
	if err != nil || parsed < 1 || parsed > 65_535 {
		return errors.New("an explicit nonzero TCP port is required")
	}
	return nil
}

func validateRedisURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Hostname() == "" || parsed.Port() == "" {
		return errors.New("redis_url must be a redis or rediss URL with an explicit host and port")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65_535 || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("redis_url contains unsupported connection options")
	}
	return nil
}

func validateRevocationPolicy(policy wire.RevocationPolicy) error {
	maximum := durationMillis(policy.MaxGrantLifetimeMillis)
	poll := durationMillis(policy.PollIntervalMillis)
	operation := durationMillis(policy.OperationTimeoutMillis)
	if maximum < redisrevocation.MinGrantLifetime || maximum > redisrevocation.MaxGrantLifetime ||
		poll < redisrevocation.MinPollInterval || poll > redisrevocation.MaxPollInterval ||
		operation < redisrevocation.MinOperationTimeout || operation > redisrevocation.MaxOperationTimeout || operation > poll {
		return errors.New("durable revocation policy is invalid")
	}
	return nil
}

func durationMillis(value int64) time.Duration {
	if value < 1 || value > int64((1<<63-1)/int64(time.Millisecond)) {
		return 0
	}
	return time.Duration(value) * time.Millisecond
}

func validateLocalCapacity(policy wire.LocalCapacityPolicy) error {
	if policy.MaxTotal < 1 || policy.MaxTotal > gateway.MaxConnectionCapacity ||
		policy.MaxPerTenant < 1 || policy.MaxPerTenant > policy.MaxTotal ||
		policy.MaxPerSession < 1 || policy.MaxPerSession > policy.MaxPerTenant {
		return errors.New("local authenticated capacity policy is invalid")
	}
	return nil
}

func validateReconnectPolicy(policy wire.ReconnectPolicy) error {
	backoff := durationMillisAllowZero(policy.BackoffMillis)
	if policy.MaxReconnects < 1 || policy.MaxReconnects > gateway.MaxReconnectAttempts ||
		backoff < 0 || backoff > gateway.MaxReconnectBackoff {
		return errors.New("Gateway reconnect policy is invalid")
	}
	return nil
}

func durationMillisAllowZero(value int64) time.Duration {
	if value == 0 {
		return 0
	}
	if value < 0 || value > int64((1<<63-1)/int64(time.Millisecond)) {
		return -1
	}
	return time.Duration(value) * time.Millisecond
}

func validatePrincipals(principals []wire.Principal) error {
	if len(principals) == 0 || len(principals) > 32 {
		return errors.New("principals must contain between 1 and 32 entries")
	}
	ids := make(map[string]struct{}, len(principals))
	tokens := make(map[string]struct{}, len(principals))
	bindings := make(map[string]struct{}, len(principals))
	for _, principal := range principals {
		if !identifierPattern.MatchString(principal.ID) || !identifierPattern.MatchString(principal.CallerID) ||
			!identifierPattern.MatchString(principal.TenantID) || !validBearerToken(principal.Token) {
			return errors.New("principal fields are invalid")
		}
		binding := principal.CallerID + "\x00" + principal.TenantID
		if _, exists := ids[principal.ID]; exists {
			return errors.New("principal IDs must be unique")
		}
		if _, exists := tokens[principal.Token]; exists {
			return errors.New("principal tokens must be unique")
		}
		if _, exists := bindings[binding]; exists {
			return errors.New("principal caller and tenant bindings must be unique")
		}
		ids[principal.ID], tokens[principal.Token], bindings[binding] = struct{}{}, struct{}{}, struct{}{}
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

func validateEndpoints(endpoints []wire.Endpoint, principals []wire.Principal) error {
	if len(endpoints) == 0 || len(endpoints) > 128 {
		return errors.New("endpoints must contain between 1 and 128 entries")
	}
	tenantPrincipals := make(map[string]bool, len(principals))
	for _, principal := range principals {
		tenantPrincipals[principal.TenantID] = true
	}
	ids := make(map[string]struct{}, len(endpoints))
	references := make(map[string]struct{}, len(endpoints))
	sessions := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if !identifierPattern.MatchString(endpoint.ID) || !identifierPattern.MatchString(endpoint.TenantID) ||
			!identifierPattern.MatchString(endpoint.SandboxID) || !identifierPattern.MatchString(endpoint.BrowserSessionID) ||
			endpoint.CapabilityProfileID != providerbrowser.CapabilityProfileID ||
			!referencePattern.MatchString(endpoint.HandoffReference) || endpoint.ConnectionGeneration < 1 ||
			!tenantPrincipals[endpoint.TenantID] {
			return errors.New("endpoint fields are invalid")
		}
		request := gateway.ConnectRequest{
			CallerID: "fixture", TenantID: endpoint.TenantID, SandboxID: endpoint.SandboxID,
			BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
			HandoffReference: endpoint.HandoffReference,
		}
		if err := request.Validate(); err != nil {
			return errors.New("endpoint Gateway identity is invalid")
		}
		session := endpoint.TenantID + "\x00" + endpoint.SandboxID + "\x00" + endpoint.BrowserSessionID
		if _, exists := ids[endpoint.ID]; exists {
			return errors.New("endpoint IDs must be unique")
		}
		if _, exists := references[endpoint.HandoffReference]; exists {
			return errors.New("endpoint handoff references must be unique")
		}
		if _, exists := sessions[session]; exists {
			return errors.New("endpoint session bindings must be unique")
		}
		ids[endpoint.ID], references[endpoint.HandoffReference], sessions[session] = struct{}{}, struct{}{}, struct{}{}
	}
	return nil
}

func validateGrantBindings(bindings []wire.GrantBinding, principals []wire.Principal, endpoints []wire.Endpoint) error {
	if len(bindings) == 0 || len(bindings) > 256 {
		return errors.New("grant_bindings must contain between 1 and 256 entries")
	}
	principalsByID := make(map[string]wire.Principal, len(principals))
	for _, principal := range principals {
		principalsByID[principal.ID] = principal
	}
	endpointsByID := make(map[string]wire.Endpoint, len(endpoints))
	for _, endpoint := range endpoints {
		endpointsByID[endpoint.ID] = endpoint
	}
	ids := make(map[string]struct{}, len(bindings))
	grants := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		expiresAt, err := parseCanonicalExpiry(binding.ExpiresAt)
		principal, principalOK := principalsByID[binding.PrincipalID]
		endpoint, endpointOK := endpointsByID[binding.EndpointID]
		if !identifierPattern.MatchString(binding.ID) || !identifierPattern.MatchString(binding.GrantID) ||
			err != nil || !principalOK || !endpointOK || principal.TenantID != endpoint.TenantID {
			return errors.New("grant binding fields are invalid")
		}
		if err := (gateway.RevocationSubject{GrantID: binding.GrantID, ExpiresAt: expiresAt}).Validate(); err != nil {
			return errors.New("grant binding subject is invalid")
		}
		if _, exists := ids[binding.ID]; exists {
			return errors.New("grant binding IDs must be unique")
		}
		if _, exists := grants[binding.GrantID]; exists {
			return errors.New("grant IDs must be unique")
		}
		ids[binding.ID], grants[binding.GrantID] = struct{}{}, struct{}{}
	}
	return nil
}

func parseCanonicalExpiry(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("expiry must be canonical RFC3339Nano")
	}
	return parsed.UTC(), nil
}

func cloneConfig(config wire.GatewayConfig) wire.GatewayConfig {
	config.Principals = append([]wire.Principal(nil), config.Principals...)
	config.Endpoints = append([]wire.Endpoint(nil), config.Endpoints...)
	config.GrantBindings = append([]wire.GrantBinding(nil), config.GrantBindings...)
	return config
}
