package stack

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
	basestack "github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
	"github.com/shell-echo/sandbox-runtime/gateway"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	"github.com/shell-echo/sandbox-runtime/gateway/edge"
)

const maxConfigBytes = 1 << 20

const (
	lockedMaxTotal                  = 4
	lockedMaxPerTenant              = 2
	lockedMaxPerSession             = 1
	lockedLeaseTTLMillis            = 3000
	lockedRenewIntervalMillis       = 400
	lockedRenewalSafetyMarginMillis = 500
	lockedOperationTimeoutMillis    = 200
	lockedResolveTimeoutMillis      = 1000
	lockedActivationTimeoutMillis   = 2000
	lockedActionTimeoutMillis       = 1000
	lockedCloseTimeoutMillis        = 5000
	lockedMaxSessions               = 4
	lockedMaxActionBytes            = 64 << 10
	lockedMaxConnections            = 32
	lockedReadHeaderTimeoutMillis   = 1000
	lockedReadTimeoutMillis         = 30000
	lockedWriteTimeoutMillis        = 30000
	lockedIdleTimeoutMillis         = 60000
	lockedMaxHeaderBytes            = 16 << 10
)

var namespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Config is owned only by the independently started Provider/private-ingress
// process. It deliberately contains no public Gateway or caller credential.
type Config struct {
	Provider  basestack.BrowserProviderConfig `json:"provider"`
	Ingress   IngressConfig                   `json:"ingress"`
	Authority AuthorityConfig                 `json:"authority"`
}

type IngressConfig struct {
	Address                 string   `json:"address"`
	ServerCertificateFile   string   `json:"server_certificate_file"`
	ServerPrivateKeyFile    string   `json:"server_private_key_file"`
	ClientCAFile            string   `json:"client_ca_file"`
	AllowedGatewayURIs      []string `json:"allowed_gateway_uris"`
	ResolveTimeoutMillis    int64    `json:"resolve_timeout_millis"`
	ActivationTimeoutMillis int64    `json:"activation_and_io_timeout_millis"`
	ActionTimeoutMillis     int64    `json:"action_timeout_millis"`
	CloseTimeoutMillis      int64    `json:"close_timeout_millis"`
	MaxSessions             int      `json:"max_sessions"`
	MaxActionBytes          int64    `json:"max_action_bytes"`
	MaxConnections          int      `json:"max_connections"`
	ReadHeaderTimeoutMillis int64    `json:"read_header_timeout_millis"`
	ReadTimeoutMillis       int64    `json:"read_timeout_millis"`
	WriteTimeoutMillis      int64    `json:"write_timeout_millis"`
	IdleTimeoutMillis       int64    `json:"idle_timeout_millis"`
	MaxHeaderBytes          int      `json:"max_header_bytes"`
}

type AuthorityConfig struct {
	RedisURL          string         `json:"redis_url"`
	CapacityNamespace string         `json:"capacity_namespace"`
	CapacityPolicy    CapacityPolicy `json:"capacity_policy"`
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

func LoadConfig(path string) (Config, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return Config{}, errors.New("Provider/ingress configuration path must be absolute")
	}
	contents, err := readBoundedRegularFile(path, maxConfigBytes, true)
	if err != nil {
		return Config{}, errors.New("read bounded Provider/ingress configuration")
	}
	if err := validateUniqueJSONFields(contents); err != nil {
		return Config{}, errors.New("Provider/ingress configuration contains duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("decode Provider/ingress configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("Provider/ingress configuration has trailing input")
	}
	if err := ValidateConfig(config); err != nil {
		return Config{}, err
	}
	return cloneConfig(config), nil
}

func ValidateConfig(config Config) error {
	if err := config.Provider.Validate(); err != nil {
		return fmt.Errorf("Provider configuration: %w", err)
	}
	if err := validateProviderPaths(config.Provider); err != nil {
		return err
	}
	providerPort, err := validateLoopbackAddress(config.Provider.ProviderAddress)
	if err != nil {
		return fmt.Errorf("provider address: %w", err)
	}
	ingressPort, err := validateLoopbackAddress(config.Ingress.Address)
	if err != nil {
		return fmt.Errorf("ingress address: %w", err)
	}
	if providerPort == ingressPort {
		return errors.New("Provider and private ingress must use distinct TCP ports")
	}
	if err := validateIngress(config.Ingress, config.Authority.CapacityPolicy); err != nil {
		return err
	}
	if err := validateAuthority(config.Authority); err != nil {
		return err
	}
	if err := validateCriticalPathSeparation(config); err != nil {
		return err
	}
	return nil
}

func validateProviderPaths(config basestack.BrowserProviderConfig) error {
	paths := map[string]string{
		"provider certificate": config.ProviderCertificateFile,
		"provider private key": config.ProviderPrivateKeyFile,
		"provider client CA":   config.ClientCAFile,
		"Provider state root":  config.StateRoot,
		"runtime data root":    config.RuntimeDataRoot,
	}
	if config.Browser != nil {
		paths["Browser manifest"] = config.Browser.ManifestPath
		paths["Browser seccomp profile"] = config.Browser.SeccompPath
		paths["provenance executable"] = config.Browser.ProvenanceExecutablePath
	}
	for name, path := range paths {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("%s path must be absolute", name)
		}
	}
	for _, key := range config.TrustedJWSKeys {
		if !filepath.IsAbs(key.Path) {
			return errors.New("trusted JWS key paths must be absolute")
		}
	}
	if filepath.Clean(config.StateRoot) == filepath.Clean(config.RuntimeDataRoot) {
		return errors.New("Provider state and runtime data roots must be distinct")
	}
	return nil
}

func validateIngress(config IngressConfig, capacity CapacityPolicy) error {
	for name, path := range map[string]string{
		"ingress server certificate": config.ServerCertificateFile,
		"ingress server private key": config.ServerPrivateKeyFile,
		"ingress client CA":          config.ClientCAFile,
	} {
		if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
			return fmt.Errorf("%s path must be absolute", name)
		}
	}
	if filepath.Clean(config.ServerCertificateFile) == filepath.Clean(config.ServerPrivateKeyFile) ||
		filepath.Clean(config.ServerPrivateKeyFile) == filepath.Clean(config.ClientCAFile) {
		return errors.New("ingress private key path must be distinct from certificate and CA paths")
	}
	if !exactGatewayRoles(config.AllowedGatewayURIs) {
		return errors.New("ingress must admit exactly the two locked Gateway URI identities")
	}
	if config.ResolveTimeoutMillis != lockedResolveTimeoutMillis ||
		config.ActivationTimeoutMillis != lockedActivationTimeoutMillis ||
		config.ActionTimeoutMillis != lockedActionTimeoutMillis ||
		config.CloseTimeoutMillis != lockedCloseTimeoutMillis ||
		config.MaxSessions != lockedMaxSessions || config.MaxActionBytes != lockedMaxActionBytes ||
		config.MaxConnections != lockedMaxConnections ||
		config.ReadHeaderTimeoutMillis != lockedReadHeaderTimeoutMillis ||
		config.ReadTimeoutMillis != lockedReadTimeoutMillis ||
		config.WriteTimeoutMillis != lockedWriteTimeoutMillis ||
		config.IdleTimeoutMillis != lockedIdleTimeoutMillis ||
		config.MaxHeaderBytes != lockedMaxHeaderBytes {
		return errors.New("ingress policy differs from the locked downstream-fencing profile")
	}
	resolve := durationMillis(config.ResolveTimeoutMillis)
	activation := durationMillis(config.ActivationTimeoutMillis)
	action := durationMillis(config.ActionTimeoutMillis)
	closeTimeout := durationMillis(config.CloseTimeoutMillis)
	for name, value := range map[string]time.Duration{
		"resolve timeout": resolve, "activation timeout": activation,
		"action timeout": action, "close timeout": closeTimeout,
	} {
		if value < gateway.MinDownstreamActionWindow || value > gateway.MaxDownstreamActionWindow {
			return fmt.Errorf("ingress %s is outside the supported bounds", name)
		}
	}
	if activation <= action {
		return errors.New("ingress activation and I/O timeout must exceed the downstream action timeout")
	}
	availableWindow := durationMillis(capacity.LeaseTTLMillis) - durationMillis(capacity.RenewIntervalMillis) -
		durationMillis(capacity.RenewalSafetyMarginMillis) - durationMillis(capacity.OperationTimeoutMillis)
	if availableWindow <= 0 || action >= availableWindow {
		return errors.New("ingress action timeout must fit inside the confirmed capacity safety window")
	}
	if config.MaxSessions < 1 || config.MaxSessions > cdpfence.MaxSessions {
		return errors.New("ingress session limit is invalid")
	}
	if config.MaxActionBytes < 1 || config.MaxActionBytes > cdpfence.MaxActionBytes || config.MaxActionBytes > wire.MaxMessageBytes {
		return errors.New("ingress action byte limit is invalid")
	}
	if config.MaxConnections < 1 || config.MaxConnections > edge.MaxAcceptedConnections {
		return errors.New("ingress accepted-connection limit is invalid")
	}
	readHeader := durationMillis(config.ReadHeaderTimeoutMillis)
	read := durationMillis(config.ReadTimeoutMillis)
	write := durationMillis(config.WriteTimeoutMillis)
	idle := durationMillis(config.IdleTimeoutMillis)
	for name, value := range map[string]time.Duration{
		"read-header timeout": readHeader, "read timeout": read,
		"write timeout": write, "idle timeout": idle,
	} {
		if value < edge.MinHTTPTimeout || value > edge.MaxHTTPTimeout {
			return fmt.Errorf("ingress HTTP %s is outside the supported bounds", name)
		}
	}
	if read < readHeader || read < activation || write < activation || idle < activation {
		return errors.New("ingress HTTP timeouts do not cover the private transport budget")
	}
	if config.MaxHeaderBytes < edge.MinHTTPHeaderBytes || config.MaxHeaderBytes > edge.MaxHTTPHeaderBytes {
		return errors.New("ingress HTTP header byte limit is invalid")
	}
	return nil
}

func validateAuthority(config AuthorityConfig) error {
	if err := validateRedisURL(config.RedisURL); err != nil {
		return err
	}
	if !namespacePattern.MatchString(config.CapacityNamespace) {
		return errors.New("capacity namespace is invalid")
	}
	policy := config.CapacityPolicy
	if policy != (CapacityPolicy{
		MaxTotal: lockedMaxTotal, MaxPerTenant: lockedMaxPerTenant, MaxPerSession: lockedMaxPerSession,
		LeaseTTLMillis: lockedLeaseTTLMillis, RenewIntervalMillis: lockedRenewIntervalMillis,
		RenewalSafetyMarginMillis: lockedRenewalSafetyMarginMillis, OperationTimeoutMillis: lockedOperationTimeoutMillis,
	}) {
		return errors.New("capacity policy differs from the locked downstream-fencing profile")
	}
	if policy.MaxTotal < 1 || policy.MaxTotal > gateway.MaxConnectionCapacity ||
		policy.MaxPerTenant < 1 || policy.MaxPerTenant > policy.MaxTotal || policy.MaxPerSession != 1 {
		return errors.New("capacity policy must be bounded with an exact per-session limit of one")
	}
	lease := durationMillis(policy.LeaseTTLMillis)
	renew := durationMillis(policy.RenewIntervalMillis)
	safety := durationMillis(policy.RenewalSafetyMarginMillis)
	operation := durationMillis(policy.OperationTimeoutMillis)
	if lease < rediscapacity.MinLeaseTTL || lease > rediscapacity.MaxLeaseTTL ||
		renew < rediscapacity.MinRenewInterval || renew > lease/2 ||
		operation < rediscapacity.MinOperationTimeout || operation > rediscapacity.MaxOperationTimeout ||
		safety < operation || renew+operation+safety >= lease {
		return errors.New("capacity lease policy is invalid")
	}
	return nil
}

func validateCriticalPathSeparation(config Config) error {
	unique := map[string]string{
		"Provider certificate":        config.Provider.ProviderCertificateFile,
		"Provider private key":        config.Provider.ProviderPrivateKeyFile,
		"private ingress certificate": config.Ingress.ServerCertificateFile,
		"private ingress key":         config.Ingress.ServerPrivateKeyFile,
	}
	for index, key := range config.Provider.TrustedJWSKeys {
		unique[fmt.Sprintf("trusted JWS key %d", index)] = key.Path
	}
	if config.Provider.Browser != nil {
		unique["Browser manifest"] = config.Provider.Browser.ManifestPath
		unique["Browser seccomp profile"] = config.Provider.Browser.SeccompPath
		unique["provenance executable"] = config.Provider.Browser.ProvenanceExecutablePath
	}
	seen := make(map[string]string, len(unique))
	for name, path := range unique {
		clean := filepath.Clean(path)
		if previous, exists := seen[clean]; exists {
			return fmt.Errorf("critical paths for %s and %s must be distinct", previous, name)
		}
		seen[clean] = name
	}
	for name, path := range map[string]string{
		"Provider client CA": config.Provider.ClientCAFile,
		"ingress client CA":  config.Ingress.ClientCAFile,
	} {
		if previous, exists := seen[filepath.Clean(path)]; exists {
			return fmt.Errorf("critical paths for %s and %s must be distinct", previous, name)
		}
	}
	for name, path := range map[string]string{
		"Provider state root": config.Provider.StateRoot,
		"runtime data root":   config.Provider.RuntimeDataRoot,
	} {
		clean := filepath.Clean(path)
		if previous, exists := seen[clean]; exists {
			return fmt.Errorf("critical paths for %s and %s must be distinct", previous, name)
		}
		if clean == filepath.Clean(config.Provider.ClientCAFile) || clean == filepath.Clean(config.Ingress.ClientCAFile) {
			return fmt.Errorf("%s must not collide with a CA bundle", name)
		}
	}
	return nil
}

func validateLoopbackAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
		return "", errors.New("an explicit TCP host and port are required")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", errors.New("only a loopback listener is permitted")
		}
	}
	parsed, err := strconv.Atoi(port)
	if err != nil || parsed < 1 || parsed > 65_535 {
		return "", errors.New("an explicit nonzero TCP port is required")
	}
	return port, nil
}

func validateRedisURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/0" || parsed.User == nil {
		return errors.New("Redis authority URL must select database zero with explicit credentials")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65_535 {
		return errors.New("Redis authority URL port is invalid")
	}
	password, hasPassword := parsed.User.Password()
	if parsed.User.Username() == "" || !hasPassword || password == "" {
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

func exactGatewayRoles(values []string) bool {
	if len(values) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if value != wire.GatewayARoleURI && value != wire.GatewayBRoleURI {
			return false
		}
		seen[value] = true
	}
	return seen[wire.GatewayARoleURI] && seen[wire.GatewayBRoleURI]
}

func durationMillis(value int64) time.Duration {
	if value < 1 || value > int64((1<<63-1)/int64(time.Millisecond)) {
		return 0
	}
	return time.Duration(value) * time.Millisecond
}

func validateUniqueJSONFields(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
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

func cloneConfig(config Config) Config {
	result := config
	result.Provider.AllowedClientURIs = append([]string(nil), config.Provider.AllowedClientURIs...)
	result.Provider.TrustedJWSKeys = append([]basestack.TrustedJWSKey(nil), config.Provider.TrustedJWSKeys...)
	if config.Provider.Browser != nil {
		browser := *config.Provider.Browser
		browser.AllowedHosts = append([]string(nil), config.Provider.Browser.AllowedHosts...)
		result.Provider.Browser = &browser
	}
	result.Ingress.AllowedGatewayURIs = append([]string(nil), config.Ingress.AllowedGatewayURIs...)
	return result
}
