package caller

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxConfigBytes   = 1 << 20
	maxCABundleBytes = 256 << 10
	maxGateways      = 2
	maxEndpoints     = 128
	maxBindings      = 256
	maxSecretBytes   = 8 << 10
)

var (
	logicalIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	referencePattern  = regexp.MustCompile(`^ref:browser-session:[0-9a-f]{32}$`)
)

type resolvedGrantBinding struct {
	grantID   string
	expiresAt time.Time
	principal Principal
	endpoint  Endpoint
}

type preparedConfig struct {
	roots       *x509.CertPool
	gateways    map[string]*url.URL
	bindings    map[string]resolvedGrantBinding
	privateText [][]byte
}

// LoadConfig reads one strict, bounded, private regular JSON file.
func LoadConfig(path string) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("invalid caller configuration")
	}
	contents, err := readBoundedRegularFile(path, maxConfigBytes, true)
	if err != nil || validateUniqueJSONFields(contents) != nil {
		return Config{}, errors.New("invalid caller configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("invalid caller configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("invalid caller configuration")
	}
	if _, err := prepareConfig(config); err != nil {
		return Config{}, err
	}
	return cloneConfig(config), nil
}

func prepareConfig(config Config) (preparedConfig, error) {
	roots, err := loadRoots(config.CAFile)
	if err != nil {
		return preparedConfig{}, err
	}
	if len(config.Gateways) == 0 || len(config.Gateways) > maxGateways || len(config.Principals) != 1 ||
		len(config.Endpoints) == 0 || len(config.Endpoints) > maxEndpoints || len(config.GrantBindings) == 0 || len(config.GrantBindings) > maxBindings {
		return preparedConfig{}, errors.New("invalid caller configuration")
	}

	privateText := make([][]byte, 0, len(config.Gateways)+len(config.Principals)+len(config.Endpoints)+len(config.GrantBindings)*2+1)
	privateText = appendPrivate(privateText, config.CAFile)
	gateways := make(map[string]*url.URL, len(config.Gateways))
	gatewayPorts := make(map[string]bool, len(config.Gateways))
	for id, raw := range config.Gateways {
		if (id != "gateway-a" && id != "gateway-b") || gateways[id] != nil {
			return preparedConfig{}, errors.New("invalid Gateway configuration")
		}
		parsed, err := validateGatewayURL(raw)
		if err != nil || gatewayPorts[parsed.Port()] {
			return preparedConfig{}, errors.New("invalid Gateway configuration")
		}
		gateways[id] = parsed
		gatewayPorts[parsed.Port()] = true
		privateText = appendPrivate(privateText, raw)
	}

	principals := make(map[string]Principal, len(config.Principals))
	tokens := make(map[string]bool, len(config.Principals))
	callerTenants := make(map[string]bool, len(config.Principals))
	for _, principal := range config.Principals {
		binding := principal.CallerID + "\x00" + principal.TenantID
		if !validLogicalID(principal.ID) || !validBearerToken(principal.Token) || !validIdentifier(principal.CallerID) || !validIdentifier(principal.TenantID) ||
			principals[principal.ID].ID != "" || tokens[principal.Token] || callerTenants[binding] {
			return preparedConfig{}, errors.New("invalid principal configuration")
		}
		principals[principal.ID] = principal
		tokens[principal.Token], callerTenants[binding] = true, true
		privateText = appendPrivate(privateText, principal.Token)
	}

	endpoints := make(map[string]Endpoint, len(config.Endpoints))
	references := make(map[string]bool, len(config.Endpoints))
	sessions := make(map[string]bool, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		session := endpoint.TenantID + "\x00" + endpoint.SandboxID + "\x00" + endpoint.BrowserSessionID
		if !validEndpoint(endpoint) || principalsForTenant(principals, endpoint.TenantID) == 0 || endpoints[endpoint.ID].ID != "" || references[endpoint.HandoffReference] || sessions[session] {
			return preparedConfig{}, errors.New("invalid endpoint configuration")
		}
		endpoints[endpoint.ID] = endpoint
		references[endpoint.HandoffReference], sessions[session] = true, true
		privateText = appendPrivate(privateText, endpoint.HandoffReference)
	}

	bindings := make(map[string]resolvedGrantBinding, len(config.GrantBindings))
	grants := make(map[string]bool, len(config.GrantBindings))
	for _, binding := range config.GrantBindings {
		principal, principalOK := principals[binding.PrincipalID]
		endpoint, endpointOK := endpoints[binding.EndpointID]
		expiresAt, expiryOK := parseCanonicalExpiry(binding.ExpiresAt)
		if !validLogicalID(binding.ID) || !validIdentifier(binding.GrantID) || !principalOK || !endpointOK || !expiryOK ||
			principal.TenantID != endpoint.TenantID || bindings[binding.ID].grantID != "" || grants[binding.GrantID] {
			return preparedConfig{}, errors.New("invalid grant binding configuration")
		}
		bindings[binding.ID] = resolvedGrantBinding{grantID: binding.GrantID, expiresAt: expiresAt, principal: principal, endpoint: endpoint}
		grants[binding.GrantID] = true
		privateText = appendPrivate(privateText, binding.GrantID, binding.ExpiresAt)
	}
	return preparedConfig{roots: roots, gateways: gateways, bindings: bindings, privateText: privateText}, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid CA configuration")
	}
	contents, err := readBoundedRegularFile(path, maxCABundleBytes, false)
	if err != nil {
		return nil, errors.New("invalid CA configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("invalid CA configuration")
	}
	return roots, nil
}

func validateGatewayURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 256 || strings.TrimSpace(raw) != raw {
		return nil, errors.New("invalid URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errors.New("invalid URL")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return nil, errors.New("invalid URL")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid URL")
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		return nil, errors.New("invalid URL")
	}
	return parsed, nil
}

func validEndpoint(endpoint Endpoint) bool {
	return validLogicalID(endpoint.ID) && validIdentifier(endpoint.TenantID) && validIdentifier(endpoint.SandboxID) &&
		validIdentifier(endpoint.BrowserSessionID) && endpoint.CapabilityProfileID == lockedCapabilityProfileID &&
		referencePattern.MatchString(endpoint.HandoffReference) && endpoint.ConnectionGeneration > 0
}

func principalsForTenant(principals map[string]Principal, tenant string) int {
	count := 0
	for _, principal := range principals {
		if principal.TenantID == tenant {
			count++
		}
	}
	return count
}

func validLogicalID(value string) bool  { return logicalIDPattern.MatchString(value) }
func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }

func validBearerToken(value string) bool {
	return len(value) >= 32 && len(value) <= 512 && validOpaque(value, maxSecretBytes)
}

func validOpaque(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func parseCanonicalExpiry(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func appendPrivate(target [][]byte, values ...string) [][]byte {
	for _, value := range values {
		if value != "" {
			target = append(target, []byte(value))
		}
	}
	return target
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
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
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
	gateways := make(map[string]string, len(config.Gateways))
	for key, value := range config.Gateways {
		gateways[key] = value
	}
	config.Gateways = gateways
	config.Principals = append([]Principal(nil), config.Principals...)
	config.Endpoints = append([]Endpoint(nil), config.Endpoints...)
	config.GrantBindings = append([]GrantBinding(nil), config.GrantBindings...)
	return config
}
