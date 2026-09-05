package caller

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
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
)

const (
	maxConfigBytes = 1 << 20
	maxCABytes     = 1 << 20
	maxEntries     = 128
	maxSecretBytes = 8 << 10
	maxValueBytes  = 2 << 10
)

var (
	logicalIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

type resolvedGrantBinding struct {
	grantID   string
	expiresAt time.Time
	principal wire.Principal
	endpoint  wire.Endpoint
}

// LoadConfig reads and validates one bounded caller configuration document.
func LoadConfig(path string) (wire.CallerConfig, error) {
	content, err := readConfigFile(path)
	if err != nil || !uniqueJSONFields(content) {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config wire.CallerConfig
	if err := decoder.Decode(&config); err != nil {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	if _, _, _, err := prepareConfig(config); err != nil {
		return wire.CallerConfig{}, err
	}
	return config, nil
}

func prepareConfig(config wire.CallerConfig) (*x509.CertPool, map[string]*url.URL, map[string]resolvedGrantBinding, error) {
	roots, err := loadRoots(config.CAFile)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(config.Gateways) == 0 || len(config.Gateways) > maxEntries || len(config.Principals) == 0 || len(config.Principals) > maxEntries ||
		len(config.Endpoints) == 0 || len(config.Endpoints) > maxEntries || len(config.GrantBindings) == 0 || len(config.GrantBindings) > maxEntries {
		return nil, nil, nil, errors.New("invalid caller configuration")
	}

	gateways := make(map[string]*url.URL, len(config.Gateways))
	for id, raw := range config.Gateways {
		if !validLogicalID(id) {
			return nil, nil, nil, errors.New("invalid gateway configuration")
		}
		parsed, err := validateGatewayURL(raw)
		if err != nil {
			return nil, nil, nil, errors.New("invalid gateway configuration")
		}
		gateways[id] = parsed
	}

	principals := make(map[string]wire.Principal, len(config.Principals))
	principalTokens := make(map[string]struct{}, len(config.Principals))
	for _, principal := range config.Principals {
		if !validLogicalID(principal.ID) || !validBearerToken(principal.Token) || !validIdentifier(principal.CallerID) || !validIdentifier(principal.TenantID) {
			return nil, nil, nil, errors.New("invalid principal configuration")
		}
		if _, exists := principals[principal.ID]; exists {
			return nil, nil, nil, errors.New("duplicate principal configuration")
		}
		if _, exists := principalTokens[principal.Token]; exists {
			return nil, nil, nil, errors.New("duplicate principal configuration")
		}
		principals[principal.ID] = principal
		principalTokens[principal.Token] = struct{}{}
	}

	endpoints := make(map[string]wire.Endpoint, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		if !validEndpoint(endpoint) {
			return nil, nil, nil, errors.New("invalid endpoint configuration")
		}
		if _, exists := endpoints[endpoint.ID]; exists {
			return nil, nil, nil, errors.New("duplicate endpoint configuration")
		}
		endpoints[endpoint.ID] = endpoint
	}

	bindings := make(map[string]resolvedGrantBinding, len(config.GrantBindings))
	rawGrantIDs := make(map[string]struct{}, len(config.GrantBindings))
	for _, binding := range config.GrantBindings {
		principal, principalOK := principals[binding.PrincipalID]
		endpoint, endpointOK := endpoints[binding.EndpointID]
		expiresAt, expiryOK := parseAbsoluteExpiry(binding.ExpiresAt)
		if !validLogicalID(binding.ID) || !validIdentifier(binding.GrantID) || !principalOK || !endpointOK || !expiryOK || principal.TenantID != endpoint.TenantID {
			return nil, nil, nil, errors.New("invalid grant binding configuration")
		}
		if _, exists := bindings[binding.ID]; exists {
			return nil, nil, nil, errors.New("duplicate grant binding configuration")
		}
		if _, exists := rawGrantIDs[binding.GrantID]; exists {
			return nil, nil, nil, errors.New("duplicate grant binding configuration")
		}
		bindings[binding.ID] = resolvedGrantBinding{
			grantID: binding.GrantID, expiresAt: expiresAt, principal: principal, endpoint: endpoint,
		}
		rawGrantIDs[binding.GrantID] = struct{}{}
	}
	return roots, gateways, bindings, nil
}

func readConfigFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid configuration path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxConfigBytes {
		return nil, errors.New("configuration is not a bounded private regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(content) > maxConfigBytes {
		return nil, errors.New("configuration exceeds bound")
	}
	return content, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid CA configuration")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("invalid CA configuration")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxCABytes {
		return nil, errors.New("invalid CA configuration")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxCABytes+1))
	if err != nil || len(content) > maxCABytes {
		return nil, errors.New("invalid CA configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(content) {
		return nil, errors.New("invalid CA configuration")
	}
	return roots, nil
}

func validateGatewayURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 256 || strings.TrimSpace(raw) != raw {
		return nil, errors.New("invalid URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
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

func validEndpoint(endpoint wire.Endpoint) bool {
	return validLogicalID(endpoint.ID) && validIdentifier(endpoint.TenantID) && validIdentifier(endpoint.SandboxID) &&
		validIdentifier(endpoint.BrowserSessionID) && validIdentifier(endpoint.CapabilityProfileID) &&
		strings.HasPrefix(endpoint.HandoffReference, "ref:browser-session:") && validOpaque(endpoint.HandoffReference, maxValueBytes) &&
		endpoint.ConnectionGeneration > 0
}

func validLogicalID(value string) bool { return logicalIDPattern.MatchString(value) }

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

func parseAbsoluteExpiry(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func uniqueJSONFields(content []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if !uniqueJSONValue(decoder) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func uniqueJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			if _, exists := seen[key]; exists {
				return false
			}
			seen[key] = struct{}{}
			if !uniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !uniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}
