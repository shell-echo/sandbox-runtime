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

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
)

const (
	maxConfigBytes = 1 << 20
	maxCABytes     = 1 << 20
	maxEntries     = 128
	maxSecretBytes = 8 << 10
	maxValueBytes  = 2 << 10
)

var logicalIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// LoadConfig reads and validates one bounded caller configuration document.
func LoadConfig(path string) (wire.CallerConfig, error) {
	content, err := readBoundedFile(path, maxConfigBytes)
	if err != nil {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	if !uniqueTopLevelFields(content) {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document struct {
		CAFile     string           `json:"ca_file"`
		Gateways   uniqueStringMap  `json:"gateways"`
		Principals []wire.Principal `json:"principals"`
		Endpoints  []wire.Endpoint  `json:"endpoints"`
	}
	if err := decoder.Decode(&document); err != nil {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wire.CallerConfig{}, errors.New("invalid caller configuration")
	}
	config := wire.CallerConfig{
		CAFile: document.CAFile, Gateways: document.Gateways,
		Principals: document.Principals, Endpoints: document.Endpoints,
	}
	if _, _, _, _, err := prepareConfig(config); err != nil {
		return wire.CallerConfig{}, err
	}
	return config, nil
}

type uniqueStringMap map[string]string

func (m *uniqueStringMap) UnmarshalJSON(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid map")
	}
	values := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return errors.New("invalid map")
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("invalid map")
		}
		if _, exists := values[key]; exists {
			return errors.New("duplicate map key")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return errors.New("invalid map value")
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return errors.New("invalid map")
	}
	*m = values
	return nil
}

func uniqueTopLevelFields(content []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(content))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok {
			return false
		}
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}')
}

func prepareConfig(config wire.CallerConfig) (*x509.CertPool, map[string]*url.URL, map[string]wire.Principal, map[string]wire.Endpoint, error) {
	roots, err := loadRoots(config.CAFile)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(config.Gateways) == 0 || len(config.Gateways) > maxEntries || len(config.Principals) == 0 || len(config.Principals) > maxEntries || len(config.Endpoints) == 0 || len(config.Endpoints) > maxEntries {
		return nil, nil, nil, nil, errors.New("invalid caller configuration")
	}

	gateways := make(map[string]*url.URL, len(config.Gateways))
	for id, raw := range config.Gateways {
		if !validLogicalID(id) {
			return nil, nil, nil, nil, errors.New("invalid gateway configuration")
		}
		parsed, err := validateGatewayURL(raw)
		if err != nil {
			return nil, nil, nil, nil, errors.New("invalid gateway configuration")
		}
		gateways[id] = parsed
	}

	principals := make(map[string]wire.Principal, len(config.Principals))
	for _, principal := range config.Principals {
		if !validLogicalID(principal.ID) || !validOpaque(principal.Token, maxSecretBytes) || !validOpaque(principal.CallerID, maxValueBytes) || !validOpaque(principal.TenantID, maxValueBytes) {
			return nil, nil, nil, nil, errors.New("invalid principal configuration")
		}
		if _, exists := principals[principal.ID]; exists {
			return nil, nil, nil, nil, errors.New("duplicate principal configuration")
		}
		principals[principal.ID] = principal
	}

	endpoints := make(map[string]wire.Endpoint, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		if !validLogicalID(endpoint.ID) || !validOpaque(endpoint.TenantID, maxValueBytes) || !validOpaque(endpoint.SandboxID, maxValueBytes) || !validOpaque(endpoint.BrowserSessionID, maxValueBytes) || !validOpaque(endpoint.CapabilityProfileID, maxValueBytes) || !validOpaque(endpoint.HandoffReference, maxValueBytes) || endpoint.ConnectionGeneration < 1 {
			return nil, nil, nil, nil, errors.New("invalid endpoint configuration")
		}
		if _, exists := endpoints[endpoint.ID]; exists {
			return nil, nil, nil, nil, errors.New("duplicate endpoint configuration")
		}
		endpoints[endpoint.ID] = endpoint
	}
	return roots, gateways, principals, endpoints, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid CA configuration")
	}
	content, err := readBoundedFile(path, maxCABytes)
	if err != nil {
		return nil, errors.New("invalid CA configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(content) {
		return nil, errors.New("invalid CA configuration")
	}
	return roots, nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("file is not a bounded regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, errors.New("file exceeds bound")
	}
	return content, nil
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

func validLogicalID(value string) bool {
	return logicalIDPattern.MatchString(value)
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
