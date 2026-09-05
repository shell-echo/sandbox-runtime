package revoker

import (
	"bytes"
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
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

const (
	maxConfigBytes = 1 << 20
	maxEntries     = 128
)

var (
	logicalIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	namespacePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type resolvedGrantBinding struct {
	grantID   string
	expiresAt time.Time
}

// LoadConfig reads and validates one bounded private revoker configuration.
func LoadConfig(path string) (wire.RevokerConfig, error) {
	content, err := readConfigFile(path)
	if err != nil || !uniqueJSONFields(content) {
		return wire.RevokerConfig{}, errors.New("invalid revoker configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config wire.RevokerConfig
	if err := decoder.Decode(&config); err != nil {
		return wire.RevokerConfig{}, errors.New("invalid revoker configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return wire.RevokerConfig{}, errors.New("invalid revoker configuration")
	}
	if _, err := prepareConfig(config); err != nil {
		return wire.RevokerConfig{}, err
	}
	return config, nil
}

func prepareConfig(config wire.RevokerConfig) (map[string]resolvedGrantBinding, error) {
	if err := validateRedisURL(config.RedisURL); err != nil || !namespacePattern.MatchString(config.RevocationNamespace) ||
		!validPolicy(config.RevocationPolicy) || !validPrivateOutputPath(config.ControlLogFile) ||
		len(config.GrantBindings) == 0 || len(config.GrantBindings) > maxEntries {
		return nil, errors.New("invalid revoker configuration")
	}
	bindings := make(map[string]resolvedGrantBinding, len(config.GrantBindings))
	rawGrantIDs := make(map[string]struct{}, len(config.GrantBindings))
	for _, binding := range config.GrantBindings {
		expiresAt, expiryOK := parseAbsoluteExpiry(binding.ExpiresAt)
		if !logicalIDPattern.MatchString(binding.ID) || !identifierPattern.MatchString(binding.GrantID) ||
			!logicalIDPattern.MatchString(binding.PrincipalID) || !logicalIDPattern.MatchString(binding.EndpointID) || !expiryOK {
			return nil, errors.New("invalid revoker grant binding")
		}
		if _, exists := bindings[binding.ID]; exists {
			return nil, errors.New("duplicate revoker grant binding")
		}
		if _, exists := rawGrantIDs[binding.GrantID]; exists {
			return nil, errors.New("duplicate revoker grant binding")
		}
		bindings[binding.ID] = resolvedGrantBinding{grantID: binding.GrantID, expiresAt: expiresAt}
		rawGrantIDs[binding.GrantID] = struct{}{}
	}
	return bindings, nil
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

func validateRedisURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return errors.New("invalid Redis configuration")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("invalid Redis configuration")
		}
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid Redis configuration")
	}
	return nil
}

func validPolicy(policy wire.RevocationPolicy) bool {
	return policy.MaxGrantLifetimeMillis >= redisrevocation.MinGrantLifetime.Milliseconds() &&
		policy.MaxGrantLifetimeMillis <= redisrevocation.MaxGrantLifetime.Milliseconds() &&
		policy.PollIntervalMillis >= redisrevocation.MinPollInterval.Milliseconds() &&
		policy.PollIntervalMillis <= redisrevocation.MaxPollInterval.Milliseconds() &&
		policy.OperationTimeoutMillis >= redisrevocation.MinOperationTimeout.Milliseconds() &&
		policy.OperationTimeoutMillis <= redisrevocation.MaxOperationTimeout.Milliseconds() &&
		policy.OperationTimeoutMillis <= policy.PollIntervalMillis
}

func validPrivateOutputPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
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
