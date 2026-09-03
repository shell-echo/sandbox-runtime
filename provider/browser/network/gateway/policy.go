// Package gateway implements the process-local enforcement used by the
// Browser restricted-egress Docker network. It is not a public Runtime Gateway.
package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

const (
	ConfigEnvironment = "SANDBOX_RUNTIME_BROWSER_EGRESS_CONFIG"
	maxPolicyHosts    = 256
	maxPolicyBytes    = 32 << 10
)

var (
	ErrInvalidConfig = errors.New("invalid Browser egress gateway configuration")
	ErrPolicyDenied  = errors.New("Browser egress policy denied the destination")
)

type Policy struct {
	Reference    string   `json:"reference"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type Config struct {
	GatewayAddress string `json:"gateway_address"`
	Policy         Policy `json:"policy"`
}

func NormalizePolicy(policy Policy) (Policy, error) {
	if !validIdentifier(policy.Reference) || len(policy.AllowedHosts) == 0 || len(policy.AllowedHosts) > maxPolicyHosts {
		return Policy{}, ErrInvalidConfig
	}
	hosts := make([]string, 0, len(policy.AllowedHosts))
	seen := make(map[string]struct{}, len(policy.AllowedHosts))
	for _, raw := range policy.AllowedHosts {
		host := strings.ToLower(strings.TrimSpace(raw))
		wildcard := strings.HasPrefix(host, "*.")
		name := host
		if wildcard {
			name = strings.TrimPrefix(host, "*.")
		}
		if !validHostname(name) || (wildcard && strings.Count(name, ".") < 1) {
			return Policy{}, fmt.Errorf("%w: invalid allowed host", ErrInvalidConfig)
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return Policy{Reference: policy.Reference, AllowedHosts: hosts}, nil
}

func (p Policy) Allows(host string) bool {
	normalized, err := normalizeDestinationHost(host)
	if err != nil {
		return false
	}
	for _, allowed := range p.AllowedHosts {
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(allowed, "*")
			if strings.HasSuffix(normalized, suffix) && normalized != strings.TrimPrefix(suffix, ".") {
				return true
			}
			continue
		}
		if normalized == allowed {
			return true
		}
	}
	return false
}

func (p Policy) Digest() (string, error) {
	normalized, err := NormalizePolicy(p)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func EncodeConfig(config Config) (string, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil || len(encoded) > maxPolicyBytes {
		return "", ErrInvalidConfig
	}
	return string(encoded), nil
}

func DecodeConfig(value string) (Config, error) {
	if len(value) == 0 || len(value) > maxPolicyBytes {
		return Config{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, ErrInvalidConfig
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, ErrInvalidConfig
	}
	return normalizeConfig(config)
}

func normalizeConfig(config Config) (Config, error) {
	address, err := netip.ParseAddr(config.GatewayAddress)
	if err != nil || !address.Is4() || !address.IsPrivate() {
		return Config{}, fmt.Errorf("%w: gateway address", ErrInvalidConfig)
	}
	policy, err := NormalizePolicy(config.Policy)
	if err != nil {
		return Config{}, err
	}
	return Config{GatewayAddress: address.String(), Policy: policy}, nil
}

func normalizeDestinationHost(value string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if strings.ContainsAny(host, "@:/[]") || !validHostname(host) {
		return "", ErrPolicyDenied
	}
	return host, nil
}

func validHostname(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.Count(value, ".") < 1 {
		return false
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 200 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48",
	"100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
	"5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
)

func PublicUpstreamAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Is4In6() {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}
