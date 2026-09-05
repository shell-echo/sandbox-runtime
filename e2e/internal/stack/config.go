package stack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	ProfileCodingShell = "coding-shell"
	ProfileBrowser     = "browser"
)

type TrustedJWSKey struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Path      string `json:"path"`
}

type GatewayPrincipal struct {
	Token    string `json:"token"`
	CallerID string `json:"caller_id"`
	TenantID string `json:"tenant_id"`
}

type Config struct {
	Profile                  string             `json:"profile"`
	ProviderAddress          string             `json:"provider_address"`
	GatewayAddress           string             `json:"gateway_address"`
	ProviderCertificateFile  string             `json:"provider_certificate_file"`
	ProviderPrivateKeyFile   string             `json:"provider_private_key_file"`
	GatewayCertificateFile   string             `json:"gateway_certificate_file"`
	GatewayPrivateKeyFile    string             `json:"gateway_private_key_file"`
	ClientCAFile             string             `json:"client_ca_file"`
	AllowedClientURIs        []string           `json:"allowed_client_uris"`
	TrustedJWSKeys           []TrustedJWSKey    `json:"trusted_jws_keys"`
	ProviderRevisionID       string             `json:"provider_revision_id"`
	ProviderInstanceAudience string             `json:"provider_instance_audience"`
	StateRoot                string             `json:"state_root"`
	RuntimeDataRoot          string             `json:"runtime_data_root"`
	RuntimeImage             string             `json:"runtime_image"`
	RuntimeControllerID      string             `json:"runtime_controller_id"`
	TerminalBrokerPath       string             `json:"terminal_broker_path"`
	GatewayPrincipals        []GatewayPrincipal `json:"gateway_principals"`
	GatewayAdminToken        string             `json:"gateway_admin_token"`
	GatewayAuditFile         string             `json:"gateway_audit_file"`
	GatewayListenerLimit     int                `json:"gateway_listener_limit"`
	Browser                  *BrowserConfig     `json:"browser,omitempty"`
}

// BrowserProviderConfig contains only the Provider listener, admission,
// runtime, and Browser dependencies owned by the Provider/ingress process.
// Public Gateway configuration deliberately belongs to its separate process.
type BrowserProviderConfig struct {
	ProviderAddress         string          `json:"provider_address"`
	ProviderCertificateFile string          `json:"provider_certificate_file"`
	ProviderPrivateKeyFile  string          `json:"provider_private_key_file"`
	ClientCAFile            string          `json:"client_ca_file"`
	AllowedClientURIs       []string        `json:"allowed_client_uris"`
	TrustedJWSKeys          []TrustedJWSKey `json:"trusted_jws_keys"`
	ProviderRevisionID      string          `json:"provider_revision_id"`
	StateRoot               string          `json:"state_root"`
	RuntimeDataRoot         string          `json:"runtime_data_root"`
	RuntimeImage            string          `json:"runtime_image"`
	RuntimeControllerID     string          `json:"runtime_controller_id"`
	Browser                 *BrowserConfig  `json:"browser"`
}

type BrowserConfig struct {
	GatewayImage               string   `json:"gateway_image"`
	UplinkNetwork              string   `json:"uplink_network"`
	Namespace                  string   `json:"namespace"`
	RuntimeArchitecture        string   `json:"runtime_architecture"`
	ManifestPath               string   `json:"manifest_path"`
	SeccompPath                string   `json:"seccomp_path"`
	ProvenanceExecutablePath   string   `json:"provenance_executable_path"`
	ProvenanceExecutableDigest string   `json:"provenance_executable_digest"`
	NetworkPolicyReference     string   `json:"network_policy_reference"`
	AllowedHosts               []string `json:"allowed_hosts"`
}

func LoadConfig(path string) (Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode stack configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("stack configuration has trailing input")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	for name, value := range map[string]string{
		"profile":          c.Profile,
		"provider_address": c.ProviderAddress, "gateway_address": c.GatewayAddress,
		"provider_certificate_file": c.ProviderCertificateFile, "provider_private_key_file": c.ProviderPrivateKeyFile,
		"gateway_certificate_file": c.GatewayCertificateFile, "gateway_private_key_file": c.GatewayPrivateKeyFile,
		"client_ca_file": c.ClientCAFile, "provider_revision_id": c.ProviderRevisionID,
		"provider_instance_audience": c.ProviderInstanceAudience, "state_root": c.StateRoot,
		"runtime_data_root": c.RuntimeDataRoot, "runtime_image": c.RuntimeImage,
		"runtime_controller_id": c.RuntimeControllerID,
		"gateway_admin_token":   c.GatewayAdminToken, "gateway_audit_file": c.GatewayAuditFile,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if c.ProviderAddress == c.GatewayAddress {
		return errors.New("Provider and Gateway addresses must differ")
	}
	if c.GatewayListenerLimit < 1 || c.GatewayListenerLimit > 256 {
		return errors.New("gateway_listener_limit must be between 1 and 256")
	}
	switch c.Profile {
	case ProfileCodingShell:
		if strings.TrimSpace(c.TerminalBrokerPath) == "" || c.Browser != nil {
			return errors.New("coding/shell profile requires terminal_broker_path and forbids Browser configuration")
		}
	case ProfileBrowser:
		if strings.TrimSpace(c.TerminalBrokerPath) != "" || c.Browser == nil {
			return errors.New("Browser profile requires Browser configuration and forbids terminal_broker_path")
		}
		if err := c.Browser.validate(); err != nil {
			return err
		}
	default:
		return errors.New("reference stack profile is unsupported")
	}
	if _, _, err := splitAddress(c.ProviderAddress); err != nil {
		return fmt.Errorf("provider_address: %w", err)
	}
	if _, _, err := splitAddress(c.GatewayAddress); err != nil {
		return fmt.Errorf("gateway_address: %w", err)
	}
	if len(c.AllowedClientURIs) != 2 || len(c.TrustedJWSKeys) != 2 || len(c.GatewayPrincipals) != 2 {
		return errors.New("reference stack requires exactly two caller identities, JWS keys, and Gateway principals")
	}
	if err := validateProviderCallerAdmission(c.AllowedClientURIs, c.TrustedJWSKeys); err != nil {
		return err
	}
	seenTokens := make(map[string]struct{})
	seenBindings := make(map[string]struct{})
	for _, principal := range c.GatewayPrincipals {
		if strings.TrimSpace(principal.Token) == "" || strings.TrimSpace(principal.CallerID) == "" || strings.TrimSpace(principal.TenantID) == "" {
			return errors.New("Gateway principal fields are required")
		}
		if _, exists := seenTokens[principal.Token]; exists {
			return errors.New("Gateway principal tokens must be unique")
		}
		binding := principal.CallerID + "\x00" + principal.TenantID
		if _, exists := seenBindings[binding]; exists {
			return errors.New("Gateway principal bindings must be unique")
		}
		seenTokens[principal.Token] = struct{}{}
		seenBindings[binding] = struct{}{}
	}
	return nil
}

func (c BrowserProviderConfig) Validate() error {
	for name, value := range map[string]string{
		"provider_address":          c.ProviderAddress,
		"provider_certificate_file": c.ProviderCertificateFile,
		"provider_private_key_file": c.ProviderPrivateKeyFile,
		"client_ca_file":            c.ClientCAFile,
		"provider_revision_id":      c.ProviderRevisionID,
		"state_root":                c.StateRoot,
		"runtime_data_root":         c.RuntimeDataRoot,
		"runtime_image":             c.RuntimeImage,
		"runtime_controller_id":     c.RuntimeControllerID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if c.Browser == nil {
		return errors.New("Browser Provider requires Browser configuration")
	}
	if err := c.Browser.validate(); err != nil {
		return err
	}
	if _, _, err := splitAddress(c.ProviderAddress); err != nil {
		return fmt.Errorf("provider_address: %w", err)
	}
	if len(c.AllowedClientURIs) != 2 || len(c.TrustedJWSKeys) != 2 {
		return errors.New("Browser Provider requires exactly two caller identities and JWS keys")
	}
	return validateProviderCallerAdmission(c.AllowedClientURIs, c.TrustedJWSKeys)
}

func validateProviderCallerAdmission(allowedClientURIs []string, trustedJWSKeys []TrustedJWSKey) error {
	seenURIs := make(map[string]struct{}, len(allowedClientURIs))
	for _, identity := range allowedClientURIs {
		if strings.TrimSpace(identity) == "" || identity != strings.TrimSpace(identity) {
			return errors.New("allowed client URI identities are invalid")
		}
		if _, exists := seenURIs[identity]; exists {
			return errors.New("allowed client URI identities must be unique")
		}
		seenURIs[identity] = struct{}{}
	}
	seenKeyIDs := make(map[string]struct{}, len(trustedJWSKeys))
	for _, key := range trustedJWSKeys {
		if strings.TrimSpace(key.ID) == "" || key.Algorithm != "EdDSA" || strings.TrimSpace(key.Path) == "" {
			return errors.New("trusted JWS keys require an ID, EdDSA algorithm, and path")
		}
		if _, exists := seenKeyIDs[key.ID]; exists {
			return errors.New("trusted JWS key IDs must be unique")
		}
		seenKeyIDs[key.ID] = struct{}{}
	}
	return nil
}

func (c Config) browserProviderConfig() BrowserProviderConfig {
	var browser *BrowserConfig
	if c.Browser != nil {
		browserCopy := *c.Browser
		browserCopy.AllowedHosts = append([]string(nil), c.Browser.AllowedHosts...)
		browser = &browserCopy
	}
	return BrowserProviderConfig{
		ProviderAddress: c.ProviderAddress, ProviderCertificateFile: c.ProviderCertificateFile,
		ProviderPrivateKeyFile: c.ProviderPrivateKeyFile, ClientCAFile: c.ClientCAFile,
		AllowedClientURIs:  append([]string(nil), c.AllowedClientURIs...),
		TrustedJWSKeys:     append([]TrustedJWSKey(nil), c.TrustedJWSKeys...),
		ProviderRevisionID: c.ProviderRevisionID, StateRoot: c.StateRoot,
		RuntimeDataRoot: c.RuntimeDataRoot, RuntimeImage: c.RuntimeImage,
		RuntimeControllerID: c.RuntimeControllerID, Browser: browser,
	}
}

func (c BrowserConfig) validate() error {
	for name, value := range map[string]string{
		"gateway_image": c.GatewayImage, "uplink_network": c.UplinkNetwork, "namespace": c.Namespace,
		"runtime_architecture": c.RuntimeArchitecture,
		"manifest_path":        c.ManifestPath, "seccomp_path": c.SeccompPath,
		"provenance_executable_path":   c.ProvenanceExecutablePath,
		"provenance_executable_digest": c.ProvenanceExecutableDigest,
		"network_policy_reference":     c.NetworkPolicyReference,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("browser.%s is required", name)
		}
	}
	if c.RuntimeArchitecture != "amd64" && c.RuntimeArchitecture != "arm64" {
		return errors.New("Browser runtime architecture must be amd64 or arm64")
	}
	if !filepath.IsAbs(c.ManifestPath) || !filepath.IsAbs(c.SeccompPath) || !filepath.IsAbs(c.ProvenanceExecutablePath) {
		return errors.New("Browser manifest, seccomp, and provenance executable paths must be absolute")
	}
	if len(c.AllowedHosts) != 1 || c.AllowedHosts[0] != "example.com" {
		return errors.New("Browser reference policy must allow only example.com")
	}
	return nil
}
