package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

// DataPlaneRole identifies one independently administered Phase 6 data-plane
// process. The role is selected by the command, never by a shared listener.
type DataPlaneRole string

const (
	DataPlaneLegacyLocalCandidateSchema = "sandbox-runtime.data-plane-process.legacy-local-candidate.v1"
	DataPlaneProductionSchemaV2         = "sandbox-runtime.data-plane-process.v2"

	DataPlaneGateway DataPlaneRole = "gateway"
	DataPlaneGuest   DataPlaneRole = "guest"
	DataPlaneBrowser DataPlaneRole = "browser"
	DataPlaneDesktop DataPlaneRole = "desktop"
)

type DataPlaneTLSConfig struct {
	CertificateFile            string   `mapstructure:"certificate_file"`
	PrivateKeyFile             string   `mapstructure:"private_key_file"`
	ClientCABundleFile         string   `mapstructure:"client_ca_bundle_file"`
	ClientCertificateFile      string   `mapstructure:"client_certificate_file"`
	ClientPrivateKeyFile       string   `mapstructure:"client_private_key_file"`
	CertificateBindingID       string   `mapstructure:"certificate_binding_id"`
	PrivateKeyBindingID        string   `mapstructure:"private_key_binding_id"`
	ClientCABundleBindingID    string   `mapstructure:"client_ca_bundle_binding_id"`
	ClientCertificateBindingID string   `mapstructure:"client_certificate_binding_id"`
	ClientPrivateKeyBindingID  string   `mapstructure:"client_private_key_binding_id"`
	ExpectedServerName         string   `mapstructure:"expected_server_name"`
	AllowedClientIdentity      []string `mapstructure:"allowed_client_identities"`
}

type DataPlaneDrainConfig struct {
	GraceSeconds       int `mapstructure:"grace_seconds"`
	ReconnectSeconds   int `mapstructure:"reconnect_seconds"`
	DependencyTimeouts int `mapstructure:"dependency_timeout_seconds"`
}

type DataPlaneAuthorityConfig struct {
	CredentialFile  string `mapstructure:"credential_file"`
	DependencyFile  string `mapstructure:"dependency_file"`
	PolicyFile      string `mapstructure:"policy_file"`
	RecordingKeyRef string `mapstructure:"recording_key_reference"`
	ReleaseProfile  string `mapstructure:"release_profile_file"`
}

// DataPlaneProcessConfig is deliberately transport-only. Business
// authorization, Provider handoffs, Guest identity, and recording truth are
// supplied through role-specific private references and are not projected by
// the process probe.
type DataPlaneProcessConfig struct {
	SchemaVersion   string                   `mapstructure:"schema_version"`
	Enabled         bool                     `mapstructure:"enabled"`
	DeploymentLevel ProviderDeploymentLevel  `mapstructure:"deployment_level"`
	Public          option.HTTP              `mapstructure:"public"`
	Private         option.HTTP              `mapstructure:"private"`
	Probe           option.HTTP              `mapstructure:"probe"`
	TLS             DataPlaneTLSConfig       `mapstructure:"tls"`
	Authority       DataPlaneAuthorityConfig `mapstructure:"authority"`
	Materials       RoleMaterialsConfig      `mapstructure:"materials"`
	Drain           DataPlaneDrainConfig     `mapstructure:"drain"`
	OutboundURL     string                   `mapstructure:"outbound_url"`
	Role            DataPlaneRole            `mapstructure:"-"`
}

const (
	defaultDataPlaneHost    = "127.0.0.1"
	defaultGatewayPort      = 8445
	defaultGuestPort        = 0
	defaultBrowserPort      = 8446
	defaultDesktopPort      = 8447
	defaultGatewayProbePort = 8085
	defaultGuestProbePort   = 8086
	defaultBrowserProbePort = 8087
	defaultDesktopProbePort = 8088
)

func defaultDataPlaneProcess(role DataPlaneRole, port int) *DataPlaneProcessConfig {
	probePort := defaultGatewayProbePort
	switch role {
	case DataPlaneGuest:
		probePort = defaultGuestProbePort
	case DataPlaneBrowser:
		probePort = defaultBrowserProbePort
	case DataPlaneDesktop:
		probePort = defaultDesktopProbePort
	}
	return &DataPlaneProcessConfig{
		SchemaVersion: DataPlaneLegacyLocalCandidateSchema, Role: role, DeploymentLevel: ProviderLocalCandidateLevel,
		Public:  option.HTTP{Host: defaultDataPlaneHost, Port: port},
		Private: option.HTTP{Host: defaultDataPlaneHost, Port: port},
		Probe:   option.HTTP{Host: defaultDataPlaneHost, Port: probePort},
		Drain:   DataPlaneDrainConfig{GraceSeconds: 30, ReconnectSeconds: 30, DependencyTimeouts: 5},
	}
}

var (
	GatewayProcess = defaultDataPlaneProcess(DataPlaneGateway, defaultGatewayPort)
	GuestProcess   = defaultDataPlaneProcess(DataPlaneGuest, defaultGuestPort)
	BrowserProcess = defaultDataPlaneProcess(DataPlaneBrowser, defaultBrowserPort)
	DesktopProcess = defaultDataPlaneProcess(DataPlaneDesktop, defaultDesktopPort)
)

func (c *DataPlaneProcessConfig) Validate() error {
	if c == nil {
		return errors.New("data-plane process configuration is required")
	}
	if !c.Enabled {
		return nil
	}
	production := c.SchemaVersion == DataPlaneProductionSchemaV2 && c.DeploymentLevel == ProviderProductionLevel
	legacyCandidate := c.SchemaVersion == DataPlaneLegacyLocalCandidateSchema && c.DeploymentLevel == ProviderLocalCandidateLevel
	if !production && !legacyCandidate {
		return fmt.Errorf("%s process schema and deployment level are incompatible", c.Role)
	}
	if err := c.Probe.Validate(); err != nil || !exactLoopbackIP(c.Probe.Host) {
		return fmt.Errorf("%s probe must use an explicit loopback address", c.Role)
	}
	if c.Probe.Port == c.Public.Port || c.Probe.Port == c.Private.Port {
		return fmt.Errorf("%s probe port must be distinct from role listeners", c.Role)
	}
	if c.Drain.GraceSeconds < 1 || c.Drain.GraceSeconds > 600 || c.Drain.ReconnectSeconds < 1 || c.Drain.ReconnectSeconds > 600 || c.Drain.DependencyTimeouts < 1 || c.Drain.DependencyTimeouts > 60 {
		return fmt.Errorf("%s drain bounds are invalid", c.Role)
	}
	if err := validateAbsoluteSecretPath(fmt.Sprintf("%s authority credential", c.Role), c.Authority.CredentialFile); err != nil {
		return err
	}
	if err := validateAbsoluteSecretPath(fmt.Sprintf("%s authority dependency", c.Role), c.Authority.DependencyFile); err != nil {
		return err
	}
	if err := validateAbsoluteSecretPath(fmt.Sprintf("%s authority policy", c.Role), c.Authority.PolicyFile); err != nil {
		return err
	}
	if c.Authority.ReleaseProfile != "" {
		if err := validateAbsoluteSecretPath(fmt.Sprintf("%s release profile", c.Role), c.Authority.ReleaseProfile); err != nil {
			return err
		}
	}
	if c.Authority.RecordingKeyRef == "" || len(c.Authority.RecordingKeyRef) > 256 || strings.TrimSpace(c.Authority.RecordingKeyRef) != c.Authority.RecordingKeyRef || strings.ContainsAny(c.Authority.RecordingKeyRef, "\x00\r\n") {
		return fmt.Errorf("%s recording key reference is invalid", c.Role)
	}
	paths := []string{filepath.Clean(c.Authority.CredentialFile), filepath.Clean(c.Authority.DependencyFile), filepath.Clean(c.Authority.PolicyFile)}
	if c.Authority.ReleaseProfile != "" {
		paths = append(paths, filepath.Clean(c.Authority.ReleaseProfile))
	}
	if production {
		if c.TLS.CertificateFile != "" || c.TLS.PrivateKeyFile != "" || c.TLS.ClientCABundleFile != "" || c.TLS.ClientCertificateFile != "" || c.TLS.ClientPrivateKeyFile != "" {
			return fmt.Errorf("%s production TLS configuration cannot contain raw paths", c.Role)
		}
	} else {
		if !c.Materials.IsZero() || c.TLS.CertificateBindingID != "" || c.TLS.PrivateKeyBindingID != "" || c.TLS.ClientCABundleBindingID != "" || c.TLS.ClientCertificateBindingID != "" || c.TLS.ClientPrivateKeyBindingID != "" || c.TLS.ExpectedServerName != "" {
			return fmt.Errorf("%s legacy local-candidate configuration cannot contain production material bindings", c.Role)
		}
		for _, value := range []string{c.TLS.CertificateFile, c.TLS.PrivateKeyFile, c.TLS.ClientCABundleFile, c.TLS.ClientCertificateFile, c.TLS.ClientPrivateKeyFile} {
			if value != "" {
				paths = append(paths, filepath.Clean(value))
			}
		}
	}
	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			if paths[i] == paths[j] {
				return fmt.Errorf("%s authority files must be distinct", c.Role)
			}
		}
	}
	switch c.Role {
	case DataPlaneGateway:
		if err := validateListener(c.Public, false); err != nil {
			return fmt.Errorf("gateway public listener: %w", err)
		}
		if c.Private.Port != defaultGatewayPort || c.Private.Host != defaultDataPlaneHost {
			return errors.New("gateway private listener must remain disabled")
		}
		if err := c.validateServerTLS(production, false); err != nil {
			return fmt.Errorf("gateway public TLS: %w", err)
		}
		if c.OutboundURL != "" {
			return errors.New("gateway outbound_url is forbidden")
		}
	case DataPlaneGuest:
		if c.Public.Port != defaultGuestPort || c.Private.Port != defaultGuestPort {
			return errors.New("guest must not bind an inbound listener")
		}
		if err := validateOutboundURL(c.OutboundURL); err != nil {
			return fmt.Errorf("guest outbound_url: %w", err)
		}
		if err := c.validateClientTLS(production); err != nil {
			return fmt.Errorf("guest client TLS: %w", err)
		}
	case DataPlaneBrowser, DataPlaneDesktop:
		if c.OutboundURL != "" {
			return fmt.Errorf("%s outbound_url must remain disabled; executor backend belongs in private authority", c.Role)
		}
		if err := validateListener(c.Private, true); err != nil {
			return fmt.Errorf("%s private listener: %w", c.Role, err)
		}
		if c.Public.Port != c.Private.Port || c.Public.Host != c.Private.Host {
			return fmt.Errorf("%s public listener must remain disabled", c.Role)
		}
		if err := c.validateServerTLS(production, true); err != nil {
			return fmt.Errorf("%s private TLS: %w", c.Role, err)
		}
	default:
		return fmt.Errorf("unknown data-plane role %q", c.Role)
	}
	if production {
		if err := c.validateProductionMaterials(); err != nil {
			return err
		}
	}
	return nil
}

func validateListener(value option.HTTP, required bool) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if net.ParseIP(value.Host) == nil {
		return errors.New("listener host must be an explicit IP address")
	}
	if !required && value.Port == 0 {
		return errors.New("listener port must be explicit")
	}
	return nil
}

func (c *DataPlaneProcessConfig) validateServerTLS(production, requireClient bool) error {
	value := c.TLS
	if production {
		if value.CertificateBindingID == "" || value.PrivateKeyBindingID == "" || value.ExpectedServerName == "" {
			return errors.New("TLS server material bindings and expected name are required")
		}
		if requireClient {
			if value.ClientCABundleBindingID == "" || value.ClientCertificateBindingID == "" || value.ClientPrivateKeyBindingID == "" || len(value.AllowedClientIdentity) == 0 || len(value.AllowedClientIdentity) > 32 {
				return errors.New("mutual TLS material bindings and client identity allowlist are required")
			}
		} else if value.ClientCABundleBindingID != "" || value.ClientCertificateBindingID != "" || value.ClientPrivateKeyBindingID != "" || len(value.AllowedClientIdentity) != 0 {
			return errors.New("public TLS cannot configure client identity authority")
		}
		return nil
	}
	for name, path := range map[string]string{"certificate": value.CertificateFile, "private key": value.PrivateKeyFile} {
		if err := validateAbsoluteSecretPath("TLS "+name, path); err != nil {
			return err
		}
	}
	if requireClient {
		if err := validateAbsoluteSecretPath("TLS client CA", value.ClientCABundleFile); err != nil {
			return err
		}
		if len(value.AllowedClientIdentity) == 0 || len(value.AllowedClientIdentity) > 32 {
			return errors.New("TLS client identity allowlist must contain 1..32 entries")
		}
	} else if value.ClientCABundleFile != "" || value.ClientCertificateFile != "" || value.ClientPrivateKeyFile != "" || len(value.AllowedClientIdentity) != 0 {
		return errors.New("public TLS cannot configure client identity authority")
	}
	return nil
}

func (c *DataPlaneProcessConfig) validateClientTLS(production bool) error {
	value := c.TLS
	if production {
		if value.CertificateBindingID != "" || value.PrivateKeyBindingID != "" || value.ClientCABundleBindingID == "" || value.ClientCertificateBindingID == "" || value.ClientPrivateKeyBindingID == "" || value.ExpectedServerName == "" || len(value.AllowedClientIdentity) != 0 {
			return errors.New("guest requires client TLS material bindings and cannot configure a server identity")
		}
		return nil
	}
	if value.CertificateFile != "" || value.PrivateKeyFile != "" || value.ClientCABundleFile == "" || len(value.AllowedClientIdentity) != 0 {
		return errors.New("guest requires a trust bundle and cannot configure a server certificate")
	}
	for name, path := range map[string]string{"guest TLS client CA": value.ClientCABundleFile, "guest TLS client certificate": value.ClientCertificateFile, "guest TLS client key": value.ClientPrivateKeyFile} {
		if err := validateAbsoluteSecretPath(name, path); err != nil {
			return err
		}
	}
	return nil
}

func (c *DataPlaneProcessConfig) validateProductionMaterials() error {
	role, ok := dataPlaneSecretRole(c.Role)
	if !ok {
		return errors.New("data-plane material role is invalid")
	}
	bindings, err := c.Materials.DecodeBindings(role)
	if err != nil || c.Materials.Provider.CacheSeconds < 1 {
		return fmt.Errorf("%s production material registry is invalid", c.Role)
	}
	selections := []struct {
		id      string
		purpose secretref.Purpose
	}{
		{c.TLS.ClientCABundleBindingID, secretref.PurposeCABundle},
		{c.TLS.ClientCertificateBindingID, secretref.PurposeTLSCertificate},
		{c.TLS.ClientPrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
	}
	if c.Role != DataPlaneGuest {
		selections = append(selections,
			struct {
				id      string
				purpose secretref.Purpose
			}{c.TLS.CertificateBindingID, secretref.PurposeTLSCertificate},
			struct {
				id      string
				purpose secretref.Purpose
			}{c.TLS.PrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
		)
	}
	if c.Role == DataPlaneGateway {
		selections = selections[3:]
	}
	selected := make(map[string]struct{}, len(selections))
	for _, selection := range selections {
		binding, exists := bindings[selection.id]
		if selection.id == "" || !exists || binding.Purpose != selection.purpose || binding.TenantID != secretref.SystemTenant || binding.Role != role {
			return fmt.Errorf("%s production TLS material selection is invalid", c.Role)
		}
		if _, duplicate := selected[selection.id]; duplicate {
			return fmt.Errorf("%s production TLS material selections must be distinct", c.Role)
		}
		selected[selection.id] = struct{}{}
	}
	return nil
}

func dataPlaneSecretRole(role DataPlaneRole) (secretref.Role, bool) {
	switch role {
	case DataPlaneGateway:
		return secretref.RoleGateway, true
	case DataPlaneGuest:
		return secretref.RoleGuest, true
	case DataPlaneBrowser:
		return secretref.RoleBrowser, true
	case DataPlaneDesktop:
		return secretref.RoleDesktop, true
	default:
		return "", false
	}
}

func validateOutboundURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Host == "" || (parsed.Scheme != "wss" && parsed.Scheme != "https") || parsed.String() != value || strings.TrimSpace(value) != value {
		return errors.New("must be an explicit https or wss URL without credentials")
	}
	return nil
}

func registerDataPlaneProcess(section string, role DataPlaneRole, target **DataPlaneProcessConfig, port int) {
	register(func(v *viper.Viper) (commit, error) {
		defaults := defaultDataPlaneProcess(role, port)
		if err := bindEnvDefaults(v, section, defaults); err != nil {
			return nil, fmt.Errorf("bind config %q: %w", section, err)
		}
		sectionValue := v.Sub(section)
		if sectionValue == nil {
			return nil, fmt.Errorf("parse config %q: section unavailable", section)
		}
		candidate := defaultDataPlaneProcess(role, port)
		if err := sectionValue.UnmarshalExact(candidate); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", section, err)
		}
		candidate.Role = role
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		return func() error { *target = candidate; return nil }, nil
	})
}

func init() {
	registerDataPlaneProcess("gateway_process", DataPlaneGateway, &GatewayProcess, defaultGatewayPort)
	registerDataPlaneProcess("guest_process", DataPlaneGuest, &GuestProcess, defaultGuestPort)
	registerDataPlaneProcess("browser_process", DataPlaneBrowser, &BrowserProcess, defaultBrowserPort)
	registerDataPlaneProcess("desktop_process", DataPlaneDesktop, &DesktopProcess, defaultDesktopPort)
}
