package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

// DataPlaneRole identifies one independently administered Phase 6 data-plane
// process. The role is selected by the command, never by a shared listener.
type DataPlaneRole string

const (
	DataPlaneGateway DataPlaneRole = "gateway"
	DataPlaneGuest   DataPlaneRole = "guest"
	DataPlaneBrowser DataPlaneRole = "browser"
	DataPlaneDesktop DataPlaneRole = "desktop"
)

type DataPlaneTLSConfig struct {
	CertificateFile       string   `mapstructure:"certificate_file"`
	PrivateKeyFile        string   `mapstructure:"private_key_file"`
	ClientCABundleFile    string   `mapstructure:"client_ca_bundle_file"`
	ClientCertificateFile string   `mapstructure:"client_certificate_file"`
	ClientPrivateKeyFile  string   `mapstructure:"client_private_key_file"`
	AllowedClientIdentity []string `mapstructure:"allowed_client_identities"`
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
	Enabled         bool                     `mapstructure:"enabled"`
	DeploymentLevel ProviderDeploymentLevel  `mapstructure:"deployment_level"`
	Public          option.HTTP              `mapstructure:"public"`
	Private         option.HTTP              `mapstructure:"private"`
	Probe           option.HTTP              `mapstructure:"probe"`
	TLS             DataPlaneTLSConfig       `mapstructure:"tls"`
	Authority       DataPlaneAuthorityConfig `mapstructure:"authority"`
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
		Role: role, DeploymentLevel: ProviderProductionLevel,
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
	if c.DeploymentLevel != ProviderProductionLevel {
		return fmt.Errorf("%s process requires deployment_level=production", c.Role)
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
	for _, value := range []string{c.TLS.CertificateFile, c.TLS.PrivateKeyFile, c.TLS.ClientCABundleFile, c.TLS.ClientCertificateFile, c.TLS.ClientPrivateKeyFile} {
		if value != "" {
			paths = append(paths, filepath.Clean(value))
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
		if err := validateServerTLS(c.TLS, false); err != nil {
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
		if err := validateClientTLS(c.TLS); err != nil {
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
		if err := validateServerTLS(c.TLS, true); err != nil {
			return fmt.Errorf("%s private TLS: %w", c.Role, err)
		}
	default:
		return fmt.Errorf("unknown data-plane role %q", c.Role)
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

func validateServerTLS(value DataPlaneTLSConfig, requireClient bool) error {
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

func validateClientTLS(value DataPlaneTLSConfig) error {
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
