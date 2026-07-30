package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

// Defaults for the server section, used when the config omits values.
const (
	defaultServerAPIHost      = "127.0.0.1"
	defaultServerAPIPort      = 8080
	defaultServerProviderHost = "127.0.0.1"
	defaultServerProviderPort = 8443
)

type ProviderTLSConfig struct {
	CertificateFile        string   `mapstructure:"certificate_file"`
	PrivateKeyFile         string   `mapstructure:"private_key_file"`
	ClientCAFile           string   `mapstructure:"client_ca_file"`
	AllowedClientSPIFFEIDs []string `mapstructure:"allowed_client_spiffe_ids"`
}

type ProviderServerConfig struct {
	Enabled bool              `mapstructure:"enabled"`
	Host    string            `mapstructure:"host"`
	Port    int               `mapstructure:"port"`
	TLS     ProviderTLSConfig `mapstructure:"tls"`
}

func (c ProviderServerConfig) HTTP() option.HTTP {
	return option.HTTP{Host: c.Host, Port: c.Port}
}

func (c *ProviderServerConfig) validate() error {
	httpConfig := c.HTTP()
	if err := httpConfig.Validate(); err != nil {
		return err
	}
	if !c.Enabled {
		return nil
	}
	if c.TLS.CertificateFile == "" || c.TLS.PrivateKeyFile == "" || c.TLS.ClientCAFile == "" {
		return errors.New("TLS certificate, private key, and client CA files are required when the Provider listener is enabled")
	}
	if len(c.TLS.AllowedClientSPIFFEIDs) == 0 {
		return errors.New("at least one allowed client SPIFFE ID is required when the Provider listener is enabled")
	}
	if len(c.TLS.AllowedClientSPIFFEIDs) > 64 {
		return errors.New("at most 64 allowed client SPIFFE IDs are supported")
	}
	for _, identity := range c.TLS.AllowedClientSPIFFEIDs {
		if identity == "" || len(identity) > 500 || strings.TrimSpace(identity) != identity {
			return errors.New("allowed client SPIFFE IDs must be between 1 and 500 bytes without surrounding whitespace")
		}
	}
	return nil
}

// ServerConfig keeps the unauthenticated local management API separate from the
// opt-in, mTLS-only Provider listener.
type ServerConfig struct {
	API      option.HTTP          `mapstructure:"api"`
	Provider ProviderServerConfig `mapstructure:"provider"`
}

// load registers the section's defaults and env bindings, unmarshals the merged
// (default < file < env) configuration over the receiver, and validates it.
func (c *ServerConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "server", defaultServerConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "server", err)
	}

	var wrap struct {
		Server ServerConfig `mapstructure:"server"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "server", err)
	}
	*c = wrap.Server

	if err := c.API.Validate(); err != nil {
		return fmt.Errorf("server.api %w", err)
	}
	if err := c.Provider.validate(); err != nil {
		return fmt.Errorf("server.provider %w", err)
	}
	return nil
}

// defaultServerConfig returns the built-in server defaults.
func defaultServerConfig() *ServerConfig {
	return &ServerConfig{
		API: option.HTTP{
			Host: defaultServerAPIHost,
			Port: defaultServerAPIPort,
		},
		Provider: ProviderServerConfig{
			Host: defaultServerProviderHost,
			Port: defaultServerProviderPort,
		},
	}
}

// Server is the committed server configuration, initialised to the defaults and
// replaced by Load.
var Server = defaultServerConfig()

// init registers the loader that parses the server section and commits it.
func init() {
	register(func(v *viper.Viper) (commit, error) {
		c := &ServerConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Server = c; return nil }, nil
	})
}
