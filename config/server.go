package config

import (
	"fmt"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/spf13/viper"
)

// Defaults for the server section, used when the config omits values.
const (
	defaultServerAPIHost = "0.0.0.0"
	defaultServerAPIPort = 8080
)

// ServerConfig is the parsed server section. It currently exposes only the API
// listener; additional servers (worker, scheduler, ...) can be added as fields.
type ServerConfig struct {
	API option.HTTP `mapstructure:"api"`
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
	return nil
}

// defaultServerConfig returns the built-in server defaults.
func defaultServerConfig() *ServerConfig {
	return &ServerConfig{
		API: option.HTTP{
			Host: defaultServerAPIHost,
			Port: defaultServerAPIPort,
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
