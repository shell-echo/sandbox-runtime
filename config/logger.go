package config

import (
	"fmt"

	"github.com/shell-echo/sandbox-runtime/logger"
	"github.com/spf13/viper"
)

// Defaults for the logger section, used when the config omits values.
const (
	defaultLoggerFileName       = ""
	defaultLoggerFileMaxSize    = 100
	defaultLoggerFileMaxBackups = 7
	defaultLoggerFileMaxAge     = 30
)

// LoggerConfig is the parsed logger section. It embeds logger.Options with
// mapstructure squash so the option fields appear directly under [logger].
type LoggerConfig struct {
	logger.Options `mapstructure:",squash"`
}

// load registers the section's defaults and env bindings, unmarshals the merged
// (default < file < env) configuration over the receiver, and validates it.
func (c *LoggerConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "logger", defaultLoggerConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "logger", err)
	}

	var wrap struct {
		Logger LoggerConfig `mapstructure:"logger"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "logger", err)
	}
	*c = wrap.Logger

	return c.Validate()
}

// defaultLoggerConfig returns the built-in logger defaults.
func defaultLoggerConfig() *LoggerConfig {
	config := &LoggerConfig{
		Options: logger.Options{
			Level:     logger.InfoLevel,
			AddSource: false,
			File: logger.File{
				Name:       defaultLoggerFileName,
				MaxSize:    defaultLoggerFileMaxSize,
				MaxBackups: defaultLoggerFileMaxBackups,
				MaxAge:     defaultLoggerFileMaxAge,
				Compress:   true,
			},
		},
	}
	return config
}

// Logger is the committed logger configuration, initialised to the defaults and
// replaced by Load.
var Logger = defaultLoggerConfig()

// init registers the loader that parses the logger section and commits it.
func init() {
	register(func(v *viper.Viper) (commit, error) {
		c := &LoggerConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Logger = c; return nil }, nil
	})
}
