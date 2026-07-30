package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

const (
	defaultProviderMaxCPUMillis             int64 = 1000
	defaultProviderMaxMemoryBytes           int64 = 512 << 20
	defaultProviderMaxEphemeralStorageBytes int64 = 64 << 20
	defaultProviderMaxLeaseSeconds          int64 = 3600
	defaultProviderMaxExecSeconds           int64 = 30
)

type ProviderLimitsConfig struct {
	MaxCPUMillis             int64 `mapstructure:"max_cpu_millis"`
	MaxMemoryBytes           int64 `mapstructure:"max_memory_bytes"`
	MaxEphemeralStorageBytes int64 `mapstructure:"max_ephemeral_storage_bytes"`
	MaxLeaseSeconds          int64 `mapstructure:"max_lease_seconds"`
	MaxExecSeconds           int64 `mapstructure:"max_exec_seconds"`
}

// ProviderConfig contains application-owned immutable discovery values. TLS
// listener and caller identity policy remain under server.provider.
type ProviderConfig struct {
	RevisionID string               `mapstructure:"revision_id"`
	Limits     ProviderLimitsConfig `mapstructure:"limits"`
}

func (c *ProviderConfig) validate() error {
	if c.RevisionID != "" && (strings.TrimSpace(c.RevisionID) != c.RevisionID || len(c.RevisionID) > 200) {
		return errors.New("provider.revision_id must be at most 200 bytes without surrounding whitespace")
	}
	if c.Limits.MaxCPUMillis <= 0 || c.Limits.MaxMemoryBytes <= 0 || c.Limits.MaxEphemeralStorageBytes <= 0 || c.Limits.MaxLeaseSeconds <= 0 || c.Limits.MaxExecSeconds <= 0 {
		return errors.New("provider limits must be greater than zero")
	}
	return nil
}

func (c *ProviderConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "provider", defaultProviderConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "provider", err)
	}
	var wrap struct {
		Provider ProviderConfig `mapstructure:"provider"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "provider", err)
	}
	*c = wrap.Provider
	return c.validate()
}

func defaultProviderConfig() *ProviderConfig {
	return &ProviderConfig{Limits: ProviderLimitsConfig{
		MaxCPUMillis:             defaultProviderMaxCPUMillis,
		MaxMemoryBytes:           defaultProviderMaxMemoryBytes,
		MaxEphemeralStorageBytes: defaultProviderMaxEphemeralStorageBytes,
		MaxLeaseSeconds:          defaultProviderMaxLeaseSeconds,
		MaxExecSeconds:           defaultProviderMaxExecSeconds,
	}}
}

var Provider = defaultProviderConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		c := &ProviderConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Provider = c; return nil }, nil
	})
}
