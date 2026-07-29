package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

const defaultRepositoryFilePath = "data/instances.json"

// RepositoryDriver identifies the configured metadata store.
type RepositoryDriver string

const (
	RepositoryMemoryDriver RepositoryDriver = "memory"
	RepositoryFileDriver   RepositoryDriver = "file"
)

type RepositoryFileConfig struct {
	Path string `mapstructure:"path"`
}

// RepositoryConfig selects instance metadata persistence independently of the
// runtime backend.
type RepositoryConfig struct {
	Driver RepositoryDriver     `mapstructure:"driver"`
	File   RepositoryFileConfig `mapstructure:"file"`
}

func (c *RepositoryConfig) validate() error {
	switch c.Driver {
	case RepositoryMemoryDriver:
		return nil
	case RepositoryFileDriver:
		if c.File.Path == "" {
			return errors.New("repository.file.path is required")
		}
		return nil
	default:
		return fmt.Errorf("repository.driver %q invalid (%s|%s)", c.Driver, RepositoryMemoryDriver, RepositoryFileDriver)
	}
}

func (c *RepositoryConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "repository", defaultRepositoryConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "repository", err)
	}
	var wrap struct {
		Repository RepositoryConfig `mapstructure:"repository"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "repository", err)
	}
	*c = wrap.Repository
	return c.validate()
}

func defaultRepositoryConfig() *RepositoryConfig {
	return &RepositoryConfig{
		Driver: RepositoryMemoryDriver,
		File:   RepositoryFileConfig{Path: defaultRepositoryFilePath},
	}
}

var Repository = defaultRepositoryConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		c := &RepositoryConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Repository = c; return nil }, nil
	})
}
