package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/spf13/viper"
)

type Phase6DependenciesConfig struct {
	Coordination CoordinationConfig `mapstructure:"coordination"`
	ObjectStore  ObjectStoreConfig  `mapstructure:"object_store"`
	KMS          KMSConfig          `mapstructure:"kms"`
}

type CoordinationConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	EndpointRef      string `mapstructure:"endpoint_reference"`
	CAReference      string `mapstructure:"ca_reference"`
	IdentityRef      string `mapstructure:"identity_reference"`
	Namespace        string `mapstructure:"namespace"`
	OperationTimeout int    `mapstructure:"operation_timeout_seconds"`
	MaxConnections   int    `mapstructure:"max_connections"`
}

type ObjectStoreConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	EndpointRef      string `mapstructure:"endpoint_reference"`
	CAReference      string `mapstructure:"ca_reference"`
	IdentityRef      string `mapstructure:"identity_reference"`
	Bucket           string `mapstructure:"bucket"`
	Prefix           string `mapstructure:"prefix"`
	OperationTimeout int    `mapstructure:"operation_timeout_seconds"`
	MaxObjectBytes   int64  `mapstructure:"max_object_bytes"`
}

type KMSConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	EndpointRef      string `mapstructure:"endpoint_reference"`
	IdentityRef      string `mapstructure:"identity_reference"`
	KeyReference     string `mapstructure:"key_reference"`
	CacheSeconds     int    `mapstructure:"cache_seconds"`
	OperationTimeout int    `mapstructure:"operation_timeout_seconds"`
}

func defaultPhase6Dependencies() *Phase6DependenciesConfig {
	return &Phase6DependenciesConfig{
		Coordination: CoordinationConfig{OperationTimeout: 3, MaxConnections: 16},
		ObjectStore:  ObjectStoreConfig{OperationTimeout: 10, MaxObjectBytes: 1 << 30},
		KMS:          KMSConfig{CacheSeconds: 30, OperationTimeout: 5},
	}
}

var Phase6Dependencies = defaultPhase6Dependencies()

func (c *Phase6DependenciesConfig) Validate() error {
	if c == nil {
		return errors.New("phase6 dependencies configuration is required")
	}
	if err := c.Coordination.validate(); err != nil {
		return fmt.Errorf("phase6 coordination: %w", err)
	}
	if err := c.ObjectStore.validate(); err != nil {
		return fmt.Errorf("phase6 object store: %w", err)
	}
	if err := c.KMS.validate(); err != nil {
		return fmt.Errorf("phase6 KMS: %w", err)
	}
	return nil
}

func (c CoordinationConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.OperationTimeout < 1 || c.OperationTimeout > 60 || c.MaxConnections < 1 || c.MaxConnections > 256 {
		return errors.New("connection bounds are invalid")
	}
	return validateReferences(c.EndpointRef, c.CAReference, c.IdentityRef)
}

func (c ObjectStoreConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.OperationTimeout < 1 || c.OperationTimeout > 120 || c.MaxObjectBytes < 1 || c.MaxObjectBytes > 1<<40 || !validStorageName(c.Bucket) || !validStoragePrefix(c.Prefix) {
		return errors.New("object-store bounds or names are invalid")
	}
	return validateReferences(c.EndpointRef, c.CAReference, c.IdentityRef)
}

func (c KMSConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	if c.CacheSeconds < 0 || c.CacheSeconds > 3600 || c.OperationTimeout < 1 || c.OperationTimeout > 60 {
		return errors.New("KMS bounds are invalid")
	}
	if err := validateReferences(c.EndpointRef, c.IdentityRef, c.KeyReference); err != nil {
		return err
	}
	if !strings.HasPrefix(c.KeyReference, "kms://") {
		return errors.New("KMS key_reference must use kms://")
	}
	return nil
}

func validateReferences(values ...string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		reference, err := secretref.Parse(value)
		if err != nil || strings.HasPrefix(reference.String(), "file://") {
			return errors.New("dependency references must be secret:// or kms://")
		}
		if _, exists := seen[reference.String()]; exists {
			return errors.New("dependency references must be distinct")
		}
		seen[reference.String()] = struct{}{}
	}
	return nil
}

func validStorageName(value string) bool {
	return len(value) > 2 && len(value) <= 63 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "/\\\x00\r\n")
}

func validStoragePrefix(value string) bool {
	return len(value) <= 256 && filepath.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\\\x00\r\n")
}

func init() {
	register(func(v *viper.Viper) (commit, error) {
		defaults := defaultPhase6Dependencies()
		if err := bindEnvDefaults(v, "phase6_dependencies", defaults); err != nil {
			return nil, fmt.Errorf("bind config %q: %w", "phase6_dependencies", err)
		}
		section := v.Sub("phase6_dependencies")
		if section == nil {
			return nil, errors.New("parse config \"phase6_dependencies\": section unavailable")
		}
		candidate := defaultPhase6Dependencies()
		if err := section.UnmarshalExact(candidate); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", "phase6_dependencies", err)
		}
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		return func() error { Phase6Dependencies = candidate; return nil }, nil
	})
}
