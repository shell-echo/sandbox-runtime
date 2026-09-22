package config

import (
	"errors"
	"path/filepath"
	"regexp"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const UnixWorkloadMaterialProviderV1 = "unix-workload-material.v1"

var materialIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// RoleMaterialsConfig is the shared shape used by each independently owned
// role registry. Sharing this parser does not share a registry, provider,
// cache, socket, or resolved material between roles.
type RoleMaterialsConfig struct {
	Provider RoleMaterialProviderConfig  `mapstructure:"provider"`
	Bindings []RoleMaterialBindingConfig `mapstructure:"bindings"`
}

type RoleMaterialProviderConfig struct {
	Type                    string `mapstructure:"type"`
	Alias                   string `mapstructure:"alias"`
	SocketPath              string `mapstructure:"socket_path"`
	ExpectedUID             int64  `mapstructure:"expected_uid"`
	ExpectedGID             int64  `mapstructure:"expected_gid"`
	OperationTimeoutSeconds int    `mapstructure:"operation_timeout_seconds"`
	CacheSeconds            int    `mapstructure:"cache_seconds"`
}

type RoleMaterialBindingConfig struct {
	ID       string `mapstructure:"id"`
	Provider string `mapstructure:"provider"`
	Document string `mapstructure:"document"`
}

func (c RoleMaterialsConfig) IsZero() bool {
	return c.Provider == (RoleMaterialProviderConfig{}) && len(c.Bindings) == 0
}

// DecodeBindings validates one role-private provider and every closed binding
// document. It intentionally returns no provider implementation and resolves
// no material.
func (c RoleMaterialsConfig) DecodeBindings(role secretref.Role) (map[string]secretref.Binding, error) {
	provider := c.Provider
	if provider.Type != UnixWorkloadMaterialProviderV1 || !materialIDPattern.MatchString(provider.Alias) ||
		!filepath.IsAbs(provider.SocketPath) || filepath.Clean(provider.SocketPath) != provider.SocketPath || len(provider.SocketPath) > 100 ||
		provider.ExpectedUID < 0 || provider.ExpectedUID > (1<<32)-1 || provider.ExpectedGID < 0 || provider.ExpectedGID > (1<<32)-1 ||
		provider.OperationTimeoutSeconds < 1 || provider.OperationTimeoutSeconds > 60 || provider.CacheSeconds < 0 || provider.CacheSeconds > 60 ||
		len(c.Bindings) < 1 || len(c.Bindings) > 32 {
		return nil, errors.New("role material provider configuration is invalid")
	}
	decoded := make(map[string]secretref.Binding, len(c.Bindings))
	references := make(map[string]struct{}, len(c.Bindings))
	for _, item := range c.Bindings {
		if !materialIDPattern.MatchString(item.ID) || item.Provider != provider.Alias || len(item.Document) < 1 || len(item.Document) > 4<<10 {
			return nil, errors.New("role material binding configuration is invalid")
		}
		if _, duplicate := decoded[item.ID]; duplicate {
			return nil, errors.New("role material binding IDs must be unique")
		}
		binding, err := secretref.DecodeBinding([]byte(item.Document))
		if err != nil || binding.Role != role || binding.Kind != secretref.KindSecret {
			return nil, errors.New("role material binding is invalid")
		}
		if _, duplicate := references[binding.Reference.String()]; duplicate {
			return nil, errors.New("role material references must be distinct")
		}
		references[binding.Reference.String()] = struct{}{}
		decoded[item.ID] = binding
	}
	return decoded, nil
}
