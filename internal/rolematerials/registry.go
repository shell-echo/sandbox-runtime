// Package rolematerials constructs one isolated role-owned material registry.
// It is shared implementation only: every call creates a distinct workload
// agent client, cache, binding map, and lifetime.
package rolematerials

import (
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

func New(materials config.RoleMaterialsConfig, role secretref.Role, allowedPurposes []secretref.Purpose, cache bool, now func() time.Time) (*secretref.Registry, error) {
	if now == nil || now().IsZero() {
		return nil, errors.New("invalid role material clock")
	}
	bindings, err := materials.DecodeBindings(role)
	if err != nil || materials.Provider.Type != config.UnixWorkloadMaterialProviderV1 {
		return nil, errors.New("invalid role material registry configuration")
	}
	provider, err := workloadagent.NewProduction(workloadagent.Config{
		SocketPath:       materials.Provider.SocketPath,
		ExpectedUID:      uint32(materials.Provider.ExpectedUID),
		ExpectedGID:      uint32(materials.Provider.ExpectedGID),
		Role:             role,
		OperationTimeout: time.Duration(materials.Provider.OperationTimeoutSeconds) * time.Second,
		Now:              now,
	})
	if err != nil {
		return nil, errors.New("workload material agent is unavailable")
	}
	var registeredProvider secretref.SecretProvider = provider
	var cached *secretref.CachedSecretProvider
	if cache {
		cached, err = secretref.NewCachedSecretProvider(provider, time.Duration(materials.Provider.CacheSeconds)*time.Second, len(bindings), now)
		if err != nil {
			return nil, errors.New("construct role material cache")
		}
		registeredProvider = cached
	}
	registrations := make([]secretref.BindingRegistration, 0, len(materials.Bindings))
	for _, configured := range materials.Bindings {
		binding, ok := bindings[configured.ID]
		if !ok {
			if cached != nil {
				cached.Close()
			}
			return nil, errors.New("construct role material registry")
		}
		registrations = append(registrations, secretref.BindingRegistration{ID: configured.ID, Provider: configured.Provider, Binding: binding})
	}
	registry, err := secretref.NewRegistry(role, allowedPurposes,
		[]secretref.ProviderRegistration{{Name: materials.Provider.Alias, Provider: registeredProvider}}, registrations, now)
	if err != nil {
		if cached != nil {
			cached.Close()
		}
		return nil, errors.New("construct role material registry")
	}
	return registry, nil
}
