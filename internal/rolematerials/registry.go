// Package rolematerials constructs one isolated role-owned material registry.
// It is shared implementation only: every call creates a distinct workload
// agent client, cache, binding map, and lifetime.
package rolematerials

import (
	"errors"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

func New(materials config.RoleMaterialsConfig, role secretref.Role, allowedPurposes []secretref.Purpose, cache bool, now func() time.Time) (*secretref.Registry, error) {
	return NewForDeployment(materials, "", role, allowedPurposes, cache, now)
}

// NewForDeployment makes the Gateway-family external purpose allowlist an
// explicit process identity check, not merely a shared logical Role check.
func NewForDeployment(materials config.RoleMaterialsConfig, deployment string, role secretref.Role,
	allowedPurposes []secretref.Purpose, cache bool, now func() time.Time) (*secretref.Registry, error) {
	return newForDeployment(materials, deployment, role, allowedPurposes, cache, now, false)
}

// NewSlice6ForDeployment requires a fully admitted Profile before an owner
// can connect to its one v2 material agent. The ordinary v1 constructors do
// not silently gain cross-UID authority.
func NewSlice6ForDeployment(materials config.RoleMaterialsConfig, deployment string, profile phase6security.Profile,
	role secretref.Role, allowedPurposes []secretref.Purpose, cache bool, now func() time.Time) (*secretref.Registry, error) {
	binding, err := profile.Slice6MaterialSocketForOwner(deployment)
	if err != nil || materials.Provider.Type != config.UnixWorkloadMaterialProviderV2 ||
		materials.Provider.SocketPath != binding.SocketPath ||
		materials.Provider.ExpectedUID != int64(binding.AgentUID) ||
		materials.Provider.ExpectedGID != int64(binding.AgentGID) ||
		materials.Provider.DirectoryGID != int64(binding.OwnerGID) ||
		uint32(os.Getuid()) != binding.OwnerUID || uint32(os.Getgid()) != binding.OwnerGID ||
		materials.Provider.OperationTimeoutSeconds > binding.MaxOperationSeconds {
		return nil, errors.New("Slice 6 material owner boundary is invalid")
	}
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		return nil, errors.New("Slice 6 material access plan is invalid")
	}
	var expected *phase6security.Slice6MaterialAccess
	for index := range plan {
		if plan[index].Owner == deployment && plan[index].Agent == binding.AgentDeployment {
			expected = &plan[index]
			break
		}
	}
	configured, err := materials.DecodeBindings(role)
	if err != nil || expected == nil || expected.Role != role || len(configured) != len(expected.Bindings) ||
		len(allowedPurposes) != len(expected.Bindings) {
		return nil, errors.New("Slice 6 material binding plan is invalid")
	}
	for _, wanted := range expected.Bindings {
		matchedBinding, matchedPurpose := false, false
		for _, configuredBinding := range configured {
			if configuredBinding == wanted {
				matchedBinding = true
			}
		}
		for _, purpose := range allowedPurposes {
			if purpose == wanted.Purpose {
				matchedPurpose = true
			}
		}
		if !matchedBinding || !matchedPurpose {
			return nil, errors.New("Slice 6 material binding plan is invalid")
		}
	}
	return newForDeployment(materials, deployment, role, allowedPurposes, cache, now, true)
}

func newForDeployment(materials config.RoleMaterialsConfig, deployment string, role secretref.Role,
	allowedPurposes []secretref.Purpose, cache bool, now func() time.Time, allowV2 bool) (*secretref.Registry, error) {
	if now == nil || now().IsZero() {
		return nil, errors.New("invalid role material clock")
	}
	for _, purpose := range allowedPurposes {
		if !secretref.DeploymentPurposeAllowed(deployment, role, purpose) {
			return nil, errors.New("role material purpose does not match deployment")
		}
		if cache && (purpose == secretref.PurposeActionHistoryWitnessDSN ||
			purpose == secretref.PurposeCapacityValkeyCredentials) {
			return nil, errors.New("external database credentials require uncached material resolution")
		}
	}
	bindings, err := materials.DecodeBindings(role)
	if err != nil || (materials.Provider.Type != config.UnixWorkloadMaterialProviderV1 && !allowV2) ||
		(allowV2 && materials.Provider.Type != config.UnixWorkloadMaterialProviderV2) {
		return nil, errors.New("invalid role material registry configuration")
	}
	for _, binding := range bindings {
		if !secretref.DeploymentPurposeAllowed(deployment, role, binding.Purpose) {
			return nil, errors.New("role material binding does not match deployment")
		}
		if cache && (binding.Purpose == secretref.PurposeActionHistoryWitnessDSN ||
			binding.Purpose == secretref.PurposeCapacityValkeyCredentials) {
			return nil, errors.New("external database credentials require uncached material resolution")
		}
	}
	providerConfig := workloadagent.Config{
		SocketPath:       materials.Provider.SocketPath,
		ExpectedUID:      uint32(materials.Provider.ExpectedUID),
		ExpectedGID:      uint32(materials.Provider.ExpectedGID),
		Role:             role,
		OperationTimeout: time.Duration(materials.Provider.OperationTimeoutSeconds) * time.Second,
		Now:              now,
	}
	var provider *workloadagent.Client
	if allowV2 {
		provider, err = workloadagent.NewProductionV2(providerConfig, uint32(materials.Provider.DirectoryGID))
	} else {
		provider, err = workloadagent.NewProduction(providerConfig)
	}
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
