package secretref

import (
	"context"
	"regexp"
	"time"
)

const (
	MaxRegistryProviders = 32
	MaxRegistryBindings  = 512
)

var registryNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// ProviderRegistration gives one role-local provider a non-secret identity.
// Registries are never shared across OS roles.
type ProviderRegistration struct {
	Name     string
	Provider SecretProvider
}

// BindingRegistration maps one role-private configuration ID to an exact
// scoped binding and provider. The ID is not a secret reference and cannot
// change any field of Binding at resolution time.
type BindingRegistration struct {
	ID       string
	Provider string
	Binding  Binding
}

// Registry is an immutable role-owned map from typed binding IDs to scoped
// providers. It stores no resolved material.
type Registry struct {
	role      Role
	allowed   map[Purpose]struct{}
	providers map[string]SecretProvider
	bindings  map[string]registeredBinding
	now       func() time.Time
}

type registeredBinding struct {
	provider SecretProvider
	binding  Binding
}

func NewRegistry(role Role, allowedPurposes []Purpose, providers []ProviderRegistration, bindings []BindingRegistration, now func() time.Time) (*Registry, error) {
	if !validScopedRole(role) || len(allowedPurposes) < 1 || len(allowedPurposes) > len(secretPurposes) ||
		len(providers) < 1 || len(providers) > MaxRegistryProviders || len(bindings) < 1 || len(bindings) > MaxRegistryBindings ||
		now == nil || now().IsZero() {
		return nil, ErrUnavailable
	}
	registry := &Registry{
		role:      role,
		allowed:   make(map[Purpose]struct{}, len(allowedPurposes)),
		providers: make(map[string]SecretProvider, len(providers)),
		bindings:  make(map[string]registeredBinding, len(bindings)),
		now:       now,
	}
	for _, purpose := range allowedPurposes {
		if _, valid := secretPurposes[purpose]; !valid {
			return nil, ErrUnavailable
		}
		if _, duplicate := registry.allowed[purpose]; duplicate {
			return nil, ErrUnavailable
		}
		registry.allowed[purpose] = struct{}{}
	}
	for _, registration := range providers {
		if !registryNamePattern.MatchString(registration.Name) || registration.Provider == nil {
			return nil, ErrUnavailable
		}
		if _, duplicate := registry.providers[registration.Name]; duplicate {
			return nil, ErrUnavailable
		}
		registry.providers[registration.Name] = registration.Provider
	}
	for _, registration := range bindings {
		if !registryNamePattern.MatchString(registration.ID) || !registryNamePattern.MatchString(registration.Provider) ||
			registration.Binding.Validate() != nil || registration.Binding.Kind != KindSecret || registration.Binding.Role != role {
			return nil, ErrUnavailable
		}
		if _, allowed := registry.allowed[registration.Binding.Purpose]; !allowed {
			return nil, ErrUnavailable
		}
		provider, ok := registry.providers[registration.Provider]
		if !ok {
			return nil, ErrUnavailable
		}
		if _, duplicate := registry.bindings[registration.ID]; duplicate {
			return nil, ErrUnavailable
		}
		registry.bindings[registration.ID] = registeredBinding{provider: provider, binding: registration.Binding}
	}
	return registry, nil
}

// Resolve returns one caller-owned material copy only when the requested
// purpose and tenant exactly match protected registry configuration.
func (r *Registry) Resolve(ctx context.Context, bindingID string, purpose Purpose, tenantID string) (SecretMaterial, error) {
	if r == nil || ctx == nil || !registryNamePattern.MatchString(bindingID) || !validScopedTenant(tenantID) {
		return SecretMaterial{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return SecretMaterial{}, err
	}
	registered, ok := r.bindings[bindingID]
	if !ok || registered.binding.Purpose != purpose || registered.binding.TenantID != tenantID || registered.binding.Role != r.role {
		return SecretMaterial{}, ErrUnavailable
	}
	material, err := registered.provider.ResolveSecret(ctx, registered.binding)
	if err != nil {
		material.Destroy()
		return SecretMaterial{}, normalizeProviderError(err)
	}
	if material.Binding != registered.binding || material.Validate(r.now()) != nil {
		material.Destroy()
		return SecretMaterial{}, ErrUnavailable
	}
	return material, nil
}

// Invalidate forwards an operator-observed rotation or revocation to the
// exact role-local provider cache. Providers without invalidation support fail
// closed; the registry never silently retains material.
func (r *Registry) Invalidate(bindingID string) error {
	if r == nil || !registryNamePattern.MatchString(bindingID) {
		return ErrInvalidReference
	}
	registered, ok := r.bindings[bindingID]
	if !ok {
		return ErrUnavailable
	}
	invalidator, ok := registered.provider.(interface{ Invalidate(Binding) error })
	if !ok {
		return ErrUnavailable
	}
	return normalizeProviderError(invalidator.Invalidate(registered.binding))
}

// Close clears every role-local provider alias when the owning process drains.
// Provider Close operations must be idempotent.
func (r *Registry) Close() {
	if r == nil {
		return
	}
	for _, provider := range r.providers {
		if closer, ok := provider.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}
