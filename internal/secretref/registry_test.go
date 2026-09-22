package secretref

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type registryProvider struct {
	material SecretMaterial
	err      error
	calls    int
}

func (p *registryProvider) ResolveSecret(_ context.Context, binding Binding) (SecretMaterial, error) {
	p.calls++
	if p.err != nil {
		return SecretMaterial{}, p.err
	}
	material := p.material
	material.Binding = binding
	material.Bytes = append([]byte(nil), p.material.Bytes...)
	return material, nil
}

func registryBinding(purpose Purpose, role Role, tenant, name string) Binding {
	return Binding{
		Schema: BindingSchema, Kind: KindSecret,
		Reference: Reference("secret://vault/" + name), Version: "v1",
		Purpose: purpose, TenantID: tenant, Role: role,
	}
}

func registryMaterial(binding Binding, now time.Time, value []byte) SecretMaterial {
	digest := sha256.Sum256(value)
	return SecretMaterial{
		Binding: binding, Bytes: append([]byte(nil), value...),
		Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
		Window: RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive},
	}
}

func TestRegistryResolvesOnlyExactRolePurposeAndTenant(t *testing.T) {
	now := time.Date(2026, 9, 22, 5, 0, 0, 0, time.UTC)
	binding := registryBinding(PurposeTLSPrivateKey, RoleProduct, SystemTenant, "product-tls-key")
	provider := &registryProvider{material: registryMaterial(binding, now, []byte("private material"))}
	registry, err := NewRegistry(RoleProduct, []Purpose{PurposeTLSPrivateKey},
		[]ProviderRegistration{{Name: "vault-primary", Provider: provider}},
		[]BindingRegistration{{ID: "product-tls-key", Provider: "vault-primary", Binding: binding}},
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	material, err := registry.Resolve(context.Background(), "product-tls-key", PurposeTLSPrivateKey, SystemTenant)
	if err != nil || string(material.Bytes) != "private material" || provider.calls != 1 {
		t.Fatalf("Resolve() = %#v, %v, calls=%d", material, err, provider.calls)
	}
	material.Destroy()
	for name, resolve := range map[string]func() error{
		"binding id": func() error {
			_, err := registry.Resolve(context.Background(), "other", PurposeTLSPrivateKey, SystemTenant)
			return err
		},
		"purpose": func() error {
			_, err := registry.Resolve(context.Background(), "product-tls-key", PurposeTLSCertificate, SystemTenant)
			return err
		},
		"tenant": func() error {
			_, err := registry.Resolve(context.Background(), "product-tls-key", PurposeTLSPrivateKey, "tenant-a")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := resolve(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Resolve() error = %v", err)
			}
		})
	}
	if provider.calls != 1 {
		t.Fatalf("mismatched resolution reached provider %d times", provider.calls)
	}
}

func TestRegistryRejectsCrossRoleDisallowedAndAmbiguousConfiguration(t *testing.T) {
	now := time.Date(2026, 9, 22, 5, 0, 0, 0, time.UTC)
	provider := &registryProvider{}
	valid := registryBinding(PurposeTLSCertificate, RoleProduct, SystemTenant, "product-tls-cert")
	baseProviders := []ProviderRegistration{{Name: "vault-primary", Provider: provider}}
	baseBindings := []BindingRegistration{{ID: "product-tls-cert", Provider: "vault-primary", Binding: valid}}
	tests := map[string]func() ([]ProviderRegistration, []BindingRegistration, []Purpose){
		"cross role": func() ([]ProviderRegistration, []BindingRegistration, []Purpose) {
			bindings := append([]BindingRegistration(nil), baseBindings...)
			bindings[0].Binding.Role = RoleProvider
			return baseProviders, bindings, []Purpose{PurposeTLSCertificate}
		},
		"disallowed purpose": func() ([]ProviderRegistration, []BindingRegistration, []Purpose) {
			return baseProviders, baseBindings, []Purpose{PurposeTLSPrivateKey}
		},
		"unknown provider": func() ([]ProviderRegistration, []BindingRegistration, []Purpose) {
			bindings := append([]BindingRegistration(nil), baseBindings...)
			bindings[0].Provider = "missing"
			return baseProviders, bindings, []Purpose{PurposeTLSCertificate}
		},
		"duplicate provider": func() ([]ProviderRegistration, []BindingRegistration, []Purpose) {
			return append(baseProviders, baseProviders[0]), baseBindings, []Purpose{PurposeTLSCertificate}
		},
		"duplicate binding": func() ([]ProviderRegistration, []BindingRegistration, []Purpose) {
			return baseProviders, append(baseBindings, baseBindings[0]), []Purpose{PurposeTLSCertificate}
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			providers, bindings, purposes := build()
			if _, err := NewRegistry(RoleProduct, purposes, providers, bindings, func() time.Time { return now }); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("NewRegistry() error = %v", err)
			}
		})
	}
}

func TestRegistryPreservesCancellationAndRejectsInvalidMaterial(t *testing.T) {
	now := time.Date(2026, 9, 22, 5, 0, 0, 0, time.UTC)
	binding := registryBinding(PurposeTLSCertificate, RoleProduct, SystemTenant, "product-tls-cert")
	provider := &registryProvider{material: registryMaterial(binding, now, []byte("certificate"))}
	registry, err := NewRegistry(RoleProduct, []Purpose{PurposeTLSCertificate},
		[]ProviderRegistration{{Name: "vault-primary", Provider: provider}},
		[]BindingRegistration{{ID: "product-tls-cert", Provider: "vault-primary", Binding: binding}},
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Resolve(ctx, "product-tls-cert", PurposeTLSCertificate, SystemTenant); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Resolve() error = %v", err)
	}
	provider.material.Digest = "sha256:" + string(make([]byte, 64))
	if _, err := registry.Resolve(context.Background(), "product-tls-cert", PurposeTLSCertificate, SystemTenant); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid material error = %v", err)
	}
}
