package secretref

import (
	"time"
)

const MaxEnvelopeKeyVersions = 32

// EnvelopeKeyVersion is protected role configuration for one external KMS or
// HSM key version. It is never encoded into a persisted recording handle.
type EnvelopeKeyVersion struct {
	Reference Reference
	Version   string
	KeyID     string
	Window    RotationWindow
}

// EnvelopeBindingSet is the immutable authority that reconstructs a complete
// tenant binding from protected role configuration. Persisted handles can
// select only a configured key ID/version and must match the reconstructed
// binding digest; they cannot introduce a reference.
type EnvelopeBindingSet struct {
	purpose       Purpose
	role          Role
	activeVersion string
	activeKeyID   string
	versions      map[string]EnvelopeKeyVersion
	now           func() time.Time
}

func (s *EnvelopeBindingSet) Scope() (Purpose, Role, bool) {
	if s == nil {
		return "", "", false
	}
	return s.purpose, s.role, true
}

func NewEnvelopeBindingSet(purpose Purpose, role Role, activeKeyID, activeVersion string, versions []EnvelopeKeyVersion, now func() time.Time) (*EnvelopeBindingSet, error) {
	if now == nil || len(versions) < 1 || len(versions) > MaxEnvelopeKeyVersions {
		return nil, ErrUnavailable
	}
	current := now()
	if current.IsZero() {
		return nil, ErrUnavailable
	}
	set := &EnvelopeBindingSet{
		purpose:       purpose,
		role:          role,
		activeVersion: activeVersion,
		activeKeyID:   activeKeyID,
		versions:      make(map[string]EnvelopeKeyVersion, len(versions)),
		now:           now,
	}
	for _, version := range versions {
		binding := set.binding(SystemTenant, version)
		if binding.Validate() != nil || binding.Kind != KindEnvelopeKey || version.Window.Validate(current) != nil {
			return nil, ErrUnavailable
		}
		key := envelopeVersionKey(version.KeyID, version.Version)
		if _, duplicate := set.versions[key]; duplicate {
			return nil, ErrUnavailable
		}
		set.versions[key] = version
	}
	active, ok := set.versions[envelopeVersionKey(activeKeyID, activeVersion)]
	if !ok || active.Window.State != KeyActive || current.Before(active.Window.NotBefore) || !current.Before(active.Window.NotAfter) {
		return nil, ErrUnavailable
	}
	return set, nil
}

func (s *EnvelopeBindingSet) BindingForSeal(tenantID string) (Binding, error) {
	if s == nil || s.now == nil {
		return Binding{}, ErrUnavailable
	}
	version, ok := s.versions[envelopeVersionKey(s.activeKeyID, s.activeVersion)]
	if !ok {
		return Binding{}, ErrUnavailable
	}
	now := s.now()
	if version.Window.State == KeyRevoked {
		return Binding{}, ErrRevoked
	}
	if version.Window.State != KeyActive || now.IsZero() || now.Before(version.Window.NotBefore) || !now.Before(version.Window.NotAfter) {
		return Binding{}, ErrExpired
	}
	binding := s.binding(tenantID, version)
	if binding.Validate() != nil {
		return Binding{}, ErrUnavailable
	}
	return binding, nil
}

func (s *EnvelopeBindingSet) BindingForOpen(tenantID, bindingDigest, keyID, versionID string) (Binding, error) {
	binding, version, err := s.bindingForHandle(tenantID, bindingDigest, keyID, versionID)
	if err != nil {
		return Binding{}, err
	}
	if version.Window.State == KeyRevoked {
		return Binding{}, ErrRevoked
	}
	now := s.now()
	if (version.Window.State != KeyActive && version.Window.State != KeyGrace) || now.IsZero() || now.Before(version.Window.NotBefore) || !now.Before(version.Window.NotAfter) {
		return Binding{}, ErrExpired
	}
	return binding, nil
}

// BindingForHandle authenticates persisted non-secret key metadata without
// authorizing a cryptographic operation. Cleanup uses it so revoked or expired
// ciphertext can still be deleted without reopening the key.
func (s *EnvelopeBindingSet) BindingForHandle(tenantID, bindingDigest, keyID, versionID string) (Binding, error) {
	binding, _, err := s.bindingForHandle(tenantID, bindingDigest, keyID, versionID)
	return binding, err
}

func (s *EnvelopeBindingSet) bindingForHandle(tenantID, bindingDigest, keyID, versionID string) (Binding, EnvelopeKeyVersion, error) {
	if s == nil || s.now == nil || !validSHA256Digest(bindingDigest) {
		return Binding{}, EnvelopeKeyVersion{}, ErrUnavailable
	}
	version, ok := s.versions[envelopeVersionKey(keyID, versionID)]
	if !ok {
		return Binding{}, EnvelopeKeyVersion{}, ErrUnavailable
	}
	binding := s.binding(tenantID, version)
	if binding.Validate() != nil || binding.Digest() != bindingDigest {
		return Binding{}, EnvelopeKeyVersion{}, ErrUnavailable
	}
	return binding, version, nil
}

func (s *EnvelopeBindingSet) binding(tenantID string, version EnvelopeKeyVersion) Binding {
	return Binding{
		Schema:    BindingSchema,
		Kind:      KindEnvelopeKey,
		Reference: version.Reference,
		Version:   version.Version,
		KeyID:     version.KeyID,
		Purpose:   s.purpose,
		TenantID:  tenantID,
		Role:      s.role,
	}
}

func envelopeVersionKey(keyID, version string) string {
	return keyID + "\x00" + version
}
