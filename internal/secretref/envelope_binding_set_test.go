package secretref

import (
	"errors"
	"testing"
	"time"
)

func TestEnvelopeBindingSetSelectsActiveAndOpensGrace(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	versions := []EnvelopeKeyVersion{
		{
			Reference: "kms://primary/recording/key-v1",
			Version:   "v1",
			KeyID:     "recording-key",
			Window:    RotationWindow{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), State: KeyGrace},
		},
		{
			Reference: "kms://primary/recording/key-v2",
			Version:   "v2",
			KeyID:     "recording-key",
			Window:    RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), State: KeyActive},
		},
	}
	set, err := NewEnvelopeBindingSet(PurposeRecordingEnvelopeKey, RoleProduct, "recording-key", "v2", versions, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	active, err := set.BindingForSeal("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if active.Version != "v2" || active.Reference != versions[1].Reference || active.TenantID != "tenant-a" {
		t.Fatalf("active binding = %#v", active)
	}
	grace := set.binding("tenant-a", versions[0])
	opened, err := set.BindingForOpen("tenant-a", grace.Digest(), grace.KeyID, grace.Version)
	if err != nil || opened != grace {
		t.Fatalf("grace binding = %#v, %v", opened, err)
	}
	if _, err := set.BindingForOpen("tenant-b", grace.Digest(), grace.KeyID, grace.Version); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-tenant open error = %v", err)
	}
	if _, err := set.BindingForOpen("tenant-a", active.Digest(), active.KeyID, "v3"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown version error = %v", err)
	}
}

func TestEnvelopeBindingSetRejectsRevokedExpiredAndUnsafeConfiguration(t *testing.T) {
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	active := EnvelopeKeyVersion{
		Reference: "kms://primary/recording/key-v2",
		Version:   "v2",
		KeyID:     "recording-key",
		Window:    RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive},
	}
	revoked := EnvelopeKeyVersion{
		Reference: "kms://primary/recording/key-v1",
		Version:   "v1",
		KeyID:     "recording-key",
		Window:    RotationWindow{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), State: KeyRevoked},
	}
	set, err := NewEnvelopeBindingSet(PurposeRecordingEnvelopeKey, RoleProduct, active.KeyID, active.Version, []EnvelopeKeyVersion{revoked, active}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	revokedBinding := set.binding("tenant-a", revoked)
	if binding, err := set.BindingForHandle("tenant-a", revokedBinding.Digest(), revoked.KeyID, revoked.Version); err != nil || binding != revokedBinding {
		t.Fatalf("revoked cleanup binding = %#v, %v", binding, err)
	}
	if _, err := set.BindingForOpen("tenant-a", revokedBinding.Digest(), revoked.KeyID, revoked.Version); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked error = %v", err)
	}
	now = active.Window.NotAfter
	if _, err := set.BindingForSeal("tenant-a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired seal error = %v", err)
	}
	if _, err := set.BindingForOpen("tenant-a", active.DigestForTest("tenant-a", PurposeRecordingEnvelopeKey, RoleProduct), active.KeyID, active.Version); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired open error = %v", err)
	}

	invalid := []struct {
		name      string
		purpose   Purpose
		role      Role
		activeID  string
		activeVer string
		versions  []EnvelopeKeyVersion
	}{
		{name: "secret purpose", purpose: PurposeTLSPrivateKey, role: RoleProduct, activeID: active.KeyID, activeVer: active.Version, versions: []EnvelopeKeyVersion{active}},
		{name: "unknown role", purpose: PurposeRecordingEnvelopeKey, role: "scheduler", activeID: active.KeyID, activeVer: active.Version, versions: []EnvelopeKeyVersion{active}},
		{name: "missing active", purpose: PurposeRecordingEnvelopeKey, role: RoleProduct, activeID: active.KeyID, activeVer: "v9", versions: []EnvelopeKeyVersion{active}},
		{name: "duplicate", purpose: PurposeRecordingEnvelopeKey, role: RoleProduct, activeID: active.KeyID, activeVer: active.Version, versions: []EnvelopeKeyVersion{active, active}},
		{name: "active grace", purpose: PurposeRecordingEnvelopeKey, role: RoleProduct, activeID: revoked.KeyID, activeVer: revoked.Version, versions: []EnvelopeKeyVersion{revoked}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewEnvelopeBindingSet(test.purpose, test.role, test.activeID, test.activeVer, test.versions, func() time.Time { return time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC) }); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("NewEnvelopeBindingSet() error = %v", err)
			}
		})
	}
}

func (v EnvelopeKeyVersion) DigestForTest(tenantID string, purpose Purpose, role Role) string {
	return Binding{
		Schema: BindingSchema, Kind: KindEnvelopeKey, Reference: v.Reference,
		Version: v.Version, KeyID: v.KeyID, Purpose: purpose, TenantID: tenantID, Role: role,
	}.Digest()
}
