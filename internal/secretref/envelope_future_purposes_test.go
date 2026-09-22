package secretref

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUncomposedTicketAndDataEnvelopePurposeIsolationMatrix(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	for _, purpose := range []Purpose{PurposeTicketEnvelopeKey, PurposeDataEnvelopeKey} {
		t.Run(string(purpose), func(t *testing.T) {
			v1 := EnvelopeKeyVersion{Reference: "kms://primary/future/key", Version: "v1", KeyID: "future-primary",
				Window: RotationWindow{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), State: KeyGrace}}
			v2 := EnvelopeKeyVersion{Reference: v1.Reference, Version: "v2", KeyID: v1.KeyID,
				Window: RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive}}
			set, err := NewEnvelopeBindingSet(purpose, RoleProduct, v2.KeyID, v2.Version, []EnvelopeKeyVersion{v1, v2}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			active, err := set.BindingForSeal("tenant-a")
			if err != nil || active.Purpose != purpose || active.Version != "v2" || active.TenantID != "tenant-a" {
				t.Fatalf("active binding=%#v error=%v", active, err)
			}
			grace := Binding{Schema: BindingSchema, Kind: KindEnvelopeKey, Reference: v1.Reference, Version: v1.Version, KeyID: v1.KeyID,
				Purpose: purpose, TenantID: "tenant-a", Role: RoleProduct}
			if opened, err := set.BindingForOpen("tenant-a", grace.Digest(), grace.KeyID, grace.Version); err != nil || opened != grace {
				t.Fatalf("grace binding=%#v error=%v", opened, err)
			}
			if _, err := set.BindingForOpen("tenant-b", grace.Digest(), grace.KeyID, grace.Version); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("cross-tenant error=%v", err)
			}

			backendFailureBytes := []byte("backend-sensitive-plaintext")
			source := &fakeEnvelopeProvider{
				seal: func(got Binding, plaintext, _ []byte) (OpaqueEnvelope, error) {
					return validOpaqueEnvelope(got, append([]byte(nil), plaintext...)), nil
				},
				open: func(Binding, OpaqueEnvelope, []byte) ([]byte, error) {
					return backendFailureBytes, errors.New("private KMS endpoint unavailable")
				},
			}
			provider, err := NewBoundEnvelopeKeyProvider(source)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := provider.SealEnvelope(context.Background(), active, []byte("future-consumer-key"), []byte("tenant-a/future/aad"))
			if err != nil {
				t.Fatal(err)
			}
			otherPurpose := PurposeTicketEnvelopeKey
			if purpose == otherPurpose {
				otherPurpose = PurposeDataEnvelopeKey
			}
			substituted := active
			substituted.Purpose = otherPurpose
			if _, err := provider.OpenEnvelope(context.Background(), substituted, envelope, []byte("tenant-a/future/aad")); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("cross-purpose error=%v", err)
			}
			if source.openCalls != 0 {
				t.Fatal("cross-purpose substitution reached KMS backend")
			}
			if _, err := provider.OpenEnvelope(context.Background(), active, envelope, []byte("tenant-a/future/aad")); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "endpoint") {
				t.Fatalf("KMS-loss error=%v", err)
			}
			for index, value := range backendFailureBytes {
				if value != 0 {
					t.Fatalf("KMS failure bytes[%d]=%d", index, value)
				}
			}

			revoked := v1
			revoked.Window.State = KeyRevoked
			revokedSet, err := NewEnvelopeBindingSet(purpose, RoleProduct, v2.KeyID, v2.Version, []EnvelopeKeyVersion{revoked, v2}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := revokedSet.BindingForOpen("tenant-a", grace.Digest(), grace.KeyID, grace.Version); !errors.Is(err, ErrRevoked) {
				t.Fatalf("revoked key error=%v", err)
			}
		})
	}
}
