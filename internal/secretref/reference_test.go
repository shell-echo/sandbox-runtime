package secretref

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

type unavailableProvider struct{}

func (unavailableProvider) Resolve(context.Context, Reference) ([]byte, error) {
	return nil, ErrUnavailable
}

func TestReferenceRejectsInlineAndUnsafePaths(t *testing.T) {
	for _, value := range []string{"password", "secret://inline\n", "file://relative", "file:///tmp/../secret"} {
		if _, err := Parse(value); err == nil {
			t.Fatalf("accepted unsafe reference %q", value)
		}
	}
	if _, err := Parse("file:///run/secrets/provider-key"); err != nil {
		t.Fatal(err)
	}
}

func TestRotatingKeySetEnforcesWindowAndRevocation(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	clockNow := now
	set, err := NewRotatingKeySet(unavailableProvider{}, func() time.Time { return clockNow })
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := Parse("kms://recording/key")
	bytes := []byte(strings.Repeat("k", 32))
	digest := sha256.Sum256(bytes)
	material := KeyMaterial{Reference: ref, Version: "v1", Bytes: bytes, Digest: "sha256:" + hex.EncodeToString(digest[:])}
	if err := set.Install(material, RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive}); err != nil {
		t.Fatal(err)
	}
	resolved, err := set.Resolve(context.Background(), ref, "v1")
	if err != nil || string(resolved.Bytes) != string(bytes) {
		t.Fatalf("resolve = %v, %v", resolved.Redacted(), err)
	}
	if err := set.Revoke("v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := set.Resolve(context.Background(), ref, "v1"); err != ErrRevoked {
		t.Fatalf("revoked resolve = %v, want %v", err, ErrRevoked)
	}
}

type countingKeyProvider struct {
	calls int
	value KeyMaterial
}

func (p *countingKeyProvider) ResolveKey(context.Context, Reference, string) (KeyMaterial, error) {
	p.calls++
	return p.value, nil
}

func TestCachedKeyProviderExpiresAndInvalidatesMaterial(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	ref, err := Parse("kms://recording/key")
	if err != nil {
		t.Fatal(err)
	}
	bytes := []byte(strings.Repeat("k", 32))
	digest := sha256.Sum256(bytes)
	provider := &countingKeyProvider{value: KeyMaterial{Reference: ref, Version: "v1", Bytes: bytes, Digest: "sha256:" + hex.EncodeToString(digest[:])}}
	cache, err := NewCachedKeyProvider(provider, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ResolveKey(context.Background(), ref, "v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ResolveKey(context.Background(), ref, "v1"); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls = %d, want one cached resolution", provider.calls)
	}
	if err := cache.Invalidate(ref, "v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ResolveKey(context.Background(), ref, "v1"); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 2 {
		t.Fatalf("provider calls after invalidation = %d, want two", provider.calls)
	}
}

func TestEnvelopeBindsKeyVersionAndAssociatedData(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	ref, _ := Parse("kms://recording/key")
	bytes := []byte(strings.Repeat("k", 32))
	digest := sha256.Sum256(bytes)
	set, err := NewRotatingKeySet(unavailableProvider{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	material := KeyMaterial{Reference: ref, Version: "v1", Bytes: bytes, Digest: "sha256:" + hex.EncodeToString(digest[:])}
	if err := set.Install(material, RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: KeyActive}); err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(context.Background(), set, ref, "v1", []byte("recording"), []byte("tenant-a/segment-1"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Open(context.Background(), set, ref, envelope, []byte("tenant-a/segment-1"))
	if err != nil || string(plaintext) != "recording" {
		t.Fatalf("open = %q, %v", plaintext, err)
	}
	if _, err := Open(context.Background(), set, ref, envelope, []byte("tenant-b/segment-1")); err == nil {
		t.Fatal("accepted envelope with different associated data")
	}
	if err := set.Revoke("v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), set, ref, envelope, []byte("tenant-a/segment-1")); err != ErrRevoked {
		t.Fatalf("revoked envelope = %v, want %v", err, ErrRevoked)
	}
}
