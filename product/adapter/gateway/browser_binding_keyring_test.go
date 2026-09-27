package productgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type browserKeySource struct {
	version string
	role    secretref.Role
	bytes   []byte
	calls   int
	err     error
}

func (s *browserKeySource) Resolve(_ context.Context, id string, purpose secretref.Purpose, tenant string) (secretref.SecretMaterial, error) {
	s.calls++
	if s.err != nil {
		return secretref.SecretMaterial{}, s.err
	}
	if id != "browser-key-v2" || purpose != secretref.PurposeBrowserTenantBindingKey || tenant != secretref.SystemTenant {
		return secretref.SecretMaterial{}, errors.New("unexpected key selector")
	}
	sum := sha256.Sum256(s.bytes)
	now := time.Now().UTC()
	return secretref.SecretMaterial{Binding: secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/browser/key", Version: s.version, Purpose: purpose, TenantID: tenant, Role: s.role},
		Bytes: s.bytes, Digest: fmt.Sprintf("sha256:%x", sum[:]), Revision: "revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive}}, nil
}

func TestBrowserBindingKeyringRequiresExactCommittedVersionAndWipesMaterial(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	source := &browserKeySource{version: "v2", role: secretref.RoleGateway, bytes: append([]byte(nil), key...)}
	versions := map[string]string{"v2": "browser-key-v2"}
	keyring, err := NewBrowserBindingKeyring(source, versions)
	if err != nil {
		t.Fatal(err)
	}
	versions["v2"] = "changed-after-construction"
	got, err := keyring.Derive(context.Background(), "v2", browserBindingFixture())
	if err != nil || got != "hmac-sha256:v2:55c4fb034159f2adbe6afc3cf8d81b1183fd46843c50ae5bcb8473939848cb58" {
		t.Fatalf("exact version derivation = %q, %v", got, err)
	}
	if !bytes.Equal(source.bytes, make([]byte, 32)) {
		t.Fatal("resolved key material was not destroyed")
	}
	if got, err := keyring.Derive(context.Background(), "v3", browserBindingFixture()); err == nil || got != "" || source.calls != 1 {
		t.Fatalf("missing committed version used a fallback key: %q, %v, calls=%d", got, err, source.calls)
	}
	source.bytes = bytes.Repeat([]byte{0x42}, 32)
	source.version = "v3"
	if got, err := keyring.Derive(context.Background(), "v2", browserBindingFixture()); err == nil || got != "" {
		t.Fatalf("substituted material version = %q, %v", got, err)
	}
	if !bytes.Equal(source.bytes, make([]byte, 32)) {
		t.Fatal("substituted key material was not destroyed")
	}
}

func TestBrowserBindingKeyringRejectsAmbiguousConfigurationAndKeyLoss(t *testing.T) {
	source := &browserKeySource{version: "v2", role: secretref.RoleGateway, bytes: bytes.Repeat([]byte{0x42}, 32)}
	for _, versions := range []map[string]string{nil, {}, {"V2": "browser-key-v2"}, {"v2": "bad/id"}, {"v1": "same", "v2": "same"}} {
		if _, err := NewBrowserBindingKeyring(source, versions); err == nil {
			t.Fatalf("ambiguous key selection accepted: %#v", versions)
		}
	}
	keyring, err := NewBrowserBindingKeyring(source, map[string]string{"v2": "browser-key-v2"})
	if err != nil {
		t.Fatal(err)
	}
	source.err = secretref.ErrUnavailable
	if got, err := keyring.Derive(context.Background(), "v2", browserBindingFixture()); err == nil || got != "" {
		t.Fatalf("key loss used a fallback: %q, %v", got, err)
	}
}
