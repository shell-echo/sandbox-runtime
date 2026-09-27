package productpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/product"
)

type testBrowserKeySource struct {
	key     []byte
	version string
	lost    bool
}

func (s *testBrowserKeySource) Resolve(_ context.Context, id string, purpose secretref.Purpose, tenant string) (secretref.SecretMaterial, error) {
	if s.lost || id != "browser-key-v2" || purpose != secretref.PurposeBrowserTenantBindingKey || tenant != secretref.SystemTenant {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	now := time.Now().UTC()
	sum := sha256.Sum256(s.key)
	return secretref.SecretMaterial{Binding: secretref.Binding{Schema: secretref.BindingSchema,
		Kind: secretref.KindSecret, Reference: "secret://vault/browser/key", Version: s.version,
		Purpose: purpose, TenantID: tenant, Role: secretref.RoleProduct},
		Bytes: append([]byte(nil), s.key...), Digest: fmt.Sprintf("sha256:%x", sum[:]), Revision: "revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive}}, nil
}

func TestBrowserHandoffKeyPreparerDerivesOnlyExactSelectedVersion(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	source := &testBrowserKeySource{key: key, version: "v2"}
	config := BrowserHandoffKeySelection{CallerAuthorityScope: "product-alpha",
		ProviderInstanceAudience: "provider-browser-a", ActiveVersion: "v2",
		BindingIDsByVersion: map[string]string{"v2": "browser-key-v2"}}
	preparer, err := NewBrowserHandoffKeyPreparer(source, config)
	if err != nil {
		t.Fatal(err)
	}
	config.BindingIDsByVersion["v2"] = "changed-after-construction"
	now := time.Now().UTC()
	work := product.ProviderObservationWork{TenantID: "tenant-a", SessionID: "browser-a",
		ProviderAction: "open_browser_session", SessionKind: product.SessionKindBrowserLive,
		ProviderRevisionID: "revision-a", SandboxID: "sandbox-a"}
	evidence := product.ProviderOperationEvidence{State: "succeeded", ProviderRevisionID: work.ProviderRevisionID,
		SandboxID: work.SandboxID, HandoffReference: "ref:browser-session:" + strings.Repeat("1", 32),
		ConnectionGeneration: 7, HandoffExpiresAt: now.Add(time.Minute)}
	selected, err := preparer.PrepareBrowserHandoffBinding(context.Background(), work, evidence)
	if err != nil || selected.Validate() != nil || selected.KeyBindingID != "browser-key-v2" ||
		selected.KeyVersion != "v2" || selected.TenantBindingDigest == "" {
		t.Fatalf("prepared Browser binding = %#v, %v", selected, err)
	}
	source.lost = true
	if selected, err := preparer.PrepareBrowserHandoffBinding(context.Background(), work, evidence); err == nil || selected.TenantBindingDigest != "" {
		t.Fatalf("lost key used fallback: %#v, %v", selected, err)
	}
	source.lost = false
	source.version = "v3"
	if selected, err := preparer.PrepareBrowserHandoffBinding(context.Background(), work, evidence); err == nil || selected.TenantBindingDigest != "" {
		t.Fatalf("substituted key version = %#v, %v", selected, err)
	}
}

func TestBrowserHandoffKeyPreparerRejectsUnselectedVersion(t *testing.T) {
	source := &testBrowserKeySource{key: bytes.Repeat([]byte{0x42}, 32), version: "v2"}
	_, err := NewBrowserHandoffKeyPreparer(source, BrowserHandoffKeySelection{
		CallerAuthorityScope: "product-alpha", ProviderInstanceAudience: "provider-browser-a",
		ActiveVersion: "v3", BindingIDsByVersion: map[string]string{"v2": "browser-key-v2"}})
	if err == nil {
		t.Fatal("missing active version silently selected another key")
	}
}
