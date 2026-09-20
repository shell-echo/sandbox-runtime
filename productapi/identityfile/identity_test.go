package identityfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const testToken = "product-identity-file-token-000001"

func TestLoadStrictIdentityBindings(t *testing.T) {
	path := writeIdentityFile(t, `{"version":"sandbox-runtime-product-static-identities-v1","bindings":[{"token":"product-identity-file-token-000001","tenant_id":"tenant-1","actor_type":"human","actor_id":"actor-1","role":"owner"}]}`)
	authenticator, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	principal, err := authenticator.Authenticate(context.Background(), testToken)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if principal.TenantID != "tenant-1" || principal.Actor != (product.ActorRef{Type: product.ActorHuman, ID: "actor-1"}) || principal.Role != productapi.RoleOwner {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestLoadRejectsUnknownDuplicateAndUnsafeBindings(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":   `{"version":"sandbox-runtime-product-static-identities-v1","bindings":[],"extra":true}`,
		"version":   `{"version":"other","bindings":[]}`,
		"duplicate": `{"version":"sandbox-runtime-product-static-identities-v1","bindings":[{"token":"product-identity-file-token-000001","tenant_id":"tenant-1","actor_type":"human","actor_id":"actor-1","role":"owner"},{"token":"product-identity-file-token-000001","tenant_id":"tenant-2","actor_type":"human","actor_id":"actor-2","role":"owner"}]}`,
		"multiple":  `{"version":"sandbox-runtime-product-static-identities-v1","bindings":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeIdentityFile(t, body)); err == nil {
				t.Fatal("invalid identity document was accepted")
			}
		})
	}
	path := writeIdentityFile(t, `{"version":"sandbox-runtime-product-static-identities-v1","bindings":[{"token":"product-identity-file-token-000001","tenant_id":"tenant-1","actor_type":"human","actor_id":"actor-1","role":"owner"}]}`)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("public identity file was accepted")
	}
}

func writeIdentityFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identities.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
