package main

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestVaultMTLSBootstrapCategoryIsFiniteAndUnavailable(t *testing.T) {
	for _, test := range []struct{ message, category string }{
		{"invalid live TLS client authority", "authority"},
		{"live TLS signer is unavailable", "signer-unavailable"},
		{"live TLS leaf is invalid", "leaf"},
		{"live TLS issuer is not pinned", "issuer"},
		{"live TLS signer challenge failed", "signer-challenge"},
		{"private/path/token", "other"},
	} {
		err := vaultMTLSBootstrapUnavailable(vaultMTLSBootstrapCategory(errors.New(test.message)), 1200*time.Millisecond)
		if !errors.Is(err, secretref.ErrUnavailable) ||
			err.Error() != "vault-mtls-signer-bootstrap-"+test.category+": bootstrap_ms=1200: "+secretref.ErrUnavailable.Error() {
			t.Fatalf("unsafe fixed bootstrap category for %q: %v", test.category, err)
		}
	}
}
