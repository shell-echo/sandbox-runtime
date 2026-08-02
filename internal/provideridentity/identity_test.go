package provideridentity

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateAllowlistBoundaries(t *testing.T) {
	identities := make([]string, MaxAllowedIdentities)
	for index := range identities {
		identities[index] = fmt.Sprintf("spiffe://agent-platform/client-%d", index)
	}
	if err := ValidateAllowlist(identities); err != nil {
		t.Fatalf("maximum allowlist rejected: %v", err)
	}
	if err := ValidateAllowlist(nil); err == nil {
		t.Fatal("empty allowlist accepted")
	}
	identities = append(identities, "spiffe://agent-platform/overflow")
	if err := ValidateAllowlist(identities); err == nil {
		t.Fatal("oversized allowlist accepted")
	}
	if err := ValidateAllowlist([]string{"urn:client:1", "urn:client:1"}); err == nil {
		t.Fatal("duplicate allowlist entry accepted")
	}
}

func TestValidateExactAbsoluteURIBoundaries(t *testing.T) {
	prefix := "urn:client:"
	exact := prefix + strings.Repeat("a", MaxIdentityBytes-len(prefix))
	if err := ValidateExactAbsoluteURI(exact); err != nil {
		t.Fatalf("maximum identity rejected: %v", err)
	}
	tests := []string{
		"",
		"relative/client",
		" urn:client:1",
		"https://example.test/a b",
		"urn:client:1#fragment",
		exact + "a",
		string([]byte{0xff}),
	}
	for _, identity := range tests {
		if err := ValidateExactAbsoluteURI(identity); err == nil {
			t.Fatalf("invalid identity accepted: %q", identity)
		}
	}
}
