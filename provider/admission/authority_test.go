package admission

import (
	"strings"
	"testing"
)

func TestNewAdmissionAuthorityAcceptsExactGenericIssuer(t *testing.T) {
	authority, err := NewAdmissionAuthority(testAdmissionIssuer, testProviderRevision, testProviderAudience)
	if err != nil {
		t.Fatalf("NewAdmissionAuthority() error = %v", err)
	}
	if authority.Issuer() != testAdmissionIssuer ||
		authority.ProviderRevisionID() != testProviderRevision ||
		authority.ProviderInstanceAudience() != testProviderAudience {
		t.Fatalf("authority = %#v", authority)
	}
}

func TestNewAdmissionAuthorityAcceptsExplicitLegacyStringOrURI(t *testing.T) {
	authority, err := NewAdmissionAuthority("agent-platform", testProviderRevision, testProviderAudience)
	if err != nil {
		t.Fatalf("NewAdmissionAuthority() error = %v", err)
	}
	if authority.Issuer() != "agent-platform" {
		t.Fatalf("Issuer() = %q", authority.Issuer())
	}
}

func TestNewAdmissionAuthorityRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		revision string
		audience string
	}{
		{name: "empty issuer", issuer: "", revision: testProviderRevision, audience: testProviderAudience},
		{name: "whitespace issuer", issuer: " " + testAdmissionIssuer, revision: testProviderRevision, audience: testProviderAudience},
		{name: "invalid UTF-8 issuer", issuer: string([]byte{0xff}), revision: testProviderRevision, audience: testProviderAudience},
		{name: "oversized issuer", issuer: strings.Repeat("i", maxAdmissionAuthorityTextRunes+1), revision: testProviderRevision, audience: testProviderAudience},
		{name: "malformed URI issuer", issuer: "https://caller.example.invalid/%zz", revision: testProviderRevision, audience: testProviderAudience},
		{name: "fragment issuer", issuer: testAdmissionIssuer + "#fragment", revision: testProviderRevision, audience: testProviderAudience},
		{name: "empty revision", issuer: testAdmissionIssuer, revision: "", audience: testProviderAudience},
		{name: "oversized revision", issuer: testAdmissionIssuer, revision: strings.Repeat("r", maxAdmissionAuthorityTextRunes+1), audience: testProviderAudience},
		{name: "invalid audience", issuer: testAdmissionIssuer, revision: testProviderRevision, audience: "provider-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewAdmissionAuthority(test.issuer, test.revision, test.audience); err == nil {
				t.Fatal("NewAdmissionAuthority() error = nil")
			}
		})
	}
}
