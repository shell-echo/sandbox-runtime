package admission

import (
	"errors"
	"net/url"
	"strings"
)

const maxAdmissionAuthorityTextRunes = 200

// AdmissionAuthority is the immutable Provider-local identity selected for one
// protected listener. It is never populated from bearer claims or an admission
// context supplied by the caller.
type AdmissionAuthority struct {
	issuer                   string
	providerRevisionID       string
	providerInstanceAudience string
}

// NewAdmissionAuthority validates and freezes the exact issuer, Provider
// revision, and Provider-instance audience accepted by one protected listener.
// Issuer follows JWT StringOrURI rules: a value containing ':' must be an exact
// absolute URI. Fragment-bearing identifiers are rejected to avoid ambiguous
// trust identities.
func NewAdmissionAuthority(issuer, providerRevisionID, providerInstanceAudience string) (AdmissionAuthority, error) {
	if !validIssuer(issuer) {
		return AdmissionAuthority{}, errors.New("provider admission issuer is invalid")
	}
	if !validBoundedText(providerRevisionID, 1, maxAdmissionAuthorityTextRunes) {
		return AdmissionAuthority{}, errors.New("provider admission revision is invalid")
	}
	if !audiencePattern.MatchString(providerInstanceAudience) {
		return AdmissionAuthority{}, errors.New("provider admission audience is invalid")
	}
	return AdmissionAuthority{
		issuer:                   issuer,
		providerRevisionID:       providerRevisionID,
		providerInstanceAudience: providerInstanceAudience,
	}, nil
}

// Issuer returns the exact configured JWT issuer.
func (a AdmissionAuthority) Issuer() string { return a.issuer }

// ProviderRevisionID returns the exact Provider revision protected by the
// listener.
func (a AdmissionAuthority) ProviderRevisionID() string { return a.providerRevisionID }

// ProviderInstanceAudience returns the exact audience protected by the
// listener.
func (a AdmissionAuthority) ProviderInstanceAudience() string { return a.providerInstanceAudience }

func (a AdmissionAuthority) valid() bool {
	return validIssuer(a.issuer) &&
		validBoundedText(a.providerRevisionID, 1, maxAdmissionAuthorityTextRunes) &&
		audiencePattern.MatchString(a.providerInstanceAudience)
}

func validIssuer(issuer string) bool {
	if !validBoundedText(issuer, 1, maxAdmissionAuthorityTextRunes) || strings.TrimSpace(issuer) != issuer {
		return false
	}
	if !strings.Contains(issuer, ":") {
		return true
	}
	parsed, err := url.Parse(issuer)
	return err == nil && parsed.IsAbs() && parsed.Scheme != "" && parsed.Fragment == "" && parsed.String() == issuer
}
